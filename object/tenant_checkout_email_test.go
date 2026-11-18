package object

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/pp"
)

func TestTenantCheckoutPaymentMailRunsOnceAfterWinningCommit(t *testing.T) {
	payment := &Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", PersonEmail: "untrusted@example.test", Type: "Dummy", State: pp.PaymentStatePaid}
	committed, sends := false, 0
	context := &groupPaymentEmailContext{payer: &User{Owner: "org", Name: "payer", Email: "current@example.test", EmailVerified: true, Language: "en"}, provider: &Provider{Owner: "org", Category: "Email"}, sender: "Application"}
	notify := func(payment *Payment) {
		if !committed {
			t.Fatal("mail ran before transaction commit")
		}
		status := attemptGroupPaymentEmail(payment, func(*Payment) (*groupPaymentEmailContext, error) { return context, nil }, func(_ *Provider, title, body string, to []string, _ string) error {
			sends++
			if !reflect.DeepEqual(to, []string{"current@example.test"}) {
				t.Fatalf("mail recipient was not current persisted payer: %v", to)
			}
			if !strings.Contains(title, "Test payment") || !strings.Contains(body, "No money was collected") {
				t.Fatal("Dummy mail presented a real collection")
			}
			return errors.New("SMTP failure with recipient and secret payload")
		})
		if status != "failed" {
			t.Fatalf("mail failure must return only a bounded status: %s", status)
		}
	}
	commit := func() error { committed = true; return nil }
	paid, err := finishGroupPayment(commit, payment, pp.PaymentStateCreated, notify)
	if err != nil || paid != payment || paid.State != pp.PaymentStatePaid || !committed || sends != 1 {
		t.Fatalf("mail failure changed successful payment: %v sends=%d", err, sends)
	}
	if _, err = finishGroupPayment(commit, payment, pp.PaymentStatePaid, notify); err != nil || sends != 1 {
		t.Fatal("duplicate paid callback sent mail again")
	}
	if _, err = finishGroupPayment(commit, payment, pp.PaymentStateCanceled, notify); err != nil || sends != 1 {
		t.Fatal("non-Created transition sent payment mail")
	}
}

func TestTenantCheckoutPaymentMailSubmitsOnlyCurrentVerifiedPayer(t *testing.T) {
	payment := &Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", PersonEmail: "untrusted@example.test", Type: "Stripe", State: pp.PaymentStatePaid}
	loads, sends := 0, 0
	status := attemptGroupPaymentEmail(payment, func(stored *Payment) (*groupPaymentEmailContext, error) {
		loads++
		if stored.Owner != "org" || stored.User != "payer" {
			t.Fatal("looked up another payer")
		}
		return &groupPaymentEmailContext{payer: &User{Owner: "org", Name: "payer", Email: "current@example.test", EmailVerified: true, Language: "en"}, provider: &Provider{Owner: "org", Category: "Email"}}, nil
	}, func(_ *Provider, _ string, _ string, to []string, _ string) error {
		sends++
		if !reflect.DeepEqual(to, []string{"current@example.test"}) {
			t.Fatal("untrusted payment email overrode current verified recipient")
		}
		return nil
	})
	if status != "sent" || loads != 1 || sends != 1 {
		t.Fatalf("verified mail was not submitted once: %s %d %d", status, loads, sends)
	}
}

func TestTenantCheckoutPaymentMailDoesNotRunOnCommitFailure(t *testing.T) {
	payment := &Payment{State: pp.PaymentStatePaid}
	commitError := errors.New("transaction commit failed")
	result, err := finishGroupPayment(func() error { return commitError }, payment, pp.PaymentStateCreated, func(*Payment) { t.Fatal("mail ran after failed commit") })
	if !errors.Is(err, commitError) || result != nil {
		t.Fatal("failed commit was presented as payment success")
	}
}

func TestTenantCheckoutPaymentMailRejectsUnverifiedForeignOrMissingRecipient(t *testing.T) {
	payment := &Payment{Owner: "org", User: "payer", Group: "tenant", State: pp.PaymentStatePaid}
	for _, payer := range []*User{
		nil,
		{Owner: "org", Name: "payer", Email: "unverified@example.test"},
		{Owner: "foreign", Name: "payer", Email: "verified@example.test", EmailVerified: true},
		{Owner: "org", Name: "other", Email: "verified@example.test", EmailVerified: true},
		{Owner: "org", Name: "payer", EmailVerified: true},
		{Owner: "org", Name: "payer", Email: "invalid-address", EmailVerified: true},
		{Owner: "org", Name: "payer", Email: "deleted@example.test", EmailVerified: true, IsDeleted: true},
	} {
		status := attemptGroupPaymentEmail(payment, func(*Payment) (*groupPaymentEmailContext, error) {
			return &groupPaymentEmailContext{payer: payer, provider: &Provider{Owner: "org", Category: "Email"}}, nil
		}, func(*Provider, string, string, []string, string) error {
			t.Fatal("sent email to an unavailable/unverified/foreign recipient")
			return nil
		})
		if status != "skipped" {
			t.Fatalf("unexpected recipient refusal status: %s", status)
		}
	}
}

func TestTenantCheckoutPaymentMailFailurePrivacyAndNoRetry(t *testing.T) {
	payment := &Payment{Owner: "org", User: "payer", Group: "tenant", Type: "Stripe", State: pp.PaymentStatePaid}
	context := &groupPaymentEmailContext{payer: &User{Owner: "org", Name: "payer", Email: "current@example.test", EmailVerified: true, Language: "en"}, provider: &Provider{Owner: "org", Category: "Email"}}
	loads, sends := 0, 0
	load := func(*Payment) (*groupPaymentEmailContext, error) { loads++; return context, nil }
	status := attemptGroupPaymentEmail(payment, load, func(_ *Provider, title, body string, _ []string, _ string) error {
		sends++
		if strings.Contains(title, "Test") || strings.Contains(body, "No money") {
			t.Fatal("real provider mail mislabeled as Dummy")
		}
		panic("SMTP exception containing private recipient and credentials")
	})
	if status != "failed" || loads != 1 || sends != 1 {
		t.Fatalf("mail panic escaped or retried: status=%s loads=%d sends=%d", status, loads, sends)
	}
	status = attemptGroupPaymentEmail(payment, func(*Payment) (*groupPaymentEmailContext, error) {
		return nil, errors.New("lookup error with a private payload")
	}, func(*Provider, string, string, []string, string) error {
		t.Fatal("sent after lookup failure")
		return nil
	})
	if status != "unavailable" {
		t.Fatal("lookup payload leaked into notification status")
	}
	context.provider.Owner = "foreign"
	status = attemptGroupPaymentEmail(payment, load, func(*Provider, string, string, []string, string) error {
		t.Fatal("used another tenant email provider")
		return nil
	})
	if status != "unavailable" {
		t.Fatal("foreign provider was accepted")
	}
}
