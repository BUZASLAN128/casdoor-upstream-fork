package object

import (
	"errors"
	"testing"

	"github.com/casdoor/casdoor/pp"
)

func TestTenantCheckoutProtectedPricingRejectsPersonalBeforeStorage(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "commerce")
	if ormer != nil {
		t.Fatal("unit test must have no database")
	}
	infos := []ProductInfo{{Name: "product", PricingName: "commerce", PlanName: "plan", Quantity: 1}}
	if _, err := PlaceOrder("org", infos, nil, ""); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatalf("personal placement reached storage: %v", err)
	}
	mixed := append([]ProductInfo{{Name: "other", PricingName: "personal", Quantity: 1}}, infos...)
	if _, err := PlaceOrder("org", mixed, nil, ""); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatalf("mixed checkout reached storage: %v", err)
	}
	legacy := &Order{Owner: "org", State: "Created", User: "payer", ProductInfos: infos}
	if _, _, err := PayOrder("dummy", "127.0.0.1", "demo", legacy, nil, "en"); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatalf("old personal order reached provider: %v", err)
	}
	if _, _, err := BuyProduct("org/product", nil, "dummy", "commerce", "plan", "127.0.0.1", "demo", 0, "en", ""); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatalf("legacy buy-product reached storage/provider: %v", err)
	}
	for _, principal := range []string{"org/payer", "app/foreign", "built-in/admin"} {
		if err := CheckTenantCheckoutRequest(principal, "org", "tenant", infos); !errors.Is(err, ErrTenantCheckoutRequired) {
			t.Fatalf("browser principal %s established protected Group checkout", principal)
		}
	}
	if err := CheckTenantCheckoutRequest("app/cerberus", "org", "tenant", infos); err != nil {
		t.Fatal(err)
	}
	if err := CheckTenantCheckoutRequest("app/cerberus", "foreign", "", infos); err != nil {
		t.Fatal("changed another organization personal checkout")
	}
	other := []ProductInfo{{Name: "product", PricingName: "personal", PlanName: "plan", Quantity: 1}}
	if err := CheckTenantCheckoutRequest("org/payer", "org", "", other); err != nil {
		t.Fatal("changed another pricing personal checkout")
	}
	if err := CheckTenantCheckoutRequest("app/cerberus", "org", "tenant", other); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("Group checkout accepted another pricing")
	}
}

func TestTenantCheckoutPartialBindingFailsClosed(t *testing.T) {
	for _, missing := range []string{"tenantCheckoutApplication", "tenantCheckoutOrganization", "tenantCheckoutPricing"} {
		t.Setenv("tenantCheckoutApplication", "app/cerberus")
		t.Setenv("tenantCheckoutOrganization", "org")
		t.Setenv("tenantCheckoutPricing", "commerce")
		t.Setenv(missing, "")
		if err := CheckTenantCheckoutRequest("", "org", "", []ProductInfo{{PricingName: "commerce"}}); !errors.Is(err, ErrTenantCheckoutRequired) {
			t.Fatalf("partial %s binding silently enabled personal payment", missing)
		}
		if err := CheckTenantCheckoutPrincipal("app/cerberus", "org"); !errors.Is(err, ErrTenantCheckoutRequired) {
			t.Fatalf("partial %s binding enabled Group checkout", missing)
		}
	}
	t.Setenv("tenantCheckoutApplication", "")
	t.Setenv("tenantCheckoutOrganization", "")
	t.Setenv("tenantCheckoutPricing", "")
	if err := CheckTenantCheckoutRequest("org/payer", "org", "", []ProductInfo{{PricingName: "personal"}}); err != nil {
		t.Fatal("all-blank config changed personal checkout")
	}
	if err := CheckTenantCheckoutRequest("app/cerberus", "org", "tenant", []ProductInfo{{PricingName: "commerce"}}); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("all-blank config enabled Group checkout")
	}
}

func TestTenantCheckoutPrincipalIsConfiguredApplicationOnly(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "tenant-org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	if err := CheckTenantCheckoutPrincipal("app/cerberus", "tenant-org"); err != nil {
		t.Fatal(err)
	}
	for _, principal := range []string{"", "tenant-org/payer", "built-in/admin", "app/other", "app-dcr/cerberus"} {
		if err := CheckTenantCheckoutPrincipal(principal, "tenant-org"); err == nil {
			t.Errorf("accepted untrusted principal %q", principal)
		}
	}
	if err := CheckTenantCheckoutPrincipal("app/cerberus", "foreign-org"); err == nil {
		t.Fatal("accepted a foreign organization")
	}
	t.Setenv("tenantCheckoutApplication", "")
	if err := CheckTenantCheckoutPrincipal("app/cerberus", "tenant-org"); err == nil {
		t.Fatal("unset configuration must fail closed")
	}
}

func TestTenantCheckoutRejectsForeignOrUnavailablePayer(t *testing.T) {
	infos := []ProductInfo{{Name: "product", PlanName: "plan", PricingName: "pricing", Quantity: 1}}
	if err := validateTenantCheckoutIdentity("org", "group", &User{Owner: "org", Name: "payer"}, infos); err != nil {
		t.Fatal(err)
	}
	for _, payer := range []*User{nil, {Owner: "other", Name: "payer"}, {Owner: "org"}, {Owner: "org", Name: "payer", IsForbidden: true}, {Owner: "org", Name: "payer", IsDeleted: true}} {
		if err := validateTenantCheckoutIdentity("org", "group", payer, infos); err == nil {
			t.Errorf("accepted unavailable or foreign payer: %#v", payer)
		}
	}
	if err := validateTenantCheckoutIdentity("org", "other/group", &User{Owner: "org", Name: "payer"}, infos); err == nil {
		t.Fatal("accepted qualified group from another organization")
	}
}

func TestTenantCheckoutOpenOrderReuseIsExactAndUnpaid(t *testing.T) {
	info := ProductInfo{Name: "product", PlanName: "plan", PricingName: "pricing", Quantity: 1}
	order := &Order{Owner: "org", Name: "order", Group: "group", User: "payer", State: "Created", ProductInfos: []ProductInfo{info}}
	if !sameGroupCheckoutRequest(order, "payer", []ProductInfo{info}) {
		t.Fatal("lost-response retry must reuse its exact order")
	}
	if sameGroupCheckoutRequest(order, "other", []ProductInfo{info}) {
		t.Fatal("reused another payer's order")
	}
	changed := info
	changed.PlanName = "other-plan"
	if sameGroupCheckoutRequest(order, "payer", []ProductInfo{changed}) {
		t.Fatal("reused another plan's order")
	}
	for _, state := range []string{"Paid", "Processing", "Canceled", "Failed"} {
		order.State = state
		if sameGroupCheckoutRequest(order, "payer", []ProductInfo{info}) {
			t.Errorf("reused order in %s", state)
		}
	}
}

func TestTenantCheckoutPaymentCannotSubstituteGroupOrPayer(t *testing.T) {
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", Payment: "payment", Price: 5, Currency: "USD", Products: []string{"product"}}
	payment := Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", Order: "order", Price: 5, Currency: "USD", Products: []string{"product"}}
	if err := validateGroupPayment(order, &payment); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Payment){
		func(p *Payment) { p.Group = "foreign" },
		func(p *Payment) { p.User = "another-payer" },
		func(p *Payment) { p.Owner = "foreign-org" },
		func(p *Payment) { p.Order = "foreign-order" },
		func(p *Payment) { p.Price = 0 },
		func(p *Payment) { p.Products = []string{"other"} },
	} {
		forged := payment
		mutate(&forged)
		if err := validateGroupPayment(order, &forged); err == nil {
			t.Fatal("accepted substituted payment context")
		}
	}
}

func TestTenantCheckoutDummyNeedsTrustedDeploymentAndExplicitOptIn(t *testing.T) {
	for _, environment := range []string{"", "prod", "production", "unknown", "demo", "dev", "test"} {
		t.Setenv("paymentDeploymentEnvironment", environment)
		for _, enabled := range []string{"", "false", "true"} {
			t.Setenv("allowDummyPayment", enabled)
			_, err := GetPaymentProvider(&Provider{Type: "Dummy"})
			allowed := enabled == "true" && (environment == "demo" || environment == "dev" || environment == "test")
			if (err == nil) != allowed {
				t.Errorf("environment=%q optIn=%q err=%v", environment, enabled, err)
			}
		}
	}
	t.Setenv("paymentDeploymentEnvironment", "prod")
	t.Setenv("allowDummyPayment", "true")
	_, err := completeGroupPayment(&Payment{Type: "Dummy"}, &pp.NotifyResult{PaymentStatus: pp.PaymentStatePaid}, nil)
	if err == nil {
		t.Fatal("existing Dummy payment bypassed deployment gate")
	}
	if err := checkDummyPayment("Stripe"); err != nil {
		t.Fatal("changed another provider's contract")
	}
}

func TestTenantCheckoutPersonalSubscriptionRemainsPersonal(t *testing.T) {
	sub, err := NewSubscription("org", "payer", "plan", "payment", PeriodMonthly)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Group != "" || sub.User != "payer" || sub.State != SubStatePending || sub.Payment != "payment" {
		t.Fatalf("changed personal subscription: %#v", sub)
	}
}
