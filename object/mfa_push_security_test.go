package object

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCerberusSecurityPushMfaRequiresNotificationApprovalToken(t *testing.T) {
	challenge := &PushChallenge{
		Id:            "polling-id",
		ApprovalToken: "notification-only-approval-token",
		UserId:        "org-a/alice",
		Provider:      "admin/provider",
		Receiver:      "receiver",
		Status:        PushChallengePending,
		CreatedTime:   time.Now(),
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushChallengeApprovals.Store(challenge.ApprovalToken, challenge.Id)
	defer deletePushChallenge(challenge)

	if _, err := AnswerPushChallenge(challenge.Id, true); err == nil {
		t.Fatal("the polling identifier returned to the initiating browser must not approve the challenge")
	}
	if challenge.Status != PushChallengePending {
		t.Fatalf("polling identifier changed challenge status to %q", challenge.Status)
	}
	if polled := GetPushChallenge(challenge.Id); polled == nil || polled.Id != challenge.Id || polled.ApprovalToken != "" {
		t.Fatal("the initiating browser must still be able to poll by the public identifier")
	}
	if confirmed := GetPushChallenge(challenge.ApprovalToken); confirmed == nil || confirmed.Id != challenge.Id || confirmed.ApprovalToken != "" {
		t.Fatal("the notification confirmation page must resolve the separate approval token")
	}

	encoded, err := json.Marshal(challenge)
	if err != nil {
		t.Fatalf("marshal challenge: %v", err)
	}
	if strings.Contains(string(encoded), challenge.ApprovalToken) {
		t.Fatal("the approval token must not be exposed in the challenge response")
	}

	approved, err := AnswerPushChallenge(challenge.ApprovalToken, true)
	if err != nil {
		t.Fatalf("approve with notification token: %v", err)
	}
	if approved.Status != PushChallengeApproved {
		t.Fatalf("approval token produced status %q", approved.Status)
	}
	if err = consumePushChallenge(challenge.Id, challenge.UserId, challenge.Provider, challenge.Receiver); err != nil {
		t.Fatalf("consume approved challenge with polling identifier: %v", err)
	}
	if GetPushChallenge(challenge.Id) != nil || GetPushChallenge(challenge.ApprovalToken) != nil {
		t.Fatal("consuming a challenge must invalidate both identifiers")
	}
}

func TestCerberusSecurityPushMfaBindsUserAndConsumesOnce(t *testing.T) {
	challenge := &PushChallenge{
		Id:            "single-use-polling-id",
		ApprovalToken: "single-use-approval-token",
		UserId:        "org-a/alice",
		Provider:      "admin/provider",
		Receiver:      "shared-receiver",
		Status:        PushChallengePending,
		CreatedTime:   time.Now(),
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushChallengeApprovals.Store(challenge.ApprovalToken, challenge.Id)
	defer deletePushChallenge(challenge)

	if _, err := AnswerPushChallenge(challenge.ApprovalToken, true); err != nil {
		t.Fatalf("approve challenge: %v", err)
	}
	if err := consumePushChallenge(challenge.Id, "org-b/bob", challenge.Provider, challenge.Receiver); err == nil {
		t.Fatal("a challenge was consumed for a different user with the same provider and receiver")
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if consumePushChallenge(challenge.Id, challenge.UserId, challenge.Provider, challenge.Receiver) == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent consumption succeeded %d times, want exactly once", got)
	}
}

func TestCerberusSecurityPushMfaExpiryInvalidatesBothIdentifiers(t *testing.T) {
	challenge := &PushChallenge{
		Id:            "expired-polling-id",
		ApprovalToken: "expired-approval-token",
		Status:        PushChallengePending,
		CreatedTime:   time.Now().Add(-3 * pushChallengeLifetime),
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushChallengeApprovals.Store(challenge.ApprovalToken, challenge.Id)
	defer deletePushChallenge(challenge)

	if GetPushChallenge(challenge.ApprovalToken) != nil {
		t.Fatal("an expired approval token must not resolve a challenge")
	}
	if _, ok := pushChallenges.Load(challenge.Id); ok {
		t.Fatal("expired polling identifier remained stored")
	}
	if _, ok := pushChallengeApprovals.Load(challenge.ApprovalToken); ok {
		t.Fatal("expired approval token remained stored")
	}
}

func TestCerberusSecurityPushMfaApprovalDoesNotExtendExpiry(t *testing.T) {
	challenge := &PushChallenge{
		Id:            "expired-approved-polling-id",
		ApprovalToken: "expired-approved-token",
		UserId:        "org-a/alice",
		Provider:      "admin/provider",
		Receiver:      "receiver",
		Status:        PushChallengeApproved,
		CreatedTime:   time.Now().Add(-pushChallengeLifetime - time.Second),
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushChallengeApprovals.Store(challenge.ApprovalToken, challenge.Id)
	defer deletePushChallenge(challenge)

	polled := GetPushChallenge(challenge.Id)
	if polled == nil || polled.Status != PushChallengeExpired {
		t.Fatalf("approved challenge status after expiry = %#v, want Expired", polled)
	}
	if err := consumePushChallenge(challenge.Id, challenge.UserId, challenge.Provider, challenge.Receiver); err == nil {
		t.Fatal("an approval was consumed after its five-minute lifetime")
	}
}

func TestCerberusSecurityPushMfaTransitionsRecheckExpiryUnderLock(t *testing.T) {
	challenge := &PushChallenge{
		Id:            "transition-expired-polling-id",
		ApprovalToken: "transition-expired-approval-token",
		UserId:        "org-a/alice",
		Provider:      "admin/provider",
		Receiver:      "receiver",
		Status:        PushChallengePending,
		CreatedTime:   time.Now().Add(-pushChallengeLifetime),
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushChallengeApprovals.Store(challenge.ApprovalToken, challenge.Id)
	defer deletePushChallenge(challenge)

	answered, err := AnswerPushChallenge(challenge.ApprovalToken, true)
	if err == nil {
		t.Fatal("an approval transition succeeded at the expiry boundary")
	}
	if answered == nil || answered.Status != PushChallengeExpired {
		t.Fatalf("expired approval returned %#v, want Expired", answered)
	}
	if err = consumePushChallenge(challenge.Id, challenge.UserId, challenge.Provider, challenge.Receiver); err == nil {
		t.Fatal("an expired challenge was consumed")
	}
}
