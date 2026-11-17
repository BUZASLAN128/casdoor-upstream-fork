package object

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/casdoor/casdoor/pp"
)

func checkoutUnitPeriod(t *testing.T, start, end string) *groupPaidPeriod {
	t.Helper()
	sub := &Subscription{Owner: "org", Name: "sub_order", Group: "tenant", Plan: "plan", Pricing: "pricing", Payment: "payment", StartTime: start, EndTime: end, Period: PeriodMonthly, State: SubStateActive}
	revision, err := groupPeriodRevision(sub)
	if err != nil {
		t.Fatal(err)
	}
	s, e, _ := checkoutInterval(start, end)
	return &groupPaidPeriod{Sub: sub, Start: s, End: e, Revision: revision}
}

func TestTenantCheckoutPeriodFingerprintCanonicalVersionedAndUnambiguous(t *testing.T) {
	period := checkoutUnitPeriod(t, "2026-11-01T03:00:00+03:00", "2026-12-01T03:00:00+03:00")
	// Independent fixed encoding oracle, not a call back into the encoder.
	canonical := `{"encoding":"casdoor-group-period/v1","fields":["org","tenant","sub_order","plan","pricing","payment","2026-11-01T00:00:00Z","2026-12-01T00:00:00Z","Monthly","direct-paid"]}`
	sum := sha256.Sum256([]byte(canonical))
	if period.Revision != hex.EncodeToString(sum[:]) {
		t.Fatal("changed v1 canonical period fingerprint")
	}
	copy := *period.Sub
	copy.StartTime, copy.EndTime, copy.State, copy.DisplayName = "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z", SubStateExpired, "changed display"
	if revision, err := groupPeriodRevision(&copy); err != nil || revision != period.Revision {
		t.Fatal("mutable state/display or timezone changed financial identity")
	}
	for _, mutate := range []func(*Subscription){
		func(s *Subscription) { s.Group = "other" }, func(s *Subscription) { s.Plan = "other" }, func(s *Subscription) { s.Payment = "other" }, func(s *Subscription) { s.EndTime = "2026-12-02T00:00:00Z" },
	} {
		changed := *period.Sub
		mutate(&changed)
		if revision, err := groupPeriodRevision(&changed); err != nil || revision == period.Revision {
			t.Fatal("different financial period reused a fingerprint")
		}
	}
	for _, mutate := range []func(*Subscription){func(s *Subscription) { s.Payment = "" }, func(s *Subscription) { s.User = "payer" }, func(s *Subscription) { s.EndTime = s.StartTime }, func(s *Subscription) { s.StartTime = "malformed" }} {
		changed := *period.Sub
		mutate(&changed)
		if _, err := groupPeriodRevision(&changed); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("malformed period became proof of absence")
		}
	}
}

func TestTenantCheckoutNextPeriodWindowAndStaleQuoteNeverRebases(t *testing.T) {
	previous := checkoutUnitPeriod(t, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	window := previous.End.AddDate(0, 0, -14)
	early, _ := groupTimeline([]*groupPaidPeriod{previous}, window.Add(-time.Nanosecond))
	if allowed, reason := periodPurchaseEligibility(early, window.Add(-time.Nanosecond)); allowed || reason != "outside_window" {
		t.Fatal("early next-period charge allowed")
	}
	timeline, _ := groupTimeline([]*groupPaidPeriod{previous}, window)
	terms, err := newCheckoutTerms(timeline, previous.Revision, PeriodYearly, window)
	if err != nil || terms.Kind != "next" || terms.StartTime != "2026-12-01T00:00:00Z" || terms.EndTime != "2027-12-01T00:00:00Z" {
		t.Fatal("window boundary or immutable next period is wrong")
	}
	if _, err := newCheckoutTerms(timeline, "none", PeriodYearly, window); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("stale absence bypassed predecessor")
	}
	justBefore := previous.End.Add(-time.Nanosecond)
	timeline, _ = groupTimeline([]*groupPaidPeriod{previous}, justBefore)
	if claimed, err := claimCheckoutTerms(terms, timeline, justBefore); err != nil || *claimed != *terms {
		t.Fatal("valid quoted next term changed at claim")
	}
	for _, now := range []time.Time{previous.End, previous.End.Add(time.Hour)} {
		timeline, _ = groupTimeline([]*groupPaidPeriod{previous}, now)
		if timeline.revision() != "none" {
			t.Fatal("half-open ended period stayed current")
		}
		if _, err := claimCheckoutTerms(terms, timeline, now); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("stale next quote silently became a fresh purchase")
		}
	}
}

func TestTenantCheckoutFreshClaimFreezesDatesAndLateConfirmationCanExpire(t *testing.T) {
	quotedAt := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	timeline, _ := groupTimeline(nil, quotedAt)
	terms, err := newCheckoutTerms(timeline, "none", PeriodMonthly, quotedAt)
	if err != nil || terms.StartTime != "" || terms.EndTime != "" {
		t.Fatal("fresh quote sampled claim dates early")
	}
	claimTime := quotedAt.Add(2 * time.Hour)
	claimed, err := claimCheckoutTerms(terms, timeline, claimTime)
	if err != nil || claimed.StartTime != "2026-11-12T14:00:00Z" || claimed.EndTime != "2026-12-12T14:00:00Z" || terms.StartTime != "" {
		t.Fatal("claim did not freeze a copy at its single server time")
	}
	sub := &Subscription{StartTime: claimed.StartTime, EndTime: claimed.EndTime, State: SubStateActive}
	end, _ := time.Parse(time.RFC3339, claimed.EndTime)
	if state, err := effectiveGroupPeriodState(sub, end); err != nil || state != SubStateExpired {
		t.Fatal("late confirmation extended or revived the fixed term")
	}
	if _, err := claimCheckoutTerms(claimed, timeline, end); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("claimed dates were reused as an unattempted quote")
	}
}

func TestTenantCheckoutCurrentUpcomingHalfOpenRolloverAndOverlap(t *testing.T) {
	first := checkoutUnitPeriod(t, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	next := checkoutUnitPeriod(t, "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z")
	next.Sub.Name, next.Sub.Payment = "sub_next", "payment_next"
	next.Revision, _ = groupPeriodRevision(next.Sub)
	timeline, err := groupTimeline([]*groupPaidPeriod{next, first}, first.End.Add(-time.Nanosecond))
	if err != nil || timeline.Current != first || timeline.Upcoming != next {
		t.Fatal("current entitlement was replaced by its next period")
	}
	if allowed, reason := periodPurchaseEligibility(timeline, first.End.Add(-time.Nanosecond)); allowed || reason != "upcoming_exists" {
		t.Fatal("second upcoming purchase allowed")
	}
	timeline, err = groupTimeline([]*groupPaidPeriod{first, next}, first.End)
	if err != nil || timeline.Current != next || timeline.Upcoming != nil {
		t.Fatal("rollover depends on an absent state-update job")
	}
	overlap := *next
	overlap.Start = first.End.Add(-time.Nanosecond)
	if _, err := groupTimeline([]*groupPaidPeriod{first, &overlap}, first.End); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("overlapping paid periods accepted")
	}
	if _, err := groupTimeline([]*groupPaidPeriod{first, next}, first.Start.Add(-time.Nanosecond)); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("ambiguous multiple upcoming periods accepted")
	}
}

func TestTenantCheckoutPaidPeriodRequiresExactFinancialBinding(t *testing.T) {
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "true")
	period := checkoutUnitPeriod(t, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", Payment: "payment", Price: 5, Currency: "USD", Products: []string{"product"}, ProductInfos: []ProductInfo{{Name: "product", PlanName: "plan", PricingName: "pricing", Quantity: 1}}, State: "Paid"}
	payment := &Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", Order: "order", Price: 5, Currency: "USD", Products: []string{"product"}, Provider: "dummy", Type: "Dummy", State: pp.PaymentStatePaid}
	if _, err := paidGroupPeriod(period.Sub, order, payment); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Payment){func(p *Payment) { p.State = pp.PaymentStateCreated }, func(p *Payment) { p.Group = "other" }, func(p *Payment) { p.Price = 0 }, func(p *Payment) { p.Type = "" }} {
		copy := *payment
		mutate(&copy)
		if _, err := paidGroupPeriod(period.Sub, order, &copy); err == nil {
			t.Fatal("unpaid/forged period established canonical revision")
		}
	}
	t.Setenv("paymentDeploymentEnvironment", "prod")
	if _, err := paidGroupPeriod(period.Sub, order, payment); !errors.Is(err, ErrGroupCheckoutUnavailable) {
		t.Fatal("prod accepted a Dummy entitlement")
	}
}

func TestTenantCheckoutMalformedSnapshotAndConsumedRevisionFailClosed(t *testing.T) {
	timeline, _ := groupTimeline(nil, time.Now())
	valid, _ := newCheckoutTerms(timeline, "none", PeriodMonthly, time.Now())
	for _, mutate := range []func(*GroupCheckoutTerms){func(t *GroupCheckoutTerms) { t.Version = 2 }, func(t *GroupCheckoutTerms) { t.Kind = "renewal" }, func(t *GroupCheckoutTerms) { t.Period = "Unlimited" }, func(t *GroupCheckoutTerms) { t.PreviousPeriodRevision = "unknown" }, func(t *GroupCheckoutTerms) { t.EndTime = "2027-01-01T00:00:00Z" }} {
		copy := *valid
		mutate(&copy)
		if validateCheckoutTerms(&copy, false) == nil {
			t.Fatal("invalid version/period/partial terms accepted")
		}
	}
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", State: "Created", CheckoutRevision: 7}
	if checkGroupOrderCancellation(order, order, 7) != nil {
		t.Fatal("current predispatch revision rejected")
	}
	canceled := *order
	canceled.State, canceled.CheckoutRevision = "Canceled", 8
	if checkGroupOrderCancellation(&canceled, order, 7) != nil {
		t.Fatal("original consumed revision replay rejected")
	}
	for _, revision := range []int64{-1, 0, 6, 8, 9} {
		if checkGroupOrderCancellation(&canceled, order, revision) == nil {
			t.Fatal("arbitrary stale/current cancellation replay accepted")
		}
	}
	if _, err := nextCheckoutRevision(math.MaxInt64); err == nil {
		t.Fatal("revision wrapped")
	}
}

func TestTenantCheckoutManagerBindingNeverUsesOrgOrInheritedRoleAlone(t *testing.T) {
	member := &User{Owner: "org", Name: "manager", Groups: []string{"org/tenant"}}
	if !checkoutDirectMember(member, "org", "tenant") {
		t.Fatal("exact direct binding rejected")
	}
	for _, mutate := range []func(*User){func(u *User) { u.Groups = nil; u.IsAdmin = true }, func(u *User) { u.Groups = []string{"org/parent"} }, func(u *User) { u.Groups = []string{"other/tenant"} }, func(u *User) { u.Owner = "other" }, func(u *User) { u.IsForbidden = true }, func(u *User) { u.IsDeleted = true }} {
		copy := *member
		mutate(&copy)
		if checkoutDirectMember(&copy, "org", "tenant") {
			t.Fatal("nonmember/foreign/disabled actor binding accepted")
		}
	}
}

func TestTenantCheckoutGenericWritesCannotSupplyTermsOrRevisionBeforeStorage(t *testing.T) {
	if ormer != nil {
		t.Fatal("requires no initialized DB")
	}
	for _, order := range []*Order{{CheckoutRevision: 1}, {CheckoutTerms: &GroupCheckoutTerms{Version: 1}}} {
		if _, err := AddOrder(order); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("generic insert accepted client checkout metadata")
		}
		if _, err := UpdateOrder("org/order", order); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("generic update accepted client checkout metadata")
		}
	}
	old := &Subscription{Owner: "org", Name: "sub", Group: "tenant", Payment: "payment", StartTime: "start", EndTime: "end", Period: PeriodMonthly}
	for _, mutate := range []func(*Subscription){func(s *Subscription) { s.StartTime = "changed" }, func(s *Subscription) { s.EndTime = "changed" }, func(s *Subscription) { s.Period = PeriodYearly }, func(s *Subscription) { s.Group = "changed" }, func(s *Subscription) { s.CreatedTime = "changed" }} {
		copy := *old
		mutate(&copy)
		if samePaidGroupSubscriptionTerms(old, &copy) {
			t.Fatal("generic paid-term rewrite accepted")
		}
	}
	copy := *old
	copy.State = SubStateExpired
	copy.DisplayName = "renamed"
	if !samePaidGroupSubscriptionTerms(old, &copy) {
		t.Fatal("native temporal/manual policy metadata was made immutable")
	}
}

func TestTenantCheckoutLateFreshNeedsPositiveBoundPaymentAndMatchingWinnerTime(t *testing.T) {
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "true")
	period := checkoutUnitPeriod(t, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", Payment: "payment", Price: 5, Currency: "USD", Products: []string{"product"}, ProductInfos: []ProductInfo{{Name: "product", PricingName: "pricing", PlanName: "plan", Quantity: 1}}, State: "Paid", CheckoutRevision: 3,
		CheckoutTerms: &GroupCheckoutTerms{Version: 1, Kind: "fresh", PreviousPeriodRevision: "none", StartTime: period.Sub.StartTime, EndTime: period.Sub.EndTime, Period: PeriodMonthly}}
	payment := &Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", Order: "order", Price: 5, Currency: "USD", Products: []string{"product"}, Provider: "dummy", Type: "Dummy", State: pp.PaymentStatePaid}
	period.Order, period.Payment = order, payment
	period.Sub.State = SubStateExpired
	period.Sub.CreatedTime, order.UpdateTime = "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"
	if latestLateFreshPeriod([]*groupPaidPeriod{period}) != nil {
		t.Fatal("ordinary later expiry was called late confirmation")
	}
	period.Sub.CreatedTime, order.UpdateTime = "2026-12-01T00:00:00Z", "2026-12-01T00:00:00Z"
	if latestLateFreshPeriod([]*groupPaidPeriod{period}) != period {
		t.Fatal("positive fixed-end boundary evidence lost")
	}
	for _, mutate := range []func(){
		func() { order.UpdateTime = "2026-12-02T00:00:00Z" },
		func() { order.CheckoutTerms = nil },
		func() { payment.Group = "foreign" },
		func() { order.CheckoutRevision = 2 },
	} {
		oldOrder := *order
		oldPayment := *payment
		mutate()
		if latestLateFreshPeriod([]*groupPaidPeriod{period}) != nil {
			t.Fatal("legacy/contradictory metadata manufactured late evidence")
		}
		*order, *payment = oldOrder, oldPayment
	}
}

func TestTenantCheckoutCancelRequiresConfiguredAppBeforeStorage(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	if ormer != nil {
		t.Fatal("requires no DB")
	}
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "original", State: "Created", CheckoutRevision: 1}
	for _, principal := range []string{"", "org/manager", "built-in/admin", "app/other"} {
		if _, err := CancelGroupOrder(principal, "manager", order, 1); !errors.Is(err, ErrTenantCheckoutRequired) {
			t.Fatal("wrong principal reached cancellation storage")
		}
	}
}
