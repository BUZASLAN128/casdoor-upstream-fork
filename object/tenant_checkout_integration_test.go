package object

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/xorm/contexts"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/casdoor/casdoor/pp"
	"github.com/xorm-io/xorm"
)

// This test never calls InitConfig/InitAdapter/CreateTables. The only permitted
// database is a newly created, process-local, in-memory SQLite database.

func checkoutFixtureAdmission(order *Order) GroupPaymentAdmission {
	principal := "app/" + order.Owner
	if order.Owner == "org" {
		principal = "app/cerberus"
	}
	return GroupPaymentAdmission{Principal: principal, Owner: order.Owner, Group: order.Group, OrderName: order.Name, PayerName: order.User, ExpectedCheckoutRevision: order.CheckoutRevision}
}

func TestTenantCheckoutDisposablePersistence(t *testing.T) {
	if os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_DB") != "memory" {
		t.Skip("requires explicit CASDOOR_TENANT_CHECKOUT_TEST_DB=memory on an authorized test host")
	}
	if ormer != nil {
		t.Fatal("refusing to replace an initialized shared database")
	}
	engine, err := xorm.NewEngine("sqlite", "file:tenant-checkout-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	ormer = &Ormer{Engine: engine, driverName: "sqlite"}
	t.Cleanup(func() { ormer = nil; engine.Close() })
	if err = engine.Sync2(&Order{}, &Payment{}, &Subscription{}, &Group{}, &User{}, &Pricing{}, &Plan{}, &Product{}, &Provider{}, &Application{}, &Transaction{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	t.Setenv("allowDummyPayment", "true")
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("origin", "https://casdoor.example.test")
	t.Setenv("originFrontend", "")
	payer := &User{Owner: "org", Name: "payer", Groups: []string{"org/tenant"}}
	for _, row := range []interface{}{
		&Application{Owner: "admin", Name: "cerberus", Organization: "org"},
		&Group{Owner: "org", Name: "tenant", IsEnabled: true},
		payer,
		&User{Owner: "org", Name: "other"},
		&Provider{Owner: "org", Name: "dummy", Category: "Payment", Type: "Dummy"},
		&Product{Owner: "org", Name: "product", Price: 5, Currency: "USD", Quantity: 10, Providers: []string{"dummy"}},
		&Plan{Owner: "org", Name: "plan", Product: "product", Period: PeriodMonthly, IsEnabled: true, Role: "unrelated-platform-role"},
		&Pricing{Owner: "org", Name: "pricing", Plans: []string{"plan"}, IsEnabled: true},
		&Pricing{Owner: "org", Name: "personal", Plans: []string{"plan"}, IsEnabled: true},
	} {
		if _, err = engine.Insert(row); err != nil {
			t.Fatal(err)
		}
	}
	infos := []ProductInfo{{Name: "product", PlanName: "plan", PricingName: "pricing", Quantity: 1}}
	order, err := PlaceGroupOrder("app/cerberus", "org", "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	retried, err := PlaceGroupOrder("app/cerberus", "org", "tenant", infos, payer, "none")
	if err != nil || retried.Name != order.Name {
		t.Fatalf("lost-response retry: order=%v err=%v", retried, err)
	}
	if _, err = PlaceGroupOrder("app/cerberus", "org", "foreign", infos, payer, "none"); err == nil {
		t.Fatal("accepted a missing/foreign group")
	}
	if _, err = PlaceGroupOrder("app/cerberus", "org", "tenant", infos, &User{Owner: "org", Name: "other"}, "none"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatalf("another payer must conflict, got %v", err)
	}
	payment, _, err := PayGroupOrder(checkoutFixtureAdmission(order), "dummy", "127.0.0.1:8000", "en")
	if err != nil {
		t.Fatal(err)
	}
	if payment.Group != "tenant" || payment.User != "payer" {
		t.Fatal("lost target or real payer")
	}
	if !strings.Contains(payment.SuccessUrl, "/buy-plan/org/pricing/result?payment="+payment.Name) {
		t.Fatal("tenant payment return bypassed the public result route")
	}
	changedOrder := *order
	changedOrder.Group = "foreign"
	if _, err = UpdateOrder(order.GetId(), &changedOrder); err == nil {
		t.Fatal("order target was reassigned")
	}
	changedPayment := *payment
	changedPayment.User = "other"
	if _, err = UpdatePayment(payment.GetId(), &changedPayment); err == nil {
		t.Fatal("payment payer was reassigned")
	}
	count, err := engine.Count(&Subscription{})
	if err != nil || count != 0 {
		t.Fatal("created a tenant subscription before provider confirmation")
	}
	// The notification body is never authority for a Group or payer.
	for i := 0; i < 2; i++ {
		paid, err := NotifyPayment([]byte(`{"group":"foreign","user":"other"}`), "org", payment.Name, "en")
		if err != nil || paid.State != pp.PaymentStatePaid {
			t.Fatalf("notification %d: payment=%v err=%v", i, paid, err)
		}
	}
	subs := []*Subscription{}
	if err = engine.Find(&subs); err != nil || len(subs) != 1 {
		t.Fatalf("replayed callback created duplicate subscriptions: %v %v", subs, err)
	}
	sub := subs[0]
	if sub.Owner != "org" || sub.Group != "tenant" || sub.User != "" || sub.Plan != "plan" || sub.Pricing != "pricing" || sub.Payment != payment.Name || sub.State != SubStateActive {
		t.Fatalf("non-canonical subscription: %#v", sub)
	}
	listed, err := GetPaginationSubscriptions("org", 0, 10, "group", "tenant", "", "")
	if err != nil || len(listed) != 1 || listed[0].Group != "tenant" {
		t.Fatalf("canonical Group paged reader: %v %v", listed, err)
	}
	count, err = engine.Count(&Transaction{})
	if err != nil || count != 1 {
		t.Fatalf("duplicate purchase bookkeeping: %d %v", count, err)
	}
	product, err := GetProduct("org/product")
	if err != nil || product.Quantity != 9 || product.Sold != 1 {
		t.Fatal("callback replay changed stock twice")
	}
	if _, err = PlaceGroupOrder("app/cerberus", "org", "tenant", infos, payer, "none"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatalf("active direct subscription must conflict: %v", err)
	}
	storedPayer, err := GetUser("org/payer")
	if err != nil || len(storedPayer.Roles) != 0 {
		t.Fatal("plan role leaked into user privileges")
	}
	personalInfos := []ProductInfo{{Name: "product", PlanName: "plan", PricingName: "personal", Quantity: 1}}
	personalOrder, err := PlaceOrder("org", personalInfos, payer, "")
	if err != nil || personalOrder.Group != "" {
		t.Fatalf("ordinary user order changed: %v", err)
	}
	personalPayment, _, err := PayOrder("dummy", "127.0.0.1:8000", "", personalOrder, nil, "en")
	if err != nil || personalPayment.Group != "" || personalPayment.User != "payer" {
		t.Fatalf("ordinary user payment changed: %v", err)
	}
	personalSubs := []*Subscription{}
	if err = engine.Where("payment = ?", personalPayment.Name).Find(&personalSubs); err != nil || len(personalSubs) != 1 || personalSubs[0].Group != "" || personalSubs[0].User != "payer" || personalSubs[0].State != SubStatePending {
		t.Fatal("ordinary user subscription behavior changed")
	}
	t.Setenv("paymentDeploymentEnvironment", "prod")
	if _, err = NotifyPayment(nil, "org", payment.Name, "en"); err == nil {
		t.Fatal("existing Dummy payment bypassed production denial")
	}
}

// These lifecycle cases reuse the exact opt-in task-CRDB fixture above. Clock
// seams select domain boundaries; no main/listener, provider network or SMTP.
func seedPaidGroupPeriodAt(t *testing.T, payer *User, infos []ProductInfo, now time.Time) (*Order, *Subscription) {
	t.Helper()
	clock := func() time.Time { return now }
	order, err := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none", clock)
	if err != nil {
		t.Fatal(err)
	}
	payment, request, err := claimGroupPaymentAt(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order), clock)
	if err != nil || request == nil {
		t.Fatal("seed claim failed")
	}
	native, _ := pp.NewDummyPaymentProvider()
	response, err := native.Pay(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = finishGroupDispatch(payment, response); err != nil {
		t.Fatal(err)
	}
	result, err := native.Notify(nil, payment.OutOrderId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = completeGroupPaymentAt(payment, result, nil, clock); err != nil {
		t.Fatal(err)
	}
	sub, err := GetSubscription(payer.Owner + "/sub_" + order.Name)
	if err != nil || sub == nil {
		t.Fatal("seed paid period missing")
	}
	return order, sub
}

func TestTenantCheckoutNextPeriodPersistsDatesAndLateSettlementNeverReprices(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	t0 := time.Now().UTC().AddDate(0, 0, -20).Truncate(time.Second)
	_, previous := seedPaidGroupPeriodAt(t, payer, infos, t0)
	_, end, _ := checkoutInterval(previous.StartTime, previous.EndTime)
	quoteTime := end.AddDate(0, 0, -7)
	clock := func() time.Time { return quoteTime }
	revision, err := groupPeriodRevision(previous)
	if err != nil {
		t.Fatal(err)
	}
	// Different native product/price/period; cap classification stays App-owned.
	for _, row := range []interface{}{
		&Product{Owner: payer.Owner, Name: "product_next", Price: 12, Currency: "USD", Quantity: 10, Providers: []string{payer.Owner + "_dummy"}},
		&Plan{Owner: payer.Owner, Name: "plan_next", Product: "product_next", Period: PeriodYearly, IsEnabled: true},
	} {
		if _, err := engine.Insert(row); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "pricing").Cols("plans").Update(&Pricing{Plans: []string{"plan", "plan_next"}}); err != nil {
		t.Fatal(err)
	}
	nextInfos := []ProductInfo{{Name: "product_next", PlanName: "plan_next", PricingName: "pricing", Quantity: 1}}
	order, err := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", nextInfos, payer, revision, clock)
	if err != nil {
		t.Fatal(err)
	}
	frozen := *order.CheckoutTerms
	if frozen.Kind != "next" || frozen.StartTime != previous.EndTime || frozen.EndTime != checkoutTimestamp(end.AddDate(1, 0, 0)) || order.CheckoutRevision != 1 || order.Price != 12 {
		t.Fatal("next-period quote did not freeze predecessor/price/term")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "product_next").Cols("price").Update(&Product{Price: 99}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := claimGroupPaymentAt(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order), clock); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("stale quoted price dispatched")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "product_next").Cols("price").Update(&Product{Price: 12}); err != nil {
		t.Fatal(err)
	}
	payment, request, err := claimGroupPaymentAt(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order), clock)
	if err != nil || request == nil {
		t.Fatal("next claim failed")
	}
	status, err := getGroupCheckoutAt("app/"+payer.Owner, payer.Owner, "tenant", payer.Name, "", clock)
	if err != nil || status.CurrentSubscription == nil || status.CurrentSubscription.Name != previous.Name || status.UpcomingSubscription != nil || status.OpenOrder == nil || status.OpenOrder.State != "Processing" || status.PurchaseEligible {
		t.Fatal("unknown checkout replaced current entitlement")
	}
	// Accepted Dummy operation with lost synchronous result is resolved through
	// the precommitted reference, after live catalog price/period are changed.
	native, _ := pp.NewDummyPaymentProvider()
	if _, err := native.Pay(request); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "plan_next").Cols("period", "is_enabled").Update(&Plan{Period: PeriodMonthly, IsEnabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "product_next").Cols("price").Update(&Product{Price: 999}); err != nil {
		t.Fatal(err)
	}
	result, err := native.Notify(nil, payment.OutOrderId)
	if err != nil {
		t.Fatal(err)
	}
	_, targetEnd, _ := checkoutInterval(frozen.StartTime, frozen.EndTime)
	late := func() time.Time { return targetEnd.Add(time.Hour) }
	for i := 0; i < 2; i++ {
		if _, err := completeGroupPaymentAt(payment, result, nil, late); err != nil {
			t.Fatal(err)
		}
	}
	sub, err := GetSubscription(payer.Owner + "/sub_" + order.Name)
	if err != nil || sub.StartTime != frozen.StartTime || sub.EndTime != frozen.EndTime || sub.Period != PeriodYearly || sub.State != SubStateExpired {
		t.Fatal("late settlement repriced/redated/reactivated fixed period")
	}
	stored, err := GetOrder(order.GetId())
	if err != nil || stored.CheckoutRevision != 3 || stored.Price != 12 || *stored.CheckoutTerms != frozen {
		t.Fatal("callback replay changed frozen order or revision")
	}
	changed := *sub
	changed.EndTime = checkoutTimestamp(targetEnd.AddDate(0, 1, 0))
	if _, err := UpdateSubscription(sub.GetId(), &changed); err == nil {
		t.Fatal("paid term was editable")
	}
	changed = *sub
	changed.CreatedTime = "2020-01-01T00:00:00Z"
	if _, err := UpdateSubscription(sub.GetId(), &changed); err == nil {
		t.Fatal("paid settlement evidence was editable")
	}
	if _, err := DeleteSubscription(&Subscription{Owner: sub.Owner, Name: sub.Name}); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("paid term deletion bypassed immutable target")
	}
	if _, err := AddSubscription(sub); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("payment created a second paid term")
	}
	count, err := engine.Where("owner = ?", payer.Owner).Count(&Subscription{})
	if err != nil || count != 2 {
		t.Fatal("duplicate or missing period")
	}
	product, err := GetProduct(payer.Owner + "/product_next")
	if err != nil || product.Quantity != 9 || product.Sold != 1 {
		t.Fatal("replay changed stock")
	}
}

func TestTenantCheckoutConcurrentNextQuoteAndReadOnlyRollover(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	_, previous := seedPaidGroupPeriodAt(t, payer, infos, time.Now().UTC().AddDate(0, 0, -20).Truncate(time.Second))
	_, end, _ := checkoutInterval(previous.StartTime, previous.EndTime)
	now := end.AddDate(0, 0, -7)
	clock := func() time.Time { return now }
	revision, _ := groupPeriodRevision(previous)
	type outcome struct {
		order *Order
		err   error
	}
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, e := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, revision, clock)
			outcomes <- outcome{o, e}
		}()
	}
	wg.Wait()
	close(outcomes)
	var order *Order
	for result := range outcomes {
		if result.err == nil {
			if order != nil && order.Name != result.order.Name {
				t.Fatal("concurrent next quotes created two identities")
			}
			order = result.order
		}
	}
	if order == nil {
		t.Fatal("no next quote admitted")
	}
	count, err := engine.Where("owner = ? and state = ?", payer.Owner, "Created").Count(&Order{})
	if err != nil || count != 1 {
		t.Fatal("more than one next quote persisted")
	}
	payment, request, err := claimGroupPaymentAt(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order), clock)
	if err != nil {
		t.Fatal(err)
	}
	native, _ := pp.NewDummyPaymentProvider()
	if _, err := native.Pay(request); err != nil {
		t.Fatal(err)
	}
	result, err := native.Notify(nil, payment.OutOrderId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := completeGroupPaymentAt(payment, result, nil, clock); err != nil {
		t.Fatal(err)
	}
	if _, err := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, revision, clock); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("second Upcoming admitted")
	}
	newSub, err := GetSubscription(payer.Owner + "/sub_" + order.Name)
	if err != nil || newSub.State != SubStateUpcoming {
		t.Fatal("next period did not persist Upcoming")
	}
	before, err := getGroupCheckoutAt("app/"+payer.Owner, payer.Owner, "tenant", payer.Name, "", func() time.Time { return end.Add(-time.Nanosecond) })
	if err != nil || before.CurrentSubscription.Name != previous.Name || before.UpcomingSubscription.Name != newSub.Name {
		t.Fatal("pre-rollover summary is wrong")
	}
	rolled, err := getGroupCheckoutAt("app/"+payer.Owner, payer.Owner, "tenant", "", "", func() time.Time { return end })
	if err != nil || rolled.CurrentSubscription.Name != newSub.Name || rolled.CurrentSubscription.State != SubStateActive || rolled.UpcomingSubscription != nil || rolled.CanResume || rolled.CanCancel {
		t.Fatal("actorless half-open rollover failed")
	}
	unchanged, err := GetSubscription(newSub.GetId())
	if err != nil || unchanged.State != SubStateUpcoming {
		t.Fatal("GET performed lazy State writes")
	}
	if _, err := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, revision, func() time.Time { return end }); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("stale period revision survived rollover")
	}
}

func TestTenantCheckoutManagerCancelsDepartedPayerWithoutImpersonation(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	manager := &User{Owner: payer.Owner, Name: "manager", Groups: []string{payer.Owner + "/tenant"}}
	if _, err := engine.Insert(manager); err != nil {
		t.Fatal(err)
	}
	read, err := GetGroupCheckout("app/"+payer.Owner, payer.Owner, "tenant", manager.Name, "")
	if err != nil || read.CanResume || !read.CanCancel || read.OpenOrder.User != payer.Name {
		t.Fatal("manager assumed payer identity or lost cancel")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, payer.Name).Cols("is_deleted", "groups").Update(&User{IsDeleted: true, Groups: []string{}}); err != nil {
		t.Fatal(err)
	}
	// App active membership+billing authority is attested by this principal;
	// native exact direct Groups is additional, not an App-active-state proof.
	canceled, err := CancelGroupOrder("app/"+payer.Owner, manager.Name, order, 1)
	if err != nil || canceled.User != payer.Name || canceled.CheckoutRevision != 2 {
		t.Fatal("departed payer prevented authorized predispatch recovery")
	}
	replay, err := CancelGroupOrder("app/"+payer.Owner, manager.Name, order, 1)
	if err != nil || replay.UpdateTime != canceled.UpdateTime || replay.CheckoutRevision != 2 {
		t.Fatal("semantic replay mutated canceled order")
	}
	for _, stale := range []int64{0, 2, 3} {
		if _, err := CancelGroupOrder("app/"+payer.Owner, manager.Name, order, stale); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("arbitrary revision replay accepted")
		}
	}
	read, err = GetGroupCheckout("app/"+payer.Owner, payer.Owner, "tenant", manager.Name, order.Name)
	if err != nil || read.OpenOrder != nil || read.RequestedOrder == nil || read.RequestedOrder.Group != "tenant" || read.RequestedOrder.Owner != payer.Owner || read.RequestedOrder.State != "Canceled" || read.RequestedOrder.User != payer.Name {
		t.Fatal("scoped canceled replay lookup failed")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, manager.Name).Cols("groups").Update(&User{Groups: []string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CancelGroupOrder("app/"+payer.Owner, manager.Name, order, 1); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("semantic replay skipped current actor binding")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, manager.Name).Cols("groups").Update(manager); err != nil {
		t.Fatal(err)
	}
	next, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, manager, "none")
	if err != nil || next.Name == order.Name || next.User != manager.Name {
		t.Fatal("manager could not create independent fresh quote")
	}
	if _, _, err := claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(next)); err != nil {
		t.Fatal(err)
	}
	if repeated, err := CancelGroupOrder("app/"+payer.Owner, manager.Name, order, 1); err != nil || repeated.CheckoutRevision != 2 || repeated.UpdateTime != canceled.UpdateTime {
		t.Fatal("later independent intent broke original canceled-revision replay")
	}
	forged := *order
	forged.User = manager.Name
	if _, _, err := claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(&forged)); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("manager became original payer")
	}
	if _, err := engine.Insert(&Group{Owner: payer.Owner, Name: "other", IsEnabled: true}); err != nil {
		t.Fatal(err)
	}
	foreign, err := GetGroupCheckout("app/"+payer.Owner, payer.Owner, "other", "", order.Name)
	if err != nil || foreign.RequestedOrder != nil || foreign.CanResume || foreign.CanCancel {
		t.Fatal("requestedOrder leaked another canonical Group")
	}
}

func TestTenantCheckoutLegacyUnattemptedCleanupReadIsIndependentOfPaymentAndHistory(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	// A pre-Go5 unattempted record has no quoted terms/revision. Never infer a
	// period or rebase it into a charge, but allow explicit revision-zero cleanup.
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, order.Name).Cols("checkout_terms", "checkout_revision").Update(&Order{}); err != nil {
		t.Fatal(err)
	}
	legacy, err := GetOrder(order.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(legacy)); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("legacy missing terms were charged/rebased")
	}
	if _, err := engine.Insert(&Subscription{Owner: payer.Owner, Name: "broken_history", Group: "tenant", StartTime: "malformed", EndTime: "malformed"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("paymentDeploymentEnvironment", "prod")
	t.Setenv("allowDummyPayment", "false")
	read, err := GetGroupCheckout("app/"+payer.Owner, payer.Owner, "tenant", payer.Name, legacy.Name)
	if err != nil || read.ReadScope != "order" || read.PeriodSummaryState != "not_requested" || read.CurrentPeriodRevision != "" || read.CurrentSubscription != nil || read.UpcomingSubscription != nil || read.PlanQuotes != nil || read.CheckoutAvailable || read.CanCancel || read.CanResume || read.RequestedOrder == nil || read.RequestedOrder.CheckoutTerms != nil || read.RequestedOrder.CheckoutRevision != 0 {
		t.Fatal("order lookup manufactured period state or depended on unavailable financial history")
	}
	if _, err := GetGroupCheckout("app/"+payer.Owner, payer.Owner, "tenant", "", ""); err == nil {
		t.Fatal("normal group summary weakened malformed-history guard")
	}
	canceled, err := CancelGroupOrder("app/"+payer.Owner, payer.Name, legacy, 0)
	if err != nil || canceled.CheckoutRevision != 1 || canceled.User != payer.Name || canceled.CheckoutTerms != nil {
		t.Fatal("safe legacy cleanup did not preserve identity/unknown terms")
	}
	replayed, err := CancelGroupOrder("app/"+payer.Owner, payer.Name, legacy, 0)
	if err != nil || replayed.UpdateTime != canceled.UpdateTime || replayed.CheckoutRevision != 1 {
		t.Fatal("legacy cleanup replay mutated revision")
	}
	count, err := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
	if err != nil || count != 0 {
		t.Fatal("legacy cleanup dispatched payment")
	}
}

func TestTenantCheckoutLateFreshEvidenceDoesNotMaskLaterCurrent(t *testing.T) {
	_, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	t0 := time.Now().UTC().AddDate(0, 0, -60).Truncate(time.Second)
	clock := func() time.Time { return t0 }
	order, err := placeGroupOrderAt("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none", clock)
	if err != nil {
		t.Fatal(err)
	}
	payment, request, err := claimGroupPaymentAt(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order), clock)
	if err != nil {
		t.Fatal(err)
	}
	native, _ := pp.NewDummyPaymentProvider()
	if _, err := native.Pay(request); err != nil {
		t.Fatal(err)
	}
	result, err := native.Notify(nil, payment.OutOrderId)
	if err != nil {
		t.Fatal(err)
	}
	end, _ := checkoutPeriodEnd(t0, PeriodMonthly)
	late := end.Add(time.Hour)
	if _, err := completeGroupPaymentAt(payment, result, nil, func() time.Time { return late }); err != nil {
		t.Fatal(err)
	}
	first, err := GetSubscription(payer.Owner + "/sub_" + order.Name)
	if err != nil || first.State != SubStateExpired {
		t.Fatal("late fresh was rebased")
	}
	paid, err := GetOrder(order.GetId())
	if err != nil || paid.UpdateTime != first.CreatedTime {
		t.Fatal("winning settlement timestamp not bound")
	}
	_, current := seedPaidGroupPeriodAt(t, payer, infos, end.AddDate(0, 0, 2))
	view, err := getGroupCheckoutAt("app/"+payer.Owner, payer.Owner, "tenant", payer.Name, "", func() time.Time { return end.AddDate(0, 0, 3) })
	if err != nil || view.CurrentSubscription == nil || view.CurrentSubscription.Name != current.Name || view.LastLateFreshPeriod == nil || view.LastLateFreshPeriod.Name != first.Name || view.LastLateFreshPeriod.ConfirmedAt != first.CreatedTime {
		t.Fatal("old late confirmation replaced or masked later current plan")
	}
	if _, err := completeGroupPaymentAt(payment, result, nil, func() time.Time { return end.AddDate(0, 2, 0) }); err != nil {
		t.Fatal(err)
	}
	repeated, err := GetOrder(order.GetId())
	if err != nil || repeated.UpdateTime != paid.UpdateTime || repeated.CheckoutRevision != paid.CheckoutRevision {
		t.Fatal("replay manufactured later confirmation evidence")
	}
	_, currentEnd, _ := checkoutInterval(current.StartTime, current.EndTime)
	view, err = getGroupCheckoutAt("app/"+payer.Owner, payer.Owner, "tenant", "", "", func() time.Time { return currentEnd.Add(time.Hour) })
	if err != nil || view.CurrentSubscription != nil || view.LastLateFreshPeriod == nil || view.LastLateFreshPeriod.Name != first.Name {
		t.Fatal("on-time purchase became late merely by expiring")
	}
}

func TestTenantCheckoutClaimCancelRaceHasOneWinner(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var claimed *Payment
	var request *pp.PayReq
	var claimErr, cancelErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		claimed, request, claimErr = claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order))
	}()
	go func() { defer wg.Done(); _, cancelErr = CancelGroupOrder("app/"+payer.Owner, payer.Name, order, 1) }()
	wg.Wait()
	if (claimErr == nil) == (cancelErr == nil) {
		t.Fatal("claim/cancel did not have exactly one winner")
	}
	stored, err := GetOrder(order.GetId())
	if err != nil {
		t.Fatal(err)
	}
	count, err := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
	if err != nil {
		t.Fatal(err)
	}
	if cancelErr == nil {
		if stored.State != "Canceled" || stored.CheckoutRevision != 2 || count != 0 || request != nil {
			t.Fatal("canceled quote dispatched or left an intent")
		}
		if _, _, err := claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order)); !errors.Is(err, ErrGroupCheckoutConflict) {
			t.Fatal("canceled quote later dispatched")
		}
	} else if stored.State != "Processing" || stored.CheckoutRevision != 2 || count != 1 || claimed == nil || request == nil {
		t.Fatal("winning claim lost atomic intent/revision")
	}
}

// The Daybreak oracle below keeps its original security outcome: admitting B
// while A can still settle always fails, even if a later uniqueness check wins.
// This fixture has NO SQLite fallback and never calls main/InitConfig/Reset.
const tenantCheckoutAbuseDatabase = "casdoor_commerce_abuse_test_20261112"
const tenantCheckoutAbuseOptIn = "casdoor-commerce-abuse-20261112"
const tenantCheckoutAbuseRole = "casdoor_commerce_abuse_20261112"

func validateTenantCheckoutTestDSN(dsn, expectedRole string) error {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed == nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() != "127.0.0.1" || parsed.Port() != "26267" || parsed.Path != "/"+tenantCheckoutAbuseDatabase || parsed.Fragment != "" || parsed.User == nil || expectedRole != tenantCheckoutAbuseRole || parsed.User.Username() != expectedRole {
		return errors.New("refusing database outside exact disposable checkout profile")
	}
	switch strings.ToLower(expectedRole) {
	case "root", "admin", "postgres", "casdoor", "casdoor_db":
		return errors.New("refusing shared or administrative database role")
	}
	// URL query routing overrides must not bypass the checked host/database/user.
	for key := range parsed.Query() {
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name":
		default:
			return errors.New("refusing database routing or schema override")
		}
	}
	switch parsed.Query().Get("sslmode") {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return errors.New("requires explicit owner-selected TLS profile")
	}
	return nil
}

func TestTenantCheckoutDisposableProfileFailsClosed(t *testing.T) {
	// Synthetic parser input uses the planned identity only; it does not prove
	// provisioning, role scope or permission to execute on the DEV host.
	valid := "postgres://" + tenantCheckoutAbuseRole + "@127.0.0.1:26267/" + tenantCheckoutAbuseDatabase + "?sslmode=verify-full"
	if err := validateTenantCheckoutTestDSN(valid, tenantCheckoutAbuseRole); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{strings.Replace(valid, "127.0.0.1", "0.0.0.0", 1), strings.Replace(valid, "26267", "26257", 1), strings.Replace(valid, tenantCheckoutAbuseDatabase, "casdoor_db", 1), valid + "&host=foreign", valid + "&search_path=other", strings.Replace(valid, tenantCheckoutAbuseRole, "root", 1)} {
		if validateTenantCheckoutTestDSN(candidate, tenantCheckoutAbuseRole) == nil {
			t.Fatal("unsafe disposable profile accepted")
		}
	}
	if validateTenantCheckoutTestDSN(valid, "") == nil {
		t.Fatal("pending scoped role accepted")
	}
}

// The DEV owner must separately produce a fresh ownership/role/other-DB-denial
// receipt before setting these opt-ins. Identity probes are not a grants audit.
func setupTenantCheckoutReplacementAbuseFixture(t *testing.T) (*xorm.Engine, *User, []ProductInfo) {
	t.Helper()
	if os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_DB") != "postgres" || os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_ALLOW_DISPOSABLE") != tenantCheckoutAbuseOptIn {
		t.Skip("requires separate root release of exact owned PostgreSQL/Cockroach checkout profile")
	}
	if ormer != nil {
		t.Fatal("refusing initialized shared storage")
	}
	dsn, role := os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_DSN"), os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_ROLE")
	if validateTenantCheckoutTestDSN(dsn, role) != nil {
		t.Fatal("missing or invalid owned checkout database profile")
	}
	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("disposable identity probe open failed")
	}
	probe.SetMaxOpenConns(1)
	defer probe.Close()
	var version, database, user string
	if err := probe.QueryRow("SELECT version(), current_database(), current_user").Scan(&version, &database, &user); err != nil {
		t.Fatal("disposable identity probe failed")
	}
	if !strings.Contains(version, "CockroachDB") || !strings.Contains(version, "v25.2.20") || database != tenantCheckoutAbuseDatabase || user != role {
		t.Fatal("unexpected disposable database/version/role identity")
	}
	engine, err := xorm.NewEngine("postgres", dsn)
	if err != nil {
		t.Fatal("disposable checkout engine open failed")
	}
	engine.SetMaxOpenConns(4)
	engine.SetMaxIdleConns(2)
	ormer = &Ormer{Engine: engine, driverName: "postgres"}
	t.Cleanup(func() {
		ormer = nil
		if err := engine.Close(); err != nil {
			t.Error("disposable checkout engine close failed")
		}
	})
	// Task database only, with per-run synthetic organizations retained after
	// RED and GREEN; no DROP, TRUNCATE, Reset or existing fixture overwrite.
	if err := engine.Sync2(&Order{}, &Payment{}, &Subscription{}, &Group{}, &User{}, &Pricing{}, &Plan{}, &Product{}, &Provider{}, &Application{}, &Transaction{}); err != nil {
		t.Fatal("disposable checkout table setup failed")
	}
	org := "abuse_" + strings.ReplaceAll(util.GenerateId(), "-", "")
	provider := org + "_dummy"
	t.Logf("synthetic_checkout_org=%s", org)
	t.Setenv("tenantCheckoutApplication", "app/"+org)
	t.Setenv("tenantCheckoutOrganization", org)
	t.Setenv("tenantCheckoutPricing", "pricing")
	t.Setenv("allowDummyPayment", "true")
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("origin", "https://casdoor.example.test")
	t.Setenv("originFrontend", "")
	payer := &User{Owner: org, Name: "payer", Groups: []string{org + "/tenant"}} // no verified recipient or Email provider
	for _, row := range []interface{}{
		&Application{Owner: "admin", Name: org, Organization: org}, &Group{Owner: org, Name: "tenant", IsEnabled: true}, payer,
		&Provider{Owner: org, Name: provider, Category: "Payment", Type: "Dummy"},
		&Product{Owner: org, Name: "product", Price: 5, Currency: "USD", Quantity: 10, Providers: []string{provider}},
		&Plan{Owner: org, Name: "plan", Product: "product", Period: PeriodMonthly, IsEnabled: true},
		&Pricing{Owner: org, Name: "pricing", Plans: []string{"plan"}, IsEnabled: true},
	} {
		if _, err := engine.Insert(row); err != nil {
			t.Fatal("isolated synthetic checkout fixture insert failed")
		}
	}
	return engine, payer, []ProductInfo{{Name: "product", PlanName: "plan", PricingName: "pricing", Quantity: 1}}
}

func TestTenantCheckoutCannotDispatchReplacementWhileEarlierPaymentCanSettle(
	t *testing.T,
) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)

	orderA, err := PlaceGroupOrder(
		"app/"+payer.Owner,
		payer.Owner,
		"tenant",
		infos,
		payer,
		"none",
	)
	if err != nil {
		t.Fatal(err)
	}
	paymentA, _, err := PayGroupOrder(checkoutFixtureAdmission(orderA), payer.Owner+"_dummy", "127.0.0.1:8000", "en")
	if err != nil {
		t.Fatalf("dispatch payment A: %v", err)
	}

	canonicalA, err := GetOrder(orderA.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if canonicalA == nil {
		t.Fatal("payment A lost its canonical order")
	}
	if canonicalA.Payment != paymentA.Name {
		t.Fatalf(
			"payment A was not durably linked: order payment=%q, payment=%q, state=%q",
			canonicalA.Payment,
			paymentA.Name,
			canonicalA.State,
		)
	}

	cancelled, cancelErr := CancelOrder(canonicalA)
	if cancelErr != nil {
		// Either result is an acceptable security gate:
		//   1. the payment claim remained Processing, so ordinary cancellation
		//      cannot run; or
		//   2. cancellation explicitly rejects a dispatched Group payment.
		if canonicalA.State == "Processing" &&
			strings.Contains(cancelErr.Error(), "cannot cancel order in state") {
			return
		}
		if errors.Is(cancelErr, ErrGroupCheckoutConflict) {
			return
		}
		t.Fatalf(
			"unexpected cancellation result for payment A: state=%q payment=%q err=%v",
			canonicalA.State,
			canonicalA.Payment,
			cancelErr,
		)
	}
	if !cancelled {
		t.Fatal("cancellation reported neither a persisted change nor an error")
	}

	orderB, err := PlaceGroupOrder(
		"app/"+payer.Owner,
		payer.Owner,
		"tenant",
		infos,
		payer,
		"none",
	)
	if err != nil {
		// A canceled order with an unresolved provider payment must continue to
		// occupy the Group until that payment is reconciled.
		if errors.Is(err, ErrGroupCheckoutConflict) {
			return
		}
		t.Fatalf("unexpected replacement-order error: %v", err)
	}
	if orderB.Name == orderA.Name {
		t.Fatal("replacement unexpectedly reused canceled order A")
	}

	paymentB, _, err := PayGroupOrder(checkoutFixtureAdmission(orderB), payer.Owner+"_dummy", "127.0.0.1:8000", "en")
	if err != nil {
		// A final conditional provider-dispatch guard may block the replacement.
		if errors.Is(err, ErrGroupCheckoutConflict) {
			return
		}
		t.Fatalf("unexpected replacement-payment error: %v", err)
	}

	// Payment B has now crossed the provider boundary while payment A can still
	// report a late success. Continue through both callbacks so this test also
	// diagnoses whether settlement duplicates fulfillment.
	settledA, settleAErr := NotifyPayment(
		nil,
		payer.Owner,
		paymentA.Name,
		"en",
	)
	settledB, settleBErr := NotifyPayment(
		nil,
		payer.Owner,
		paymentB.Name,
		"en",
	)

	paidA := settleAErr == nil &&
		settledA != nil &&
		settledA.State == pp.PaymentStatePaid
	paidB := settleBErr == nil &&
		settledB != nil &&
		settledB.State == pp.PaymentStatePaid

	subscriptions := []*Subscription{}
	subErr := engine.
		Where("owner = ?", payer.Owner).
		And(fmt.Sprintf("%s = ?", engine.Quote("group")), "tenant").
		Find(&subscriptions)

	transactions := []*Transaction{}
	transactionErr := engine.
		Where(
			"(payment = ? OR payment = ?)",
			paymentA.Name,
			paymentB.Name,
		).
		Find(&transactions)

	product, productErr := GetProduct(util.GetId(payer.Owner, "product"))

	if paidA && paidB ||
		len(subscriptions) > 1 ||
		len(transactions) > 1 {
		t.Fatalf(
			"late payment A and replacement payment B duplicated fulfillment: "+
				"paidA=%v errA=%v paidB=%v errB=%v "+
				"subscriptions=%d subErr=%v transactions=%d transactionErr=%v "+
				"product=%#v productErr=%v",
			paidA,
			settleAErr,
			paidB,
			settleBErr,
			len(subscriptions),
			subErr,
			len(transactions),
			transactionErr,
			product,
			productErr,
		)
	}

	t.Fatalf(
		"replacement provider payment was dispatched while payment A remained "+
			"capable of late settlement: paymentA=%q paymentB=%q "+
			"paidA=%v errA=%v paidB=%v errB=%v "+
			"subscriptions=%d transactions=%d product=%#v",
		paymentA.Name,
		paymentB.Name,
		paidA,
		settleAErr,
		paidB,
		settleBErr,
		len(subscriptions),
		len(transactions),
		product,
	)
}

// Native Xorm SQL hook: fail the actual intent/link/result write while keeping
// fresh database reads and provider-confirmed settlement as independent oracles.
type checkoutWriteFault struct {
	match func(string) bool
	fired bool
}

func (h *checkoutWriteFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.fired && h.match(strings.ToLower(c.SQL)) {
		h.fired = true
		return c.Ctx, errors.New("injected checkout write failure")
	}
	return c.Ctx, nil
}
func (h *checkoutWriteFault) AfterProcess(*contexts.ContextHook) error { return nil }

func assertSingleTenantFulfillment(t *testing.T, engine *xorm.Engine, payer *User, paymentName string) {
	t.Helper()
	for _, model := range []interface{}{&Subscription{}, &Transaction{}} {
		n, err := engine.Where("owner = ? and payment = ?", payer.Owner, paymentName).Count(model)
		if err != nil || n != 1 {
			t.Fatalf("expected one committed fulfillment row for %T: count=%d", model, n)
		}
	}
	product, err := GetProduct(util.GetId(payer.Owner, "product"))
	if err != nil || product.Quantity != 9 || product.Sold != 1 {
		t.Fatal("stock did not commit exactly once")
	}
}

func TestTenantCheckoutDurableIntentSurvivesProviderAndPersistenceFaults(t *testing.T) {
	if os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_DB") != "postgres" || os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_ALLOW_DISPOSABLE") != tenantCheckoutAbuseOptIn {
		t.Skip("requires separate root release of exact owned PostgreSQL/Cockroach checkout profile")
	}

	for _, point := range []string{"stock-reserve", "intent-insert", "order-link", "lost-response", "result-write", "callback-before-result"} {
		t.Run(point, func(t *testing.T) {
			engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
			order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
			if err != nil {
				t.Fatal(err)
			}
			fault := &checkoutWriteFault{match: func(q string) bool {
				switch point {
				case "stock-reserve":
					return strings.HasPrefix(q, "update "+engine.Quote("product")) && strings.Contains(q, engine.Quote("quantity"))
				case "intent-insert":
					return strings.HasPrefix(q, "insert into "+engine.Quote("payment"))
				case "order-link":
					return strings.HasPrefix(q, "update "+engine.Quote("order")) && strings.Contains(q, engine.Quote("payment"))
				case "result-write":
					return strings.HasPrefix(q, "update "+engine.Quote("payment")) && strings.Contains(q, engine.Quote("pay_url"))
				}
				return false
			}}
			engine.AddHook(fault)
			var acceptedName string
			var response *pp.PayResp
			payment, _, err := dispatchGroupPayment(func() (*Payment, *pp.PayReq, error) {
				return claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order))
			}, func(request *pp.PayReq) (*pp.PayResp, error) {
				// This read happens at provider acceptance, independently of the
				// claim return object; both durable records must already exist.
				storedOrder, e := GetOrder(order.GetId())
				if e != nil || storedOrder.Payment != request.PaymentName || storedOrder.State != "Processing" {
					t.Fatal("provider crossed boundary without committed order link")
				}
				stored, e := GetPayment(util.GetId(payer.Owner, request.PaymentName))
				stock, stockErr := GetProduct(util.GetId(payer.Owner, "product"))
				if e != nil || stored == nil || !stored.GroupStockReserved || stored.OutOrderId == "" || validateGroupPayment(storedOrder, stored) != nil || stockErr != nil || stock.Quantity != 9 || stock.Sold != 0 {
					t.Fatal("provider crossed boundary without immutable persisted intent")
				}
				acceptedName = request.PaymentName
				dummy, _ := pp.NewDummyPaymentProvider()
				response, e = dummy.Pay(request)
				if e != nil {
					t.Fatal(e)
				}
				if point == "lost-response" {
					return nil, errors.New("accepted Dummy operation; response lost")
				}
				if point == "callback-before-result" {
					if paid, e := NotifyPayment(nil, payer.Owner, acceptedName, "en"); e != nil || paid.State != pp.PaymentStatePaid {
						t.Fatal("callback could not resolve predispatch identity")
					}
				}
				return response, nil
			}, finishGroupDispatch)
			storedOrder, readErr := GetOrder(order.GetId())
			if readErr != nil {
				t.Fatal(readErr)
			}
			if point == "stock-reserve" || point == "intent-insert" || point == "order-link" {
				n, e := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
				product, stockErr := GetProduct(util.GetId(payer.Owner, "product"))
				if err == nil || !fault.fired || acceptedName != "" || storedOrder.State != "Created" || storedOrder.Payment != "" || n != 0 || e != nil || stockErr != nil || product.Quantity != 10 || product.Sold != 0 {
					t.Fatal("precommit write failure dispatched or left a half-linked intent")
				}
				return
			}
			if acceptedName == "" || payment == nil || payment.Name != acceptedName || storedOrder.Payment != acceptedName {
				t.Fatal("accepted operation lost durable correlation")
			}
			if point != "callback-before-result" {
				if !errors.Is(err, ErrGroupCheckoutUnavailable) {
					t.Fatal("lost result was not sanitized unavailable")
				}
				if _, _, stale := PayGroupOrder(checkoutFixtureAdmission(order), payer.Owner+"_dummy", "127.0.0.1:8000", "en"); !errors.Is(stale, ErrGroupCheckoutConflict) {
					t.Fatal("original quote revision replay was accepted after claim")
				}
				// Explicitly refresh the committed revision; linked replay is
				// identity/status only, not an automatic provider retry.
				retry, _, e := PayGroupOrder(checkoutFixtureAdmission(storedOrder), payer.Owner+"_dummy", "127.0.0.1:8000", "en")
				held, stockErr := GetProduct(util.GetId(payer.Owner, "product"))
				if stockErr != nil || held.Quantity != 9 || held.Sold != 0 {
					t.Fatal("unknown outcome released or consumed its reservation")
				}
				if retry == nil || retry.Name != acceptedName || e != nil || retry.PayUrl != retry.SuccessUrl || retry.OrderObj == nil || retry.OrderObj.CheckoutRevision != storedOrder.CheckoutRevision || retry.OrderObj.State != "Processing" || retry.State != pp.PaymentStateCreated {
					t.Fatal("unknown outcome did not keep same unresolved identity")
				}
				if _, e := CancelOrder(order); !errors.Is(e, ErrGroupCheckoutConflict) {
					t.Fatal("stale Created object canceled dispatched intent")
				}
				if _, e := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none"); !errors.Is(e, ErrGroupCheckoutConflict) {
					t.Fatal("unknown operation permitted replacement")
				}
			} else if err != nil || payment.State != pp.PaymentStatePaid || payment.OrderObj == nil || payment.OrderObj.State != "Paid" || payment.OrderObj.CheckoutRevision != storedOrder.CheckoutRevision || !reflect.DeepEqual(payment.OrderObj.CheckoutTerms, storedOrder.CheckoutTerms) {
				t.Fatal("late provider result erased Paid")
			}
			for i := 0; i < 2; i++ {
				paid, e := NotifyPayment(nil, payer.Owner, acceptedName, "en")
				if e != nil || paid.State != pp.PaymentStatePaid {
					t.Fatal("stable callback/replay failed")
				}
			}
			fault.fired = true // allow a delayed metadata response after Paid
			if late, e := finishGroupDispatch(payment, response); e != nil || late.State != pp.PaymentStatePaid || late.OrderObj == nil || late.OrderObj.State != "Paid" || late.OrderObj.CheckoutRevision != 3 {
				t.Fatal("late metadata result overwrote Paid")
			}
			assertSingleTenantFulfillment(t, engine, payer, acceptedName)
			n, e := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
			if e != nil || n != 1 {
				t.Fatal("retry admitted a second provider intent")
			}
			if _, e := DeletePayment(&Payment{Owner: payer.Owner, Name: acceptedName}); !errors.Is(e, ErrGroupCheckoutConflict) {
				t.Fatal("durable payment could be erased")
			}
			if _, e := DeleteOrder(&Order{Owner: payer.Owner, Name: order.Name}); !errors.Is(e, ErrGroupCheckoutConflict) {
				t.Fatal("durable order link could be erased")
			}
		})
	}
}

func TestTenantCheckoutConcurrentDispatchAndCallbacksKeepOneIdentity(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	// Native direct binding/enabled checks supplement App's attestation. A
	// rejected actor must leave neither an intent nor an advanced revision.
	for _, actor := range []*User{{Groups: nil}, {Groups: payer.Groups, IsForbidden: true}} {
		if _, e := engine.Where("owner = ? and name = ?", payer.Owner, payer.Name).Cols("groups", "is_forbidden").Update(actor); e != nil {
			t.Fatal(e)
		}
		if _, _, e := claimGroupPayment(payer.Owner+"_dummy", "127.0.0.1:8000", checkoutFixtureAdmission(order)); !errors.Is(e, ErrTenantCheckoutRequired) {
			t.Fatal("native forbidden/unbound payer reached claim")
		}
		stored, e := GetOrder(order.GetId())
		n, countErr := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
		if e != nil || countErr != nil || n != 0 || stored.Payment != "" || stored.State != "Created" || stored.CheckoutRevision != 1 {
			t.Fatal("rejected payer changed canonical checkout")
		}
	}
	if _, e := engine.Where("owner = ? and name = ?", payer.Owner, payer.Name).Cols("groups", "is_forbidden").Update(&User{Groups: payer.Groups}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = PayGroupOrder(checkoutFixtureAdmission(order), payer.Owner+"_dummy", "127.0.0.1:8000", "en")
		}()
	}
	wg.Wait()
	stored, err := GetOrder(order.GetId())
	if err != nil || stored.Payment == "" || stored.State != "Processing" {
		t.Fatal("concurrent dispatch did not leave one durable claim")
	}
	payments := []*Payment{}
	if err := engine.Where("owner = ?", payer.Owner).Find(&payments); err != nil || len(payments) != 1 || payments[0].Name != stored.Payment {
		t.Fatal("concurrent provider admission created multiple intents")
	}
	// Cockroach may reject one serialization loser. The fresh persisted oracle
	// and an explicit callback replay must still show one committed fulfillment.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = NotifyPayment(nil, payer.Owner, stored.Payment, "en") }()
	}
	wg.Wait()
	if paid, err := NotifyPayment(nil, payer.Owner, stored.Payment, "en"); err != nil || paid.State != pp.PaymentStatePaid {
		t.Fatal("callback reconciliation failed")
	}
	assertSingleTenantFulfillment(t, engine, payer, stored.Payment)
}

func TestTenantCheckoutPredispatchCancelRetainsIdentityAndIsIdempotent(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	if canceled, err := CancelGroupOrder("app/"+payer.Owner, payer.Name, order, order.CheckoutRevision); err != nil || canceled == nil {
		t.Fatal("predispatch cancellation failed")
	}
	first, err := GetOrder(order.GetId())
	if err != nil || first.State != "Canceled" || first.Payment != "" {
		t.Fatal("cancellation did not retain immutable unpaid order")
	}
	if canceled, err := CancelGroupOrder("app/"+payer.Owner, payer.Name, order, order.CheckoutRevision); err != nil || canceled == nil {
		t.Fatal("repeat stale cancellation is not idempotent")
	}
	second, err := GetOrder(order.GetId())
	if err != nil || second.UpdateTime != first.UpdateTime || second.Name != first.Name {
		t.Fatal("repeat cancellation mutated identity or timestamp")
	}
	next, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil || next.Name == order.Name {
		t.Fatal("safe predispatch cancellation did not release checkout")
	}
	n, err := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
	if err != nil || n != 0 {
		t.Fatal("predispatch cancel created provider intent")
	}
}

func TestTenantCheckoutLegacyCanceledIntentCannotBeReplacedOrRevived(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	payment, _, err := PayGroupOrder(checkoutFixtureAdmission(order), payer.Owner+"_dummy", "127.0.0.1:8000", "en")
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately reproduce contradictory legacy state in this synthetic org.
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, order.Name).Cols("state").Update(&Order{State: "Canceled"}); err != nil {
		t.Fatal(err)
	}
	if _, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("unresolved canceled intent freed another purchase")
	}
	if _, err := NotifyPayment(nil, payer.Owner, payment.Name, "en"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("late confirmation revived a canceled order")
	}
	stored, err := GetPayment(payment.GetId())
	if err != nil || stored.State != pp.PaymentStateCreated {
		t.Fatal("contradiction silently rewrote financial state")
	}
	n, err := engine.Where("owner = ?", payer.Owner).Count(&Subscription{})
	if err != nil || n != 0 {
		t.Fatal("contradictory order issued entitlement")
	}
	product, err := GetProduct(util.GetId(payer.Owner, "product"))
	if err != nil || product.Quantity != 9 || product.Sold != 0 {
		t.Fatal("contradictory callback changed held reservation or sold stock")
	}
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, payment.Name).Cols("state").Update(&Payment{State: pp.PaymentStateCanceled}); err != nil {
		t.Fatal(err)
	}
	if _, err := NotifyPayment(nil, payer.Owner, payment.Name, "en"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("late Paid was silently ignored after contradictory terminal state")
	}
	if _, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("unreviewed historical terminal state permitted redispatch")
	}

}

func stockFixtureSecondGroup(t *testing.T, engine *xorm.Engine, payer *User, infos []ProductInfo) (*User, *Order) {
	t.Helper()
	second := &User{Owner: payer.Owner, Name: "second_payer", Groups: []string{payer.Owner + "/second_group"}}
	for _, row := range []interface{}{&Group{Owner: payer.Owner, Name: "second_group", IsEnabled: true}, second} {
		if _, err := engine.Insert(row); err != nil {
			t.Fatal(err)
		}
	}
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "second_group", infos, second, "none")
	if err != nil {
		t.Fatal(err)
	}
	return second, order
}

func TestTenantCheckoutSharedStockReservationSerializesGroups(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	if _, err := engine.Where("owner = ? and name = ?", payer.Owner, "product").Cols("quantity").Update(&Product{Quantity: 1}); err != nil {
		t.Fatal(err)
	}
	first, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	_, second := stockFixtureSecondGroup(t, engine, payer, infos)
	orders := []*Order{first, second}
	type outcome struct {
		payment *Payment
		request *pp.PayReq
		err     error
	}
	results := make([]outcome, 2)
	var wg sync.WaitGroup
	for i := range orders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].payment, results[i].request, results[i].err = claimGroupPayment(payer.Owner+"_dummy", "internal.invalid", checkoutFixtureAdmission(orders[i]))
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, result := range results {
		if result.err == nil {
			if winner != -1 || result.payment == nil || result.request == nil || !result.payment.GroupStockReserved {
				t.Fatal("more than one one-unit claim admitted")
			}
			winner = i
		}
	}
	if winner < 0 {
		t.Fatal("neither one-unit claim committed")
	}
	stock, err := GetProduct(util.GetId(payer.Owner, "product"))
	count, countErr := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
	if err != nil || countErr != nil || count != 1 || stock.Quantity != 0 || stock.Sold != 0 {
		t.Fatal("committed claim did not reserve exactly one unit")
	}
	losing, err := GetOrder(orders[1-winner].GetId())
	if err != nil || losing.State != "Created" || losing.Payment != "" || losing.CheckoutRevision != 1 {
		t.Fatal("losing Group retained a partial intent")
	}
	native, _ := pp.NewDummyPaymentProvider()
	response, err := native.Pay(results[winner].request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finishGroupDispatch(results[winner].payment, response); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if paid, err := NotifyPayment(nil, payer.Owner, results[winner].payment.Name, "en"); err != nil || paid.State != pp.PaymentStatePaid {
			t.Fatal("reserved winner did not settle/replay")
		}
	}
	stock, err = GetProduct(util.GetId(payer.Owner, "product"))
	subs, subErr := engine.Where("owner = ?", payer.Owner).Count(&Subscription{})
	transactions, txErr := engine.Where("owner = ?", payer.Owner).Count(&Transaction{})
	if err != nil || subErr != nil || txErr != nil || stock.Quantity != 0 || stock.Sold != 1 || subs != 1 || transactions != 1 {
		t.Fatal("Paid replay double-consumed reservation or fulfillment")
	}
}

func TestTenantCheckoutReservedIntentSurvivesCatalogMutationAndGroupDisable(t *testing.T) {
	if os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_DB") != "postgres" || os.Getenv("CASDOOR_TENANT_CHECKOUT_TEST_ALLOW_DISPOSABLE") != tenantCheckoutAbuseOptIn {
		t.Skip("requires separate root release of exact owned PostgreSQL/Cockroach checkout profile")
	}
	for _, change := range []string{"provider-association", "provider-deletion", "group-disabled"} {
		t.Run(change, func(t *testing.T) {
			engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
			before, err := GetProduct(util.GetId(payer.Owner, "product"))
			if err != nil {
				t.Fatal(err)
			}
			order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
			if err != nil {
				t.Fatal(err)
			}
			_, second := stockFixtureSecondGroup(t, engine, payer, infos)
			payment, _, err := PayGroupOrder(checkoutFixtureAdmission(order), payer.Owner+"_dummy", "internal.invalid", "en")
			if err != nil || !payment.GroupStockReserved {
				t.Fatal("claim failed")
			}
			if _, err := DeleteProduct(before); !errors.Is(err, ErrGroupCheckoutConflict) {
				t.Fatal("generic delete erased pending stock")
			}
			before.DisplayName = "stale presentation"
			if _, err := UpdateProduct(before.GetId(), before); !errors.Is(err, ErrGroupCheckoutConflict) {
				t.Fatal("stale AllCols reset reserved quantity")
			}
			current, err := GetProduct(before.GetId())
			if err != nil {
				t.Fatal(err)
			}
			wrongSold := *current
			wrongSold.Sold++
			if _, err := UpdateProduct(wrongSold.GetId(), &wrongSold); !errors.Is(err, ErrGroupCheckoutConflict) {
				t.Fatal("generic edit changed pending sold count")
			}
			current.DisplayName = "safe presentation"
			if _, err := UpdateProduct(current.GetId(), current); err != nil {
				t.Fatal("canonical-counter presentation edit blocked")
			}
			switch change {
			case "provider-association":
				current.Providers = []string{"removed-provider"}
				if _, err := UpdateProduct(current.GetId(), current); err != nil {
					t.Fatal(err)
				}
			case "provider-deletion":
				if _, err := DeleteProvider(&Provider{Owner: payer.Owner, Name: payer.Owner + "_dummy"}); err != nil {
					t.Fatal(err)
				}
			case "group-disabled":
				if _, err := engine.Where("owner = ?", payer.Owner).In("name", []string{"tenant", "second_group"}).Cols("is_enabled").Update(&Group{IsEnabled: false}); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := PayGroupOrder(checkoutFixtureAdmission(second), payer.Owner+"_dummy", "internal.invalid", "en"); err == nil {
				t.Fatal("new claim bypassed current catalog/Group eligibility")
			}
			secondNow, err := GetOrder(second.GetId())
			count, countErr := engine.Where("owner = ?", payer.Owner).Count(&Payment{})
			if err != nil || countErr != nil || count != 1 || secondNow.Payment != "" || secondNow.State != "Created" {
				t.Fatal("rejected new claim changed intent state")
			}
			t.Setenv("allowDummyPayment", "false")
			if _, err := NotifyPayment(nil, payer.Owner, payment.Name, "en"); err == nil {
				t.Fatal("admitted callback bypassed deployment Dummy deny")
			}
			held, err := GetProduct(current.GetId())
			stored, storedErr := GetPayment(payment.GetId())
			if err != nil || storedErr != nil || held.Quantity != 9 || held.Sold != 0 || stored.State != pp.PaymentStateCreated {
				t.Fatal("denied callback changed reserved counters/state")
			}
			t.Setenv("allowDummyPayment", "true")
			for i := 0; i < 2; i++ {
				if paid, err := NotifyPayment(nil, payer.Owner, payment.Name, "en"); err != nil || paid.State != pp.PaymentStatePaid {
					t.Fatal("immutable admitted Dummy outcome was stranded")
				}
			}
			assertSingleTenantFulfillment(t, engine, payer, payment.Name)
			if change == "group-disabled" {
				group, err := GetGroup(util.GetId(payer.Owner, "tenant"))
				if err != nil || group.IsEnabled {
					t.Fatal("settlement re-enabled Group")
				}
			}
			if ok, err := DeleteProduct(current); err != nil || !ok {
				t.Fatal("fully settled product remained reservation-locked")
			}
			if paid, err := NotifyPayment(nil, payer.Owner, payment.Name, "en"); err != nil || paid.State != pp.PaymentStatePaid {
				t.Fatal("Paid replay depended on current product existence")
			}
		})
	}
}

func TestTenantCheckoutLegacyUnreservedIntentRequiresReconciliation(t *testing.T) {
	engine, payer, infos := setupTenantCheckoutReplacementAbuseFixture(t)
	order, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none")
	if err != nil {
		t.Fatal(err)
	}
	product, err := GetProduct(util.GetId(payer.Owner, "product"))
	if err != nil {
		t.Fatal(err)
	}
	// Explicit old-format fixture: committed Payment/link, but no reservation.
	// Do not obtain it by invoking the new reserve operation or mint its flag.
	legacy, _, err := newGroupPaymentIntent(order, payer, product, &Provider{Owner: payer.Owner, Name: payer.Owner + "_dummy", Type: "Dummy", Category: "Payment"}, "internal.invalid")
	if err != nil || legacy.GroupStockReserved {
		t.Fatal("legacy fixture established a reservation")
	}
	if _, err := engine.Insert(legacy); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	timeline, _ := groupTimeline(nil, now)
	terms, err := claimCheckoutTerms(order.CheckoutTerms, timeline, now)
	if err != nil {
		t.Fatal(err)
	}
	order.Payment = legacy.Name
	order.State = "Processing"
	order.CheckoutTerms = terms
	order.CheckoutRevision = 2
	if _, err := engine.Where("owner = ? and name = ?", order.Owner, order.Name).Cols("payment", "state", "checkout_terms", "checkout_revision").Update(order); err != nil {
		t.Fatal(err)
	}
	if _, err := NotifyPayment(nil, payer.Owner, legacy.Name, "en"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("pre-reservation callback synthesized reserved stock")
	}
	if _, _, err := PayGroupOrder(checkoutFixtureAdmission(order), payer.Owner+"_dummy", "internal.invalid", "en"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("legacy intent redispatched")
	}
	if _, err := CancelGroupOrder("app/"+payer.Owner, payer.Name, order, 2); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("legacy linked intent canceled")
	}
	if _, err := PlaceGroupOrder("app/"+payer.Owner, payer.Owner, "tenant", infos, payer, "none"); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatal("legacy intent replaced")
	}
	stock, err := GetProduct(product.GetId())
	stored, storedErr := GetPayment(legacy.GetId())
	subs, subErr := engine.Where("owner = ?", payer.Owner).Count(&Subscription{})
	transactions, txErr := engine.Where("owner = ?", payer.Owner).Count(&Transaction{})
	if err != nil || storedErr != nil || subErr != nil || txErr != nil || stock.Quantity != 10 || stock.Sold != 0 || stored.GroupStockReserved || stored.State != pp.PaymentStateCreated || subs != 0 || transactions != 0 {
		t.Fatal("legacy reconciliation guard mutated financial/stock truth")
	}
}
