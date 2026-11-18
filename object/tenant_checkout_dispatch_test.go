package object

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/pp"
)

func TestTenantCheckoutGroupOnlyAllowsBoundTrustedDummy(t *testing.T) {
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "true")
	product := &Product{Owner: "org", Name: "product", Providers: []string{"dummy"}}
	provider := Provider{Owner: "org", Name: "dummy", Category: "Payment", Type: "Dummy"}
	if err := checkGroupProductProvider(product, &provider); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Provider){
		func(p *Provider) { p.Owner = "foreign" }, func(p *Provider) { p.Name = "unbound" },
		func(p *Provider) { p.Category = "Email" }, func(p *Provider) { p.State = "Disabled" },
		func(p *Provider) { p.Type = "Stripe" }, func(p *Provider) { p.Type = "Balance" },
	} {
		changed := provider
		mutate(&changed)
		if !errors.Is(checkGroupProductProvider(product, &changed), ErrGroupCheckoutUnavailable) {
			t.Fatal("unsupported/unbound Group provider accepted")
		}
	}
	for _, deployment := range []string{"", "prod", "production", "unknown"} {
		t.Setenv("paymentDeploymentEnvironment", deployment)
		if !errors.Is(checkGroupProductProvider(product, &provider), ErrGroupCheckoutUnavailable) {
			t.Fatal("Group Dummy accepted outside trusted test deployment")
		}
	}
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "false")
	if checkGroupProductProvider(product, &provider) == nil {
		t.Fatal("Group Dummy accepted without explicit opt-in")
	}
	if checkDummyPayment("Stripe") != nil {
		t.Fatal("changed personal real-provider contract")
	}
	// The old private path may never bypass the durable Group claim.
	if _, _, err := payOrder("dummy", "localhost", "demo", &Order{Group: "tenant", State: "Created"}, nil, "en"); !errors.Is(err, ErrGroupCheckoutUnavailable) {
		t.Fatal("legacy Group path still dispatches")
	}
}

func TestTenantCheckoutNativeDummyIdentityPreparedBeforeDispatch(t *testing.T) {
	t.Setenv("origin", "https://casdoor.example.test")
	t.Setenv("originFrontend", "")
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "true")
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", Price: 5, Currency: "USD", Products: []string{"product"}, ProductInfos: []ProductInfo{{Name: "product", PricingName: "pricing", PlanName: "plan", Quantity: 1}}}
	payer := &User{Owner: "org", Name: "payer", Id: "real-payer-id", Email: "verified@example.test"}
	product := &Product{Owner: "org", Name: "product", Providers: []string{"dummy"}}
	provider := &Provider{Owner: "org", Name: "dummy", Category: "Payment", Type: "Dummy"}
	payment, request, err := newGroupPaymentIntent(order, payer, product, provider, "127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	if payment.Name == "" || payment.OutOrderId == "" || request.PaymentName != payment.Name || request.PayerId != payer.Id || request.PayerEmail != payer.Email || request.PaymentEnv != "test" || payment.Order != order.Name || payment.Group != order.Group || payment.User != payer.Name {
		t.Fatal("lost immutable intent or persisted payer")
	}
	if !strings.HasPrefix(payment.PayUrl, "https://casdoor.example.test/buy-plan/") || strings.Contains(payment.PayUrl, "127.0.0.1") {
		t.Fatal("internal HTTP host became public URL authority")
	}
	native, _ := pp.NewDummyPaymentProvider()
	response, err := native.Pay(request)
	if err != nil || response.OrderId != payment.OutOrderId || response.PayUrl != payment.PayUrl {
		t.Fatal("predispatch native Dummy identity differs from provider response")
	}
	confirmed, err := native.Notify(nil, payment.OutOrderId)
	if err != nil || confirmed.PaymentStatus != pp.PaymentStatePaid || confirmed.Price != 5 || confirmed.Currency != "USD" {
		t.Fatal("prepared identity cannot resolve native confirmation")
	}
}

func TestTenantCheckoutGroupDispatchAdmissionAndGenericBoundary(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", CheckoutRevision: 1}
	admission := GroupPaymentAdmission{Principal: "app/cerberus", Owner: "org", Group: "tenant", OrderName: "order", PayerName: "payer", ExpectedCheckoutRevision: 1}
	if err := matchGroupPaymentAdmission(admission, order); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*GroupPaymentAdmission){func(a *GroupPaymentAdmission) { a.Principal = "org/payer" }, func(a *GroupPaymentAdmission) { a.Principal = "app/foreign" }, func(a *GroupPaymentAdmission) { a.Owner = "foreign" }, func(a *GroupPaymentAdmission) { a.Group = "other" }, func(a *GroupPaymentAdmission) { a.OrderName = "other" }, func(a *GroupPaymentAdmission) { a.PayerName = "manager" }, func(a *GroupPaymentAdmission) { a.ExpectedCheckoutRevision = 0 }, func(a *GroupPaymentAdmission) { a.ExpectedCheckoutRevision = 2 }} {
		changed := admission
		mutate(&changed)
		if matchGroupPaymentAdmission(changed, order) == nil {
			t.Fatal("unbound admission accepted")
		}
	}
	// No ORM exists here: the generic entry must reject before claim/provider.
	if _, _, err := PayOrder("dummy", "attacker.example", "demo", order, nil, "en"); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("generic Group dispatch reached storage")
	}
	if _, _, err := PayGroupOrder(GroupPaymentAdmission{}, "dummy", "attacker.example", "en"); !errors.Is(err, ErrTenantCheckoutRequired) {
		t.Fatal("unadmitted Group dispatch reached storage")
	}
}

func TestTenantCheckoutGroupPublicOriginIsTrustedAndRequired(t *testing.T) {
	t.Setenv("originFrontend", "")
	for _, origin := range []string{"", "//attacker.example", "https://user:secret@example.test", "https://example.test/path", "https://example.test?next=evil", "https://example.test#fragment", "https://example.test?", "javascript:alert(1)"} {
		t.Setenv("origin", origin)
		if _, _, err := groupPaymentOrigins(); !errors.Is(err, ErrGroupCheckoutUnavailable) {
			t.Fatal("missing/invalid trusted origin accepted")
		}
	}
	t.Setenv("origin", "https://backend.example.test/")
	t.Setenv("originFrontend", "https://public.example.test/")
	front, back, err := groupPaymentOrigins()
	if err != nil || front != "https://public.example.test" || back != "https://backend.example.test" {
		t.Fatal("configured origin pair changed")
	}
}

func TestTenantCheckoutGroupResponseRejectsMixedCanonicalStates(t *testing.T) {
	t.Setenv("origin", "https://casdoor.example.test")
	t.Setenv("originFrontend", "")
	order := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", Payment: "payment", State: "Processing", CheckoutRevision: 2, Price: 5, Currency: "USD", Products: []string{"product"}, ProductInfos: []ProductInfo{{Name: "product", PricingName: "pricing", PlanName: "plan", Quantity: 1}}, CheckoutTerms: &GroupCheckoutTerms{Version: 1, Kind: "fresh", PreviousPeriodRevision: "none", Period: PeriodMonthly, StartTime: "2026-11-12T00:00:00Z", EndTime: "2026-12-12T00:00:00Z"}}
	resultURL := "https://casdoor.example.test/buy-plan/org/pricing/result?payment=payment"
	payment := &Payment{Owner: "org", Name: "payment", Group: "tenant", User: "payer", Order: "order", State: pp.PaymentStateCreated, Price: 5, Currency: "USD", Products: []string{"product"}, PayUrl: resultURL, SuccessUrl: resultURL, GroupStockReserved: true}
	payment.GroupStockReserved = false
	if !errors.Is(validateGroupPaymentResponse(order, payment), ErrGroupCheckoutConflict) {
		t.Fatal("pre-reservation intent was treated as reserved")
	}
	payment.GroupStockReserved = true
	if err := validateGroupPaymentResponse(order, payment); err != nil {
		t.Fatal("valid committed pair rejected")
	}
	order.State = "Paid"
	order.CheckoutRevision = 3
	if !errors.Is(validateGroupPaymentResponse(order, payment), ErrGroupCheckoutConflict) {
		t.Fatal("stale Created Payment paired with callback's Paid order")
	}
	payment.State = pp.PaymentStatePaid
	if err := validateGroupPaymentResponse(order, payment); err != nil {
		t.Fatal("callback-winning canonical pair rejected")
	}
	payment.PayUrl = "http://internal.invalid/pay"
	if !errors.Is(validateGroupPaymentResponse(order, payment), ErrGroupCheckoutUnavailable) {
		t.Fatal("stored untrusted result URL was returned")
	}
}

func TestTenantCheckoutStockReservationIsServerOnlyJSON(t *testing.T) {
	payment := &Payment{GroupStockReserved: true}
	encoded, err := json.Marshal(payment)
	if err != nil || strings.Contains(strings.ToLower(string(encoded)), "stockreserved") {
		t.Fatal("internal reservation leaked into payment JSON")
	}
	var supplied Payment
	if err := json.Unmarshal([]byte(`{"groupStockReserved":true,"GroupStockReserved":true}`), &supplied); err != nil || supplied.GroupStockReserved {
		t.Fatal("browser JSON established a stock reservation")
	}
}

func TestTenantCheckoutReservedProductMutationProtectsCountersAndIdentity(t *testing.T) {
	canonical := &Product{Owner: "org", Name: "product", Quantity: 0, Sold: 4, Providers: []string{"dummy"}}
	changed := *canonical
	changed.DisplayName = "new presentation"
	changed.Providers = []string{"other"}
	if err := validateReservedProductMutation(canonical, &changed, true); err != nil {
		t.Fatal("safe catalog edit blocked")
	}
	for _, mutate := range []func(*Product){func(p *Product) { p.Quantity = 1 }, func(p *Product) { p.Sold = 0 }, func(p *Product) { p.Owner = "foreign" }, func(p *Product) { p.Name = "replacement" }} {
		changed := *canonical
		mutate(&changed)
		if !errors.Is(validateReservedProductMutation(canonical, &changed, true), ErrGroupCheckoutConflict) {
			t.Fatal("stale counters or product identity overwrote a held unit")
		}
		if err := validateReservedProductMutation(canonical, &changed, false); err != nil {
			t.Fatal("unrelated native mutation contract changed")
		}
	}
}

func TestTenantCheckoutDispatchRequiresCommittedClaim(t *testing.T) {
	_, _, err := dispatchGroupPayment(func() (*Payment, *pp.PayReq, error) {
		return nil, nil, errors.New("private insert/link/commit failure")
	}, func(*pp.PayReq) (*pp.PayResp, error) { t.Fatal("provider ran before durable claim"); return nil, nil }, func(*Payment, *pp.PayResp) (*Payment, error) { t.Fatal("finish after claim failure"); return nil, nil })
	if !errors.Is(err, ErrGroupCheckoutUnavailable) {
		t.Fatal("unsanitized failed claim")
	}
}

func TestTenantCheckoutUnknownProviderOutcomeRetainsIdentityWithoutRedispatch(t *testing.T) {
	intent := &Payment{Owner: "org", Name: "stable", Group: "tenant", Order: "order", OutOrderId: "stable-native-order", State: pp.PaymentStateCreated}
	for _, failAt := range []string{"provider-response", "metadata-write"} {
		t.Run(failAt, func(t *testing.T) {
			payment, _, err := dispatchGroupPayment(func() (*Payment, *pp.PayReq, error) { return intent, &pp.PayReq{PaymentName: intent.Name}, nil }, func(request *pp.PayReq) (*pp.PayResp, error) {
				if request.PaymentName != "stable" {
					t.Fatal("provider correlation changed")
				}
				if failAt == "provider-response" {
					return nil, errors.New("accepted operation; synchronous result lost")
				}
				return &pp.PayResp{OrderId: intent.OutOrderId}, nil
			}, func(p *Payment, r *pp.PayResp) (*Payment, error) {
				return nil, errors.New("postdispatch metadata persistence failure")
			})
			if !errors.Is(err, ErrGroupCheckoutUnavailable) || payment != intent || payment.State != pp.PaymentStateCreated || payment.OutOrderId != "stable-native-order" {
				t.Fatal("unknown result erased stable intent")
			}
			repeated, _, err := dispatchGroupPayment(func() (*Payment, *pp.PayReq, error) { return intent, nil, nil }, func(*pp.PayReq) (*pp.PayResp, error) { t.Fatal("unknown outcome redispatched"); return nil, nil }, func(*Payment, *pp.PayResp) (*Payment, error) {
				t.Fatal("repeat wrote provider result")
				return nil, nil
			})
			if repeated != intent || !errors.Is(err, ErrGroupCheckoutUnavailable) {
				t.Fatal("retry lost unresolved identity")
			}
		})
	}
}

func TestTenantCheckoutCanonicalCancelRejectsStaleOrLinkedOrder(t *testing.T) {
	requested := &Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", State: "Created", CheckoutRevision: 1}
	canonical := *requested
	if checkGroupOrderCancellation(&canonical, requested, 1) != nil {
		t.Fatal("unpaid predispatch cancellation blocked")
	}
	canceled := canonical
	canceled.State = "Canceled"
	canceled.CheckoutRevision = 2
	if checkGroupOrderCancellation(&canceled, requested, 1) != nil {
		t.Fatal("repeat predispatch cancellation must be idempotent")
	}
	for _, mutate := range []func(*Order){func(o *Order) { o.State = "Processing" }, func(o *Order) { o.Payment = "stable" }, func(o *Order) { o.State = "Paid" }, func(o *Order) { o.Group = "other" }, func(o *Order) { o.User = "other" }} {
		changed := canonical
		mutate(&changed)
		if !errors.Is(checkGroupOrderCancellation(&changed, requested, 1), ErrGroupCheckoutConflict) {
			t.Fatal("stale client could cancel canonical intent")
		}
	}
}
