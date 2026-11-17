package object

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/pp"
	"github.com/xorm-io/core"
)

func historyFixture() (*Order, *Payment) {
	order := &Order{Owner: "org", Group: "tenant", Name: "order_00000000-0000-4000-8000-000000000001", User: "persisted-payer", CreatedTime: "2026-11-13T10:00:00Z", State: "Paid", Price: 5, Currency: "USD", Products: []string{"retired-product"}, ProductInfos: []ProductInfo{{Name: "retired-product", PlanName: "retired-plan", PricingName: "retired-pricing", DisplayName: "Stored PRODUCT label", Quantity: 1}}, Payment: "payment_00000000-0000-4000-8000-000000000001", CheckoutTerms: &GroupCheckoutTerms{Version: 1, Kind: "fresh", PreviousPeriodRevision: "none", Period: PeriodMonthly, StartTime: "2026-11-13T10:00:00Z", EndTime: "2026-12-13T10:00:00Z"}}
	raw, _ := json.Marshal(pp.DummyOrderInfo{Price: 5, Currency: "USD"})
	payment := &Payment{Owner: order.Owner, Group: order.Group, Name: order.Payment, User: order.User, Order: order.Name, Products: []string{"retired-product"}, Price: 5, Currency: "USD", Type: "Dummy", State: pp.PaymentStatePaid, GroupStockReserved: true, OutOrderId: string(raw), PersonEmail: "private-contact-canary", PersonIdCard: "private-card-canary", InvoiceUrl: "private-invoice-canary", Message: "private-message-canary", PayUrl: "private-url-canary"}
	return order, payment
}

func TestTenantCheckoutHistoryCursorIsBoundedAndTenantScoped(t *testing.T) {
	order, _ := historyFixture()
	token, err := encodeGroupHistoryCursor(order)
	if err != nil {
		t.Fatal("valid native cursor rejected")
	}
	cursor, err := parseGroupHistoryCursor("org", "tenant", token)
	if err != nil || cursor.Name != order.Name || cursor.CreatedTime != order.CreatedTime {
		t.Fatal("cursor lost native tie-break key")
	}
	for _, tc := range []struct{ owner, group, token string }{
		{"foreign", "tenant", token}, {"org", "foreign", token}, {"org", "tenant", strings.Repeat("x", groupHistoryMaxCursor+1)}, {"org", "tenant", "not base64"},
		{"org", "tenant", base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"owner":"org","group":"tenant","createdTime":"2026-11-13T10:00:00Z","name":"` + order.Name + `"}`))},
		{"org", "tenant", base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"owner":"org","group":"tenant","createdTime":"bad","name":"` + order.Name + `"}`))},
		{"org", "tenant", base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"owner":"org","group":"tenant","createdTime":"2026-11-13T10:00:00Z","name":"payer@example.test"}`))},
		{"org", "tenant", base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"owner":"org","group":"tenant","createdTime":"2026-11-13T10:00:00Z","name":"` + order.Name + `","extra":true}`))},
		{"org", "tenant", base64.RawURLEncoding.EncodeToString([]byte(`{"v":1} {"v":1}`))},
	} {
		if _, err := parseGroupHistoryCursor(tc.owner, tc.group, tc.token); !errors.Is(err, ErrGroupHistoryInvalidQuery) {
			t.Fatal("foreign/malformed cursor accepted")
		}
	}
	for _, name := range []string{"order_20261113_100000_abcdef0", "payment_20261113_100000_123abcd"} {
		if !groupHistoryReference.MatchString(name) {
			t.Fatal("native legacy time ID rejected")
		}
	}
}

func TestTenantCheckoutHistoryProjectionUsesStoredFactsOnly(t *testing.T) {
	t.Setenv("paymentDeploymentEnvironment", "prod")
	t.Setenv("allowDummyPayment", "false")
	order, payment := historyFixture()
	item, err := projectGroupHistory(order, payment)
	if err != nil || item.Plan != "retired-plan" || item.ProductDisplayName == nil || *item.ProductDisplayName != "Stored PRODUCT label" || item.PurchaseKind == nil || *item.PurchaseKind != "fresh" || item.PeriodEnd == nil || *item.PeriodEnd != "2026-12-13T10:00:00Z" || item.PaymentMode == nil || *item.PaymentMode != "test" {
		t.Fatal("stored period/price/test facts depend on live capability")
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-", "persisted-payer", "outOrderId", "personEmail", "invoiceUrl", "checkoutRevision", "payUrl", "provider"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("history leaked non-whitelisted fields")
		}
	}
	// Old terms are unknown, never reconstructed from date, current catalog or subscription.
	order.CheckoutTerms = nil
	payment.GroupStockReserved = false
	item, err = projectGroupHistory(order, payment)
	if err != nil || item.Period != nil || item.PeriodStart != nil || item.PeriodEnd != nil || item.PurchaseKind != nil || item.PaymentMode != nil || item.PaymentState == nil || *item.PaymentState != pp.PaymentStatePaid {
		t.Fatal("legacy unknown was reconstructed or Paid pair lost")
	}
	order.Payment = ""
	order.State = "Canceled"
	item, err = projectGroupHistory(order, nil)
	if err != nil || item.PaymentName != nil || item.PaymentState != nil || item.Price != 5 {
		t.Fatal("unpaid quote became a charge")
	}
	order.State = "UnexpectedNativeState"
	item, err = projectGroupHistory(order, nil)
	if err != nil || item.OrderState != "UnexpectedNativeState" || item.PaymentState != nil {
		t.Fatal("unknown native state became Paid")
	}
}

func TestTenantCheckoutHistoryContradictoryFinancialPairFailsClosed(t *testing.T) {
	for _, mutate := range []func(*Order, *Payment){
		func(o *Order, p *Payment) { p.Group = "foreign" }, func(o *Order, p *Payment) { p.Owner = "foreign" }, func(o *Order, p *Payment) { p.User = "other" }, func(o *Order, p *Payment) { p.Order = "other" }, func(o *Order, p *Payment) { p.Price = 6 }, func(o *Order, p *Payment) { p.Currency = "TRY" }, func(o *Order, p *Payment) { p.Products = []string{"other"} }, func(o *Order, p *Payment) { p.State = pp.PaymentStateCreated }, func(o *Order, p *Payment) { o.State = "Created" }, func(o *Order, p *Payment) { o.Name = "payer@example.test" }, func(o *Order, p *Payment) { p.Name = "payer@example.test"; o.Payment = p.Name }, func(o *Order, p *Payment) { o.Price = math.NaN() }, func(o *Order, p *Payment) { o.ProductInfos[0].IsRecharge = true }, func(o *Order, p *Payment) { o.CheckoutTerms.EndTime = "2030-01-01T00:00:00Z" },
	} {
		o, p := historyFixture()
		mutate(o, p)
		if _, err := projectGroupHistory(o, p); !errors.Is(err, ErrGroupCheckoutUnavailable) {
			t.Fatal("contradiction became a successful financial row")
		}
	}
	o, p := historyFixture()
	if _, err := projectGroupHistory(o, nil); !errors.Is(err, ErrGroupCheckoutUnavailable) {
		t.Fatal("missing Paid evidence accepted")
	}
	p.OutOrderId = "unproven legacy reference"
	item, err := projectGroupHistory(o, p)
	if err != nil || item.PaymentMode != nil {
		t.Fatal("test mode inferred without stored admission snapshot")
	}
}

func TestTenantCheckoutHistoryScopeAndBoundsRejectBeforeStorage(t *testing.T) {
	if ormer != nil {
		t.Fatal("refusing initialized storage")
	}
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	for _, tc := range []struct {
		principal, owner, group string
		limit                   int
		cursor                  string
		want                    error
	}{
		{"org/payer", "org", "tenant", 20, "", ErrTenantCheckoutRequired}, {"app/foreign", "org", "tenant", 20, "", ErrTenantCheckoutRequired}, {"app/cerberus", "foreign", "tenant", 20, "", ErrTenantCheckoutRequired}, {"app/cerberus", "org", "foreign/tenant", 20, "", ErrTenantCheckoutRequired}, {"app/cerberus", "org", "tenant", 0, "", ErrGroupHistoryInvalidQuery}, {"app/cerberus", "org", "tenant", 51, "", ErrGroupHistoryInvalidQuery}, {"app/cerberus", "org", "tenant", 20, "bad", ErrGroupHistoryInvalidQuery},
	} {
		if _, err := GetGroupCheckoutHistory(tc.principal, tc.owner, tc.group, tc.limit, tc.cursor); !errors.Is(err, tc.want) {
			t.Fatal("invalid history scope reached storage")
		}
	}
}

// Default OFF. This case inherits the existing exact owned-profile guard; it
// cannot run until the future owner receipt/profile and explicit release exist.
func TestTenantCheckoutHistoryPostgresReadOnlyScopeAndCursor(t *testing.T) {
	engine, payer, _ := setupTenantCheckoutReplacementAbuseFixture(t)
	owner := payer.Owner
	principal := "app/" + owner
	for _, suffix := range []string{"a", "b", "c"} {
		o, p := historyFixture()
		o.Owner = owner
		o.User = payer.Name
		o.Name = "order_00000000-0000-4000-8000-00000000000" + suffix
		if suffix != "c" {
			o.State = "Canceled"
			o.Payment = ""
			o.CheckoutTerms = nil
		} else {
			p.Owner = owner
			p.User = payer.Name
			p.Order = o.Name
			if _, err := engine.Insert(p); err != nil {
				t.Fatal("payment fixture insert")
			}
		}
		if _, err := engine.Insert(o); err != nil {
			t.Fatal("order fixture insert")
		}
	}
	foreign, _ := historyFixture()
	foreign.Owner = owner
	foreign.Group = "foreign"
	foreign.State = "Created"
	foreign.Payment = ""
	foreign.Name = "order_ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := engine.Insert(foreign); err != nil {
		t.Fatal("foreign fixture insert")
	}
	if _, err := engine.ID(core.PK{owner, "tenant"}).Cols("is_enabled").Update(&Group{IsEnabled: false}); err != nil {
		t.Fatal("disable fixture Group")
	}
	if _, err := engine.Where("owner = ?", owner).Delete(&Provider{}); err != nil {
		t.Fatal("remove fixture provider")
	}
	t.Setenv("allowDummyPayment", "false")
	t.Setenv("paymentDeploymentEnvironment", "prod")
	before := []*Order{}
	if err := engine.Where("owner = ?", owner).Asc("name").Find(&before); err != nil {
		t.Fatal(err)
	}
	first, err := GetGroupCheckoutHistory(principal, owner, "tenant", 2, "")
	if err != nil || first.ReadScope != "history" || first.CanResume || first.CanCancel || len(first.Items) != 2 || !strings.HasSuffix(first.Items[0].OrderName, "00c") || !strings.HasSuffix(first.Items[1].OrderName, "00b") || first.NextCursor == nil {
		t.Fatal("first scope/tie-break page failed")
	}
	// A newly inserted higher key cannot repeat already returned rows or hide the remaining lower key.
	newer, _ := historyFixture()
	newer.Owner = owner
	newer.User = payer.Name
	newer.Name = "order_00000000-0000-4000-8000-00000000000d"
	newer.State = "Created"
	newer.Payment = ""
	newer.CheckoutTerms = nil
	if _, err := engine.Insert(newer); err != nil {
		t.Fatal("newer fixture insert")
	}
	second, err := GetGroupCheckoutHistory(principal, owner, "tenant", 2, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || !strings.HasSuffix(second.Items[0].OrderName, "00a") || second.NextCursor != nil {
		t.Fatal("keyset page repeated or crossed scope")
	}
	if _, err := GetGroupCheckoutHistory(principal, owner, "foreign", 2, *first.NextCursor); !errors.Is(err, ErrGroupHistoryInvalidQuery) {
		t.Fatal("foreign cursor replaced Group authority")
	}
	after := []*Order{}
	if err := engine.Where("owner = ? AND name <> ?", owner, newer.Name).Asc("name").Find(&after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("history read changed stored lifecycle/terms")
	}
	// A corrupted persisted financial pair must fail, rather than display Paid.
	if _, err := engine.ID(core.PK{owner, "payment_00000000-0000-4000-8000-000000000001"}).Cols("price").Update(&Payment{Price: 6}); err != nil {
		t.Fatal("corrupt fixture pair")
	}
	if _, err := GetGroupCheckoutHistory(principal, owner, "tenant", 50, ""); !errors.Is(err, ErrGroupCheckoutUnavailable) {
		t.Fatal("contradictory financial history displayed Paid")
	}
}
