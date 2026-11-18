// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/pp"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

// This routing test uses no database, provider, enrollment or application cache.
func TestTenantPackageCheckoutRequiresBoundApplication(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	info := ProductInfo{Name: "ai-budget-" + strings.Repeat("a", 64), Quantity: 1}
	if err := CheckTenantCheckoutRequest("app/cerberus", "org", "tenant", []ProductInfo{info}); err != nil {
		t.Fatalf("bound application must admit a planless package to product validation: %v", err)
	}
	for _, tc := range []struct {
		name, principal, owner, group string
		infos                         []ProductInfo
	}{
		{"personal", "org/payer", "org", "tenant", []ProductInfo{info}},
		{"other application", "app/other", "org", "tenant", []ProductInfo{info}},
		{"other organization", "app/cerberus", "other", "tenant", []ProductInfo{info}},
		{"missing group", "app/cerberus", "org", "", []ProductInfo{info}},
		{"multiple products", "app/cerberus", "org", "tenant", []ProductInfo{info, info}},
		{"quantity", "app/cerberus", "org", "tenant", []ProductInfo{{Name: info.Name, Quantity: 2}}},
		{"package disguised as plan", "app/cerberus", "org", "tenant", []ProductInfo{{Name: info.Name, Quantity: 1, PricingName: "pricing", PlanName: "plan"}}},
		{"invalid reserved SKU", "app/cerberus", "org", "tenant", []ProductInfo{{Name: "ai-budget-invalid", Quantity: 1, PricingName: "pricing", PlanName: "plan"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckTenantCheckoutRequest(tc.principal, tc.owner, tc.group, tc.infos); !errors.Is(err, ErrTenantCheckoutRequired) {
				t.Fatalf("unbound package request must fail closed: %v", err)
			}
		})
	}
}

func TestTenantPackageCheckoutRequiresCanonicalPublishedProduct(t *testing.T) {
	product := Product{
		Name:       fmt.Sprintf("ai-budget-%x", sha256.Sum256([]byte("starter@v1"))),
		State:      "Published",
		Price:      5,
		Currency:   "USD",
		Quantity:   2,
		Properties: map[string]string{"checkout_kind": "package", "package_id": "starter", "package_version": "v1"},
	}
	if err := validateTenantPackageProduct(&product); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Product)
	}{
		{"wrong version", func(p *Product) {
			p.Properties = map[string]string{"checkout_kind": "package", "package_id": "starter", "package_version": "v2"}
		}},
		{"missing catalog binding", func(p *Product) { p.Properties = nil }},
		{"recharge", func(p *Product) { p.IsRecharge = true }},
		{"unpublished", func(p *Product) { p.State = "Draft" }},
		{"no stock", func(p *Product) { p.Quantity = 0 }},
		{"no charge", func(p *Product) { p.Price = 0 }},
		{"no currency", func(p *Product) { p.Currency = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := product
			tc.change(&changed)
			if !errors.Is(validateTenantPackageProduct(&changed), ErrGroupCheckoutConflict) {
				t.Fatal("invalid or changed package product accepted")
			}
		})
	}
}

func TestTenantPackageCheckoutDummyIntentAndReadbackWithoutPlan(t *testing.T) {
	t.Setenv("origin", "https://casdoor.example.test")
	t.Setenv("originFrontend", "")
	t.Setenv("paymentDeploymentEnvironment", "test")
	t.Setenv("allowDummyPayment", "true")
	sku := fmt.Sprintf("ai-budget-%x", sha256.Sum256([]byte("starter@v1")))
	product := &Product{Owner: "org", Name: sku, Providers: []string{"dummy"}}
	payer := &User{Owner: "org", Name: "payer"}
	provider := &Provider{Owner: "org", Name: "dummy", Category: "Payment", Type: "Dummy"}
	terms := GroupCheckoutTerms{Version: 1, Kind: "package", PreviousPeriodRevision: "none"}
	order := &Order{
		Owner: "org", Name: "order", Group: "tenant", User: "payer", Price: 5, Currency: "USD",
		State: "Created", CheckoutRevision: 1, CheckoutTerms: &terms, Products: []string{sku},
		ProductInfos: []ProductInfo{{Name: sku, Quantity: 1}},
	}
	payment, request, err := newGroupPaymentIntent(order, payer, product, provider, "ignored-internal.example")
	if err != nil {
		t.Fatal(err)
	}
	resultURL := "https://casdoor.example.test/buy-plan/org/ai-budget/result?payment=" + payment.Name
	if payment.PayUrl != resultURL || request.ReturnUrl != resultURL || payment.Group != "tenant" || payment.Order != order.Name || payment.User != payer.Name ||
		payment.Price != order.Price || payment.Currency != order.Currency {
		t.Fatalf("payment intent does not preserve the package order or public result route")
	}
	payment.GroupStockReserved = true
	order.Payment, order.State, order.CheckoutRevision = payment.Name, "Processing", 2
	if err := validateGroupPaymentResponse(order, payment); err != nil {
		t.Fatal(err)
	}
	order.State, order.CheckoutRevision, payment.State = "Paid", 3, pp.PaymentStatePaid
	if err := validateGroupPaymentResponse(order, payment); err != nil {
		t.Fatal(err)
	}
	terms.Period = PeriodMonthly
	if !errors.Is(validateGroupPaymentResponse(order, payment), ErrGroupCheckoutConflict) {
		t.Fatal("package payment accepted plan terms")
	}
}

func paidPackageFixture(owner, name string) (Order, Payment) {
	sku := fmt.Sprintf("ai-budget-%x", sha256.Sum256([]byte("starter@v1")))
	order := Order{
		Owner: owner, Name: name + "-order", Group: "tenant", User: "payer",
		State: "Paid", CheckoutRevision: 3, Payment: name, Price: 5, Currency: "USD",
		CheckoutTerms: &GroupCheckoutTerms{Version: 1, Kind: "package", PreviousPeriodRevision: "none"},
		Products:      []string{sku},
		ProductInfos:  []ProductInfo{{Name: sku, Quantity: 1}},
	}
	payment := Payment{
		Owner: owner, Name: name, Group: order.Group, User: order.User, Order: order.Name,
		State: pp.PaymentStatePaid, GroupStockReserved: true, Price: order.Price, Currency: order.Currency,
		Products: []string{sku},
	}
	return order, payment
}

func TestTenantPackageCheckoutUnboundPaidPaymentRequiresSettledPackage(t *testing.T) {
	order, payment := paidPackageFixture("org", "payment")
	if err := validatePaidPackagePayment(&order, &payment); err != nil {
		t.Fatalf("settled package must be admitted: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Order, *Payment)
	}{
		{"plan order", func(o *Order, p *Payment) {
			o.Products, p.Products = []string{"product"}, []string{"product"}
			o.ProductInfos = []ProductInfo{{Name: "product", Quantity: 1, PricingName: "pricing", PlanName: "plan"}}
			o.CheckoutTerms = &GroupCheckoutTerms{
				Version: 1, Kind: "fresh", PreviousPeriodRevision: "none", Period: PeriodMonthly,
				StartTime: "2026-11-01T00:00:00Z", EndTime: "2026-12-01T00:00:00Z",
			}
		}},
		{"order not paid", func(o *Order, p *Payment) { o.State = "Processing" }},
		{"revision below three", func(o *Order, p *Payment) { o.CheckoutRevision = 2 }},
		{"missing reservation", func(o *Order, p *Payment) { p.GroupStockReserved = false }},
		{"altered terms", func(o *Order, p *Payment) { o.CheckoutTerms.PreviousPeriodRevision = "changed" }},
		{"payment mismatch", func(o *Order, p *Payment) { p.Price++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order, payment := paidPackageFixture("org", "payment")
			tc.change(&order, &payment)
			if err := validatePaidPackagePayment(&order, &payment); !errors.Is(err, ErrGroupCheckoutConflict) {
				t.Fatalf("unbound paid payment must conflict: %v", err)
			}
		})
	}
}

func TestTenantPackageCheckoutMemoryPersistence(t *testing.T) {
	engine, payer, plan := setupTenantCheckoutMemoryFixture(t)
	testTenantPackageCheckoutPersistence(t, engine, payer, "app/cerberus", "dummy", plan, false)
}

func TestTenantPackageCheckoutPostgresPersistence(t *testing.T) {
	engine, payer, plan := setupTenantCheckoutReplacementAbuseFixture(t)
	testTenantPackageCheckoutPersistence(t, engine, payer, "app/"+payer.Owner, payer.Owner+"_dummy", plan, true)
}

func TestTenantPackageCheckoutPostgresPaidVolumePreservesPlanCheckout(t *testing.T) {
	engine, payer, plan := setupTenantCheckoutReplacementAbuseFixture(t)
	owner, principal := payer.Owner, "app/"+payer.Owner
	const total, batchSize = 1025, 128
	for start := 0; start < total; start += batchSize {
		var orders []Order
		var payments []Payment
		for i := start; i < min(start+batchSize, total); i++ {
			order, payment := paidPackageFixture(owner, fmt.Sprintf("top-up-%04d", i))
			orders, payments = append(orders, order), append(payments, payment)
		}
		if n, err := engine.Insert(&orders); err != nil || n != int64(len(orders)) {
			t.Fatalf("seed settled package orders: count=%d err=%v", n, err)
		}
		if n, err := engine.Insert(&payments); err != nil || n != int64(len(payments)) {
			t.Fatalf("seed settled package payments: count=%d err=%v", n, err)
		}
	}
	status, err := GetGroupCheckout(principal, owner, "tenant", payer.Name, "")
	if err != nil || !status.PurchaseEligible || status.CurrentSubscription != nil {
		t.Fatalf("paid packages blocked group checkout: %v", err)
	}
	if _, err := PlaceGroupOrder(principal, owner, "tenant", plan, payer, "none"); err != nil {
		t.Fatalf("paid package volume blocked plan placement: %v", err)
	}
	// This payment sorts after the valid pages and has no matching order.
	_, unbound := paidPackageFixture(owner, "unbound-payment")
	if _, err := engine.Insert(&unbound); err != nil {
		t.Fatal(err)
	}
	if _, err := GetGroupCheckout(principal, owner, "tenant", payer.Name, ""); !errors.Is(err, ErrGroupCheckoutConflict) {
		t.Fatalf("later unbound payment must conflict: %v", err)
	}
}

func testTenantPackageCheckoutPersistence(t *testing.T, engine *xorm.Engine, payer *User, principal, provider string, planInfos []ProductInfo, checkReadModels bool) {
	t.Helper()
	owner, group := payer.Owner, "tenant"
	planProduct, err := GetProduct(owner + "/" + planInfos[0].Name)
	if err != nil || planProduct == nil {
		t.Fatalf("read plan product control: %v", err)
	}
	// A product whose name differs in case from the reserved prefix is a plan.
	planProduct.Name = "AI-BUDGET-plan"
	if _, err = engine.Insert(planProduct); err != nil {
		t.Fatal(err)
	}
	if n, err := engine.ID(core.PK{owner, planInfos[0].PlanName}).Cols("product").Update(&Plan{Product: planProduct.Name}); err != nil || n != 1 {
		t.Fatalf("assign plan product control: count=%d err=%v", n, err)
	}
	planInfos[0].Name = planProduct.Name
	priorPlan, err := PlaceGroupOrder(principal, owner, group, planInfos, payer, "none")
	if err != nil {
		t.Fatalf("place prior plan: %v", err)
	}
	if _, err = CancelGroupOrder(principal, payer.Name, priorPlan, priorPlan.CheckoutRevision); err != nil {
		t.Fatalf("close prior plan: %v", err)
	}

	sku := fmt.Sprintf("ai-budget-%x", sha256.Sum256([]byte("starter@v1")))
	product := &Product{
		Owner: owner, Name: sku, State: "Published", Price: 8.25, Currency: "USD", Quantity: 2,
		Providers: []string{provider}, Properties: map[string]string{
			"checkout_kind": "package", "package_id": "starter", "package_version": "v1",
		},
	}
	if _, err = engine.Insert(product); err != nil {
		t.Fatal(err)
	}
	packageOrder, err := PlaceGroupOrder(principal, owner, group, []ProductInfo{{Name: sku, Quantity: 1}}, payer, "none")
	if err != nil {
		t.Fatalf("place package: %v", err)
	}
	if packageOrder.Price != 8.25 || packageOrder.Currency != "USD" || packageOrder.Group != group || packageOrder.User != payer.Name {
		t.Fatal("package quote lost its price, payer or tenant")
	}
	assertStatus := func(state string, paymentState pp.PaymentState) {
		t.Helper()
		status, err := GetGroupCheckout(principal, owner, group, payer.Name, "")
		if err != nil {
			t.Fatalf("read %s package: %v", state, err)
		}
		if status.OpenOrder == nil || status.OpenOrder.Name != packageOrder.Name || status.OpenOrder.State != state ||
			status.OpenOrder.PaymentState != paymentState || !status.CanResume || status.PurchaseEligibilityReason != "open_checkout" {
			t.Fatalf("incorrect %s package status: %#v", state, status)
		}
	}
	// The read models use the SQL read-only transaction command, exercised by CockroachDB.
	if checkReadModels {
		assertStatus("Created", "")
	}
	for _, drift := range []struct {
		field string
		row   *Product
	}{
		{"price", &Product{Price: 9.25}},
		{"currency", &Product{Currency: "EUR"}},
	} {
		t.Run(drift.field+"-drift", func(t *testing.T) {
			if n, err := engine.ID(core.PK{owner, sku}).Cols(drift.field).Update(drift.row); err != nil || n != 1 {
				t.Fatalf("change package %s: count=%d err=%v", drift.field, n, err)
			}
			if _, _, err := PayGroupOrder(checkoutFixtureAdmission(packageOrder), provider, "internal.invalid", "en"); !errors.Is(err, ErrGroupCheckoutConflict) {
				t.Fatalf("claim accepted %s drift: %v", drift.field, err)
			}
			if n, err := engine.Where("owner = ?", owner).Count(&Payment{}); err != nil || n != 0 {
				t.Fatalf("refused claim wrote a payment: count=%d err=%v", n, err)
			}
			if n, err := engine.ID(core.PK{owner, sku}).Cols(drift.field).Update(product); err != nil || n != 1 {
				t.Fatalf("restore package %s: count=%d err=%v", drift.field, n, err)
			}
		})
	}
	payment, _, err := PayGroupOrder(checkoutFixtureAdmission(packageOrder), provider, "internal.invalid", "en")
	if err != nil || payment == nil || !payment.GroupStockReserved || payment.Order != packageOrder.Name {
		t.Fatalf("claim package: %v", err)
	}
	if checkReadModels {
		assertStatus("Processing", pp.PaymentStateCreated)
	}
	for i := 0; i < 2; i++ {
		paid, err := NotifyPayment(nil, owner, payment.Name, "en")
		if err != nil || paid == nil || paid.Name != payment.Name || paid.State != pp.PaymentStatePaid {
			t.Fatalf("settle or replay package payment: %v", err)
		}
	}
	persisted, err := GetOrder(packageOrder.GetId())
	if err != nil || persisted == nil || persisted.State != "Paid" || persisted.Payment != payment.Name || persisted.CheckoutRevision != 3 {
		t.Fatalf("read persisted package payment link: %v", err)
	}
	stock, err := GetProduct(owner + "/" + sku)
	if err != nil || stock == nil || stock.Quantity != 1 || stock.Sold != 1 {
		t.Fatalf("package stock was not sold once: %v", err)
	}
	if n, err := engine.Where("owner = ? AND payment = ?", owner, payment.Name).Count(&Transaction{}); err != nil || n != 1 {
		t.Fatalf("package purchase count=%d err=%v", n, err)
	}
	if n, err := engine.Where("owner = ?", owner).Count(&Subscription{}); err != nil || n != 0 {
		t.Fatalf("package created a subscription: count=%d err=%v", n, err)
	}

	plan, err := PlaceGroupOrder(principal, owner, group, planInfos, payer, "none")
	if err != nil {
		t.Fatalf("place plan after package: %v", err)
	}
	planPayment, _, err := PayGroupOrder(checkoutFixtureAdmission(plan), provider, "internal.invalid", "en")
	if err != nil {
		t.Fatalf("claim plan after package: %v", err)
	}
	if _, err := NotifyPayment(nil, owner, planPayment.Name, "en"); err != nil {
		t.Fatalf("settle plan after package: %v", err)
	}
	sub := &Subscription{}
	if found, err := engine.ID(core.PK{owner, "sub_" + plan.Name}).Get(sub); err != nil || !found || sub.Payment != planPayment.Name || sub.Group != group {
		t.Fatalf("plan did not create its paid subscription: found=%t err=%v", found, err)
	}
	if !checkReadModels {
		return
	}
	status, err := GetGroupCheckout(principal, owner, group, payer.Name, "")
	if err != nil || status.CurrentSubscription == nil {
		t.Fatalf("group status after mixed settlement: %v", err)
	}
	page, err := GetGroupCheckoutHistory(principal, owner, group, 1, "")
	if err != nil || len(page.Items) != 1 || page.NextCursor == nil {
		t.Fatalf("first mixed history page: %v", err)
	}
	next, err := GetGroupCheckoutHistory(principal, owner, group, 1, *page.NextCursor)
	if err != nil || len(next.Items) != 1 || next.NextCursor != nil {
		t.Fatalf("last mixed history page: %v", err)
	}
	firstName, lastName := page.Items[0].OrderName, next.Items[0].OrderName
	if !(firstName == plan.Name && lastName == priorPlan.Name || firstName == priorPlan.Name && lastName == plan.Name) {
		t.Fatal("plan history included the package or lost an ordinary plan")
	}
}
