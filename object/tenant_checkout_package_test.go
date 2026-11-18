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
