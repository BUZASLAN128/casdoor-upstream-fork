// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

var ErrGroupCheckoutUnavailable = errors.New("GROUP_CHECKOUT_UNAVAILABLE")

// Constructed by the Group controller only after actual Basic authentication.
// These fields bind App's final authorization/confirmation to one native order;
// they are not a browser ticket or a claim of atomic cross-database revocation.
type GroupPaymentAdmission struct {
	Principal                string
	Owner                    string
	Group                    string
	OrderName                string
	PayerName                string
	ExpectedCheckoutRevision int64
}

func validateGroupPaymentAdmission(a GroupPaymentAdmission) error {
	if err := CheckTenantCheckoutPrincipal(a.Principal, a.Owner); err != nil {
		return err
	}
	if a.Group == "" || a.OrderName == "" || a.PayerName == "" || strings.Contains(a.Group, "/") || strings.Contains(a.OrderName, "/") || strings.Contains(a.PayerName, "/") {
		return ErrTenantCheckoutRequired
	}
	if a.ExpectedCheckoutRevision < 1 {
		return ErrGroupCheckoutConflict
	}
	return nil
}

func matchGroupPaymentAdmission(a GroupPaymentAdmission, order *Order) error {
	if err := validateGroupPaymentAdmission(a); err != nil {
		return err
	}
	if order == nil || order.Owner != a.Owner || order.Group != a.Group || order.Name != a.OrderName || order.User != a.PayerName {
		return ErrTenantCheckoutRequired
	}
	if order.CheckoutRevision != a.ExpectedCheckoutRevision {
		return ErrGroupCheckoutConflict
	}
	return nil
}

// Both origins come from existing trusted server configuration. The HTTP Host
// seen by a server client can be internal and is never a public URL authority.
func groupPaymentOrigins() (string, string, error) {
	backend := conf.GetConfigString("origin")
	frontend := conf.GetConfigString("originFrontend")
	if frontend == "" {
		frontend = backend
	}
	if backend == "" {
		backend = frontend
	}
	for _, origin := range []string{frontend, backend} {
		parsed, err := url.Parse(origin)
		if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || strings.ContainsAny(origin, "?#") || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
			return "", "", ErrGroupCheckoutUnavailable
		}
	}
	return strings.TrimSuffix(frontend, "/"), strings.TrimSuffix(backend, "/"), nil
}

func groupPaymentResultURL(frontend, owner, pricing, payment string) string {
	return fmt.Sprintf("%s/buy-plan/%s/%s/result?payment=%s", frontend, url.PathEscape(owner), url.PathEscape(pricing), url.QueryEscape(payment))
}

func groupOrderPaymentResultURL(frontend string, order *Order, payment string) string {
	pricing := order.ProductInfos[0].PricingName
	if isTenantPackageCheckout(order.ProductInfos) {
		// The public result page looks up payments by ID. It only looks up
		// pricing when a subscription query parameter is present.
		pricing = "ai-budget"
	}
	return groupPaymentResultURL(frontend, order.Owner, pricing, payment)
}

func validateGroupPaymentResponse(order *Order, payment *Payment) error {
	if validateGroupPayment(order, payment) != nil || !payment.GroupStockReserved || validateGroupOrderTerms(order, true) != nil || order.CheckoutRevision < 2 {
		return ErrGroupCheckoutConflict
	}
	if (payment.State == pp.PaymentStateCreated && order.State != "Processing") || (payment.State == pp.PaymentStatePaid && order.State != "Paid") || (payment.State != pp.PaymentStateCreated && payment.State != pp.PaymentStatePaid) {
		return ErrGroupCheckoutConflict
	}
	frontend, _, err := groupPaymentOrigins()
	if err != nil {
		return err
	}
	if len(order.ProductInfos) != 1 {
		return ErrGroupCheckoutConflict
	}
	expected := groupOrderPaymentResultURL(frontend, order, payment.Name)
	if payment.PayUrl != expected || payment.SuccessUrl != expected {
		return ErrGroupCheckoutUnavailable
	}
	return nil
}

// Real Group providers need a separately selected recover-by-stable-reference
// contract. Personal providers keep their native behavior.
func checkGroupPaymentType(providerType string) error {
	if providerType != "Dummy" || checkDummyPayment(providerType) != nil {
		return ErrGroupCheckoutUnavailable
	}
	return nil
}

func checkGroupProductProvider(product *Product, provider *Provider) error {
	if product == nil || provider == nil || provider.Owner != product.Owner || provider.Category != "Payment" || provider.State == "Disabled" {
		return ErrGroupCheckoutUnavailable
	}
	if checkGroupPaymentType(provider.Type) != nil || product.isValidProvider(provider) != nil {
		return ErrGroupCheckoutUnavailable
	}
	return nil
}

func requireGroupProductProvider(session *xorm.Session, product *Product) error {
	for _, name := range product.Providers {
		provider := &Provider{}
		found, err := session.ID(core.PK{product.Owner, name}).Get(provider)
		if err != nil {
			return err
		}
		if found && checkGroupProductProvider(product, provider) == nil {
			return nil
		}
	}
	return ErrGroupCheckoutUnavailable
}

func groupCheckoutError(err error) error {
	if errors.Is(err, ErrGroupCheckoutConflict) || errors.Is(err, ErrTenantCheckoutRequired) || errors.Is(err, ErrGroupCheckoutUnavailable) {
		return err
	}
	return ErrGroupCheckoutUnavailable
}

func checkoutOrderForUpdate(session *xorm.Session, owner, name string) (*Order, error) {
	order := &Order{}
	query := session.ID(core.PK{owner, name})
	if ormer.Engine.DriverName() != "sqlite" {
		query = query.ForUpdate()
	}
	found, err := query.Get(order)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrGroupCheckoutConflict
	}
	return order, nil
}

func sameGroupOrderIdentity(canonical, requested *Order) bool {
	return canonical != nil && requested != nil && canonical.Group != "" && canonical.Owner == requested.Owner && canonical.Name == requested.Name && canonical.Group == requested.Group && canonical.User == requested.User
}

// A non-Paid historical state is not a reviewed proof that a dispatched
// Group operation can be replaced; only Dummy Paid completion is selected.
func unresolvedGroupPayments(session *xorm.Session, owner, group string) ([]*Payment, error) {
	payments := []*Payment{}
	err := session.Where("owner = ?", owner).And(fmt.Sprintf("%s = ?", quoteColumn("group")), group).And("state <> ?", pp.PaymentStatePaid).Find(&payments)
	return payments, err
}

// Existing Payment fields are the durable intent: no new state/column/table.
// Dummy's native order payload is deterministic and needs no provider response.
func newGroupPaymentIntent(order *Order, payer *User, product *Product, provider *Provider, host string) (*Payment, *pp.PayReq, error) {
	if err := checkGroupProductProvider(product, provider); err != nil {
		return nil, nil, err
	}
	if err := validateTenantCheckoutIdentity(order.Owner, order.Group, payer, order.ProductInfos); err != nil {
		return nil, nil, err
	}
	name := "payment_" + util.GenerateId()
	frontend, backend, err := groupPaymentOrigins()
	if err != nil {
		return nil, nil, err
	}
	success := groupOrderPaymentResultURL(frontend, order, name)
	dummyID, err := json.Marshal(pp.DummyOrderInfo{Price: order.Price, Currency: order.Currency})
	if err != nil {
		return nil, nil, ErrGroupCheckoutUnavailable
	}
	payment := &Payment{Owner: order.Owner, Name: name, CreatedTime: util.GetCurrentTime(), DisplayName: name,
		Provider: provider.Name, Type: provider.Type, Products: append([]string(nil), order.Products...), ProductsDisplayName: product.DisplayName,
		Detail: product.Description, Currency: order.Currency, Price: order.Price, User: payer.Name, Group: order.Group, Order: order.Name,
		PayUrl: success, SuccessUrl: success, State: pp.PaymentStateCreated, OutOrderId: string(dummyID)}
	request := &pp.PayReq{ProviderName: provider.Name, ProductName: product.Name, PayerName: fmt.Sprintf("%s | %s", payer.Name, payer.DisplayName),
		PayerId: payer.Id, PayerEmail: payer.Email, PaymentName: name, ProductDisplayName: product.DisplayName, ProductDescription: product.Description,
		ProductImage: product.Image, Price: order.Price, Currency: order.Currency, ReturnUrl: success,
		NotifyUrl: fmt.Sprintf("%s/api/notify-payment/%s/%s", backend, order.Owner, name), PaymentEnv: conf.GetConfigString("paymentDeploymentEnvironment")}
	return payment, request, nil
}

// The group row precedes order/payment locks in claim, cancel, finish and callback.
// No external work can run until both the intent and link commit successfully.
func claimGroupPayment(providerName, host string, admission GroupPaymentAdmission) (*Payment, *pp.PayReq, error) {
	return claimGroupPaymentAt(providerName, host, admission, time.Now)
}

func claimGroupPaymentAt(providerName, host string, admission GroupPaymentAdmission, clock func() time.Time) (*Payment, *pp.PayReq, error) {
	if err := validateGroupPaymentAdmission(admission); err != nil {
		return nil, nil, err
	}
	if _, _, err := groupPaymentOrigins(); err != nil {
		return nil, nil, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, nil, err
	}
	defer session.Rollback()
	if err := lockCheckoutGroup(session, admission.Owner, admission.Group); err != nil {
		return nil, nil, err
	}
	order, err := checkoutOrderForUpdate(session, admission.Owner, admission.OrderName)
	if err != nil {
		return nil, nil, err
	}
	if err := matchGroupPaymentAdmission(admission, order); err != nil {
		return nil, nil, err
	}
	if err := checkoutApplication(session, admission.Principal, order.Owner); err != nil {
		return nil, nil, err
	}
	if err := CheckTenantCheckoutRequest(admission.Principal, order.Owner, order.Group, order.ProductInfos); err != nil {
		return nil, nil, err
	}
	payer, err := checkoutActor(session, order.Owner, order.Group, admission.PayerName)
	if err != nil {
		return nil, nil, err
	}
	if validateTenantCheckoutIdentity(order.Owner, order.Group, payer, order.ProductInfos) != nil {
		return nil, nil, ErrGroupCheckoutConflict
	}
	provider := &Provider{}
	found, err := session.ID(core.PK{order.Owner, providerName}).Get(provider)
	if err != nil {
		return nil, nil, err
	}
	if !found || provider.Category != "Payment" || provider.State == "Disabled" || checkGroupPaymentType(provider.Type) != nil {
		return nil, nil, ErrGroupCheckoutUnavailable
	}
	if order.Payment != "" {
		payment := &Payment{}
		found, err := session.ID(core.PK{order.Owner, order.Payment}).Get(payment)
		if err != nil {
			return nil, nil, err
		}
		if !found || payment.Provider != providerName || payment.Type != "Dummy" {
			return nil, nil, ErrGroupCheckoutConflict
		}
		if err := validateGroupPaymentResponse(order, payment); err != nil {
			return nil, nil, err
		}
		// An already claimed operation keeps its committed dates and identity.
		// No current-window, price or catalog rewrite can cause redispatch.
		payment.OrderObj = order
		return payment, nil, session.Commit()
	}
	if order.State != "Created" {
		return nil, nil, ErrGroupCheckoutConflict
	}
	if len(order.ProductInfos) != 1 || len(order.Products) != 1 || order.Products[0] != order.ProductInfos[0].Name {
		return nil, nil, ErrGroupCheckoutConflict
	}
	stock, err := checkoutStockProductForUpdate(session, order.Owner, order.ProductInfos[0].Name)
	if err != nil {
		return nil, nil, err
	}
	if stock == nil {
		return nil, nil, ErrGroupCheckoutConflict
	}
	now := clock().UTC()
	packageCheckout := isTenantPackageCheckout(order.ProductInfos)
	var timeline *groupPeriodTimeline
	if !packageCheckout {
		timeline, err = loadGroupTimeline(session, order.Owner, order.Group, now)
		if err != nil {
			return nil, nil, err
		}
	}
	product, err := validateUnattemptedGroupQuote(session, order, payer, timeline, now)
	if err != nil {
		return nil, nil, err
	}
	if err := checkGroupProductProvider(product, provider); err != nil {
		return nil, nil, err
	}
	pending, err := unresolvedGroupPayments(session, order.Owner, order.Group)
	if err != nil {
		return nil, nil, err
	}
	intent, err := orderHasPaymentIntent(session, order)
	if err != nil {
		return nil, nil, err
	}
	orders, err := groupOpenOrders(session, order.Owner, order.Group)
	if err != nil {
		return nil, nil, err
	}
	if len(pending) != 0 || intent || len(orders) != 1 || orders[0].Name != order.Name {
		return nil, nil, ErrGroupCheckoutConflict
	}
	terms := order.CheckoutTerms
	if !packageCheckout {
		terms, err = claimCheckoutTerms(order.CheckoutTerms, timeline, now)
		if err != nil {
			return nil, nil, err
		}
	}
	revision, err := nextCheckoutRevision(order.CheckoutRevision)
	if err != nil {
		return nil, nil, err
	}
	payment, request, err := newGroupPaymentIntent(order, payer, product, provider, host)
	if err != nil {
		return nil, nil, err
	}
	if err := reserveGroupProductStock(session, stock); err != nil {
		return nil, nil, err
	}
	payment.GroupStockReserved = true
	if affected, err := session.Insert(payment); err != nil {
		return nil, nil, err
	} else if affected != 1 {
		return nil, nil, ErrGroupCheckoutConflict
	}
	previousRevision := order.CheckoutRevision
	order.State, order.Payment, order.UpdateTime = "Processing", payment.Name, checkoutTimestamp(now)
	order.CheckoutTerms, order.CheckoutRevision = terms, revision
	affected, err := session.ID(core.PK{order.Owner, order.Name}).Where("state = ? and payment = ? and checkout_revision = ?", "Created", "", previousRevision).Cols("state", "payment", "update_time", "checkout_terms", "checkout_revision").Update(order)
	if err != nil {
		return nil, nil, err
	}
	if affected != 1 {
		return nil, nil, ErrGroupCheckoutConflict
	}
	payment.OrderObj = order
	if err := session.Commit(); err != nil {
		return nil, nil, err
	}
	return payment, request, nil
}

func finishGroupDispatch(intent *Payment, response *pp.PayResp) (*Payment, error) {
	if response == nil || response.OrderId != intent.OutOrderId {
		return intent, ErrGroupCheckoutUnavailable
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return intent, err
	}
	defer session.Rollback()
	if err := lockCheckoutGroup(session, intent.Owner, intent.Group); err != nil {
		return intent, err
	}
	order, err := checkoutOrderForUpdate(session, intent.Owner, intent.Order)
	if err != nil {
		return intent, err
	}
	stored := &Payment{}
	found, err := session.ID(core.PK{intent.Owner, intent.Name}).Get(stored)
	if err != nil {
		return intent, err
	}
	if !found || validateGroupPayment(order, stored) != nil || stored.Provider != intent.Provider || stored.Type != intent.Type || stored.OutOrderId != response.OrderId {
		return intent, ErrGroupCheckoutConflict
	}
	if err := validateGroupPaymentResponse(order, stored); err != nil {
		return intent, err
	}
	if response.PayUrl != stored.SuccessUrl {
		return intent, ErrGroupCheckoutUnavailable
	}
	// A callback may already have committed Paid. Never write State here.
	stored.PayUrl = response.PayUrl
	stored.OrderObj = order
	affected, err := session.ID(core.PK{stored.Owner, stored.Name}).Cols("pay_url").Update(stored)
	if err != nil {
		return intent, err
	}
	if affected != 1 {
		return intent, ErrGroupCheckoutConflict
	}
	if err := session.Commit(); err != nil {
		return intent, err
	}
	return stored, nil
}

// Narrow seams also let tests fail precommit or postdispatch persistence without
// replacing the provider/payment authority. Unknown outcomes never auto-retry.
func dispatchGroupPayment(claim func() (*Payment, *pp.PayReq, error), pay func(*pp.PayReq) (*pp.PayResp, error), finish func(*Payment, *pp.PayResp) (*Payment, error)) (*Payment, map[string]interface{}, error) {
	payment, request, err := claim()
	if err != nil {
		return payment, nil, groupCheckoutError(err)
	}
	if request == nil {
		if payment == nil || (payment.PayUrl == "" && payment.State != pp.PaymentStatePaid) {
			return payment, nil, ErrGroupCheckoutUnavailable
		}
		return payment, nil, nil
	}
	response, err := pay(request)
	if err != nil || response == nil {
		return payment, nil, ErrGroupCheckoutUnavailable
	}
	result, err := finish(payment, response)
	if err != nil {
		return payment, nil, groupCheckoutError(err)
	}
	return result, response.AttachInfo, nil
}

func checkGroupOrderCancellation(canonical, requested *Order, expected int64) error {
	if !sameGroupOrderIdentity(canonical, requested) || canonical.Payment != "" || expected < 0 {
		return ErrGroupCheckoutConflict
	}
	if expected == 0 && canonical.CheckoutTerms != nil {
		return ErrGroupCheckoutConflict
	}
	if canonical.State == "Canceled" {
		if canonical.CheckoutRevision < 1 || expected != canonical.CheckoutRevision-1 {
			return ErrGroupCheckoutConflict
		}
		return nil
	}
	if canonical.State != "Created" || expected != canonical.CheckoutRevision {
		return ErrGroupCheckoutConflict
	}
	return nil
}

// The configured App attests CURRENT membership+billing:manage for the actual
// actor, including replay. Native direct Groups is an additional binding only.
// The departed original payer is never substituted, looked up or rewritten.
func CancelGroupOrder(principal, actorName string, requested *Order, expected int64) (*Order, error) {
	if requested == nil || requested.Group == "" {
		return nil, ErrGroupCheckoutConflict
	}
	if err := CheckTenantCheckoutPrincipal(principal, requested.Owner); err != nil {
		return nil, err
	}
	if actorName == "" {
		return nil, ErrTenantCheckoutRequired
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, err
	}
	defer session.Rollback()
	if err := lockCheckoutGroup(session, requested.Owner, requested.Group); err != nil {
		return nil, err
	}
	if err := checkoutApplication(session, principal, requested.Owner); err != nil {
		return nil, err
	}
	canonical, err := checkoutOrderForUpdate(session, requested.Owner, requested.Name)
	if err != nil {
		return nil, err
	}
	if _, err := checkoutActor(session, canonical.Owner, canonical.Group, actorName); err != nil {
		return nil, err
	}
	if err := checkGroupOrderCancellation(canonical, requested, expected); err != nil {
		return nil, err
	}
	intent, err := orderHasPaymentIntent(session, canonical)
	if err != nil {
		return nil, err
	}
	if intent {
		return nil, ErrGroupCheckoutConflict
	}
	// The consumed original revision remains a no-op even after another,
	// independent checkout starts. It cannot release or modify that intent.
	if canonical.State == "Canceled" {
		return canonical, session.Commit()
	}
	pending, err := unresolvedGroupPayments(session, canonical.Owner, canonical.Group)
	if err != nil {
		return nil, err
	}
	if len(pending) != 0 {
		return nil, ErrGroupCheckoutConflict
	}
	revision, err := nextCheckoutRevision(canonical.CheckoutRevision)
	if err != nil {
		return nil, err
	}
	canonical.State, canonical.Message, canonical.UpdateTime = "Canceled", "Canceled by authorized workspace manager", util.GetCurrentTime()
	canonical.CheckoutRevision = revision
	affected, err := session.ID(core.PK{canonical.Owner, canonical.Name}).Where("state = ? and payment = ? and checkout_revision = ?", "Created", "", expected).Cols("state", "message", "update_time", "checkout_revision").Update(canonical)
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, ErrGroupCheckoutConflict
	}
	return canonical, session.Commit()
}
