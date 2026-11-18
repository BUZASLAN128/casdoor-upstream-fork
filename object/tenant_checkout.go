// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

var ErrGroupCheckoutConflict = errors.New("GROUP_CHECKOUT_CONFLICT")
var ErrTenantCheckoutRequired = errors.New("TENANT_CHECKOUT_REQUIRED")

type tenantCheckoutConfig struct {
	application  string
	organization string
	pricing      string
}

func getTenantCheckoutConfig() (tenantCheckoutConfig, error) {
	config := tenantCheckoutConfig{
		application:  conf.GetConfigString("tenantCheckoutApplication"),
		organization: conf.GetConfigString("tenantCheckoutOrganization"),
		pricing:      conf.GetConfigString("tenantCheckoutPricing"),
	}
	if config.application == "" && config.organization == "" && config.pricing == "" {
		return config, nil
	}
	if !strings.HasPrefix(config.application, "app/") || strings.TrimPrefix(config.application, "app/") == "" || strings.Contains(strings.TrimPrefix(config.application, "app/"), "/") || config.organization == "" || strings.Contains(config.organization, "/") || config.pricing == "" || strings.Contains(config.pricing, "/") {
		return config, ErrTenantCheckoutRequired
	}
	return config, nil
}

// CheckTenantCheckoutRequest runs before any order write or provider call. A
// partial deployment binding cannot silently turn protected checkout personal.
func CheckTenantCheckoutRequest(principal, owner, group string, infos []ProductInfo) error {
	config, err := getTenantCheckoutConfig()
	if err != nil {
		return err
	}
	if group != "" {
		if config.application == "" || principal != config.application || owner != config.organization || !matchesTenantCheckoutProduct(infos, config.pricing) {
			return ErrTenantCheckoutRequired
		}
		return nil
	}
	for _, info := range infos {
		if strings.HasPrefix(info.Name, tenantPackagePrefix) || (config.pricing != "" && owner == config.organization && info.PricingName == config.pricing) {
			return ErrTenantCheckoutRequired
		}
	}
	return nil
}

func checkDummyPayment(providerType string) error {
	if providerType != "Dummy" {
		return nil
	}
	environment := conf.GetConfigString("paymentDeploymentEnvironment")
	if !conf.GetConfigBool("allowDummyPayment") || (environment != "demo" && environment != "dev" && environment != "test") {
		return fmt.Errorf("Dummy payment is disabled in this deployment")
	}
	return nil
}

// The principal comes from Casdoor authentication, never a request's group/user
// claim. The configured application delegates billing authorization to the App.
func CheckTenantCheckoutPrincipal(principal, owner string) error {
	config, err := getTenantCheckoutConfig()
	if err != nil || config.application == "" || principal != config.application || owner != config.organization {
		return ErrTenantCheckoutRequired
	}
	return nil
}

func validateTenantCheckout(owner, groupName string, user *User, infos []ProductInfo) error {
	session := ormer.Engine.NewSession()
	defer session.Close()
	_, err := validateTenantCheckoutInSession(session, owner, groupName, user, infos)
	return err
}

func validateTenantCheckoutInSession(session *xorm.Session, owner, groupName string, user *User, infos []ProductInfo) (*Product, error) {
	config, err := getTenantCheckoutConfig()
	if err != nil || config.application == "" || owner != config.organization || !matchesTenantCheckoutProduct(infos, config.pricing) {
		return nil, ErrTenantCheckoutRequired
	}
	if err := validateTenantCheckoutIdentity(owner, groupName, user, infos); err != nil {
		return nil, err
	}
	info := infos[0]
	if isTenantPackageCheckout(infos) {
		product := &Product{}
		found, err := session.ID(core.PK{owner, info.Name}).Get(product)
		if err != nil {
			return nil, err
		}
		if !found || validateTenantPackageProduct(product) != nil {
			return nil, ErrGroupCheckoutConflict
		}
		if err := requireGroupProductProvider(session, product); err != nil {
			return nil, err
		}
		return product, nil
	}
	pricing, plan, product := &Pricing{}, &Plan{}, &Product{}
	pricingFound, err := session.ID(core.PK{owner, info.PricingName}).Get(pricing)
	if err != nil {
		return nil, err
	}
	planFound, err := session.ID(core.PK{owner, info.PlanName}).Get(plan)
	if err != nil {
		return nil, err
	}
	productFound, err := session.ID(core.PK{owner, info.Name}).Get(product)
	if err != nil {
		return nil, err
	}
	if !pricingFound || !pricing.IsEnabled || !pricing.IsUserAllowed(user) || !util.InSlice(pricing.Plans, info.PlanName) || !planFound || !plan.IsEnabled || plan.Product != info.Name || !productFound || product.IsRecharge || product.Quantity < 1 {
		return nil, fmt.Errorf("invalid tenant checkout pricing, plan or product")
	}
	if err := requireGroupProductProvider(session, product); err != nil {
		return nil, err
	}
	return product, nil
}

func validateTenantCheckoutIdentity(owner, groupName string, user *User, infos []ProductInfo) error {
	if groupName == "" || strings.Contains(groupName, "/") || user == nil || user.Owner != owner || user.Name == "" || user.IsDeleted || user.IsForbidden {
		return fmt.Errorf("invalid tenant checkout target or payer")
	}
	if !isTenantPackageCheckout(infos) && (len(infos) != 1 || infos[0].Quantity != 1 || infos[0].PricingName == "" || infos[0].PlanName == "") {
		return fmt.Errorf("tenant checkout requires one pricing plan")
	}
	return nil
}

func sameGroupCheckoutRequest(order *Order, userName string, infos []ProductInfo) bool {
	if order.State != "Created" || order.User != userName || len(order.ProductInfos) != 1 || len(infos) != 1 {
		return false
	}
	old, requested := order.ProductInfos[0], infos[0]
	return old.Name == requested.Name && old.PlanName == requested.PlanName && old.PricingName == requested.PricingName && old.Quantity == 1 && requested.Quantity == 1
}

func lockCheckoutGroup(session *xorm.Session, owner, name string) error {
	return lockCheckoutGroupRow(session, owner, name, true)
}

func lockCheckoutGroupRow(session *xorm.Session, owner, name string, requireEnabled bool) error {
	group := &Group{}
	query := session.ID(core.PK{owner, name})
	if ormer.Engine.DriverName() != "sqlite" {
		query = query.ForUpdate()
	}
	exists, err := query.Get(group)
	if err != nil {
		return err
	}
	if !exists || (requireEnabled && !group.IsEnabled) {
		return fmt.Errorf("tenant checkout group does not exist or is disabled")
	}
	if ormer.Engine.DriverName() == "sqlite" {
		// SQLite has no FOR UPDATE; take its write lock without changing metadata.
		if _, err = session.ID(core.PK{owner, name}).Cols("updated_time").Update(&Group{UpdatedTime: group.UpdatedTime}); err != nil {
			return err
		}
	}
	return nil
}

// PlaceGroupOrder is the sole checkout entry point that can bind a Group. The
// database row lock serializes admission across replicas, including Cockroach.
func PlaceGroupOrder(principal, owner, groupName string, infos []ProductInfo, user *User, expectedCurrentPeriodRevision string) (*Order, error) {
	return placeGroupOrderAt(principal, owner, groupName, infos, user, expectedCurrentPeriodRevision, time.Now)
}

func placeGroupOrderAt(principal, owner, groupName string, infos []ProductInfo, user *User, expected string, clock func() time.Time) (*Order, error) {
	if err := CheckTenantCheckoutRequest(principal, owner, groupName, infos); err != nil {
		return nil, err
	}
	if err := CheckTenantCheckoutPrincipal(principal, owner); err != nil {
		return nil, err
	}
	packageCheckout := isTenantPackageCheckout(infos)
	if expected != "none" && (packageCheckout || !validPeriodRevision(expected)) {
		return nil, ErrGroupCheckoutConflict
	}
	if err := validateTenantCheckout(owner, groupName, user, infos); err != nil {
		return nil, err
	}
	candidate, err := newOrder(owner, infos, user, "")
	if err != nil {
		return nil, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, err
	}
	defer session.Rollback()
	if err := lockCheckoutGroup(session, owner, groupName); err != nil {
		return nil, err
	}
	if err := checkoutApplication(session, principal, owner); err != nil {
		return nil, err
	}
	currentPayer := &User{}
	found, err := session.ID(core.PK{owner, user.Name}).Get(currentPayer)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrGroupCheckoutConflict
	}
	product, err := validateTenantCheckoutInSession(session, owner, groupName, currentPayer, infos)
	if err != nil {
		return nil, err
	}
	now := clock().UTC()
	var timeline *groupPeriodTimeline
	packageTerms := tenantPackageTerms
	terms := &packageTerms
	if !packageCheckout {
		plan := &Plan{}
		found, err := session.ID(core.PK{owner, infos[0].PlanName}).Get(plan)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrGroupCheckoutConflict
		}
		timeline, err = loadGroupTimeline(session, owner, groupName, now)
		if err != nil {
			return nil, err
		}
		terms, err = newCheckoutTerms(timeline, expected, plan.Period, now)
		if err != nil {
			return nil, err
		}
	}
	pending, err := unresolvedGroupPayments(session, owner, groupName)
	if err != nil {
		return nil, err
	}
	orders, err := groupOpenOrders(session, owner, groupName)
	if err != nil {
		return nil, err
	}
	if len(orders) != 0 {
		order := orders[0]
		if len(orders) != 1 || len(pending) != 0 || !sameGroupCheckoutRequest(order, currentPayer.Name, infos) || order.Payment != "" || order.CheckoutRevision < 1 || order.CheckoutTerms == nil || *order.CheckoutTerms != *terms {
			return nil, ErrGroupCheckoutConflict
		}
		intent, err := orderHasPaymentIntent(session, order)
		if err != nil {
			return nil, err
		}
		if intent {
			return nil, ErrGroupCheckoutConflict
		}
		if _, err := validateUnattemptedGroupQuote(session, order, currentPayer, timeline, now); err != nil {
			return nil, err
		}
		return order, session.Commit()
	}
	currency := product.Currency
	if currency == "" {
		currency = "USD"
	}
	if len(pending) != 0 || candidate.Price != product.Price || candidate.Currency != currency {
		return nil, ErrGroupCheckoutConflict
	}
	candidate.Name = "order_" + util.GenerateId()
	candidate.DisplayName, candidate.Group = candidate.Name, groupName
	candidate.CheckoutTerms, candidate.CheckoutRevision = terms, 1
	if _, err = session.Insert(candidate); err != nil {
		return nil, err
	}
	return candidate, session.Commit()
}

func validateUnattemptedGroupQuote(session *xorm.Session, order *Order, payer *User, timeline *groupPeriodTimeline, now time.Time) (*Product, error) {
	if order.CheckoutRevision < 1 || order.CheckoutTerms == nil {
		return nil, ErrGroupCheckoutConflict
	}
	product, err := validateTenantCheckoutInSession(session, order.Owner, order.Group, payer, order.ProductInfos)
	if err != nil {
		return nil, err
	}
	if isTenantPackageCheckout(order.ProductInfos) {
		if validateGroupOrderTerms(order, false) != nil || product.Price != order.Price || product.Currency != order.Currency {
			return nil, ErrGroupCheckoutConflict
		}
		return product, nil
	}
	plan := &Plan{}
	found, err := session.ID(core.PK{order.Owner, order.ProductInfos[0].PlanName}).Get(plan)
	if err != nil {
		return nil, err
	}
	currency := product.Currency
	if currency == "" {
		currency = "USD"
	}
	if !found || plan.Period != order.CheckoutTerms.Period || product.Price != order.Price || currency != order.Currency {
		return nil, ErrGroupCheckoutConflict
	}
	if _, err = claimCheckoutTerms(order.CheckoutTerms, timeline, now); err != nil {
		return nil, err
	}
	return product, nil
}

// PayGroupOrder receives the actual controller-validated application and payer.
// App attests its final current membership/billing decision; native Groups is
// only an additional binding, never proof of current App authorization.
func PayGroupOrder(admission GroupPaymentAdmission, providerName, host, lang string) (*Payment, map[string]interface{}, error) {
	if err := validateGroupPaymentAdmission(admission); err != nil {
		return nil, nil, err
	}
	return payGroupOrder(admission, providerName, host, lang)
}

func payGroupOrder(admission GroupPaymentAdmission, providerName, host, lang string) (*Payment, map[string]interface{}, error) {
	return dispatchGroupPayment(func() (*Payment, *pp.PayReq, error) {
		return claimGroupPayment(providerName, host, admission)
	}, func(request *pp.PayReq) (*pp.PayResp, error) {
		provider, err := GetPaymentProvider(&Provider{Type: "Dummy"})
		if err != nil {
			return nil, err
		}
		return provider.Pay(request)
	}, finishGroupDispatch)
}

func validateGroupPayment(order *Order, payment *Payment) error {
	if order == nil || payment == nil || order.Group == "" || payment.Group != order.Group || payment.Owner != order.Owner || payment.User != order.User || payment.Order != order.Name || order.Payment != payment.Name || payment.Price != order.Price || payment.Currency != order.Currency || !reflect.DeepEqual(payment.Products, order.Products) {
		return fmt.Errorf("tenant payment does not match its immutable order")
	}
	return nil
}

func validateTenantSubscriptionPayment(sub *Subscription) error {
	if sub.Payment == "" {
		return nil
	}
	payment, err := GetPayment(util.GetId(sub.Owner, sub.Payment))
	if err != nil {
		return err
	}
	// Preserve personal and manually administered Casdoor subscriptions.
	if payment == nil || payment.Group == "" {
		return nil
	}
	if sub.State == SubStateActive || sub.State == SubStateUpcoming || sub.State == SubStatePending {
		if err = checkDummyPayment(payment.Type); err != nil {
			return err
		}
	}
	order, err := GetOrder(util.GetId(payment.Owner, payment.Order))
	if err != nil {
		return err
	}
	if err = validateGroupPayment(order, payment); err != nil {
		return err
	}
	if payment.State != pp.PaymentStatePaid || sub.Owner != order.Owner || sub.Group != order.Group || sub.User != "" || len(order.ProductInfos) != 1 || sub.Plan != order.ProductInfos[0].PlanName || sub.Pricing != order.ProductInfos[0].PricingName {
		return fmt.Errorf("tenant subscription requires matching confirmed payment")
	}
	return nil
}

// Group completion keeps payment, order, subscription, purchase record and stock
// in one transaction. Replayed/concurrent notifications read the committed result.
func completeGroupPayment(payment *Payment, result *pp.NotifyResult, notifyErr error) (*Payment, error) {
	return completeGroupPaymentAt(payment, result, notifyErr, time.Now)
}

func completeGroupPaymentAt(payment *Payment, result *pp.NotifyResult, notifyErr error, clock func() time.Time) (*Payment, error) {
	if notifyErr != nil {
		return nil, notifyErr
	}
	if result == nil || payment == nil {
		return nil, fmt.Errorf("missing provider confirmation")
	}
	if err := checkGroupPaymentType(payment.Type); err != nil {
		return nil, err
	}
	if result.PaymentStatus == pp.PaymentStatePaid && (result.Price != payment.Price || (result.Currency != "" && result.Currency != payment.Currency)) {
		return nil, fmt.Errorf("tenant payment confirmation amount mismatch")
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, err
	}
	defer session.Rollback()
	if err := lockCheckoutGroupRow(session, payment.Owner, payment.Group, false); err != nil {
		return nil, err
	}
	stored := &Payment{}
	exists, err := session.ID(core.PK{payment.Owner, payment.Name}).Get(stored)
	if err != nil {
		return nil, err
	}
	if !exists || !stored.GroupStockReserved || stored.Group != payment.Group || stored.Order != payment.Order || stored.User != payment.User || stored.Type != payment.Type || stored.Provider != payment.Provider || stored.OutOrderId != payment.OutOrderId {
		return nil, ErrGroupCheckoutConflict
	}
	order, err := checkoutOrderForUpdate(session, stored.Owner, stored.Order)
	if err != nil {
		return nil, err
	}
	if err = validateGroupPayment(order, stored); err != nil {
		return nil, err
	}
	if result.PaymentStatus == pp.PaymentStatePaid && (result.Price != stored.Price || result.Currency != stored.Currency) {
		return nil, ErrGroupCheckoutConflict
	}
	packageCheckout := isTenantPackageCheckout(order.ProductInfos)
	if packageCheckout && (order.CheckoutRevision < 2 || validateGroupOrderTerms(order, true) != nil) {
		return nil, ErrGroupCheckoutConflict
	}
	if pp.IsTerminalState(stored.State) {
		if (stored.State == pp.PaymentStatePaid && order.State != "Paid") || (stored.State != pp.PaymentStatePaid && result.PaymentStatus == pp.PaymentStatePaid) {
			// Retain attribution for bounded audit/reconciliation; never report
			// a contradictory late success as a refund or revive a replacement.
			return stored, ErrGroupCheckoutConflict
		}
		if stored.State == pp.PaymentStatePaid && !packageCheckout {
			sub := &Subscription{}
			found, err := session.ID(core.PK{order.Owner, "sub_" + order.Name}).Get(sub)
			if err != nil {
				return stored, err
			}
			if !found {
				return stored, ErrGroupCheckoutConflict
			}
			if _, err := paidGroupPeriod(sub, order, stored); err != nil {
				return stored, err
			}
		}
		return stored, nil
	}
	if result.PaymentStatus == stored.State {
		return stored, nil
	}
	if order.State != "Created" && order.State != "Processing" {
		return nil, ErrGroupCheckoutConflict
	}
	if order.State != "Processing" || validateGroupOrderTerms(order, true) != nil {
		return nil, ErrGroupCheckoutConflict
	}
	now := clock().UTC()
	previousState := stored.State
	stored.State, stored.Message = result.PaymentStatus, result.NotifyMessage
	order.UpdateTime = checkoutTimestamp(now)
	revision, err := nextCheckoutRevision(order.CheckoutRevision)
	if err != nil {
		return nil, err
	}
	order.CheckoutRevision = revision
	if stored.State == pp.PaymentStatePaid {
		if len(order.ProductInfos) != 1 {
			return nil, fmt.Errorf("invalid tenant order product")
		}
		if !packageCheckout {
			if err := validateGroupSettlementTerms(session, order, now); err != nil {
				return nil, err
			}
		}
		others, err := groupOpenOrders(session, order.Owner, order.Group)
		if err != nil {
			return nil, err
		}
		if len(others) != 1 || others[0].Name != order.Name {
			return nil, ErrGroupCheckoutConflict
		}
		info := order.ProductInfos[0]
		stock, err := checkoutStockProductForUpdate(session, order.Owner, info.Name)
		if err != nil {
			return nil, err
		}
		if stock == nil {
			return nil, ErrGroupCheckoutConflict
		}
		if !packageCheckout {
			terms := order.CheckoutTerms
			sub := &Subscription{Owner: order.Owner, Name: "sub_" + order.Name, DisplayName: "Subscription - " + order.Name, CreatedTime: checkoutTimestamp(now),
				Group: order.Group, Plan: info.PlanName, Pricing: info.PricingName, Payment: stored.Name,
				StartTime: terms.StartTime, EndTime: terms.EndTime, Period: terms.Period, State: SubStateActive}
			sub.State, err = effectiveGroupPeriodState(sub, now)
			if err != nil {
				return nil, err
			}
			if _, err = session.Insert(sub); err != nil {
				return nil, err
			}
		}
		// Tenant plans cannot recharge a wallet. Keep normal purchase bookkeeping.
		transaction := &Transaction{Owner: order.Owner, Name: "purchase_" + stored.Name, DisplayName: stored.Name, CreatedTime: util.GetCurrentTime(), Amount: -stored.Price, Currency: stored.Currency, Payment: stored.Name, Category: TransactionCategoryPurchase, Type: "Payment", Subtype: stored.Type, Provider: stored.Provider, Tag: "User", User: stored.User, State: string(pp.PaymentStatePaid)}
		if _, err = session.Insert(transaction); err != nil {
			return nil, err
		}
		// Quantity was reserved atomically before dispatch. Paid consumes that
		// reservation once; unknown outcomes keep it without automatic release.
		affected, err := session.ID(core.PK{order.Owner, info.Name}).Incr("sold", 1).Update(&Product{})
		if err != nil {
			return nil, err
		}
		if affected != 1 {
			return nil, fmt.Errorf("insufficient tenant plan stock")
		}
		order.State, order.Message = "Paid", "Payment successful"
	} else if pp.IsTerminalState(stored.State) {
		order.State, order.Message = string(stored.State), stored.Message
	}
	if _, err = session.ID(core.PK{stored.Owner, stored.Name}).Cols("state", "message").Update(stored); err != nil {
		return nil, err
	}
	if _, err = session.ID(core.PK{order.Owner, order.Name}).Cols("state", "message", "update_time", "checkout_revision").Update(order); err != nil {
		return nil, err
	}
	if packageCheckout {
		// Package fulfillment is handled by App. The existing mail describes
		// a subscription and applies only to plans.
		if err := session.Commit(); err != nil {
			return nil, err
		}
		return stored, nil
	}
	return finishGroupPayment(session.Commit, stored, previousState, notifyGroupPaymentEmail)
}
