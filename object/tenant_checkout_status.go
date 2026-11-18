// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type GroupCheckoutPeriod struct {
	Owner          string            `json:"owner"`
	Name           string            `json:"name"`
	Group          string            `json:"group"`
	Plan           string            `json:"plan"`
	Pricing        string            `json:"pricing"`
	Payment        string            `json:"payment"`
	StartTime      string            `json:"startTime"`
	EndTime        string            `json:"endTime"`
	Period         string            `json:"period"`
	State          SubscriptionState `json:"state"`
	CatalogEnabled bool              `json:"catalogEnabled"`
}

type GroupCheckoutOpenOrder struct {
	Owner            string              `json:"owner"`
	Group            string              `json:"group"`
	Name             string              `json:"name"`
	User             string              `json:"user"`
	State            string              `json:"state"`
	CheckoutRevision int64               `json:"checkoutRevision"`
	CheckoutTerms    *GroupCheckoutTerms `json:"checkoutTerms,omitempty"`
	ProductInfos     []ProductInfo       `json:"productInfos"`
	Price            float64             `json:"price"`
	Currency         string              `json:"currency"`
	PaymentName      string              `json:"paymentName"`
	PaymentState     pp.PaymentState     `json:"paymentState"`
}

type GroupCheckoutStatus struct {
	ReadScope                 string                        `json:"readScope"`
	PeriodSummaryState        string                        `json:"periodSummaryState"`
	Owner                     string                        `json:"owner"`
	Group                     string                        `json:"group"`
	ServerNow                 string                        `json:"serverNow"`
	CurrentPeriodRevision     string                        `json:"currentPeriodRevision,omitempty"`
	CurrentSubscription       *GroupCheckoutPeriod          `json:"currentSubscription"`
	UpcomingSubscription      *GroupCheckoutPeriod          `json:"upcomingSubscription"`
	OpenOrder                 *GroupCheckoutOpenOrder       `json:"openOrder"`
	RequestedOrder            *GroupCheckoutOpenOrder       `json:"requestedOrder"`
	PlanQuotes                []*GroupCheckoutQuote         `json:"planQuotes"`
	LastLateFreshPeriod       *GroupCheckoutLateFreshPeriod `json:"lastLateFreshPeriod"`
	CheckoutAvailable         bool                          `json:"checkoutAvailable"`
	PurchaseEligible          bool                          `json:"purchaseEligible"`
	PurchaseEligibilityReason string                        `json:"purchaseEligibilityReason"`
	CanResume                 bool                          `json:"canResume"`
	CanCancel                 bool                          `json:"canCancel"`
}

type GroupCheckoutQuote struct {
	Plan          string              `json:"plan"`
	Pricing       string              `json:"pricing"`
	Product       string              `json:"product"`
	Price         float64             `json:"price"`
	Currency      string              `json:"currency"`
	CheckoutTerms *GroupCheckoutTerms `json:"checkoutTerms"`
}

type GroupCheckoutLateFreshPeriod struct {
	*GroupCheckoutPeriod
	OrderName   string `json:"orderName"`
	ConfirmedAt string `json:"confirmedAt"`
}

// Native Groups is an additional exact direct binding. CURRENT App membership
// and billing permission remain the configured application's responsibility;
// native membership may be residual after an App suspension/removal.
func checkoutDirectMember(user *User, owner, group string) bool {
	return user != nil && user.Owner == owner && user.Name != "" && !user.IsDeleted && !user.IsForbidden && util.InSlice(user.Groups, util.GetId(owner, group))
}

func checkoutActor(session *xorm.Session, owner, group, name string) (*User, error) {
	if name == "" || strings.Contains(name, "/") {
		return nil, ErrTenantCheckoutRequired
	}
	actor := &User{}
	found, err := session.ID(core.PK{owner, name}).Get(actor)
	if err != nil {
		return nil, err
	}
	if !found || !checkoutDirectMember(actor, owner, group) {
		return nil, ErrTenantCheckoutRequired
	}
	return actor, nil
}

func checkoutApplication(session *xorm.Session, principal, owner string) error {
	if err := CheckTenantCheckoutPrincipal(principal, owner); err != nil {
		return err
	}
	application := &Application{}
	found, err := session.ID(core.PK{"admin", strings.TrimPrefix(principal, "app/")}).Get(application)
	if err != nil {
		return err
	}
	if !found || application.Organization != owner {
		return ErrTenantCheckoutRequired
	}
	return nil
}

// No UpdateState call: all records and their paid bindings use this same session.
func loadGroupTimeline(session *xorm.Session, owner, group string, now time.Time) (*groupPeriodTimeline, error) {
	subs := []*Subscription{}
	if err := session.Where("owner = ?", owner).And(fmt.Sprintf("%s = ?", quoteColumn("group")), group).Limit(1025).Find(&subs); err != nil {
		return nil, err
	}
	// A bounded read must never turn truncation into proof of absence.
	if len(subs) > 1024 {
		return nil, ErrGroupCheckoutConflict
	}
	periods := []*groupPaidPeriod{}
	seenPayments := map[string]bool{}
	for _, sub := range subs {
		_, end, err := checkoutInterval(sub.StartTime, sub.EndTime)
		if err != nil {
			return nil, err
		}
		// Historical manual, already-ended grants are not current paid periods.
		if sub.Payment == "" && !now.Before(end) {
			continue
		}
		payment := &Payment{}
		found, err := session.ID(core.PK{owner, sub.Payment}).Get(payment)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrGroupCheckoutConflict
		}
		order := &Order{}
		found, err = session.ID(core.PK{owner, payment.Order}).Get(order)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrGroupCheckoutConflict
		}
		period, err := paidGroupPeriod(sub, order, payment)
		if err != nil {
			return nil, err
		}
		if seenPayments[payment.Name] {
			return nil, ErrGroupCheckoutConflict
		}
		seenPayments[payment.Name] = true
		periods = append(periods, period)
	}
	if err := validateUnboundGroupPayments(session, owner, group, seenPayments); err != nil {
		return nil, err
	}
	return groupTimeline(periods, now)
}

// The subscription read bounds the plan payments. Scan the remaining Paid
// payments in name order so package volume does not consume that bound.
func validateUnboundGroupPayments(session *xorm.Session, owner, group string, planPayments map[string]bool) error {
	const pageSize = 256
	var after string
	for {
		var paid []*Payment
		query := session.Where("owner = ?", owner).And(quoteColumn("group")+" = ?", group).And("state = ?", pp.PaymentStatePaid)
		if after != "" {
			query.And("name > ?", after)
		}
		if err := query.Asc("name").Limit(pageSize).Find(&paid); err != nil {
			return err
		}
		unbound := make([]*Payment, 0, len(paid))
		orderNames := make([]string, 0, len(paid))
		for _, payment := range paid {
			if !planPayments[payment.Name] {
				unbound = append(unbound, payment)
				orderNames = append(orderNames, payment.Order)
			}
		}
		if len(unbound) > 0 {
			var orders []*Order
			if err := session.Where("owner = ?", owner).In("name", orderNames).Find(&orders); err != nil {
				return err
			}
			byName := make(map[string]*Order, len(orders))
			for _, order := range orders {
				byName[order.Name] = order
			}
			for _, payment := range unbound {
				if err := validatePaidPackagePayment(byName[payment.Order], payment); err != nil {
					return err
				}
			}
		}
		if len(paid) < pageSize {
			return nil
		}
		after = paid[len(paid)-1].Name
	}
}

func validatePaidPackagePayment(order *Order, payment *Payment) error {
	if order == nil || order.State != "Paid" || order.CheckoutRevision < 3 ||
		payment.State != pp.PaymentStatePaid || !payment.GroupStockReserved ||
		!isTenantPackageCheckout(order.ProductInfos) || validateGroupOrderTerms(order, true) != nil ||
		validateGroupPayment(order, payment) != nil {
		return ErrGroupCheckoutConflict
	}
	return nil
}

func groupOpenOrders(session *xorm.Session, owner, group string) ([]*Order, error) {
	orders := []*Order{}
	err := session.Where("owner = ?", owner).And(fmt.Sprintf("%s = ?", quoteColumn("group")), group).In("state", "Created", "Processing").Limit(2).Find(&orders)
	return orders, err
}

func orderHasPaymentIntent(session *xorm.Session, order *Order) (bool, error) {
	if order.Payment != "" {
		return true, nil
	}
	return session.Where("owner = ? and "+quoteColumn("order")+" = ?", order.Owner, order.Name).Exist(&Payment{})
}

func checkoutCatalogQuotes(session *xorm.Session, owner string, timeline *groupPeriodTimeline, now time.Time) ([]*GroupCheckoutQuote, error) {
	quotes := []*GroupCheckoutQuote{}
	if checkGroupPaymentType("Dummy") != nil {
		return quotes, nil
	}
	config, err := getTenantCheckoutConfig()
	if err != nil {
		return nil, err
	}
	pricing := &Pricing{}
	found, err := session.ID(core.PK{owner, config.pricing}).Get(pricing)
	if err != nil {
		return nil, err
	}
	if !found || !pricing.IsEnabled {
		return quotes, nil
	}
	for _, name := range pricing.Plans {
		plan, product := &Plan{}, &Product{}
		found, err = session.ID(core.PK{owner, name}).Get(plan)
		if err != nil {
			return nil, err
		}
		if !found || !plan.IsEnabled {
			continue
		}
		if _, err := checkoutPeriodEnd(time.Time{}, plan.Period); err != nil {
			continue
		}
		found, err = session.ID(core.PK{owner, plan.Product}).Get(product)
		if err != nil {
			return nil, err
		}
		if !found || product.IsRecharge || product.Quantity < 1 {
			continue
		}
		if err := requireGroupProductProvider(session, product); err != nil {
			if err == ErrGroupCheckoutUnavailable {
				continue
			}
			return nil, err
		}
		currency := product.Currency
		if currency == "" {
			currency = "USD"
		}
		terms, _ := newCheckoutTerms(timeline, timeline.revision(), plan.Period, now)
		quotes = append(quotes, &GroupCheckoutQuote{Plan: plan.Name, Pricing: pricing.Name, Product: product.Name, Price: product.Price, Currency: currency, CheckoutTerms: terms})
	}
	return quotes, nil
}

func checkoutPeriodView(session *xorm.Session, period *groupPaidPeriod, now time.Time) (*GroupCheckoutPeriod, error) {
	if period == nil {
		return nil, nil
	}
	state, err := effectiveGroupPeriodState(period.Sub, now)
	if err != nil {
		return nil, err
	}
	plan := &Plan{}
	found, err := session.ID(core.PK{period.Sub.Owner, period.Sub.Plan}).Get(plan)
	if err != nil {
		return nil, err
	}
	s := period.Sub
	return &GroupCheckoutPeriod{Owner: s.Owner, Name: s.Name, Group: s.Group, Plan: s.Plan, Pricing: s.Pricing, Payment: s.Payment, StartTime: checkoutTimestamp(period.Start), EndTime: checkoutTimestamp(period.End), Period: s.Period, State: state, CatalogEnabled: found && plan.IsEnabled}, nil
}

// GetGroupCheckout returns exactly one configured Group, with an optional real
// actor. The snapshot is explicitly serializable and read-only, not a lazy list
// that changes State. Flags are advisory; mutations revalidate under locks.
func GetGroupCheckout(principal, owner, group, actorName, orderName string) (*GroupCheckoutStatus, error) {
	return getGroupCheckoutAt(principal, owner, group, actorName, orderName, time.Now)
}

func getGroupCheckoutAt(principal, owner, group, actorName, orderName string, clock func() time.Time) (*GroupCheckoutStatus, error) {
	if err := CheckTenantCheckoutPrincipal(principal, owner); err != nil {
		return nil, err
	}
	if group == "" || strings.Contains(group, "/") {
		return nil, ErrTenantCheckoutRequired
	}
	if strings.Contains(orderName, "/") {
		return nil, ErrTenantCheckoutRequired
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, err
	}
	defer session.Rollback()
	if _, err := session.Exec("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY"); err != nil {
		return nil, err
	}
	if err := checkoutApplication(session, principal, owner); err != nil {
		return nil, err
	}
	canonicalGroup := &Group{}
	found, err := session.ID(core.PK{owner, group}).Get(canonicalGroup)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrTenantCheckoutRequired
	}
	var actor *User
	if actorName != "" {
		actor, err = checkoutActor(session, owner, group, actorName)
		if err != nil {
			return nil, err
		}
	}
	now := clock().UTC()
	result := &GroupCheckoutStatus{Owner: owner, Group: group, ServerNow: checkoutTimestamp(now), ReadScope: "order", PeriodSummaryState: "not_requested"}
	if orderName != "" {
		requested := &Order{}
		found, err := session.ID(core.PK{owner, orderName}).Get(requested)
		if err != nil {
			return nil, err
		}
		if found && requested.Group == group {
			result.RequestedOrder = groupOpenOrderView(requested)
		}
		// Scoped ownership/replay lookup never depends on current entitlement,
		// catalog, Dummy availability or malformed financial history. No "none".
		if err := session.Commit(); err != nil {
			return nil, err
		}
		return result, nil
	}
	timeline, err := loadGroupTimeline(session, owner, group, now)
	if err != nil {
		return nil, err
	}
	result.ReadScope, result.PeriodSummaryState, result.CurrentPeriodRevision = "group", "available", timeline.revision()
	if result.CurrentSubscription, err = checkoutPeriodView(session, timeline.Current, now); err != nil {
		return nil, err
	}
	if result.UpcomingSubscription, err = checkoutPeriodView(session, timeline.Upcoming, now); err != nil {
		return nil, err
	}
	if result.PlanQuotes, err = checkoutCatalogQuotes(session, owner, timeline, now); err != nil {
		return nil, err
	}
	result.CheckoutAvailable = len(result.PlanQuotes) > 0 && canonicalGroup.IsEnabled
	if late := latestLateFreshPeriod(timeline.Periods); late != nil {
		view, err := checkoutPeriodView(session, late, now)
		if err != nil {
			return nil, err
		}
		result.LastLateFreshPeriod = &GroupCheckoutLateFreshPeriod{GroupCheckoutPeriod: view, OrderName: late.Order.Name, ConfirmedAt: late.Sub.CreatedTime}
	}
	result.PurchaseEligible, result.PurchaseEligibilityReason = periodPurchaseEligibility(timeline, now)
	orders, err := groupOpenOrders(session, owner, group)
	if err != nil {
		return nil, err
	}
	pending, err := unresolvedGroupPayments(session, owner, group)
	if err != nil {
		return nil, err
	}
	if len(orders) > 0 || len(pending) > 0 {
		result.PurchaseEligible, result.PurchaseEligibilityReason = false, "open_checkout"
		if len(orders) != 1 {
			result.PurchaseEligibilityReason = "reconciliation_required"
		} else {
			order := orders[0]
			result.OpenOrder = groupOpenOrderView(order)
			intent, err := orderHasPaymentIntent(session, order)
			if err != nil {
				return nil, err
			}
			if !intent && len(pending) == 0 && order.State == "Created" {
				result.CanCancel = actor != nil && canonicalGroup.IsEnabled && order.CheckoutRevision >= 0
				orderAvailable := result.CheckoutAvailable || (canonicalGroup.IsEnabled && isTenantPackageCheckout(order.ProductInfos))
				result.CanResume = actor != nil && actor.Name == order.User && orderAvailable && order.CheckoutRevision > 0 && validateGroupOrderTerms(order, false) == nil
				if result.CanResume {
					_, err = validateUnattemptedGroupQuote(session, order, actor, timeline, now)
					result.CanResume = err == nil
				}
			} else if len(pending) == 1 && order.Payment == pending[0].Name && validateGroupPayment(order, pending[0]) == nil && pending[0].State == pp.PaymentStateCreated && order.State == "Processing" && validateGroupOrderTerms(order, true) == nil {
				result.OpenOrder.PaymentState = pending[0].State
				result.CanResume = actor != nil && actor.Name == order.User && canonicalGroup.IsEnabled && checkGroupPaymentType(pending[0].Type) == nil
			} else {
				result.PurchaseEligibilityReason = "reconciliation_required"
			}
		}
	}
	if err := session.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// Positive evidence only. Expiry today is not proof that confirmation was late.
// Legacy or subsequently ambiguous timestamps are never backfilled or guessed.
func latestLateFreshPeriod(periods []*groupPaidPeriod) *groupPaidPeriod {
	var latest *groupPaidPeriod
	var latestTime time.Time
	for _, period := range periods {
		order := period.Order
		if order == nil || period.Payment == nil || order.State != "Paid" || period.Payment.State != pp.PaymentStatePaid || order.CheckoutTerms == nil || order.CheckoutTerms.Version != 1 || order.CheckoutTerms.Kind != "fresh" || order.CheckoutRevision < 3 || period.Sub.CreatedTime != order.UpdateTime {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, period.Sub.CreatedTime)
		if err != nil || checkoutTimestamp(created) != period.Sub.CreatedTime || created.Before(period.End) {
			continue
		}
		if _, err := paidGroupPeriod(period.Sub, order, period.Payment); err != nil {
			continue
		}
		if latest == nil || created.After(latestTime) {
			latest, latestTime = period, created
		}
	}
	return latest
}

func groupOpenOrderView(order *Order) *GroupCheckoutOpenOrder {
	return &GroupCheckoutOpenOrder{Owner: order.Owner, Group: order.Group, Name: order.Name, User: order.User, State: order.State, CheckoutRevision: order.CheckoutRevision, CheckoutTerms: order.CheckoutTerms, ProductInfos: order.ProductInfos, Price: order.Price, Currency: order.Currency, PaymentName: order.Payment}
}

// Settlement checks the immutable predecessor, not its current time-derived
// State/window. A delayed confirmation consumes the already committed term.
func validateGroupSettlementTerms(session *xorm.Session, order *Order, now time.Time) error {
	if order.CheckoutRevision < 2 || validateCheckoutTerms(order.CheckoutTerms, true) != nil {
		return ErrGroupCheckoutConflict
	}
	timeline, err := loadGroupTimeline(session, order.Owner, order.Group, now)
	if err != nil {
		return err
	}
	terms := order.CheckoutTerms
	start, end, _ := checkoutInterval(terms.StartTime, terms.EndTime)
	previousFound := terms.Kind == "fresh"
	for _, period := range timeline.Periods {
		if !period.Start.Before(start) || (start.Before(period.End) && period.Start.Before(end)) {
			return ErrGroupCheckoutConflict
		}
		if terms.Kind == "next" && period.Sub.Name == terms.PreviousSubscription {
			if period.Revision != terms.PreviousPeriodRevision || checkoutTimestamp(period.Start) != terms.PreviousStartTime || checkoutTimestamp(period.End) != terms.PreviousEndTime {
				return ErrGroupCheckoutConflict
			}
			previousFound = true
		}
	}
	if !previousFound {
		return ErrGroupCheckoutConflict
	}
	return nil
}
