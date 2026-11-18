// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"time"

	"github.com/casdoor/casdoor/pp"
)

// GroupCheckoutTerms is a prepaid quote, not a recurring-charge instruction.
// Fresh dates are filled once in the committed dispatch claim. Next-period
// dates are quoted at the preceding paid EndTime. Settlement never rebases them.
type GroupCheckoutTerms struct {
	Version                int    `json:"version"`
	Kind                   string `json:"kind"`
	PreviousSubscription   string `json:"previousSubscription,omitempty"`
	PreviousStartTime      string `json:"previousStartTime,omitempty"`
	PreviousEndTime        string `json:"previousEndTime,omitempty"`
	PreviousPeriodRevision string `json:"previousPeriodRevision"`
	StartTime              string `json:"startTime,omitempty"`
	EndTime                string `json:"endTime,omitempty"`
	Period                 string `json:"period"`
}

type groupPaidPeriod struct {
	Sub        *Subscription
	Order      *Order
	Payment    *Payment
	Start, End time.Time
	Revision   string
}

type groupPeriodTimeline struct {
	Periods           []*groupPaidPeriod
	Current, Upcoming *groupPaidPeriod
}

func checkoutTimestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func checkoutInterval(start, end string) (time.Time, time.Time, error) {
	s, e := time.Time{}, time.Time{}
	var err error
	if s, err = time.Parse(time.RFC3339Nano, start); err != nil {
		return s, e, ErrGroupCheckoutConflict
	}
	if e, err = time.Parse(time.RFC3339Nano, end); err != nil || !s.Before(e) {
		return s, e, ErrGroupCheckoutConflict
	}
	return s.UTC(), e.UTC(), nil
}

func checkoutPeriodEnd(start time.Time, period string) (time.Time, error) {
	switch period {
	case PeriodMonthly:
		return start.UTC().AddDate(0, 1, 0), nil
	case PeriodYearly:
		return start.UTC().AddDate(1, 0, 0), nil
	default:
		return time.Time{}, ErrGroupCheckoutConflict
	}
}

func validPeriodRevision(revision string) bool {
	decoded, err := hex.DecodeString(revision)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == revision
}

// A versioned, fixed-field JSON tuple prevents delimiter ambiguity. Dates are
// canonical UTC instants; mutable display/state/catalog fields are excluded.
func groupPeriodRevision(sub *Subscription) (string, error) {
	if sub == nil || sub.Owner == "" || sub.Name == "" || sub.Group == "" || sub.User != "" || sub.Plan == "" || sub.Pricing == "" || sub.Payment == "" {
		return "", ErrGroupCheckoutConflict
	}
	start, end, err := checkoutInterval(sub.StartTime, sub.EndTime)
	if err != nil {
		return "", err
	}
	if _, err = checkoutPeriodEnd(start, sub.Period); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(struct {
		Encoding string     `json:"encoding"`
		Fields   [10]string `json:"fields"`
	}{"casdoor-group-period/v1", [10]string{sub.Owner, sub.Group, sub.Name, sub.Plan, sub.Pricing, sub.Payment, checkoutTimestamp(start), checkoutTimestamp(end), sub.Period, "direct-paid"}})
	if err != nil {
		return "", ErrGroupCheckoutConflict
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func paidGroupPeriod(sub *Subscription, order *Order, payment *Payment) (*groupPaidPeriod, error) {
	if sub == nil || order == nil || payment == nil || validateGroupPayment(order, payment) != nil || payment.State != pp.PaymentStatePaid || payment.Type == "" || payment.Provider == "" || order.State != "Paid" || sub.Owner != order.Owner || sub.Group != order.Group || sub.User != "" || sub.Payment != payment.Name || len(order.ProductInfos) != 1 || sub.Plan != order.ProductInfos[0].PlanName || sub.Pricing != order.ProductInfos[0].PricingName {
		return nil, ErrGroupCheckoutConflict
	}
	if err := checkDummyPayment(payment.Type); err != nil {
		return nil, ErrGroupCheckoutUnavailable
	}
	revision, err := groupPeriodRevision(sub)
	if err != nil {
		return nil, err
	}
	start, end, _ := checkoutInterval(sub.StartTime, sub.EndTime)
	if order.CheckoutTerms != nil {
		if err = validateCheckoutTerms(order.CheckoutTerms, true); err != nil || order.CheckoutRevision < 3 || sub.Period != order.CheckoutTerms.Period || checkoutTimestamp(start) != order.CheckoutTerms.StartTime || checkoutTimestamp(end) != order.CheckoutTerms.EndTime {
			return nil, ErrGroupCheckoutConflict
		}
	}
	return &groupPaidPeriod{Sub: sub, Order: order, Payment: payment, Start: start, End: end, Revision: revision}, nil
}

func effectiveGroupPeriodState(sub *Subscription, now time.Time) (SubscriptionState, error) {
	start, end, err := checkoutInterval(sub.StartTime, sub.EndTime)
	if err != nil {
		return "", err
	}
	if sub.State == SubStateSuspended || sub.State == SubStateError {
		return sub.State, nil
	}
	switch sub.State {
	case SubStatePending, SubStateActive, SubStateUpcoming, SubStateExpired:
	default:
		return "", ErrGroupCheckoutConflict
	}
	if !now.Before(end) {
		return SubStateExpired, nil
	}
	if now.Before(start) {
		return SubStateUpcoming, nil
	}
	return SubStateActive, nil
}

func groupTimeline(periods []*groupPaidPeriod, now time.Time) (*groupPeriodTimeline, error) {
	result := &groupPeriodTimeline{Periods: append([]*groupPaidPeriod(nil), periods...)}
	sort.Slice(result.Periods, func(i, j int) bool { return result.Periods[i].Start.Before(result.Periods[j].Start) })
	for i, period := range result.Periods {
		if i > 0 && period.Start.Before(result.Periods[i-1].End) {
			return nil, ErrGroupCheckoutConflict
		}
		if !now.Before(period.End) {
			continue
		}
		if now.Before(period.Start) {
			if result.Upcoming != nil {
				return nil, ErrGroupCheckoutConflict
			}
			result.Upcoming = period
		} else {
			if result.Current != nil {
				return nil, ErrGroupCheckoutConflict
			}
			result.Current = period
		}
	}
	return result, nil
}

func (timeline *groupPeriodTimeline) revision() string {
	if timeline.Current == nil {
		return "none"
	}
	return timeline.Current.Revision
}

func periodPurchaseEligibility(timeline *groupPeriodTimeline, now time.Time) (bool, string) {
	if timeline.Upcoming != nil {
		return false, "upcoming_exists"
	}
	if timeline.Current == nil {
		return true, "fresh"
	}
	state, err := effectiveGroupPeriodState(timeline.Current.Sub, now)
	if err != nil || state != SubStateActive {
		return false, "reconciliation_required"
	}
	if now.Before(timeline.Current.End.AddDate(0, 0, -14)) {
		return false, "outside_window"
	}
	return true, "next_period"
}

func newCheckoutTerms(timeline *groupPeriodTimeline, expected, period string, now time.Time) (*GroupCheckoutTerms, error) {
	if expected != timeline.revision() {
		return nil, ErrGroupCheckoutConflict
	}
	if eligible, _ := periodPurchaseEligibility(timeline, now); !eligible {
		return nil, ErrGroupCheckoutConflict
	}
	if _, err := checkoutPeriodEnd(now, period); err != nil {
		return nil, err
	}
	terms := &GroupCheckoutTerms{Version: 1, Kind: "fresh", PreviousPeriodRevision: "none", Period: period}
	if previous := timeline.Current; previous != nil {
		end, _ := checkoutPeriodEnd(previous.End, period)
		terms.Kind, terms.PreviousSubscription, terms.PreviousPeriodRevision = "next", previous.Sub.Name, previous.Revision
		terms.PreviousStartTime, terms.PreviousEndTime = checkoutTimestamp(previous.Start), checkoutTimestamp(previous.End)
		terms.StartTime, terms.EndTime = checkoutTimestamp(previous.End), checkoutTimestamp(end)
	}
	return terms, nil
}

func validateCheckoutTerms(terms *GroupCheckoutTerms, claimed bool) error {
	if terms == nil || terms.Version != 1 {
		return ErrGroupCheckoutConflict
	}
	if _, err := checkoutPeriodEnd(time.Time{}, terms.Period); err != nil {
		return err
	}
	switch terms.Kind {
	case "fresh":
		if terms.PreviousPeriodRevision != "none" || terms.PreviousSubscription != "" || terms.PreviousStartTime != "" || terms.PreviousEndTime != "" {
			return ErrGroupCheckoutConflict
		}
		if !claimed && terms.StartTime == "" && terms.EndTime == "" {
			return nil
		}
	case "next":
		if terms.PreviousSubscription == "" || !validPeriodRevision(terms.PreviousPeriodRevision) {
			return ErrGroupCheckoutConflict
		}
		previousStart, previousEnd, err := checkoutInterval(terms.PreviousStartTime, terms.PreviousEndTime)
		if err != nil || checkoutTimestamp(previousStart) != terms.PreviousStartTime || checkoutTimestamp(previousEnd) != terms.PreviousEndTime || terms.StartTime != terms.PreviousEndTime {
			return ErrGroupCheckoutConflict
		}
	default:
		return ErrGroupCheckoutConflict
	}
	start, end, err := checkoutInterval(terms.StartTime, terms.EndTime)
	if err != nil {
		return err
	}
	expectedEnd, err := checkoutPeriodEnd(start, terms.Period)
	if err != nil || !end.Equal(expectedEnd) || checkoutTimestamp(start) != terms.StartTime || checkoutTimestamp(end) != terms.EndTime {
		return ErrGroupCheckoutConflict
	}
	return nil
}

func claimCheckoutTerms(terms *GroupCheckoutTerms, timeline *groupPeriodTimeline, now time.Time) (*GroupCheckoutTerms, error) {
	if err := validateCheckoutTerms(terms, false); err != nil {
		return nil, err
	}
	expected, err := newCheckoutTerms(timeline, terms.PreviousPeriodRevision, terms.Period, now)
	if err != nil {
		return nil, err
	}
	// No quote can silently become a fresh purchase after its prior term ends.
	if *expected != *terms {
		return nil, ErrGroupCheckoutConflict
	}
	claimed := *terms
	if terms.Kind == "fresh" {
		end, _ := checkoutPeriodEnd(now, terms.Period)
		claimed.StartTime, claimed.EndTime = checkoutTimestamp(now), checkoutTimestamp(end)
	}
	return &claimed, nil
}

func nextCheckoutRevision(revision int64) (int64, error) {
	if revision < 0 || revision == math.MaxInt64 {
		return 0, ErrGroupCheckoutConflict
	}
	return revision + 1, nil
}
