// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/casdoor/casdoor/pp"
	"github.com/xorm-io/core"
)

var ErrGroupHistoryInvalidQuery = errors.New("GROUP_HISTORY_INVALID_QUERY")

const groupHistoryMaxCursor = 1024

// These references contain only native generated identifiers, not arbitrary
// legacy/manual names that might contain a payer's contact information.
var groupHistoryReference = regexp.MustCompile(`^(order|payment)_([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9]{8}_[0-9]{6}_[0-9a-f]{7})$`)

type GroupCheckoutHistoryItem struct {
	Owner              string           `json:"owner"`
	Group              string           `json:"group"`
	OrderName          string           `json:"orderName"`
	CreatedTime        string           `json:"createdTime"`
	Plan               string           `json:"plan"`
	Pricing            string           `json:"pricing"`
	ProductDisplayName *string          `json:"productDisplayName"`
	Price              float64          `json:"price"`
	Currency           string           `json:"currency"`
	PurchaseKind       *string          `json:"purchaseKind"`
	Period             *string          `json:"period"`
	PeriodStart        *string          `json:"periodStart"`
	PeriodEnd          *string          `json:"periodEnd"`
	OrderState         string           `json:"orderState"`
	PaymentName        *string          `json:"paymentName"`
	PaymentState       *pp.PaymentState `json:"paymentState"`
	PaymentMode        *string          `json:"paymentMode"`
}

type GroupCheckoutHistory struct {
	ReadScope  string                      `json:"readScope"`
	Owner      string                      `json:"owner"`
	Group      string                      `json:"group"`
	ServerNow  string                      `json:"serverNow"`
	CanResume  bool                        `json:"canResume"`
	CanCancel  bool                        `json:"canCancel"`
	Items      []*GroupCheckoutHistoryItem `json:"items"`
	NextCursor *string                     `json:"nextCursor"`
}

type groupHistoryCursor struct {
	Version     int    `json:"v"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	CreatedTime string `json:"createdTime"`
	Name        string `json:"name"`
}

func validGroupHistoryReference(name, prefix string) bool {
	return strings.HasPrefix(name, prefix+"_") && groupHistoryReference.MatchString(name)
}

func parseGroupHistoryCursor(owner, group, token string) (*groupHistoryCursor, error) {
	if token == "" {
		return nil, nil
	}
	if len(token) > groupHistoryMaxCursor {
		return nil, ErrGroupHistoryInvalidQuery
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, ErrGroupHistoryInvalidQuery
	}
	cursor := &groupHistoryCursor{}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cursor); err != nil {
		return nil, ErrGroupHistoryInvalidQuery
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF || cursor.Version != 1 || cursor.Owner != owner || cursor.Group != group || !validGroupHistoryReference(cursor.Name, "order") {
		return nil, ErrGroupHistoryInvalidQuery
	}
	if _, err := time.Parse(time.RFC3339, cursor.CreatedTime); err != nil {
		return nil, ErrGroupHistoryInvalidQuery
	}
	return cursor, nil
}

func encodeGroupHistoryCursor(order *Order) (string, error) {
	cursor := groupHistoryCursor{1, order.Owner, order.Group, order.CreatedTime, order.Name}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", ErrGroupCheckoutUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseGroupHistoryCursor(order.Owner, order.Group, token); err != nil {
		return "", ErrGroupCheckoutUnavailable
	}
	return token, nil
}

// projectGroupHistory uses only stored order/payment facts. It does not resolve
// subscriptions, current catalog names, provider objects or deployment switches.
// Price is the order quote; only an exactly paired Paid payment proves payment.
func projectGroupHistory(order *Order, payment *Payment) (*GroupCheckoutHistoryItem, error) {
	if order == nil || order.Owner == "" || order.Group == "" || !validGroupHistoryReference(order.Name, "order") || math.IsNaN(order.Price) || math.IsInf(order.Price, 0) || order.Price < 0 || order.Currency == "" || len(order.ProductInfos) != 1 {
		return nil, ErrGroupCheckoutUnavailable
	}
	if _, err := time.Parse(time.RFC3339, order.CreatedTime); err != nil {
		return nil, ErrGroupCheckoutUnavailable
	}
	info := order.ProductInfos[0]
	if info.PlanName == "" || info.PricingName == "" || info.Quantity != 1 || info.IsRecharge {
		return nil, ErrGroupCheckoutUnavailable
	}
	item := &GroupCheckoutHistoryItem{Owner: order.Owner, Group: order.Group, OrderName: order.Name, CreatedTime: order.CreatedTime, Plan: info.PlanName, Pricing: info.PricingName, Price: order.Price, Currency: order.Currency, OrderState: order.State}
	if info.DisplayName != "" {
		item.ProductDisplayName = &info.DisplayName
	}
	if order.CheckoutTerms != nil {
		if validateCheckoutTerms(order.CheckoutTerms, order.State == "Paid" || order.State == "Processing") != nil {
			return nil, ErrGroupCheckoutUnavailable
		}
		terms := order.CheckoutTerms
		item.PurchaseKind, item.Period = &terms.Kind, &terms.Period
		if terms.StartTime != "" {
			item.PeriodStart, item.PeriodEnd = &terms.StartTime, &terms.EndTime
		}
	}
	if order.Payment == "" {
		if payment != nil || order.State == "Paid" {
			return nil, ErrGroupCheckoutUnavailable
		}
		return item, nil
	}
	if payment == nil || !validGroupHistoryReference(payment.Name, "payment") || validateGroupPayment(order, payment) != nil || (order.State == "Paid") != (payment.State == pp.PaymentStatePaid) {
		return nil, ErrGroupCheckoutUnavailable
	}
	item.PaymentName, item.PaymentState = &payment.Name, &payment.State
	if payment.Type == "Dummy" && payment.GroupStockReserved {
		// Match the deterministic persisted admission snapshot, not current env or
		// a mutable provider row. A legacy/default-false marker proves no test mode.
		raw, err := json.Marshal(pp.DummyOrderInfo{Price: order.Price, Currency: order.Currency})
		if err == nil && payment.OutOrderId == string(raw) {
			mode := "test"
			item.PaymentMode = &mode
		}
	}
	return item, nil
}

// GetGroupCheckoutHistory is an independent bounded financial read. The HTTP
// caller must validate actual Basic credentials; principal/owner and Group are
// rechecked before storage, and the cursor never establishes tenant authority.
func GetGroupCheckoutHistory(principal, owner, group string, limit int, token string) (*GroupCheckoutHistory, error) {
	if err := CheckTenantCheckoutPrincipal(principal, owner); err != nil {
		return nil, err
	}
	if group == "" || len(group) > 100 || strings.Contains(group, "/") {
		return nil, ErrTenantCheckoutRequired
	}
	if limit < 1 || limit > 50 {
		return nil, ErrGroupHistoryInvalidQuery
	}
	cursor, err := parseGroupHistoryCursor(owner, group, token)
	if err != nil {
		return nil, err
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
	found, err := session.ID(core.PK{owner, group}).Exist(&Group{})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrTenantCheckoutRequired
	}
	result := &GroupCheckoutHistory{ReadScope: "history", Owner: owner, Group: group, ServerNow: checkoutTimestamp(time.Now().UTC()), Items: []*GroupCheckoutHistoryItem{}}
	orders := []*Order{}
	query := session.Where("owner = ? AND "+quoteColumn("group")+" = ?", owner, group)
	// The stored single-SKU list has a canonical JSON prefix. REPLACE
	// matches its case even on databases where LIKE ignores case.
	packagePrefix := `["` + tenantPackagePrefix
	query = query.And("(products IS NULL OR LENGTH(products) < ? OR LENGTH(REPLACE(SUBSTR(products, 1, ?), ?, '')) <> 0)", len(packagePrefix), len(packagePrefix), packagePrefix)
	if cursor != nil {
		query = query.And("(created_time < ? OR (created_time = ? AND name < ?))", cursor.CreatedTime, cursor.CreatedTime, cursor.Name)
	}
	if err := query.Desc("created_time", "name").Limit(limit + 1).Find(&orders); err != nil {
		return nil, err
	}
	more := len(orders) > limit
	if more {
		orders = orders[:limit]
	}
	for _, order := range orders {
		if order.Owner != owner || order.Group != group {
			return nil, ErrGroupCheckoutUnavailable
		}
		// Recognize package rows even if their JSON list has been reformatted.
		if isTenantPackageCheckout(order.ProductInfos) && validateGroupOrderTerms(order, order.State == "Paid" || order.State == "Processing") == nil {
			continue
		}
		var payment *Payment
		if order.Payment != "" {
			payment = &Payment{}
			// Avoid loading payer contact/card/invoice fields or provider URLs/messages.
			found, err := session.Cols("owner", "name", "user", "group", "order", "products", "price", "currency", "state", "type", "group_stock_reserved", "out_order_id").ID(core.PK{owner, order.Payment}).Get(payment)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, ErrGroupCheckoutUnavailable
			}
		} else {
			// A contradictory orphan intent must not masquerade as an unpaid quote.
			exists, err := session.Where("owner = ? AND "+quoteColumn("order")+" = ?", owner, order.Name).Exist(&Payment{})
			if err != nil {
				return nil, err
			}
			if exists {
				return nil, ErrGroupCheckoutUnavailable
			}
		}
		item, err := projectGroupHistory(order, payment)
		if err != nil {
			return nil, err
		}
		result.Items = append(result.Items, item)
	}
	if more {
		token, err := encodeGroupHistoryCursor(orders[len(orders)-1])
		if err != nil {
			return nil, err
		}
		result.NextCursor = &token
	}
	if err := session.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
