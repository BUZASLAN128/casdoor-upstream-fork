// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License").

package object

import (
	"encoding/json"

	"github.com/casdoor/casdoor/pp"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

// Claims and settlement acquire Group -> Order -> Product. Generic catalog
// mutations acquire Product only; they never take a reverse Group/order lock.
func checkoutStockProductForUpdate(session *xorm.Session, owner, name string) (*Product, error) {
	product := &Product{}
	query := session.ID(core.PK{owner, name})
	if ormer.Engine.DriverName() != "sqlite" {
		query = query.ForUpdate()
	}
	found, err := query.Get(product)
	if err != nil || !found {
		return nil, err
	}
	if ormer.Engine.DriverName() == "sqlite" {
		if _, err := session.ID(core.PK{owner, name}).Cols("quantity").Update(&Product{Quantity: product.Quantity}); err != nil {
			return nil, err
		}
	}
	return product, nil
}

func reserveGroupProductStock(session *xorm.Session, product *Product) error {
	if product == nil || product.IsRecharge || product.Quantity < 1 {
		return ErrGroupCheckoutConflict
	}
	affected, err := session.ID(core.PK{product.Owner, product.Name}).Where("quantity >= ?", 1).Decr("quantity", 1).Update(&Product{})
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrGroupCheckoutConflict
	}
	return nil
}

func unresolvedGroupProductReservation(session *xorm.Session, owner, name string) (bool, error) {
	// Only canonical single-product claims can set the flag. xorm persists the
	// []string product field as this native JSON encoding in its varchar column.
	products, err := json.Marshal([]string{name})
	if err != nil {
		return false, err
	}
	return session.Where("owner = ? and group_stock_reserved = ? and state <> ?", owner, true, pp.PaymentStatePaid).
		And(quoteColumn("group")+" <> ?", "").And("products = ?", string(products)).Exist(&Payment{})
}

func validateReservedProductMutation(canonical, requested *Product, reserved bool) error {
	if reserved && (canonical == nil || requested == nil || canonical.Owner != requested.Owner || canonical.Name != requested.Name || canonical.Quantity != requested.Quantity || canonical.Sold != requested.Sold) {
		return ErrGroupCheckoutConflict
	}
	return nil
}
