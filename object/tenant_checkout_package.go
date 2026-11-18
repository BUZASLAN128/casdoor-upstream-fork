// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License").
// you may not use this file except in compliance with the License.

package object

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"
)

const tenantPackagePrefix = "ai-budget-"

var tenantPackageSKU = regexp.MustCompile(`^ai-budget-[0-9a-f]{64}$`)
var tenantPackageComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var tenantPackageCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
var tenantPackageTerms = GroupCheckoutTerms{Version: 1, Kind: "package", PreviousPeriodRevision: "none"}

func isTenantPackageCheckout(infos []ProductInfo) bool {
	if len(infos) != 1 {
		return false
	}
	info := infos[0]
	return tenantPackageSKU.MatchString(info.Name) && info.Quantity == 1 && info.PricingName == "" && info.PlanName == "" && !info.IsRecharge
}

func matchesTenantCheckoutProduct(infos []ProductInfo, pricing string) bool {
	if len(infos) != 1 {
		return false
	}
	if strings.HasPrefix(infos[0].Name, tenantPackagePrefix) {
		return isTenantPackageCheckout(infos)
	}
	return infos[0].PricingName == pricing
}

// The SKU derives from the two catalog keys. The caller's plan fields and
// product attributes never establish the kind, price, or stock of a package.
func validateTenantPackageProduct(product *Product) error {
	id := product.Properties["package_id"]
	version := product.Properties["package_version"]
	if !tenantPackageComponent.MatchString(id) || !tenantPackageComponent.MatchString(version) ||
		product.Properties["checkout_kind"] != tenantPackageTerms.Kind ||
		product.Name != fmt.Sprintf("%s%x", tenantPackagePrefix, sha256.Sum256([]byte(id+"@"+version))) ||
		product.State != "Published" || product.IsRecharge || product.Quantity < 1 ||
		!tenantPackageCurrency.MatchString(product.Currency) || product.Price <= 0 || math.IsNaN(product.Price) || math.IsInf(product.Price, 0) {
		return ErrGroupCheckoutConflict
	}
	return nil
}

func validateGroupOrderTerms(order *Order, claimed bool) error {
	if isTenantPackageCheckout(order.ProductInfos) {
		if order.CheckoutTerms == nil || *order.CheckoutTerms != tenantPackageTerms ||
			len(order.Products) != 1 || order.Products[0] != order.ProductInfos[0].Name {
			return ErrGroupCheckoutConflict
		}
		return nil
	}
	for _, info := range order.ProductInfos {
		if strings.HasPrefix(info.Name, tenantPackagePrefix) {
			return ErrGroupCheckoutConflict
		}
	}
	return validateCheckoutTerms(order.CheckoutTerms, claimed)
}
