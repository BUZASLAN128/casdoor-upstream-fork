// Copyright 2025 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// PlaceOrder
// @Title PlaceOrder
// @Tag Order API
// @Description place an order for a product
// @Param   productId     query    string  true        "The id ( owner/name ) of the product"
// @Param   pricingName   query    string  false       "The name of the pricing (for subscription)"
// @Param   planName      query    string  false       "The name of the plan (for subscription)"
// @Param   customPrice   query    number  false       "Custom price for recharge products"
// @Param   userName      query    string  false       "The username to place order for (admin only)"
// @Success 200 {object} object.Order The Response object
// @router /place-order [post]
func (c *ApiController) PlaceOrder() {
	owner := c.Ctx.Input.Query("owner")
	paidUserName := c.Ctx.Input.Query("userName")

	var req struct {
		ProductInfos                  []object.ProductInfo `json:"productInfos"`
		CouponCode                    string               `json:"couponCode"`
		Group                         string               `json:"group"`
		ExpectedCurrentPeriodRevision string               `json:"expectedCurrentPeriodRevision"`
	}
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &req)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	productInfos := req.ProductInfos
	if err := object.CheckTenantCheckoutRequest(c.GetSessionUsername(), owner, req.Group, productInfos); err != nil {
		c.respondGroupCheckoutError(err)
		return
	}
	if len(productInfos) == 0 {
		c.ResponseError(c.T("product:Product list cannot be empty"))
		return
	}
	if req.Group != "" {
		if err := object.CheckTenantCheckoutPrincipal(c.GetSessionUsername(), owner); err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		if paidUserName == "" || req.CouponCode != "" {
			c.ResponseError("tenant checkout requires an authenticated payer and no coupon")
			return
		}
		if req.ExpectedCurrentPeriodRevision == "" {
			c.respondGroupCheckoutError(object.ErrGroupCheckoutConflict)
			return
		}
		payer, err := object.GetUser(util.GetId(owner, paidUserName))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		order, err := object.PlaceGroupOrder(c.GetSessionUsername(), owner, req.Group, productInfos, payer, req.ExpectedCurrentPeriodRevision)
		if err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		c.ResponseOk(order)
		return
	}

	var userId string
	if paidUserName != "" {
		userId = util.GetId(owner, paidUserName)
		if userId != c.GetSessionUsername() && !c.IsAdminOfOrganization(owner) && userId != c.GetPaidUsername() {
			c.ResponseError(c.T("general:Only admin user can specify user"))
			return
		}

		c.SetSession("paidUsername", "")
	} else {
		userId = c.GetSessionUsername()
	}

	if userId == "" {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return
	}

	order, err := object.PlaceOrder(owner, productInfos, user, req.CouponCode)
	if err != nil {
		c.respondGroupCheckoutError(err)
		return
	}

	c.ResponseOk(order)
}

func (c *ApiController) respondGroupCheckoutError(err error) {
	if errors.Is(err, object.ErrTenantCheckoutRequired) {
		c.Ctx.Output.SetStatus(http.StatusForbidden)
		c.ResponseJsonData(&Response{Status: "error", Msg: object.ErrTenantCheckoutRequired.Error()})
		return
	}
	if errors.Is(err, object.ErrGroupCheckoutUnavailable) {
		c.Ctx.Output.SetStatus(http.StatusServiceUnavailable)
		c.ResponseJsonData(&Response{Status: "error", Msg: object.ErrGroupCheckoutUnavailable.Error()})
		return
	}
	if errors.Is(err, object.ErrGroupCheckoutConflict) {
		c.Ctx.Output.SetStatus(http.StatusConflict)
		// This stable machine code is required by the trusted App client, even
		// when ordinary human-readable errors are masked by deployment config.
		c.ResponseJsonData(&Response{Status: "error", Msg: object.ErrGroupCheckoutConflict.Error()})
		return
	}
	c.ResponseError(err.Error())
}

// PayOrder
// @Title PayOrder
// @Tag Order API
// @Description pay an existing order
// @Param   id     query    string  true        "The id ( owner/name ) of the order"
// @Param   providerName    query    string  true  "The name of the provider"
// @Param   autoRenew    query    string  false  "Whether the subscriptions of the order renew automatically, the plan's default when empty"
// @Success 200 {object} controllers.Response The Response object
// @router /pay-order [post]
func (c *ApiController) PayOrder() {
	id := c.Ctx.Input.Query("id")
	host := c.Ctx.Request.Host
	providerName := c.Ctx.Input.Query("providerName")
	paymentEnv := c.Ctx.Input.Query("paymentEnv")

	order, err := object.GetOrder(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if order == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The order: %s does not exist"), id))
		return
	}
	if order.Group != "" {
		admission, err := c.groupPaymentAdmission(order, object.GetApplicationByClientId)
		if err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		payment, attachInfo, err := object.PayGroupOrder(admission, providerName, host, c.GetAcceptLanguage())
		if err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		c.ResponseOk(payment, attachInfo)
		return
	}

	userId := c.GetSessionUsername()
	orderUserId := util.GetId(order.Owner, order.User)
	if userId != orderUserId && !c.IsAdminOfOrganization(order.Owner) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	var autoRenew *bool
	if autoRenewStr := c.Ctx.Input.Query("autoRenew"); autoRenewStr != "" {
		value := autoRenewStr == "true"
		autoRenew = &value
	}

	payment, attachInfo, err := object.PayOrder(providerName, host, paymentEnv, order, autoRenew, c.GetAcceptLanguage())
	if err != nil {
		c.respondGroupCheckoutError(err)
		return
	}

	c.ResponseOk(payment, attachInfo)
}

// ApiFilter also supports session/query credentials and impersonation. Recheck
// this operation's actual Basic credentials, not just its transformed subject.
// The lookup seam exercises native authentication without shared storage.
func (c *ApiController) groupPaymentAdmission(order *object.Order, lookup func(string) (*object.Application, error)) (object.GroupPaymentAdmission, error) {
	var admission object.GroupPaymentAdmission
	clientID, secret, basic := c.Ctx.Request.BasicAuth()
	if order == nil || order.Group == "" || !basic || clientID == "" || secret == "" || c.Ctx.Input.GetData("impersonating") == true {
		return admission, object.ErrTenantCheckoutRequired
	}
	application, err := lookup(clientID)
	if err != nil {
		return admission, object.ErrGroupCheckoutUnavailable
	}
	// GetApplicationByClientId also accepts shared-org client-id aliases. Only
	// this application's actual persisted client ID is a dispatch credential.
	if application == nil || application.ClientId != clientID || application.ClientSecret != secret || application.Organization != order.Owner {
		return admission, object.ErrTenantCheckoutRequired
	}
	for _, tag := range application.Tags {
		if tag == "dcr" {
			return admission, object.ErrTenantCheckoutRequired
		}
	}
	principal := "app/" + application.Name
	if c.GetSessionUsername() != principal {
		return admission, object.ErrTenantCheckoutRequired
	}
	if err := object.CheckTenantCheckoutPrincipal(principal, order.Owner); err != nil {
		return admission, err
	}
	revision, err := strconv.ParseInt(c.Ctx.Input.Query("expectedCheckoutRevision"), 10, 64)
	if err != nil || revision < 1 {
		return admission, object.ErrGroupCheckoutConflict
	}
	admission = object.GroupPaymentAdmission{Principal: principal, Owner: order.Owner, Group: c.Ctx.Input.Query("group"), OrderName: order.Name, PayerName: c.Ctx.Input.Query("userName"), ExpectedCheckoutRevision: revision}
	if admission.Group != order.Group || admission.PayerName != order.User {
		return admission, object.ErrTenantCheckoutRequired
	}
	if revision != order.CheckoutRevision {
		return admission, object.ErrGroupCheckoutConflict
	}
	return admission, nil
}

// CancelOrder
// @Title CancelOrder
// @Tag Order API
// @Description cancel an order
// @Param   id     query    string  true        "The id ( owner/name ) of the order"
// @Success 200 {object} controllers.Response The Response object
// @router /cancel-order [post]
func (c *ApiController) CancelOrder() {
	id := c.Ctx.Input.Query("id")
	order, err := object.GetOrder(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if order == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The order: %s does not exist"), id))
		return
	}
	if order.Group != "" {
		if err := object.CheckTenantCheckoutPrincipal(c.GetSessionUsername(), order.Owner); err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		revision, err := strconv.ParseInt(c.Ctx.Input.Query("expectedCheckoutRevision"), 10, 64)
		if err != nil || revision < 0 {
			c.respondGroupCheckoutError(object.ErrGroupCheckoutConflict)
			return
		}
		canceled, err := object.CancelGroupOrder(c.GetSessionUsername(), c.Ctx.Input.Query("userName"), order, revision)
		if err != nil {
			c.respondGroupCheckoutError(err)
			return
		}
		c.ResponseOk(canceled)
		return
	}

	userId := c.GetSessionUsername()
	orderUserId := util.GetId(order.Owner, order.User)
	if userId != orderUserId && !c.IsAdminOfOrganization(order.Owner) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	affected, err := object.CancelOrder(order)
	if order.Group != "" && err != nil {
		c.respondGroupCheckoutError(err)
		return
	}
	c.Data["json"] = wrapActionResponse(affected, err)
	c.ServeJSON()
}

// GetGroupCheckout is a configured application read, never a browser-selected
// tenant or a console-admin/payer impersonation route.
func (c *ApiController) GetGroupCheckout() {
	if c.Ctx.Input.Query("readScope") == "history" {
		c.getGroupCheckoutHistory()
		return
	}
	owner := c.Ctx.Input.Query("owner")
	if err := object.CheckTenantCheckoutPrincipal(c.GetSessionUsername(), owner); err != nil {
		c.respondGroupCheckoutError(err)
		return
	}
	status, err := object.GetGroupCheckout(c.GetSessionUsername(), owner, c.Ctx.Input.Query("group"), c.Ctx.Input.Query("userName"), c.Ctx.Input.Query("orderName"))
	if err != nil {
		c.respondGroupCheckoutError(err)
		return
	}
	c.ResponseOk(status)
}

// History requires actual credentials in addition to the transformed native App
// context. Query-only auth, browser sessions and impersonation are not evidence.
func (c *ApiController) groupHistoryPrincipal(owner string, lookup func(string) (*object.Application, error)) (string, error) {
	principal := c.GetSessionUsername()
	if err := object.CheckTenantCheckoutPrincipal(principal, owner); err != nil {
		return "", err
	}
	clientID, secret, basic := c.Ctx.Request.BasicAuth()
	if !basic || clientID == "" || secret == "" || c.Ctx.Input.GetData("impersonating") == true {
		return "", object.ErrTenantCheckoutRequired
	}
	app, err := lookup(clientID)
	if err != nil {
		return "", object.ErrGroupCheckoutUnavailable
	}
	if app == nil || app.ClientId != clientID || app.ClientSecret != secret || app.Organization != owner || "app/"+app.Name != principal {
		return "", object.ErrTenantCheckoutRequired
	}
	for _, tag := range app.Tags {
		if tag == "dcr" {
			return "", object.ErrTenantCheckoutRequired
		}
	}
	return principal, nil
}

func (c *ApiController) getGroupCheckoutHistory() {
	owner := c.Ctx.Input.Query("owner")
	principal, err := c.groupHistoryPrincipal(owner, object.GetApplicationByClientId)
	if err != nil {
		c.respondGroupCheckoutError(err)
		return
	}
	limit := 20
	rawLimit := c.Ctx.Input.Query("limit")
	if rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || strconv.Itoa(limit) != rawLimit {
			err = object.ErrGroupHistoryInvalidQuery
		}
	}
	if err == nil && (limit < 1 || limit > 50) {
		err = object.ErrGroupHistoryInvalidQuery
	}
	var result *object.GroupCheckoutHistory
	if err == nil {
		result, err = object.GetGroupCheckoutHistory(principal, owner, c.Ctx.Input.Query("group"), limit, c.Ctx.Input.Query("cursor"))
	}
	if err != nil {
		if errors.Is(err, object.ErrGroupHistoryInvalidQuery) {
			c.Ctx.Output.SetStatus(http.StatusBadRequest)
			c.ResponseJsonData(&Response{Status: "error", Msg: object.ErrGroupHistoryInvalidQuery.Error()})
		} else {
			c.respondGroupCheckoutError(err)
		}
		return
	}
	c.ResponseOk(result)
}
