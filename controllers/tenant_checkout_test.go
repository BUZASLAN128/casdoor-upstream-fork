package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestTenantCheckoutGroupDispatchRequiresActualBasicApp(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	order := &object.Order{Owner: "org", Name: "order", Group: "tenant", User: "payer", CheckoutRevision: 1}
	for _, tc := range []struct {
		name, subject, query, secret, appOrg string
		basic, impersonating, dcr, alias     bool
		want                                 error
	}{
		{name: "browser payer", subject: "org/payer", want: object.ErrTenantCheckoutRequired},
		{name: "transformed app without Basic", subject: "app/cerberus", want: object.ErrTenantCheckoutRequired},
		{name: "query credentials", subject: "app/cerberus", query: "&clientId=client&clientSecret=synthetic", want: object.ErrTenantCheckoutRequired},
		{name: "mixed user session and Basic", subject: "org/payer", basic: true, want: object.ErrTenantCheckoutRequired},
		{name: "impersonated Basic", subject: "app/cerberus", basic: true, impersonating: true, want: object.ErrTenantCheckoutRequired},
		{name: "wrong secret", subject: "app/cerberus", basic: true, secret: "wrong", want: object.ErrTenantCheckoutRequired},
		{name: "foreign application org", subject: "app/cerberus", basic: true, appOrg: "foreign", want: object.ErrTenantCheckoutRequired},
		{name: "DCR", subject: "app/cerberus", basic: true, dcr: true, want: object.ErrTenantCheckoutRequired},
		{name: "shared-org credential alias", subject: "app/cerberus", basic: true, alias: true, want: object.ErrTenantCheckoutRequired},
		{name: "foreign principal", subject: "app/foreign", basic: true, want: object.ErrTenantCheckoutRequired},
		{name: "manager cannot become payer", subject: "app/cerberus", basic: true, query: "&userName=manager", want: object.ErrTenantCheckoutRequired},
		{name: "foreign group", subject: "app/cerberus", basic: true, query: "&group=other", want: object.ErrTenantCheckoutRequired},
		{name: "missing revision", subject: "app/cerberus", basic: true, query: "&expectedCheckoutRevision=", want: object.ErrGroupCheckoutConflict},
		{name: "zero revision", subject: "app/cerberus", basic: true, query: "&expectedCheckoutRevision=0", want: object.ErrGroupCheckoutConflict},
		{name: "stale revision", subject: "app/cerberus", basic: true, query: "&expectedCheckoutRevision=2", want: object.ErrGroupCheckoutConflict},
		{name: "valid configured App payer", subject: "app/cerberus", basic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/pay-order?group=tenant&userName=payer&expectedCheckoutRevision=1", nil)
			if tc.query != "" {
				override := httptest.NewRequest("POST", "/api/pay-order?"+tc.query[1:], nil).URL.Query()
				q := request.URL.Query()
				for k, v := range override {
					q[k] = v
				}
				request.URL.RawQuery = q.Encode()
			}
			if tc.basic {
				secret := tc.secret
				if secret == "" {
					secret = "synthetic"
				}
				request.SetBasicAuth("client", secret)
			}
			ctx := context.NewContext()
			ctx.Reset(httptest.NewRecorder(), request)
			ctx.Input.SetData("currentUserId", tc.subject)
			ctx.Input.SetData("impersonating", tc.impersonating)
			controller := &ApiController{}
			controller.Init(ctx, "ApiController", "PayOrder", nil)
			lookups := 0
			admission, err := controller.groupPaymentAdmission(order, func(clientID string) (*object.Application, error) {
				lookups++
				if clientID != "client" {
					t.Fatal("wrong Basic lookup")
				}
				org := tc.appOrg
				if org == "" {
					org = "org"
				}
				app := &object.Application{Name: "cerberus", Organization: org, ClientId: "client", ClientSecret: "synthetic"}
				if tc.dcr {
					app.Tags = []string{"dcr"}
				}
				if tc.alias {
					app.ClientId = "persisted-other-id"
				}
				return app, nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("unexpected sanitized admission error: %v", err)
			}
			if (!tc.basic || tc.impersonating) && lookups != 0 {
				t.Fatal("unauthenticated/impersonated request reached application lookup")
			}
			if tc.want == nil && (admission.Principal != "app/cerberus" || admission.Owner != "org" || admission.Group != "tenant" || admission.OrderName != "order" || admission.PayerName != "payer" || admission.ExpectedCheckoutRevision != 1) {
				t.Fatal("actual App/payer/revision binding was lost")
			}
		})
	}
}

func TestTenantCheckoutBrowserCannotEstablishGroup(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	for _, principal := range []string{"", "org/payer", "built-in/admin", "app/foreign"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("POST", "/api/place-order?owner=org&userName=payer&paymentEnv=demo", nil)
		ctx := context.NewContext()
		ctx.Reset(response, request)
		ctx.Input.SetData("currentUserId", principal)
		ctx.Input.RequestBody = []byte(`{"group":"tenant","productInfos":[{"name":"product","planName":"plan","pricingName":"pricing","quantity":1}]}`)
		controller := &ApiController{}
		controller.Init(ctx, "ApiController", "PlaceOrder", nil)
		controller.PlaceOrder()
		if !strings.Contains(response.Body.String(), `"status": "error"`) && !strings.Contains(response.Body.String(), `"status":"error"`) {
			t.Fatalf("principal %q established browser Group checkout: %s", principal, response.Body.String())
		}
	}
}

func TestTenantCheckoutConflictResponseHasStableWireCode(t *testing.T) {
	t.Setenv("enableErrorMask2", "true")
	response := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(response, httptest.NewRequest("POST", "/api/place-order", nil))
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "PlaceOrder", nil)
	controller.respondGroupCheckoutError(object.ErrGroupCheckoutConflict)
	var wire struct {
		Status string `json:"status"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusConflict || wire.Status != "error" || wire.Msg != "GROUP_CHECKOUT_CONFLICT" {
		t.Fatalf("changed Group checkout conflict contract: HTTP %d %#v", response.Code, wire)
	}
}

func TestTenantCheckoutPersonalPricingReturnsForbiddenBeforePayerLookup(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	t.Setenv("enableErrorMask2", "true")
	for _, body := range []string{
		`{"productInfos":[{"name":"product","planName":"plan","pricingName":"pricing","quantity":1}]}`,
		`{"productInfos":[{"name":"other","pricingName":"personal","quantity":1},{"name":"product","planName":"plan","pricingName":"pricing","quantity":1}]}`,
	} {
		response := httptest.NewRecorder()
		ctx := context.NewContext()
		ctx.Reset(response, httptest.NewRequest("POST", "/api/place-order?owner=org", nil))
		ctx.Input.SetData("currentUserId", "org/payer")
		ctx.Input.RequestBody = []byte(body)
		controller := &ApiController{}
		controller.Init(ctx, "ApiController", "PlaceOrder", nil)
		controller.PlaceOrder()
		var wire struct {
			Status string `json:"status"`
			Msg    string `json:"msg"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusForbidden || wire.Status != "error" || wire.Msg != "TENANT_CHECKOUT_REQUIRED" {
			t.Fatalf("protected pricing response: HTTP %d %#v", response.Code, wire)
		}
	}
}

func TestTenantCheckoutLegacyBuyProductReturnsForbiddenBeforePayerLookup(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	response := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(response, httptest.NewRequest("POST", "/api/buy-product?id=org/product&pricingName=pricing&planName=plan", nil))
	ctx.Input.SetData("currentUserId", "org/payer")
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "BuyProduct", nil)
	controller.BuyProduct()
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "TENANT_CHECKOUT_REQUIRED") {
		t.Fatalf("legacy buy-product bypassed protected pricing: %d %s", response.Code, response.Body.String())
	}
}

func TestTenantCheckoutUnavailableResponseHasStableSanitizedWireCode(t *testing.T) {
	t.Setenv("enableErrorMask2", "true")
	response := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(response, httptest.NewRequest("POST", "/api/pay-order", nil))
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "PayOrder", nil)
	controller.respondGroupCheckoutError(object.ErrGroupCheckoutUnavailable)
	var wire struct {
		Status string `json:"status"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || wire.Status != "error" || wire.Msg != "GROUP_CHECKOUT_UNAVAILABLE" {
		t.Fatal("unavailable Group provider changed sanitized wire boundary")
	}
}

func TestTenantCheckoutMissingPeriodRevisionRejectedBeforePayerLookup(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	response := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(response, httptest.NewRequest("POST", "/api/place-order?owner=org&userName=payer", nil))
	ctx.Input.SetData("currentUserId", "app/cerberus")
	ctx.Input.RequestBody = []byte(`{"group":"tenant","productInfos":[{"name":"product","planName":"plan","pricingName":"pricing","quantity":1}],"checkoutTerms":{"kind":"fresh"}}`)
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "PlaceOrder", nil)
	controller.PlaceOrder()
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "GROUP_CHECKOUT_CONFLICT") {
		t.Fatal("missing expected period revision reached payer storage")
	}
}

func TestTenantCheckoutGroupReadRejectsBrowserAndForeignPrincipalBeforeStorage(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	for _, principal := range []string{"", "org/payer", "built-in/admin", "app/foreign"} {
		response := httptest.NewRecorder()
		ctx := context.NewContext()
		ctx.Reset(response, httptest.NewRequest("GET", "/api/get-group-checkout?owner=org&group=tenant&userName=payer&orderName=order", nil))
		ctx.Input.SetData("currentUserId", principal)
		controller := &ApiController{}
		controller.Init(ctx, "ApiController", "GetGroupCheckout", nil)
		controller.GetGroupCheckout()
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "TENANT_CHECKOUT_REQUIRED") {
			t.Fatal("browser group read reached storage")
		}
	}
}
