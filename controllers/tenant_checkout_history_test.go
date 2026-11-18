package controllers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestTenantCheckoutHistoryRequiresActualConfiguredBasicApp(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	for _, tc := range []struct {
		name, subject, secret                        string
		basic, impersonating, dcr, alias, foreignOrg bool
		want                                         error
	}{
		{name: "browser", subject: "org/payer", want: object.ErrTenantCheckoutRequired},
		{name: "query-only transformed app", subject: "app/cerberus", want: object.ErrTenantCheckoutRequired},
		{name: "mixed session", subject: "org/payer", basic: true, want: object.ErrTenantCheckoutRequired},
		{name: "impersonation", subject: "app/cerberus", basic: true, impersonating: true, want: object.ErrTenantCheckoutRequired},
		{name: "wrong secret", subject: "app/cerberus", basic: true, secret: "wrong", want: object.ErrTenantCheckoutRequired},
		{name: "foreign principal", subject: "app/other", basic: true, want: object.ErrTenantCheckoutRequired},
		{name: "DCR", subject: "app/cerberus", basic: true, dcr: true, want: object.ErrTenantCheckoutRequired},
		{name: "shared alias", subject: "app/cerberus", basic: true, alias: true, want: object.ErrTenantCheckoutRequired},
		{name: "foreign application org", subject: "app/cerberus", basic: true, foreignOrg: true, want: object.ErrTenantCheckoutRequired},
		{name: "valid actorless configured app", subject: "app/cerberus", basic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/api/get-group-checkout?readScope=history&owner=org&group=tenant&clientId=client&clientSecret=synthetic", nil)
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
			controller.Init(ctx, "ApiController", "GetGroupCheckout", nil)
			lookups := 0
			principal, err := controller.groupHistoryPrincipal("org", func(id string) (*object.Application, error) {
				lookups++
				if id != "client" {
					t.Fatal("wrong credential lookup")
				}
				app := &object.Application{Name: "cerberus", Organization: "org", ClientId: "client", ClientSecret: "synthetic"}
				if tc.dcr {
					app.Tags = []string{"dcr"}
				}
				if tc.alias {
					app.ClientId = "persisted-real-id"
				}
				if tc.foreignOrg {
					app.Organization = "foreign"
				}
				return app, nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatal("unexpected Basic history admission result")
			}
			if (!tc.basic || tc.impersonating || tc.subject != "app/cerberus") && lookups != 0 {
				t.Fatal("unauthorized history reached credential storage")
			}
			if tc.want == nil && principal != "app/cerberus" {
				t.Fatal("configured App identity lost")
			}
		})
	}
}

func TestTenantCheckoutHistoryBrowserQueryRejectsBeforeStorage(t *testing.T) {
	t.Setenv("tenantCheckoutApplication", "app/cerberus")
	t.Setenv("tenantCheckoutOrganization", "org")
	t.Setenv("tenantCheckoutPricing", "pricing")
	for _, subject := range []string{"", "org/payer", "app/cerberus", "app/foreign"} {
		response := httptest.NewRecorder()
		ctx := context.NewContext()
		ctx.Reset(response, httptest.NewRequest("GET", "/api/get-group-checkout?readScope=history&owner=org&group=tenant&clientId=client&clientSecret=synthetic&limit=50", nil))
		ctx.Input.SetData("currentUserId", subject)
		controller := &ApiController{}
		controller.Init(ctx, "ApiController", "GetGroupCheckout", nil)
		controller.GetGroupCheckout()
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "TENANT_CHECKOUT_REQUIRED") {
			t.Fatal("history accepted session/query credentials or exposed raw error")
		}
	}
}
