package object

import "testing"

func TestCerberusSecurityImplicitConsentDecisionFiltersDeniedScopes(t *testing.T) {
	application := &Application{
		Owner: "admin",
		Name:  "app",
		CustomScopes: []*ScopeDescription{
			{Scope: "write:billing"},
			{Scope: "read:billing"},
		},
	}
	user := &User{
		ApplicationScopes: []ConsentRecord{
			{
				Application:   application.GetId(),
				GrantedScopes: []string{"read:billing"},
				DeniedScopes:  []string{"write:billing"},
			},
		},
	}

	required, err := CheckConsentRequired(user, application, "openid read:billing write:billing")
	if err != nil {
		t.Fatalf("check consent: %v", err)
	}
	if required {
		t.Fatal("already decided custom scopes unexpectedly required consent again")
	}
	if got := GetConsentedScope(user, application, "openid read:billing write:billing"); got != "openid read:billing" {
		t.Fatalf("consented scope = %q, want denied custom scope removed", got)
	}
}

func TestCerberusSecurityImplicitConsentDecisionRequiresUndecidedScope(t *testing.T) {
	application := &Application{
		Owner:        "admin",
		Name:         "app",
		CustomScopes: []*ScopeDescription{{Scope: "write:billing"}},
	}
	user := &User{}

	required, err := CheckConsentRequired(user, application, "openid write:billing")
	if err != nil {
		t.Fatalf("check consent: %v", err)
	}
	if !required {
		t.Fatal("undecided custom scope bypassed consent")
	}
}

func TestCerberusSecurityImplicitScopeExpansionRequiresConsent(t *testing.T) {
	application := &Application{
		Owner: "admin",
		Name:  "app",
		Scopes: []*ScopeItem{
			{Name: "openid"},
			{Name: "read:billing"},
			{Name: "write:billing"},
		},
		CustomScopes: []*ScopeDescription{
			{Scope: "read:billing"},
			{Scope: "write:billing"},
		},
	}

	resolved, valid, required, err := ResolveImplicitScope(&User{}, application, ".*:billing")
	if err != nil {
		t.Fatalf("resolve implicit scope: %v", err)
	}
	if !valid || !required || resolved != "" {
		t.Fatalf("resolved=%q valid=%v required=%v, want valid consent requirement with no issuable scope", resolved, valid, required)
	}
}

func TestCerberusSecurityImplicitScopeExpansionFiltersDeniedScope(t *testing.T) {
	application := &Application{
		Owner: "admin",
		Name:  "app",
		Scopes: []*ScopeItem{
			{Name: "openid"},
			{Name: "read:billing"},
			{Name: "write:billing"},
		},
		CustomScopes: []*ScopeDescription{
			{Scope: "read:billing"},
			{Scope: "write:billing"},
		},
	}
	user := &User{ApplicationScopes: []ConsentRecord{{
		Application:   application.GetId(),
		GrantedScopes: []string{"read:billing"},
		DeniedScopes:  []string{"write:billing"},
	}}}

	resolved, valid, required, err := ResolveImplicitScope(user, application, ".*:billing")
	if err != nil {
		t.Fatalf("resolve implicit scope: %v", err)
	}
	if !valid || required || resolved != "read:billing" {
		t.Fatalf("resolved=%q valid=%v required=%v, want only granted expanded scope", resolved, valid, required)
	}
}
