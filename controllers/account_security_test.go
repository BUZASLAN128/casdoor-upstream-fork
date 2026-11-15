package controllers

import (
	"os"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCerberusSecuritySignupOAuthCodeIsBoundToSignupApplication(t *testing.T) {
	tests := []struct {
		name               string
		signup             *object.Application
		target             *object.Application
		clientId           string
		signupOrganization string
		want               bool
	}{
		{
			name:               "same application and client",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			target:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId:           "signup-client",
			signupOrganization: "tenant-a",
			want:               true,
		},
		{
			name:               "shared application with qualified client in another organization",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-home", IsShared: true},
			target:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a", IsShared: true},
			clientId:           "signup-client-org-tenant-a",
			signupOrganization: "tenant-a",
			want:               true,
		},
		{
			name:               "different application in same organization",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			target:             &object.Application{Owner: "org-a", Name: "restricted-app", ClientId: "restricted-client", Organization: "tenant-a"},
			clientId:           "restricted-client",
			signupOrganization: "tenant-a",
		},
		{
			name:               "same application identity with mismatched client selector",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			target:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId:           "restricted-client",
			signupOrganization: "tenant-a",
		},
		{
			name:               "different application owner",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			target:             &object.Application{Owner: "org-b", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId:           "signup-client",
			signupOrganization: "tenant-a",
		},
		{
			name:               "qualified client does not match posted organization",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-home", IsShared: true},
			target:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-b", IsShared: true},
			clientId:           "signup-client-org-tenant-b",
			signupOrganization: "tenant-a",
		},
		{
			name:               "qualified client cannot re-scope a non-shared application",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-home"},
			target:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-home"},
			clientId:           "signup-client-org-tenant-a",
			signupOrganization: "tenant-a",
		},
		{
			name:               "missing target application",
			signup:             &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId:           "signup-client",
			signupOrganization: "tenant-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSignupOAuthApplication(tt.signup, tt.target, tt.clientId, tt.signupOrganization); got != tt.want {
				t.Fatalf("isSignupOAuthApplication() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCerberusSecuritySignupOAuthGuardsRunBeforeAccountMutation(t *testing.T) {
	source, err := os.ReadFile("account.go")
	if err != nil {
		t.Fatalf("read account.go: %v", err)
	}
	text := string(source)
	guard := strings.Index(text, "if codeApplication != nil && (!c.checkApplicationSignin(codeApplication, user) || !c.checkUserOfApplication(user, codeApplication))")
	mutation := strings.Index(text, "affected, err := object.AddUser(user")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("OAuth signup sign-in and membership guards must run before account creation")
	}
	if !strings.Contains(text, "object.GetOAuthCode(userId, clientId,") {
		t.Fatal("OAuth signup must preserve the requested qualified client ID when issuing the code")
	}
}
