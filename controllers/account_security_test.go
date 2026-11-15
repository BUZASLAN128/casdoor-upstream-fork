package controllers

import (
	"os"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCerberusSecuritySignupOAuthCodeIsBoundToSignupApplication(t *testing.T) {
	signupApplication := &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"}

	tests := []struct {
		name     string
		target   *object.Application
		clientId string
		want     bool
	}{
		{
			name:     "same application and client",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId: "signup-client",
			want:     true,
		},
		{
			name:     "same shared application with qualified client",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a", IsShared: true},
			clientId: "signup-client-org-tenant-a",
			want:     true,
		},
		{
			name:     "different application in same organization",
			target:   &object.Application{Owner: "org-a", Name: "restricted-app", ClientId: "restricted-client", Organization: "tenant-a"},
			clientId: "restricted-client",
		},
		{
			name:     "same application identity with mismatched client selector",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId: "restricted-client",
		},
		{
			name:     "different application owner",
			target:   &object.Application{Owner: "org-b", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-a"},
			clientId: "signup-client",
		},
		{
			name:     "same shared application for a different effective organization",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client", Organization: "tenant-b", IsShared: true},
			clientId: "signup-client-org-tenant-b",
		},
		{
			name:     "missing target application",
			clientId: "signup-client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSignupOAuthApplication(signupApplication, tt.target, tt.clientId); got != tt.want {
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
