package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCerberusSecuritySignupOAuthCodeIsBoundToSignupApplication(t *testing.T) {
	signupApplication := &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client"}

	tests := []struct {
		name     string
		target   *object.Application
		clientId string
		want     bool
	}{
		{
			name:     "same application and client",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client"},
			clientId: "signup-client",
			want:     true,
		},
		{
			name:     "different application in same organization",
			target:   &object.Application{Owner: "org-a", Name: "restricted-app", ClientId: "restricted-client"},
			clientId: "restricted-client",
		},
		{
			name:     "same application identity with mismatched client selector",
			target:   &object.Application{Owner: "org-a", Name: "signup-app", ClientId: "signup-client"},
			clientId: "restricted-client",
		},
		{
			name:     "different organization",
			target:   &object.Application{Owner: "org-b", Name: "signup-app", ClientId: "signup-client"},
			clientId: "signup-client",
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
