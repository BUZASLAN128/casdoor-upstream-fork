package object

import (
	"os"
	"strings"
	"testing"
)

func TestCerberusSecurityOAuthCodeApplicationBoundary(t *testing.T) {
	tests := []struct {
		name        string
		user        *User
		application *Application
		wantDenied  bool
	}{
		{
			name:        "foreign organization is denied",
			user:        &User{Owner: "organization-a", Name: "attacker"},
			application: &Application{Organization: "organization-b", Name: "target-app"},
			wantDenied:  true,
		},
		{
			name:        "same organization remains allowed",
			user:        &User{Owner: "organization-b", Name: "member"},
			application: &Application{Organization: "organization-b", Name: "target-app"},
			wantDenied:  false,
		},
		{
			name:        "shared application remains allowed",
			user:        &User{Owner: "organization-a", Name: "member"},
			application: &Application{Organization: "organization-b", Name: "shared-app", IsShared: true},
			wantDenied:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := checkOAuthCodeUser(tt.user, tt.application, "en")
			if err != nil {
				t.Fatalf("checkOAuthCodeUser() error = %v", err)
			}
			if denied := message != ""; denied != tt.wantDenied {
				t.Fatalf("checkOAuthCodeUser() denied = %v, want %v", denied, tt.wantDenied)
			}
		})
	}
}

func TestCerberusSecurityOAuthCodeChecksUserBeforeIssuance(t *testing.T) {
	source, err := os.ReadFile("token_oauth_util.go")
	if err != nil {
		t.Fatalf("read token_oauth_util.go: %v", err)
	}
	text := string(source)
	guard := strings.Index(text, "msg, err = checkOAuthCodeUser(user, application, lang)")
	issue := strings.Index(text, "code := util.GenerateAuthorizationCode()")
	if guard == -1 || issue == -1 || guard >= issue {
		t.Fatalf("GetOAuthCode must check the user/application boundary before generating a code")
	}
}
