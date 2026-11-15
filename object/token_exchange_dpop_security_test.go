package object

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCerberusSecurityTokenExchangeRejectsSenderConstrainedSubjects(t *testing.T) {
	tests := []struct {
		name   string
		record *Token
	}{
		{
			name:   "complete DPoP binding",
			record: &Token{AccessToken: "bound-subject", TokenType: "DPoP", DPoPJkt: "bound-key"},
		},
		{
			name:   "binding metadata without token type",
			record: &Token{AccessToken: "bound-subject", TokenType: "Bearer", DPoPJkt: "bound-key"},
		},
		{
			name:   "DPoP token type without binding metadata",
			record: &Token{AccessToken: "bound-subject", TokenType: "DPoP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenError := validateTokenExchangeSubjectBinding(tt.record, tt.record.AccessToken)
			if tokenError == nil || tokenError.Error != InvalidGrant {
				t.Fatalf("sender-constrained subject error = %#v, want invalid_grant", tokenError)
			}
		})
	}
}

func TestCerberusSecurityTokenExchangePreservesBearerAndIdTokenFlows(t *testing.T) {
	bearerRecord := &Token{AccessToken: "bearer-subject", TokenType: "Bearer"}
	if tokenError := validateTokenExchangeSubjectBinding(bearerRecord, bearerRecord.AccessToken); tokenError != nil {
		t.Fatalf("bearer subject token was rejected: %#v", tokenError)
	}

	dpopRecord := &Token{AccessToken: "dpop-access", IdToken: "subject-id-token", TokenType: "DPoP", DPoPJkt: "bound-key"}
	if tokenError := validateTokenExchangeSubjectBinding(dpopRecord, dpopRecord.IdToken); tokenError != nil {
		t.Fatalf("ID token exchange was treated as DPoP access-token exchange: %#v", tokenError)
	}
}

func TestCerberusSecurityFederatedTokenExchangeRejectsConfirmationClaims(t *testing.T) {
	if !hasSenderConstrainedConfirmation(jwt.MapClaims{"cnf": map[string]any{"jkt": "bound-key"}}) {
		t.Fatal("sender-constrained federated claims were not detected")
	}
	if !hasSenderConstrainedConfirmation(jwt.MapClaims{"cnf": map[string]any{}}) {
		t.Fatal("malformed empty confirmation claim was accepted as unbound")
	}
	if hasSenderConstrainedConfirmation(jwt.MapClaims{"sub": "unbound-subject"}) {
		t.Fatal("unbound federated claims were treated as sender constrained")
	}
}

func TestCerberusSecurityFederatedTokenExchangeRejectsDeletedUsers(t *testing.T) {
	if tokenError := getInactiveUserTokenError(&User{IsDeleted: true}); tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("deleted federated user error = %#v, want invalid_grant", tokenError)
	}
	if tokenError := getInactiveUserTokenError(&User{}); tokenError != nil {
		t.Fatalf("active federated user was rejected: %#v", tokenError)
	}
}

func TestCerberusSecurityApplicationTokenRecordIsNotBoundToUserRow(t *testing.T) {
	token := &Token{
		Application:  "workload-app",
		Organization: "tenant-a",
		User:         "",
		GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
	}
	active, err := token.IsUserActive()
	if err != nil {
		t.Fatalf("application token activity check: %v", err)
	}
	if !active {
		t.Fatal("application token was treated as an absent end-user token")
	}
}
