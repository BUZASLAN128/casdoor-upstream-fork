package object

import "testing"

func TestCerberusSecuritySoftDeletedMergeSourceLosesLoginIdentifiers(t *testing.T) {
	user := &User{
		Email:         "merged@example.com",
		EmailVerified: true,
		Phone:         "5551234567",
		CountryCode:   "TR",
		GitHub:        "github-subject",
		Oidc:          "oidc-subject",
		Custom10:      "custom-subject",
		Ldap:          "ldap-subject",
		Properties: map[string]string{
			"oauth_GitHub_accessToken": "provider-token",
			"OAUTH_oidc_refreshToken":  "provider-refresh-token",
			UserPropertiesMergedUsers:  "older-account",
		},
	}

	columns := clearMergedUserLoginIdentifiers(user)
	columnSet := map[string]bool{}
	for _, column := range columns {
		columnSet[column] = true
	}

	if user.Email != "" || user.EmailVerified || user.Phone != "" || user.CountryCode != "" {
		t.Fatalf("contact login selectors remained: email=%q verified=%v phone=%q country=%q", user.Email, user.EmailVerified, user.Phone, user.CountryCode)
	}
	for _, field := range userProviderFields {
		if value := getUserStringField(user, field); value != "" {
			t.Fatalf("provider login selector %s remained %q", field, value)
		}
		if !columnSet[ormerColumnName(field)] {
			t.Fatalf("provider column %s was not selected for persistence", ormerColumnName(field))
		}
	}
	if _, ok := user.Properties["oauth_GitHub_accessToken"]; ok {
		t.Fatal("provider access-token property remained on merge source")
	}
	if _, ok := user.Properties["OAUTH_oidc_refreshToken"]; ok {
		t.Fatal("case-insensitive provider refresh-token property remained on merge source")
	}
	if user.Properties[UserPropertiesMergedUsers] != "older-account" {
		t.Fatal("unrelated merge metadata was removed")
	}
	for _, required := range []string{"email", "email_verified", "phone", "country_code", "properties"} {
		if !columnSet[required] {
			t.Fatalf("required persistence column %q is missing", required)
		}
	}
}
