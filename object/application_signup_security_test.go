package object

import "testing"

func TestCerberusSecurityFederatedSignupRequiresApplicationPermission(t *testing.T) {
	applications := []Application{
		{Name: "signup-disabled", Organization: "tenant-a"},
		{Name: "built-in", Organization: "built-in", EnableSignUp: true},
		{Name: "invitation-required", Organization: "tenant-a", EnableSignUp: true, SignupItems: []*SignupItem{{Name: "Invitation code", Required: true}}},
	}
	for _, application := range applications {
		t.Run(application.Name, func(t *testing.T) {
			user, tokenError, err := addFederatedUser(&application, "test-user", nil, "127.0.0.1", "en")
			if user != nil || tokenError == nil || tokenError.Error != InvalidGrant || err != nil {
				t.Fatalf("federated signup returned user=%v, token error=%v, error=%v, want invalid_grant", user != nil, tokenError, err)
			}
		})
	}
}

func TestApplicationIsSignupAllowedForBindsOrganization(t *testing.T) {
	tests := []struct {
		name         string
		application  *Application
		organization string
		want         bool
	}{
		{
			name:         "same organization",
			application:  &Application{Organization: "org-a"},
			organization: "org-a",
			want:         true,
		},
		{
			name:         "foreign organization",
			application:  &Application{Organization: "org-a"},
			organization: "org-b",
			want:         false,
		},
		{
			name:         "non-shared built-in organization",
			application:  &Application{Organization: "org-a"},
			organization: "built-in",
			want:         false,
		},
		{
			name:         "shared foreign organization",
			application:  &Application{Organization: "org-a", IsShared: true},
			organization: "org-b",
			want:         true,
		},
		{
			name:         "shared built-in organization",
			application:  &Application{Organization: "org-a", IsShared: true},
			organization: "built-in",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.application.IsSignupAllowedFor(tt.organization); got != tt.want {
				t.Fatalf("IsSignupAllowedFor(%q) = %v, want %v", tt.organization, got, tt.want)
			}
		})
	}
}
