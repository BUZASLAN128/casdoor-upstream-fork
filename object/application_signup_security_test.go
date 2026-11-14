package object

import "testing"

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
