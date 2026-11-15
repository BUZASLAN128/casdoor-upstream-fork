package object

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type cerberusSecurityLoginPermissionEnforcer struct {
	decisions map[string]bool
	err       error
}

func (e *cerberusSecurityLoginPermissionEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if e.err != nil {
		return false, e.err
	}
	subject, ok := rvals[0].(string)
	if !ok {
		return false, fmt.Errorf("unexpected subject")
	}
	return e.decisions[subject], nil
}

func TestCerberusSecurityPendingSignupUserResolvesPermissionGroups(t *testing.T) {
	permission := &Permission{
		Owner:  "tenant-a",
		Groups: []string{"tenant-a/billing", "tenant-a/unrelated", "tenant-a/*"},
	}
	user := &User{Owner: "tenant-a", Name: "pending", Groups: []string{"tenant-a/billing"}}

	want := []string{
		getPermissionGroupSubject("tenant-a", "tenant-a/billing"),
		getPermissionGroupSubject("tenant-a", "tenant-a/*"),
	}
	if got := permission.getGroupSubjectsForUser(user); !reflect.DeepEqual(got, want) {
		t.Fatalf("group subjects = %#v, want %#v", got, want)
	}
}

func TestCerberusSecurityPendingSignupUserWithoutGroupsMissesWildcard(t *testing.T) {
	permission := &Permission{Owner: "tenant-a", Groups: []string{"*", "tenant-a/*"}}
	if got := permission.getGroupSubjectsForUser(&User{Owner: "tenant-a", Name: "pending"}); len(got) != 0 {
		t.Fatalf("group subjects = %#v, want none", got)
	}
}

func TestCerberusSecurityPendingSignupGroupPermissionKeepsAllowAndDenyEffects(t *testing.T) {
	groupSubject := getPermissionGroupSubject("tenant-a", "tenant-a/billing")

	allow, deny, err := enforceLoginPermissionGroups(
		&cerberusSecurityLoginPermissionEnforcer{decisions: map[string]bool{groupSubject: true}},
		[]string{groupSubject},
		"portal",
		"Allow",
	)
	if err != nil || allow != 1 || deny != 0 {
		t.Fatalf("allow evaluation = (%d, %d, %v), want (1, 0, nil)", allow, deny, err)
	}

	allow, deny, err = enforceLoginPermissionGroups(
		&cerberusSecurityLoginPermissionEnforcer{decisions: map[string]bool{groupSubject: false}},
		[]string{groupSubject},
		"portal",
		"Deny",
	)
	if err != nil || allow != 0 || deny != 1 {
		t.Fatalf("deny evaluation = (%d, %d, %v), want (0, 1, nil)", allow, deny, err)
	}
}

func TestCerberusSecurityPendingSignupUserResolvesGroupGrantedRoles(t *testing.T) {
	user := &User{
		Owner:  "tenant-a",
		Name:   "pending",
		Groups: []string{"tenant-a/billing"},
	}
	role := &Role{
		Owner:  "tenant-a",
		Name:   "billing-member",
		Users:  []string{"tenant-a/other"},
		Groups: []string{"tenant-a/billing", "tenant-a/unrelated"},
	}

	want := []string{"tenant-a/billing"}
	if got := getRoleSourcesForSuppliedUser(role, user.GetId(), user); !reflect.DeepEqual(got, want) {
		t.Fatalf("role sources = %#v, want %#v", got, want)
	}
}

func TestCerberusSecurityPendingSignupRolePermissionKeepsAllowAndDenyEffects(t *testing.T) {
	groupRole := &Role{Owner: "tenant-a", Name: "billing-member"}
	ancestorRole := &Role{
		Owner: "tenant-a",
		Name:  "portal-member",
		Roles: []string{groupRole.GetId()},
	}
	permission := &Permission{
		Owner: "tenant-a",
		Roles: []string{ancestorRole.GetId()},
	}

	roleHit, matchingRoles := getMatchingLoginPermissionRoles(permission, []*Role{groupRole, ancestorRole})
	if !roleHit || len(matchingRoles) != 1 || matchingRoles[0].GetId() != ancestorRole.GetId() {
		t.Fatalf("role match = (%v, %#v), want inherited role %s", roleHit, matchingRoles, ancestorRole.GetId())
	}

	allow, deny, err := enforceLoginPermissionRoles(
		&cerberusSecurityLoginPermissionEnforcer{decisions: map[string]bool{ancestorRole.GetId(): true}},
		matchingRoles,
		"portal",
		"Allow",
	)
	if err != nil || allow != 1 || deny != 0 {
		t.Fatalf("role allow evaluation = (%d, %d, %v), want (1, 0, nil)", allow, deny, err)
	}

	allow, deny, err = enforceLoginPermissionRoles(
		&cerberusSecurityLoginPermissionEnforcer{decisions: map[string]bool{ancestorRole.GetId(): false}},
		matchingRoles,
		"portal",
		"Deny",
	)
	if err != nil || allow != 0 || deny != 1 {
		t.Fatalf("role deny evaluation = (%d, %d, %v), want (0, 1, nil)", allow, deny, err)
	}
}

func TestCerberusSecurityPendingSignupRoleWildcardRequiresAMembership(t *testing.T) {
	permission := &Permission{Owner: "tenant-a", Roles: []string{"*"}}
	if hit, roles := getMatchingLoginPermissionRoles(permission, nil); hit || len(roles) != 0 {
		t.Fatalf("role wildcard matched a role-less pending user: hit=%v roles=%#v", hit, roles)
	}

	memberRole := &Role{Owner: "tenant-a", Name: "member"}
	if hit, roles := getMatchingLoginPermissionRoles(permission, []*Role{memberRole}); !hit || len(roles) != 1 {
		t.Fatalf("role wildcard did not match a pending role member: hit=%v roles=%#v", hit, roles)
	}
}

func TestCerberusSecurityPendingSignupRoleLookupUsesPersistedUsernameCase(t *testing.T) {
	pending := &User{Owner: "tenant-a", Name: "Alice"}
	authorizationUser := normalizeLoginPermissionUser(pending, true)
	if authorizationUser.Name != "alice" || authorizationUser.GetId() != "tenant-a/alice" {
		t.Fatalf("authorization identity = %q/%q, want persisted lower-case identity", authorizationUser.Name, authorizationUser.GetId())
	}
	if pending.Name != "Alice" {
		t.Fatalf("authorization normalization mutated the pending signup object: %q", pending.Name)
	}

	directRole := &Role{Owner: "tenant-a", Name: "direct", Users: []string{"tenant-a/alice"}}
	want := []string{""}
	if got := getRoleSourcesForSuppliedUser(directRole, authorizationUser.GetId(), authorizationUser); !reflect.DeepEqual(got, want) {
		t.Fatalf("lower-case direct role sources = %#v, want %#v", got, want)
	}
	ancestorRole := &Role{Owner: "tenant-a", Name: "ancestor", Roles: []string{directRole.GetId()}}
	roles := []*Role{directRole, ancestorRole}
	sources := map[string][]string{directRole.GetId(): {""}}
	fillSourceGroups(roles, sources)
	if ancestorRole.SourceGroups != nil {
		t.Fatalf("lower-case direct assignment did not propagate to inherited role: %#v", ancestorRole.SourceGroups)
	}
}

func TestCerberusSecurityUsernameNormalizationIsSignupOnly(t *testing.T) {
	source, err := os.ReadFile("check.go")
	if err != nil {
		t.Fatalf("read check.go: %v", err)
	}
	text := string(source)
	normalStart := strings.Index(text, "func CheckLoginPermissionForUser(")
	signupStart := strings.Index(text, "func CheckLoginPermissionForSignupUser(")
	normalizeStart := strings.Index(text, "func normalizeLoginPermissionUser(")
	if normalStart < 0 || signupStart < 0 || normalizeStart < 0 || !(normalStart < signupStart && signupStart < normalizeStart) {
		t.Fatal("login permission entry points not found in expected order")
	}
	normalBody := text[normalStart:signupStart]
	signupBody := text[signupStart:normalizeStart]
	if strings.Contains(normalBody, "normalizeLoginPermissionUser(") {
		t.Fatal("ordinary sign-in rewrites the persisted username before authorization")
	}
	if !strings.Contains(signupBody, "normalizeLoginPermissionUser(") {
		t.Fatal("pending signup does not authorize the username that AddUser will persist")
	}
}
