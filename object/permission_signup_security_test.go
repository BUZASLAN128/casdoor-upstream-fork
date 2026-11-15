package object

import (
	"fmt"
	"reflect"
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
