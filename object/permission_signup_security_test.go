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
