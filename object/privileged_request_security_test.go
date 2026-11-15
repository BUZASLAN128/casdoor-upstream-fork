package object

import (
	"os"
	"strings"
	"testing"
)

func TestCerberusSecurityPamRoleMembershipMutationDoesNotUseStaleLists(t *testing.T) {
	users := []string{"tenant-a/existing"}
	users, changed := getPamRoleUsersAfterMutation(users, "tenant-a/new", true)
	if !changed || len(users) != 2 || users[1] != "tenant-a/new" {
		t.Fatalf("role add = (%#v, %v), want appended member", users, changed)
	}
	users, changed = getPamRoleUsersAfterMutation(users, "tenant-a/new", true)
	if changed || len(users) != 2 {
		t.Fatalf("duplicate role add = (%#v, %v), want unchanged", users, changed)
	}
	users, changed = getPamRoleUsersAfterMutation(users, "tenant-a/existing", false)
	if !changed || len(users) != 1 || users[0] != "tenant-a/new" {
		t.Fatalf("role removal = (%#v, %v), want only new member", users, changed)
	}
}

func TestCerberusSecurityPamRoleMembershipUsesDatabaseRowLock(t *testing.T) {
	source, err := os.ReadFile("privileged_request.go")
	if err != nil {
		t.Fatalf("read privileged_request.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func updatePamRoleMembershipInSession(")
	if start < 0 {
		t.Fatal("PAM role membership helper not found")
	}
	end := strings.Index(text[start:], "func addPamRoleRecord(")
	if end < 0 {
		t.Fatal("PAM role membership helper end not found")
	}
	helper := text[start : start+end]
	if !strings.Contains(helper, "session.ForUpdate().Get(role)") {
		t.Fatal("PAM role membership mutation must lock the role row")
	}

	for _, functionName := range []string{"insertActivePamRoleRequest", "activatePendingPamRoleRequest", "endActivePamRoleRequest"} {
		functionStart := strings.Index(text, "func "+functionName+"(")
		if functionStart < 0 {
			t.Fatalf("%s not found", functionName)
		}
		nextFunction := strings.Index(text[functionStart+5:], "\nfunc ")
		functionEnd := len(text)
		if nextFunction >= 0 {
			functionEnd = functionStart + 5 + nextFunction
		}
		body := text[functionStart:functionEnd]
		if !strings.Contains(body, "updatePamRoleMembershipInSession(") || !strings.Contains(body, "session.Commit()") {
			t.Fatalf("%s must commit request state and role membership in one transaction", functionName)
		}
		if functionName != "endActivePamRoleRequest" && !strings.Contains(body, "lockEnabledPamRoleAccount(") {
			t.Fatalf("%s must lock and revalidate the enabled privileged account before adding membership", functionName)
		}
	}
}

func TestCerberusSecurityDisabledPrivilegedAccountCannotBeApproved(t *testing.T) {
	disabled := &PrivilegedAccount{Name: "disabled"}
	if err := checkPrivilegedAccountEnabledForDecision(disabled, true, "en"); err == nil {
		t.Fatal("disabled privileged account approval was allowed")
	}
	if err := checkPrivilegedAccountEnabledForDecision(disabled, false, "en"); err != nil {
		t.Fatalf("disabled privileged account rejection was blocked: %v", err)
	}
	enabled := &PrivilegedAccount{Name: "enabled", IsEnabled: true}
	if err := checkPrivilegedAccountEnabledForDecision(enabled, true, "en"); err != nil {
		t.Fatalf("enabled privileged account approval was blocked: %v", err)
	}
}
