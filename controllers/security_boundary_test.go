package controllers

import (
	"os"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCerberusSecurityAdminOrSelfBoundary(t *testing.T) {
	ordinary := &object.User{Owner: "organization-a", Name: "member"}
	orgAdmin := &object.User{Owner: "organization-a", Name: "admin", IsAdmin: true}
	sameOrgTarget := &object.User{Owner: "organization-a", Name: "target"}
	foreignTarget := &object.User{Owner: "organization-b", Name: "victim"}

	if !isAdminOrSelf(ordinary, ordinary) {
		t.Fatal("a user must remain allowed to update their own account")
	}
	if isAdminOrSelf(ordinary, sameOrgTarget) {
		t.Fatal("an ordinary user must not update another user")
	}
	if !isAdminOrSelf(orgAdmin, sameOrgTarget) {
		t.Fatal("an organization admin must remain allowed to update a same-organization user")
	}
	if isAdminOrSelf(orgAdmin, foreignTarget) {
		t.Fatal("an organization admin must not update a foreign-organization user")
	}
	if isAdminOrSelf(ordinary, foreignTarget) {
		t.Fatal("an ordinary user must not update a foreign-organization user")
	}
}

func TestCerberusSecurityUpdateUserAuthorizesResolvedSelector(t *testing.T) {
	source, err := os.ReadFile("user.go")
	if err != nil {
		t.Fatalf("read user.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (c *ApiController) UpdateUser()")
	if start == -1 {
		t.Fatal("UpdateUser function not found")
	}
	text = text[start:]
	lookup := strings.Index(text, "object.GetUserByUserId(owner, userId)")
	guard := strings.Index(text, "!c.IsAdminOrSelf(userFromUserId)")
	bind := strings.Index(text, "id = util.GetId(userFromUserId.Owner, userFromUserId.Name)")
	if lookup == -1 || guard == -1 || bind == -1 || !(lookup < guard && guard < bind) {
		t.Fatal("UpdateUser must authorize the resolved owner/userId target before binding the update id")
	}
}

func TestCerberusSecurityGrantConsentGuardsBeforeMutation(t *testing.T) {
	source, err := os.ReadFile("consent.go")
	if err != nil {
		t.Fatalf("read consent.go: %v", err)
	}
	text := string(source)
	signinGuard := strings.Index(text, "c.checkApplicationSignin(application, userObj)")
	membershipGuard := strings.Index(text, "c.checkUserOfApplication(userObj, application)")
	mutation := strings.Index(text, "object.UpdateConsentRecord(userObj, application")
	issue := strings.Index(text, "code, err := object.GetOAuthCode(")
	if signinGuard == -1 || membershipGuard == -1 || mutation == -1 || issue == -1 ||
		!(signinGuard < mutation && membershipGuard < mutation && mutation < issue) {
		t.Fatal("GrantConsent must finish sign-in and application membership checks before consent mutation and code issuance")
	}
}

func TestCerberusSecurityMergeCannotSwitchIntoMfaProtectedAccount(t *testing.T) {
	current := &object.User{Owner: "organization-a", Name: "current"}
	protectedOther := &object.User{Owner: "organization-a", Name: "protected", PreferredMfaType: "totp"}
	unprotectedOther := &object.User{Owner: "organization-a", Name: "unprotected"}

	if canMergeAccounts(current, current, protectedOther) {
		t.Fatal("merge switched into another MFA-protected account without its second factor")
	}
	if canMergeAccounts(current, protectedOther, current) {
		t.Fatal("merge absorbed another MFA-protected account without its second factor")
	}
	if !canMergeAccounts(current, current, unprotectedOther) || !canMergeAccounts(current, unprotectedOther, current) {
		t.Fatal("merge unexpectedly rejected an unprotected target account")
	}
	current.PreferredMfaType = "totp"
	if !canMergeAccounts(current, current, unprotectedOther) {
		t.Fatal("merge rejected the MFA-authenticated current account as its own target")
	}
	if canMergeAccounts(nil, current, unprotectedOther) || canMergeAccounts(current, nil, unprotectedOther) || canMergeAccounts(current, current, nil) {
		t.Fatal("merge target guard did not fail closed for a missing identity")
	}
}

func TestCerberusSecurityMergePrecheckDoesNotExposeMfaEnrollment(t *testing.T) {
	source, err := os.ReadFile("user_merge.go")
	if err != nil {
		t.Fatalf("read user_merge.go: %v", err)
	}
	text := string(source)
	checkStart := strings.Index(text, "func (c *ApiController) CheckUserMerge()")
	mergeStart := strings.Index(text, "func (c *ApiController) MergeUser()")
	if checkStart < 0 || mergeStart < 0 || checkStart >= mergeStart {
		t.Fatal("merge endpoints not found in expected order")
	}
	if strings.Contains(text[checkStart:mergeStart], "canMergeAccounts(") {
		t.Fatal("unverified merge precheck exposes MFA-dependent eligibility")
	}
	if !strings.Contains(text[mergeStart:], "canMergeAccounts(") {
		t.Fatal("verified merge mutation does not enforce the MFA boundary")
	}
}
