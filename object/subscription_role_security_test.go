package object

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func subscriptionFunctionSource(t *testing.T, source string, functionName string) string {
	t.Helper()
	start := strings.Index(source, "func "+functionName+"(")
	if start < 0 {
		t.Fatalf("%s not found", functionName)
	}
	next := strings.Index(source[start+5:], "\nfunc ")
	if next < 0 {
		return source[start:]
	}
	return source[start : start+5+next]
}

func TestCerberusSecuritySubscriptionRoleMembershipMutation(t *testing.T) {
	members := []string{"tenant-a/existing"}
	members, changed := getSubscriptionRoleMembersAfterMutation(members, "tenant-a/new", true)
	if !changed || len(members) != 2 || members[1] != "tenant-a/new" {
		t.Fatalf("role add = (%#v, %v), want appended member", members, changed)
	}
	members, changed = getSubscriptionRoleMembersAfterMutation(members, "tenant-a/new", true)
	if changed || len(members) != 2 {
		t.Fatalf("duplicate role add = (%#v, %v), want unchanged", members, changed)
	}
	members, changed = getSubscriptionRoleMembersAfterMutation(members, "tenant-a/existing", false)
	if !changed || len(members) != 1 || members[0] != "tenant-a/new" {
		t.Fatalf("role removal = (%#v, %v), want only new member", members, changed)
	}
}

func TestCerberusSecuritySubscriptionTransactionRetryIsBounded(t *testing.T) {
	attempts := 0
	err := retrySubscriptionTransaction(func() error {
		attempts++
		if attempts < 3 {
			return &pq.Error{Code: pq.ErrorCode("40001")}
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("retryable transaction = (%d attempts, %v), want 3 attempts and success", attempts, err)
	}

	attempts = 0
	err = retrySubscriptionTransaction(func() error {
		attempts++
		return fmt.Errorf("permanent")
	})
	if err == nil || attempts != 1 {
		t.Fatalf("permanent failure = (%d attempts, %v), want one attempt and failure", attempts, err)
	}
}

func TestCerberusSecuritySubscriptionStateUsesCurrentTimes(t *testing.T) {
	now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	sub := &Subscription{
		State:     SubStateActive,
		StartTime: now.Add(-time.Hour).Format(time.RFC3339),
		EndTime:   now.Add(time.Hour).Format(time.RFC3339),
	}
	if err := calculateSubscriptionStateInSession(nil, sub, now); err != nil {
		t.Fatalf("calculate extended subscription state: %v", err)
	}
	if sub.State != SubStateActive {
		t.Fatalf("extended subscription state = %s, want Active", sub.State)
	}
	sub.EndTime = now.Add(-time.Second).Format(time.RFC3339)
	if err := calculateSubscriptionStateInSession(nil, sub, now); err != nil {
		t.Fatalf("calculate expired subscription state: %v", err)
	}
	if sub.State != SubStateExpired {
		t.Fatalf("expired subscription state = %s, want Expired", sub.State)
	}
}

func TestCerberusSecuritySubscriptionRoleGrantChecksSodAndLocksRole(t *testing.T) {
	sourceBytes, err := os.ReadFile("subscription_role.go")
	if err != nil {
		t.Fatalf("read subscription_role.go: %v", err)
	}
	body := subscriptionFunctionSource(t, string(sourceBytes), "syncSubscriptionRoleMemberInSession")
	lock := strings.Index(body, "session.ForUpdate().Get(role)")
	sod := strings.Index(body, "CheckRoleSodInSession(session, role")
	write := strings.Index(body, ".Update(role)")
	if lock < 0 {
		t.Fatal("subscription role membership mutation must lock the role row")
	}
	if sod < 0 || write < 0 || sod > write {
		t.Fatal("subscription role grants must pass separation-of-duties validation before the role write")
	}
}

func TestCerberusSecuritySubscriptionPlanLookupUsesExactIdentity(t *testing.T) {
	sourceBytes, err := os.ReadFile("subscription_role.go")
	if err != nil {
		t.Fatalf("read subscription_role.go: %v", err)
	}
	body := subscriptionFunctionSource(t, string(sourceBytes), "getPlanRoleIdInSession")
	if !strings.Contains(body, `owner == "" || planName == ""`) {
		t.Fatal("subscription role lookup must reject an empty plan identity")
	}
	if !strings.Contains(body, "session.ID(core.PK{owner, planName}).Get(plan)") {
		t.Fatal("subscription role lookup must query the exact composite plan key")
	}
}

func TestCerberusSecuritySubscriptionMutationsCommitRoleAndStateTogether(t *testing.T) {
	sourceBytes, err := os.ReadFile("subscription.go")
	if err != nil {
		t.Fatalf("read subscription.go: %v", err)
	}
	source := string(sourceBytes)
	for _, functionName := range []string{
		"updateSubscriptionStateAndRole",
		"UpdateSubscription",
		"AddSubscription",
		"DeleteSubscription",
	} {
		body := subscriptionFunctionSource(t, source, functionName)
		syncPos := strings.Index(body, "syncSubscriptionRoleInSession(")
		commitPos := strings.Index(body, "session.Commit()")
		if syncPos < 0 || commitPos < 0 || syncPos > commitPos {
			t.Fatalf("%s must write subscription state and role membership in one transaction", functionName)
		}
		if !strings.Contains(body, "session.Rollback()") {
			t.Fatalf("%s must roll back both writes when role synchronization fails", functionName)
		}
	}

	stateBody := subscriptionFunctionSource(t, source, "updateSubscriptionStateAndRole")
	lockPos := strings.Index(stateBody, "session.ForUpdate().Get(stored)")
	recomputePos := strings.Index(stateBody, "calculateSubscriptionStateInSession(session, &candidate")
	if lockPos < 0 {
		t.Fatal("subscription state transition must lock and revalidate the current row")
	}
	if recomputePos < 0 || recomputePos < lockPos {
		t.Fatal("subscription state transition must be recomputed from the locked current row")
	}
}

func TestCerberusSecuritySubscriptionSodDecisionsAreSerialized(t *testing.T) {
	governanceSourceBytes, err := os.ReadFile("governance.go")
	if err != nil {
		t.Fatalf("read governance.go: %v", err)
	}
	lockBody := subscriptionFunctionSource(t, string(governanceSourceBytes), "lockGovernanceScope")
	if !strings.Contains(lockBody, `Organization{Owner: "admin", Name: owner}`) || !strings.Contains(lockBody, "session.ForUpdate().Get(organization)") {
		t.Fatal("subscription role decisions must serialize on the organization row")
	}

	subscriptionSourceBytes, err := os.ReadFile("subscription.go")
	if err != nil {
		t.Fatalf("read subscription.go: %v", err)
	}
	subscriptionSource := string(subscriptionSourceBytes)
	for _, functionName := range []string{"updateSubscriptionStateAndRole", "UpdateSubscription", "AddSubscription", "DeleteSubscription"} {
		body := subscriptionFunctionSource(t, subscriptionSource, functionName)
		lockPos := strings.Index(body, "lockGovernanceScope")
		syncPos := strings.Index(body, "syncSubscriptionRoleInSession(")
		if lockPos < 0 || syncPos < 0 || lockPos > syncPos {
			t.Fatalf("%s must acquire the organization governance lock before role synchronization", functionName)
		}
	}
}

func TestCerberusSecurityPlanRoleIdentityCannotDisappearWithSubscriptions(t *testing.T) {
	planSourceBytes, err := os.ReadFile("plan.go")
	if err != nil {
		t.Fatalf("read plan.go: %v", err)
	}
	planSource := string(planSourceBytes)
	for _, functionName := range []string{"UpdatePlan", "DeletePlan"} {
		body := subscriptionFunctionSource(t, planSource, functionName)
		countPos := strings.Index(body, `.Count(&Subscription{})`)
		writePos := strings.Index(body, "session.ID(")
		if countPos < 0 || writePos < 0 || countPos > writePos {
			t.Fatalf("%s must reject a plan identity change while subscriptions depend on it", functionName)
		}
		if !strings.Contains(body, "lockGovernanceScope") {
			t.Fatalf("%s must serialize with subscription role mutations", functionName)
		}
	}
}

func TestCerberusSecuritySodWritersShareGovernanceSerialization(t *testing.T) {
	tests := []struct {
		file          string
		function      string
		requiredCheck string
	}{
		{"role.go", "UpdateRole", "CheckRoleSodChangeInSession("},
		{"role.go", "AddRole", "CheckRoleSodInSession("},
		{"role.go", "AddRoles", "CheckRoleSodInSession("},
		{"user.go", "updateUserGroupsWithGovernance", "CheckUserSodInSession("},
		{"user.go", "updateUserAllFieldsGroupsWithGovernance", "CheckUserSodInSession("},
		{"user.go", "AddUser", "CheckUserSodInSession("},
		{"user.go", "AddUsers", "CheckUserSodInSession("},
		{"privileged_request.go", "insertActivePamRoleRequest", "lockGovernanceScope"},
		{"privileged_request.go", "activatePendingPamRoleRequest", "lockGovernanceScope"},
		{"privileged_request.go", "endActivePamRoleRequest", "lockGovernanceScope"},
	}
	for _, tt := range tests {
		sourceBytes, err := os.ReadFile(tt.file)
		if err != nil {
			t.Fatalf("read %s: %v", tt.file, err)
		}
		body := subscriptionFunctionSource(t, string(sourceBytes), tt.function)
		if !strings.Contains(body, "lockGovernanceScope") {
			t.Fatalf("%s must serialize governance changes on the organization row", tt.function)
		}
		if !strings.Contains(body, tt.requiredCheck) {
			t.Fatalf("%s must use the transaction-aware governance check %s", tt.function, tt.requiredCheck)
		}
	}
	groupSourceBytes, err := os.ReadFile("group.go")
	if err != nil {
		t.Fatalf("read group.go: %v", err)
	}
	groupSource := string(groupSourceBytes)
	groupUpdate := subscriptionFunctionSource(t, groupSource, "updateGroupWithGovernance")
	groupReferences := subscriptionFunctionSource(t, groupSource, "groupChangeInSession")
	if !strings.Contains(groupUpdate, "lockGovernanceScope") || !strings.Contains(groupReferences, "CheckUserSodInSession(") {
		t.Fatal("group rename must serialize and validate its membership-reference transaction")
	}

	pamSourceBytes, err := os.ReadFile("privileged_request.go")
	if err != nil {
		t.Fatalf("read privileged_request.go: %v", err)
	}
	pamMutation := subscriptionFunctionSource(t, string(pamSourceBytes), "updatePamRoleMembershipInSession")
	if !strings.Contains(pamMutation, "CheckRoleSodInSession(") {
		t.Fatal("PAM role grants must use the transaction-aware SoD check")
	}
}

func TestCerberusSecurityTransactionalSodReadsPolicyFailClosed(t *testing.T) {
	sourceBytes, err := os.ReadFile("governance.go")
	if err != nil {
		t.Fatalf("read governance.go: %v", err)
	}
	source := string(sourceBytes)
	for _, functionName := range []string{"CheckRoleSodChangeInSession", "CheckUserSodInSession"} {
		body := subscriptionFunctionSource(t, source, functionName)
		if !strings.Contains(body, "getSodPolicyInSession(") {
			t.Fatalf("%s must read the policy through the mutation transaction", functionName)
		}
		if strings.Contains(body, "GetCachedEnterprisePolicy(") {
			t.Fatalf("%s must not treat a cached policy read failure as no policy", functionName)
		}
	}
}

func TestCerberusSecurityPlanAndProductMutateAtomically(t *testing.T) {
	planSourceBytes, err := os.ReadFile("plan.go")
	if err != nil {
		t.Fatalf("read plan.go: %v", err)
	}
	planSource := string(planSourceBytes)
	updateBody := subscriptionFunctionSource(t, planSource, "UpdatePlan")
	updateGuard := strings.Index(updateBody, `.Count(&Subscription{})`)
	updateProduct := strings.Index(updateBody, "UpdateProductForPlan(")
	if updateGuard < 0 || updateProduct < 0 || updateGuard > updateProduct {
		t.Fatal("plan subscription guard must run before its product is updated")
	}
	if !strings.Contains(updateBody, "oldPlan.GetRoleId() != updated.GetRoleId()") {
		t.Fatal("plan role guard must compare normalized effective role IDs")
	}
	deleteBody := subscriptionFunctionSource(t, planSource, "DeletePlan")
	deleteGuard := strings.Index(deleteBody, `.Count(&Subscription{})`)
	deleteProduct := strings.Index(deleteBody, `Delete(&Product{})`)
	if deleteGuard < 0 || deleteProduct < 0 || deleteGuard > deleteProduct {
		t.Fatal("plan subscription guard must run before its product is deleted")
	}
	addBody := subscriptionFunctionSource(t, planSource, "AddPlan")
	productInsert := strings.Index(addBody, "session.Insert(product)")
	planInsert := strings.Index(addBody, "session.Insert(&created)")
	commit := strings.Index(addBody, "session.Commit()")
	if productInsert < 0 || planInsert < 0 || commit < 0 || productInsert > planInsert || planInsert > commit {
		t.Fatal("plan creation must commit its managed product and plan together")
	}
	if !strings.Contains(addBody, "validatePlanRoleInSession(") {
		t.Fatal("plan creation must validate its role under the governance lock")
	}

	controllerBytes, err := os.ReadFile("../controllers/plan.go")
	if err != nil {
		t.Fatalf("read controllers/plan.go: %v", err)
	}
	controllerSource := string(controllerBytes)
	for _, forbidden := range []string{"object.UpdateProduct(", "object.DeleteProduct("} {
		if strings.Contains(controllerSource, forbidden) {
			t.Fatalf("plan controller must not mutate product outside the plan transaction: %s", forbidden)
		}
	}
}

func TestCerberusSecurityUserGroupPersistenceIsTransactional(t *testing.T) {
	userSourceBytes, err := os.ReadFile("user.go")
	if err != nil {
		t.Fatalf("read user.go: %v", err)
	}
	userSource := string(userSourceBytes)
	allFields := subscriptionFunctionSource(t, userSource, "UpdateUserForAllFields")
	if !strings.Contains(allFields, "updateUserAllFieldsGroupsWithGovernance(") {
		t.Fatal("all-fields updates must revalidate groups under the governance lock")
	}
	for _, functionName := range []string{"updateUserGroupsWithGovernance", "updateUserAllFieldsGroupsWithGovernance", "AddUsers"} {
		body := subscriptionFunctionSource(t, userSource, functionName)
		persistPos := strings.Index(body, "replaceGroupsForUserInSession(")
		commitPos := strings.Index(body, "session.Commit()")
		publishPos := strings.Index(body, "publishCommittedGroups()")
		if persistPos < 0 || commitPos < 0 || publishPos < 0 || persistPos > commitPos || commitPos > publishPos {
			t.Fatalf("%s must persist bindings in the user transaction and publish only after commit", functionName)
		}
		if strings.Contains(body, "UpdateGroupsForUser(") {
			t.Fatalf("%s must not persist bindings through an independent adapter transaction", functionName)
		}
	}
	addUserBody := subscriptionFunctionSource(t, userSource, "AddUser")
	stagePos := strings.Index(addUserBody, "stageNewUserGroups(")
	commitPos := strings.Index(addUserBody, "session.Commit()")
	publishPos := strings.Index(addUserBody, "publishCommittedGroups()")
	if stagePos < 0 || commitPos < 0 || publishPos < 0 || stagePos > commitPos || commitPos > publishPos {
		t.Fatal("AddUser must stage bindings in its transaction and publish only after commit")
	}
	if strings.Contains(addUserBody, "UpdateGroupsForUser(") {
		t.Fatal("AddUser must not persist bindings through an independent adapter transaction")
	}
	userEnforcerBytes, err := os.ReadFile("user_enforcer.go")
	if err != nil {
		t.Fatalf("read user_enforcer.go: %v", err)
	}
	stageBody := subscriptionFunctionSource(t, string(userEnforcerBytes), "stageNewUserGroups")
	if !strings.Contains(stageBody, "replaceGroupsForUserInSession(") ||
		!strings.Contains(stageBody, `user.Owner == "built-in" && user.Name == "admin" && len(user.Groups) == 0`) ||
		!strings.Contains(stageBody, "the user-group enforcer is not initialized") {
		t.Fatal("new-user group staging must fail closed except for the empty first-start built-in/admin bootstrap")
	}
}

func TestCerberusSecurityGroupRenameIsAtomicAndRejectsOccupiedTarget(t *testing.T) {
	groupSourceBytes, err := os.ReadFile("group.go")
	if err != nil {
		t.Fatalf("read group.go: %v", err)
	}
	body := subscriptionFunctionSource(t, string(groupSourceBytes), "updateGroupWithGovernance")
	targetPos := strings.Index(body, "targetExists")
	referencesPos := strings.Index(body, "groupChangeInSession(")
	rowPos := strings.Index(body, ".AllCols().Update(&updated)")
	commitPos := strings.Index(body, "session.Commit()")
	if targetPos < 0 || referencesPos < 0 || rowPos < 0 || commitPos < 0 || targetPos > referencesPos || referencesPos > rowPos || rowPos > commitPos {
		t.Fatal("group rename must reject an occupied target and commit identity plus references together")
	}
	permissionGuard := strings.Index(body, "hasPermissionUsingGroupInSession(")
	if permissionGuard < 0 || permissionGuard > referencesPos {
		t.Fatal("group rename must reject permission dependencies before moving its identity")
	}
	referencesBody := subscriptionFunctionSource(t, string(groupSourceBytes), "groupChangeInSession")
	roleWritePos := strings.Index(referencesBody, `.Cols("groups").Update(role)`)
	finalSodPos := strings.LastIndex(referencesBody, "CheckUserSodInSession(")
	if roleWritePos < 0 || finalSodPos < roleWritePos {
		t.Fatal("group rename must validate SoD against the complete post-reference snapshot")
	}
}

func TestCerberusSecurityRoleRenameMovesIdentityAndReferencesAtomically(t *testing.T) {
	roleSourceBytes, err := os.ReadFile("role.go")
	if err != nil {
		t.Fatalf("read role.go: %v", err)
	}
	body := subscriptionFunctionSource(t, string(roleSourceBytes), "UpdateRole")
	targetPos := strings.Index(body, "targetExists")
	referencesPos := strings.Index(body, "roleChangeReferencesInSession(")
	rowPos := strings.Index(body, ".AllCols().Update(&updated)")
	commitPos := strings.Index(body, "session.Commit()")
	if targetPos < 0 || referencesPos < 0 || rowPos < 0 || commitPos < 0 || targetPos > referencesPos || referencesPos > rowPos || rowPos > commitPos {
		t.Fatal("role rename must reject an occupied target and commit identity plus references together")
	}
	if strings.Contains(body, "roleChangeTrigger(") {
		t.Fatal("role rename must not commit dependent references through a nested transaction")
	}
	permissionGuard := strings.Index(body, "hasPermissionUsingRoleInSession(")
	if permissionGuard < 0 || permissionGuard > referencesPos {
		t.Fatal("role rename must reject permission dependencies before moving its identity")
	}
	if strings.Contains(body, "removePolicies(") || strings.Contains(body, "addPolicies(") {
		t.Fatal("role rename must not publish permission policies after its database commit")
	}
}

func TestCerberusSecurityRoleAndGroupDeletionPreservePermissionIdentity(t *testing.T) {
	tests := []struct {
		file       string
		function   string
		dependency string
	}{
		{"role.go", "DeleteRole", "hasPermissionUsingRoleInSession("},
		{"group.go", "DeleteGroup", "hasPermissionUsingGroupInSession("},
	}
	for _, tt := range tests {
		sourceBytes, err := os.ReadFile(tt.file)
		if err != nil {
			t.Fatalf("read %s: %v", tt.file, err)
		}
		body := subscriptionFunctionSource(t, string(sourceBytes), tt.function)
		if !strings.Contains(body, tt.dependency) {
			t.Fatalf("%s must reject deletion while a permission depends on the identity", tt.function)
		}
		if strings.Contains(body, "UpdatePermission(") {
			t.Fatalf("%s must not mutate permission state outside its transaction", tt.function)
		}
	}
	roleSource, err := os.ReadFile("role.go")
	if err != nil {
		t.Fatalf("read role.go: %v", err)
	}
	deleteRole := subscriptionFunctionSource(t, string(roleSource), "DeleteRole")
	if !strings.Contains(deleteRole, "hasRoleUsingRoleInSession(") {
		t.Fatal("DeleteRole must reject deletion while another role inherits it")
	}
}

func TestCerberusSecurityUserRenamePreservesPermissionIdentity(t *testing.T) {
	sourceBytes, err := os.ReadFile("user.go")
	if err != nil {
		t.Fatalf("read user.go: %v", err)
	}
	body := subscriptionFunctionSource(t, string(sourceBytes), "moveUserIdentityReferencesInSession")
	guard := strings.Index(body, "getUserIdentityDependencyInSession(")
	roleWrites := strings.Index(body, `.Update(role)`)
	if guard < 0 || roleWrites < 0 || guard > roleWrites {
		t.Fatal("user rename must reject permission dependencies before moving identity references")
	}
	if strings.Contains(body, "Update(permission)") {
		t.Fatal("user rename must not leave persisted permission policies under the old identity")
	}
}

func TestCerberusSecurityPermissionWritersSerializeIdentityAndPolicy(t *testing.T) {
	sourceBytes, err := os.ReadFile("permission.go")
	if err != nil {
		t.Fatalf("read permission.go: %v", err)
	}
	source := string(sourceBytes)
	tests := []struct {
		function string
		policy   string
	}{
		{"UpdatePermission", "replacePermissionPoliciesInSession("},
		{"UpdatePermissions", "replacePermissionPoliciesInSession("},
		{"AddPermission", "addPermissionPoliciesInSession("},
		{"AddPermissions", "addPermissionPoliciesInSession("},
		{"deletePermissionRecord", "removePermissionPoliciesInSession("},
	}
	for _, tt := range tests {
		body := subscriptionFunctionSource(t, source, tt.function)
		lockPos := strings.Index(body, "lockPermissionGovernance(")
		policyPos := strings.Index(body, tt.policy)
		commitPos := strings.Index(body, "session.Commit()")
		if lockPos < 0 || policyPos < 0 || commitPos < 0 || lockPos > policyPos || policyPos > commitPos {
			t.Fatalf("%s must serialize identity references and commit permission data with its policy", tt.function)
		}
	}
}

func TestCerberusSecurityCommittedUserRevocationSurvivesPolicyPublishFailure(t *testing.T) {
	sourceBytes, err := os.ReadFile("user.go")
	if err != nil {
		t.Fatalf("read user.go: %v", err)
	}
	userSource := string(sourceBytes)
	for _, functionName := range []string{"UpdateUser", "UpdateUserForAllFields"} {
		body := subscriptionFunctionSource(t, userSource, functionName)
		capture := strings.Index(body, "publicationErr = err")
		revoke := strings.Index(body, "TerminateUserAccess(oldUser)")
		if capture < 0 || revoke < 0 || capture > revoke {
			t.Fatalf("%s must continue to mandatory access revocation after a committed policy publication failure", functionName)
		}
	}
	for _, functionName := range []string{"updateUserGroupsWithGovernance", "updateUserAllFieldsGroupsWithGovernance"} {
		body := subscriptionFunctionSource(t, userSource, functionName)
		if !strings.Contains(body, "return affected, err") {
			t.Fatalf("%s must report that its database mutation committed when policy publication fails", functionName)
		}
	}
}

func TestCerberusSecurityRoleRenamePreservesPamRevocationIdentity(t *testing.T) {
	roleSourceBytes, err := os.ReadFile("role.go")
	if err != nil {
		t.Fatalf("read role.go: %v", err)
	}
	roleSource := string(roleSourceBytes)
	for _, functionName := range []string{"UpdateRole", "DeleteRole"} {
		body := subscriptionFunctionSource(t, roleSource, functionName)
		if !strings.Contains(body, "hasPamRoleDependencyInSession(") {
			t.Fatalf("%s must preserve PAM grant revocation identity", functionName)
		}
	}
	dependencyBody := subscriptionFunctionSource(t, roleSource, "hasPamRoleDependencyInSession")
	if !strings.Contains(dependencyBody, "role_added = ?") || !strings.Contains(dependencyBody, "PrivilegedAccount") {
		t.Fatal("PAM role dependency guard must cover configured accounts and outstanding grants")
	}
}
