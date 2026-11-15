// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

func TestCerberusSecurityPermissionDependenciesBlockIdentityReuse(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	permission := &Permission{
		Owner:  "tenant",
		Name:   "access",
		Groups: []string{"tenant/operators"},
		Roles:  []string{"tenant/billing"},
	}
	if _, err := engine.Insert(permission); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	session := engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		t.Fatalf("begin dependency check: %v", err)
	}
	defer session.Rollback()

	used, err := hasPermissionUsingGroupInSession(session, "tenant/operators")
	if err != nil {
		t.Fatalf("check group dependency: %v", err)
	}
	if !used {
		t.Fatal("permission group dependency was not detected")
	}
	used, err = hasPermissionUsingRoleInSession(session, "tenant/billing")
	if err != nil {
		t.Fatalf("check role dependency: %v", err)
	}
	if !used {
		t.Fatal("permission role dependency was not detected")
	}
}

func TestCerberusSecurityBootstrapUserGroupStagingFailsClosed(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	previousUserEnforcer := userEnforcer
	userEnforcer = nil
	t.Cleanup(func() {
		userEnforcer = previousUserEnforcer
	})

	session := engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		t.Fatalf("begin bootstrap group staging: %v", err)
	}
	defer session.Rollback()

	staged, err := stageNewUserGroups(session, &User{Owner: "built-in", Name: "admin"})
	if err != nil || staged {
		t.Fatalf("empty bootstrap user groups = (%v, %v), want (false, nil)", staged, err)
	}
	if staged, err = stageNewUserGroups(session, &User{Owner: "built-in", Name: "admin", Groups: []string{"built-in/operators"}}); err == nil || staged {
		t.Fatalf("grouped bootstrap user = (%v, %v), want fail closed", staged, err)
	}
	if staged, err = stageNewUserGroups(session, &User{Owner: "tenant", Name: "user"}); err == nil || staged {
		t.Fatalf("ordinary pre-enforcer user = (%v, %v), want fail closed", staged, err)
	}
}

func TestCerberusSecurityPermissionPoliciesFollowCallerTransaction(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	oldPermission := &Permission{
		Owner:     "tenant",
		Name:      "access",
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
	}
	newPermission := *oldPermission
	newPermission.Users = []string{"tenant/new"}

	seed := engine.NewSession()
	if err := seed.Begin(); err != nil {
		t.Fatalf("begin seed policy: %v", err)
	}
	if err := addPermissionPoliciesInSession(seed, oldPermission); err != nil {
		_ = seed.Rollback()
		seed.Close()
		t.Fatalf("seed policy: %v", err)
	}
	if err := seed.Commit(); err != nil {
		seed.Close()
		t.Fatalf("commit seed policy: %v", err)
	}
	seed.Close()
	assertPermissionPolicySubjects(t, engine, []string{"tenant/old"})

	rolledBack := engine.NewSession()
	if err := rolledBack.Begin(); err != nil {
		t.Fatalf("begin rollback policy: %v", err)
	}
	if err := replacePermissionPoliciesInSession(rolledBack, oldPermission, &newPermission); err != nil {
		_ = rolledBack.Rollback()
		rolledBack.Close()
		t.Fatalf("stage rollback policy: %v", err)
	}
	if err := rolledBack.Rollback(); err != nil {
		rolledBack.Close()
		t.Fatalf("rollback policy: %v", err)
	}
	rolledBack.Close()
	assertPermissionPolicySubjects(t, engine, []string{"tenant/old"})

	committed := engine.NewSession()
	if err := committed.Begin(); err != nil {
		t.Fatalf("begin committed policy: %v", err)
	}
	if err := replacePermissionPoliciesInSession(committed, oldPermission, &newPermission); err != nil {
		_ = committed.Rollback()
		committed.Close()
		t.Fatalf("stage committed policy: %v", err)
	}
	if err := committed.Commit(); err != nil {
		committed.Close()
		t.Fatalf("commit policy: %v", err)
	}
	committed.Close()
	assertPermissionPolicySubjects(t, engine, []string{"tenant/new"})
}

func TestCerberusSecurityPermissionLifecycleCommitsPolicyWithRecord(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	permission := &Permission{
		Owner:     "tenant",
		Name:      "lifecycle",
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	added, err := AddPermission(permission)
	if err != nil || !added {
		t.Fatalf("add permission = (%v, %v)", added, err)
	}
	assertPermissionPolicySubjects(t, engine, []string{"tenant/old"})

	permission.Users = []string{"tenant/new"}
	updated, err := UpdatePermission(permission.GetId(), permission)
	if err != nil || !updated {
		t.Fatalf("update permission = (%v, %v)", updated, err)
	}
	assertPermissionPolicySubjects(t, engine, []string{"tenant/new"})

	deleted, err := DeletePermission(permission)
	if err != nil || !deleted {
		t.Fatalf("delete permission = (%v, %v)", deleted, err)
	}
	assertPermissionPolicySubjects(t, engine, nil)
	if count, err := engine.Count(&Permission{Owner: permission.Owner, Name: permission.Name}); err != nil || count != 0 {
		t.Fatalf("permission record count = (%d, %v), want zero", count, err)
	}
}

func TestCerberusSecurityPermissionExpiryCommitsRevocationWithRecord(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	permission := &Permission{
		Owner:      "tenant",
		Name:       "expiring",
		Users:      []string{"tenant/user"},
		Resources:  []string{"resource"},
		Actions:    []string{"read"},
		Effect:     "Allow",
		IsEnabled:  true,
		ExpireTime: now.Add(-time.Minute).Format(time.RFC3339),
	}
	if added, err := AddPermission(permission); err != nil || !added {
		t.Fatalf("add expiring permission = (%v, %v)", added, err)
	}
	revoked, err := expirePermissionInTransaction(permission, now)
	if err != nil || !revoked {
		t.Fatalf("expire permission = (%v, %v)", revoked, err)
	}
	assertPermissionPolicySubjects(t, engine, nil)
	stored := &Permission{Owner: permission.Owner, Name: permission.Name}
	if existed, err := engine.Get(stored); err != nil || !existed {
		t.Fatalf("read expired permission = (%v, %v)", existed, err)
	}
	if stored.IsEnabled {
		t.Fatal("expired permission remained enabled")
	}
}

func TestCerberusSecurityUserRenameRejectsPermissionDependency(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	permission := &Permission{
		Owner:     "tenant",
		Name:      "user-binding",
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	if added, err := AddPermission(permission); err != nil || !added {
		t.Fatalf("add user-bound permission = (%v, %v)", added, err)
	}
	oldUser := &User{Owner: "tenant", Name: "old"}
	if existed, err := engine.Get(oldUser); err != nil || !existed {
		t.Fatalf("read permission-bound user = (%v, %v)", existed, err)
	}
	renamed := *oldUser
	renamed.Name = "renamed"
	if updated, err := UpdateUser("tenant/old", &renamed, []string{"name"}, true); err == nil || updated {
		t.Fatalf("rename permission-bound user = (%v, %v), want refusal", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("old user survived refusal = (%v, %v), want true", existed, err)
	}
}

func TestCerberusSecurityUserRenameRejectsReservedDestinationIdentity(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	application := &Application{
		Owner:         "admin",
		Name:          "external-app",
		ExternalUsers: []string{"tenant/reserved"},
	}
	if _, err := engine.Insert(application); err != nil {
		t.Fatalf("insert external application grant: %v", err)
	}
	oldUser := &User{Owner: "tenant", Name: "old"}
	if existed, err := engine.Get(oldUser); err != nil || !existed {
		t.Fatalf("read source user = (%v, %v)", existed, err)
	}
	renamed := *oldUser
	renamed.Name = "reserved"
	if updated, err := UpdateUser("tenant/old", &renamed, []string{"name"}, true); err == nil || updated {
		t.Fatalf("rename into reserved identity = (%v, %v), want refusal", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("source user survived refusal = (%v, %v), want true", existed, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "reserved"}); err != nil || existed {
		t.Fatalf("reserved destination exists = (%v, %v), want false", existed, err)
	}
	storedApplication := &Application{Owner: application.Owner, Name: application.Name}
	if existed, err := engine.Get(storedApplication); err != nil || !existed {
		t.Fatalf("read external application = (%v, %v)", existed, err)
	}
	if len(storedApplication.ExternalUsers) != 1 || storedApplication.ExternalUsers[0] != "tenant/reserved" {
		t.Fatalf("external user grant changed on refused rename: %v", storedApplication.ExternalUsers)
	}
}

func TestCerberusSecurityUserRenameCommitsIdentityAndReferencesTogether(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	oldUser := &User{Owner: "tenant", Name: "old"}
	if existed, err := engine.Get(oldUser); err != nil || !existed {
		t.Fatalf("read rename source = (%v, %v)", existed, err)
	}
	oldUser.Groups = []string{"tenant/operators"}
	if _, err := engine.ID(core.PK{oldUser.Owner, oldUser.Name}).Cols("groups").Update(oldUser); err != nil {
		t.Fatalf("seed source groups: %v", err)
	}
	bindings := engine.NewSession()
	if err := bindings.Begin(); err != nil {
		t.Fatalf("begin source group binding: %v", err)
	}
	if err := userEnforcer.replaceGroupsForUserInSession(bindings, oldUser.GetId(), oldUser.Groups); err != nil {
		_ = bindings.Rollback()
		bindings.Close()
		t.Fatalf("seed source group binding: %v", err)
	}
	if err := bindings.Commit(); err != nil {
		bindings.Close()
		t.Fatalf("commit source group binding: %v", err)
	}
	bindings.Close()
	if err := userEnforcer.publishCommittedGroups(); err != nil {
		t.Fatalf("publish source group binding: %v", err)
	}
	objects := []any{
		&Role{Owner: "tenant", Name: "rename-role", Users: []string{"tenant/old"}},
		&Resource{Owner: "tenant", Name: "/rename-private", User: "old"},
		&Token{Owner: "tenant", Name: "rename-token", Organization: "tenant", User: "old"},
		&ThirdPartyLink{Owner: "tenant", UserName: "old", ProviderName: "oidc", ProviderId: "rename-provider-id"},
		&PasswordHistory{Owner: "tenant", Name: "old", Entries: []*PasswordHistoryEntry{{Password: "hash"}}},
	}
	for _, object := range objects {
		if _, err := engine.Insert(object); err != nil {
			t.Fatalf("seed rename %T: %v", object, err)
		}
	}
	renamed := *oldUser
	renamed.Name = "renamed"
	if updated, err := UpdateUser("tenant/old", &renamed, []string{"name"}, true); err != nil || !updated {
		t.Fatalf("rename user = (%v, %v), want success", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || existed {
		t.Fatalf("old user exists after rename = (%v, %v), want false", existed, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "renamed"}); err != nil || !existed {
		t.Fatalf("renamed user exists = (%v, %v), want true", existed, err)
	}
	storedRole := &Role{Owner: "tenant", Name: "rename-role"}
	if existed, err := engine.Get(storedRole); err != nil || !existed || len(storedRole.Users) != 1 || storedRole.Users[0] != "tenant/renamed" {
		t.Fatalf("renamed role reference = (%v, %v, %v)", existed, err, storedRole.Users)
	}
	storedResource := &Resource{Owner: "tenant", Name: "/rename-private"}
	if existed, err := engine.Get(storedResource); err != nil || !existed || storedResource.User != "renamed" {
		t.Fatalf("renamed resource reference = (%v, %v, %q)", existed, err, storedResource.User)
	}
	storedToken := &Token{Owner: "tenant", Name: "rename-token"}
	if existed, err := engine.Get(storedToken); err != nil || !existed || storedToken.User != "renamed" {
		t.Fatalf("renamed token reference = (%v, %v, %q)", existed, err, storedToken.User)
	}
	if existed, err := engine.Get(&ThirdPartyLink{Owner: "tenant", UserName: "renamed", ProviderName: "oidc"}); err != nil || !existed {
		t.Fatalf("renamed provider link = (%v, %v)", existed, err)
	}
	if existed, err := engine.Get(&PasswordHistory{Owner: "tenant", Name: "renamed"}); err != nil || !existed {
		t.Fatalf("renamed password history = (%v, %v)", existed, err)
	}
	oldGroups, err := userEnforcer.GetGroupsForUser("tenant/old")
	if err != nil {
		t.Fatalf("read old user groups: %v", err)
	}
	newGroups, err := userEnforcer.GetGroupsForUser("tenant/renamed")
	if err != nil {
		t.Fatalf("read renamed user groups: %v", err)
	}
	if len(oldGroups) != 0 || len(newGroups) != 1 || newGroups[0] != "tenant/operators" {
		t.Fatalf("renamed group bindings old=%v new=%v", oldGroups, newGroups)
	}
}

func TestCerberusSecurityUserRenameRollsBackReferencesWhenUserWriteFails(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	role := &Role{Owner: "tenant", Name: "rename-role", Users: []string{"tenant/old"}}
	resource := &Resource{Owner: "tenant", Name: "/rename-private", User: "old"}
	if _, err := engine.Insert(role, resource); err != nil {
		t.Fatalf("seed rename references: %v", err)
	}
	if _, err := engine.Exec(`CREATE TRIGGER reject_blocked_user_rename BEFORE UPDATE OF name ON "user" WHEN NEW.name = 'blocked' BEGIN SELECT RAISE(ABORT, 'injected user rename failure'); END`); err != nil {
		t.Fatalf("install user rename failure: %v", err)
	}
	oldUser := &User{Owner: "tenant", Name: "old"}
	if existed, err := engine.Get(oldUser); err != nil || !existed {
		t.Fatalf("read rename source = (%v, %v)", existed, err)
	}
	renamed := *oldUser
	renamed.Name = "blocked"
	if updated, err := UpdateUser("tenant/old", &renamed, []string{"name"}, true); err == nil || updated {
		t.Fatalf("injected-failure rename = (%v, %v), want rollback", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("source user after rollback = (%v, %v), want true", existed, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "blocked"}); err != nil || existed {
		t.Fatalf("destination user after rollback = (%v, %v), want false", existed, err)
	}
	storedRole := &Role{Owner: role.Owner, Name: role.Name}
	if existed, err := engine.Get(storedRole); err != nil || !existed {
		t.Fatalf("read role after rollback = (%v, %v)", existed, err)
	}
	if len(storedRole.Users) != 1 || storedRole.Users[0] != "tenant/old" {
		t.Fatalf("role users after rollback = %v, want [tenant/old]", storedRole.Users)
	}
	storedResource := &Resource{Owner: resource.Owner, Name: resource.Name}
	if existed, err := engine.Get(storedResource); err != nil || !existed {
		t.Fatalf("read resource after rollback = (%v, %v)", existed, err)
	}
	if storedResource.User != "old" {
		t.Fatalf("resource user after rollback = %q, want old", storedResource.User)
	}
}

func TestCerberusSecurityUserDeleteRejectsLiveIdentityDependencies(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	permission := &Permission{
		Owner:     "tenant",
		Name:      "delete-binding",
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	if added, err := AddPermission(permission); err != nil || !added {
		t.Fatalf("add user-bound permission = (%v, %v)", added, err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete permission-bound user = (%v, %v), want refusal", deleted, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("bound user survived refusal = (%v, %v), want true", existed, err)
	}
	if deleted, err := DeletePermission(permission); err != nil || !deleted {
		t.Fatalf("delete permission = (%v, %v)", deleted, err)
	}
	role := &Role{Owner: "tenant", Name: "billing"}
	if existed, err := engine.Get(role); err != nil || !existed {
		t.Fatalf("read role = (%v, %v)", existed, err)
	}
	role.Users = []string{"tenant/old"}
	if _, err := engine.ID(core.PK{role.Owner, role.Name}).Cols("users").Update(role); err != nil {
		t.Fatalf("bind role to user: %v", err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete role-bound user = (%v, %v), want refusal", deleted, err)
	}
	role.Users = nil
	if _, err := engine.ID(core.PK{role.Owner, role.Name}).Cols("users").Update(role); err != nil {
		t.Fatalf("clear role binding: %v", err)
	}
	subscription := &Subscription{Owner: "tenant", Name: "old-subscription", User: "old", State: SubStateExpired}
	if _, err := engine.Insert(subscription); err != nil {
		t.Fatalf("insert user subscription: %v", err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete subscription-bound user = (%v, %v), want refusal", deleted, err)
	}
	if _, err := engine.Delete(subscription); err != nil {
		t.Fatalf("delete user subscription: %v", err)
	}
	if _, err := engine.ID(core.PK{"tenant", "old"}).Cols("email").Update(&User{Email: "old@example.test"}); err != nil {
		t.Fatalf("set user email: %v", err)
	}
	artifacts := []any{
		&CertLoginTicket{Owner: "tenant", Name: "ticket", User: "tenant/old", SecretHash: "ticket-hash"},
		&VerificationRecord{Owner: "tenant", Name: "verification", User: "tenant/old", Receiver: "old@example.test", Code: "123456"},
		&MagicLink{Owner: "tenant", Name: "magic", Email: "old@example.test", TokenHash: "magic-hash", SessionHash: "session-hash"},
	}
	for _, artifact := range artifacts {
		if _, err := engine.Insert(artifact); err != nil {
			t.Fatalf("insert %T: %v", artifact, err)
		}
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err != nil || !deleted {
		t.Fatalf("delete unbound user = (%v, %v), want success", deleted, err)
	}
	for _, artifact := range []any{&CertLoginTicket{}, &VerificationRecord{}, &MagicLink{}} {
		if count, err := engine.Count(artifact); err != nil || count != 0 {
			t.Fatalf("remaining %T count = (%d, %v), want zero", artifact, count, err)
		}
	}
	if _, err := engine.Insert(&User{Owner: "tenant", Name: "old"}); err != nil {
		t.Fatalf("recreate unbound user: %v", err)
	}
	assertPermissionPolicySubjects(t, engine, nil)
}

func TestCerberusSecurityAllLiveIdentitySelectorsAreReserved(t *testing.T) {
	tests := []struct {
		name string
		want string
		seed func(t *testing.T, engine *xorm.Engine)
	}{
		{"role", "role", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Role{Owner: "tenant", Name: "identity-role", Users: []string{"tenant/candidate"}})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"enterprise-admin", "enterprise administrator policy", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.ID(core.PK{"admin", "tenant"}).Cols("enterprise_policy").Update(&Organization{EnterprisePolicy: &EnterprisePolicy{SystemAdmins: []string{"candidate"}}})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"external-application", "external application grant", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Application{Owner: "admin", Name: "external", ExternalUsers: []string{"tenant/candidate"}})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"pam-policy", "privileged account policy", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&PrivilegedAccount{Owner: "tenant", Name: "database", Users: []string{"candidate"}})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"pam-request", "active privileged access request", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&PrivilegedRequest{Owner: "tenant", Name: "request", Requester: "candidate", State: PamStateApproved})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"subscription", "subscription", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Subscription{Owner: "tenant", Name: "subscription", User: "candidate", State: SubStateExpired})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"access-key", "access key", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Key{Owner: "admin", Name: "key", Organization: "tenant", User: "candidate"})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"resource", "resource", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Resource{Owner: "tenant", Name: "/private", User: "candidate"})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"pricing", "invite-only pricing", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Pricing{Owner: "tenant", Name: "private", Users: []string{"candidate"}})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"coupon", "user-scoped coupon", func(t *testing.T, engine *xorm.Engine) {
			_, err := engine.Insert(&Coupon{Owner: "tenant", Name: "private", Users: []string{"candidate"}})
			if err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newGovernanceLifecycleEngine(t)
			seedGovernanceLifecycleOwner(t, engine)
			tc.seed(t, engine)
			session := engine.NewSession()
			defer session.Close()
			if err := session.Begin(); err != nil {
				t.Fatalf("begin identity dependency check: %v", err)
			}
			defer session.Rollback()
			got, err := getUserIdentityDependencyInSession(session, &User{Owner: "tenant", Name: "candidate"}, false)
			if err != nil {
				t.Fatalf("check identity dependency: %v", err)
			}
			if got != tc.want {
				t.Fatalf("identity dependency = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCerberusSecurityCustomPermissionAdapterProvisionedOutsideRequest(t *testing.T) {
	t.Setenv("tableNamePrefix", "cerberus_")
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	adapter := &Adapter{
		Owner:     "tenant",
		Name:      "permission-adapter",
		Table:     "tenant_permission_rule",
		UseSameDb: true,
	}
	if added, err := AddAdapter(adapter); err != nil || !added {
		t.Fatalf("add permission adapter = (%v, %v)", added, err)
	}
	policyTable := "cerberus_" + adapter.Table
	if exists, err := engine.IsTableExist(policyTable); err != nil || !exists {
		t.Fatalf("custom permission table exists = (%v, %v), want true", exists, err)
	}
	if err := ensureStoredPermissionPolicyTables(engine); err != nil {
		t.Fatalf("repeat stored permission table startup provisioning: %v", err)
	}
	permission := &Permission{
		Owner:     "tenant",
		Name:      "custom-adapter-access",
		Adapter:   adapter.Name,
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	if added, err := AddPermission(permission); err != nil || !added {
		t.Fatalf("add custom-adapter permission = (%v, %v)", added, err)
	}
	var policyCount int64
	policyCount, err := engine.Table(policyTable).Where("ptype = ? AND v5 = ?", "p", permission.GetId()).Count(&safeCasbinRule{})
	if err != nil || policyCount != 1 {
		t.Fatalf("custom permission policy count = (%d, %v), want one", policyCount, err)
	}
}

func TestCerberusSecurityRoleDeleteRejectsInheritedDependency(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	parent := &Role{Owner: "tenant", Name: "parent", Roles: []string{"tenant/billing"}, IsEnabled: true}
	if added, err := AddRole(parent); err != nil || !added {
		t.Fatalf("add parent role = (%v, %v)", added, err)
	}
	child := &Role{Owner: "tenant", Name: "billing"}
	if deleted, err := DeleteRole(child); err == nil || deleted {
		t.Fatalf("delete inherited role = (%v, %v), want refusal", deleted, err)
	}
	if existed, err := engine.Get(child); err != nil || !existed {
		t.Fatalf("child role survived refusal = (%v, %v), want true", existed, err)
	}
}

func TestCerberusSecurityPlanOwnsProductLifecycle(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)

	plan := newGovernanceLifecyclePlan("starter")
	added, err := AddPlan(plan)
	if err != nil || !added {
		t.Fatalf("add plan = (%v, %v), want success", added, err)
	}
	if plan.Product == "" {
		t.Fatal("add plan did not bind a product")
	}
	product := &Product{Owner: plan.Owner, Name: plan.Product}
	if existed, err := engine.Get(product); err != nil || !existed {
		t.Fatalf("read plan product = (%v, %v)", existed, err)
	}
	if !isProductManagedByPlan(product, plan) {
		t.Fatalf("product ownership marker = %#v, want %s", product.Properties, plan.GetId())
	}

	productCount, err := engine.Count(&Product{Owner: plan.Owner})
	if err != nil {
		t.Fatalf("count products: %v", err)
	}
	duplicate := newGovernanceLifecyclePlan(plan.Name)
	if added, err = AddPlan(duplicate); err != nil || added {
		t.Fatalf("duplicate plan = (%v, %v), want clean refusal", added, err)
	}
	productCountAfter, err := engine.Count(&Product{Owner: plan.Owner})
	if err != nil {
		t.Fatalf("count products after duplicate: %v", err)
	}
	if productCountAfter != productCount {
		t.Fatalf("duplicate plan left product count %d, want %d", productCountAfter, productCount)
	}

	forged := *plan
	forged.Product = "victim-product"
	forged.Price = 25
	victim := &Product{Owner: plan.Owner, Name: forged.Product, Currency: "USD", Price: 900, Providers: []string{"stripe"}}
	if _, err = engine.Insert(victim); err != nil {
		t.Fatalf("insert victim product: %v", err)
	}
	updated, err := UpdatePlan(plan.GetId(), &forged)
	if err != nil || !updated {
		t.Fatalf("update plan = (%v, %v), want success", updated, err)
	}
	storedPlan := &Plan{Owner: plan.Owner, Name: plan.Name}
	if existed, err := engine.Get(storedPlan); err != nil || !existed {
		t.Fatalf("read updated plan = (%v, %v)", existed, err)
	}
	if storedPlan.Product != plan.Product {
		t.Fatalf("plan product changed to %q, want %q", storedPlan.Product, plan.Product)
	}
	storedVictim := &Product{Owner: plan.Owner, Name: victim.Name}
	if existed, err := engine.Get(storedVictim); err != nil || !existed {
		t.Fatalf("read victim product = (%v, %v)", existed, err)
	}
	if storedVictim.Price != victim.Price {
		t.Fatalf("victim product price = %v, want %v", storedVictim.Price, victim.Price)
	}

	direct := *product
	direct.Price = 1
	if _, err = UpdateProduct(product.GetId(), &direct); err == nil {
		t.Fatal("direct update of a plan product succeeded")
	}
	if _, err = DeleteProduct(product); err == nil {
		t.Fatal("direct delete of a plan product succeeded")
	}
}

func TestCerberusSecurityDeletingSharedPlanKeepsProduct(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)

	plan := newGovernanceLifecyclePlan("primary")
	if added, err := AddPlan(plan); err != nil || !added {
		t.Fatalf("add primary plan = (%v, %v)", added, err)
	}
	shared := newGovernanceLifecyclePlan("shared")
	shared.Product = plan.Product
	if _, err := engine.Insert(shared); err != nil {
		t.Fatalf("insert legacy shared plan: %v", err)
	}

	deleted, err := DeletePlan(plan)
	if err != nil || !deleted {
		t.Fatalf("delete primary plan = (%v, %v)", deleted, err)
	}
	product := &Product{Owner: plan.Owner, Name: plan.Product}
	if existed, err := engine.Get(product); err != nil || !existed {
		t.Fatalf("shared product survived = (%v, %v), want true", existed, err)
	}
}

func TestCerberusSecurityUnambiguousLegacyPlanProductIsClaimedOnUpdate(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)
	plan := newGovernanceLifecyclePlan("legacy")
	plan.Product = "legacy-product"
	product := &Product{
		Owner:      plan.Owner,
		Name:       plan.Product,
		Tag:        planManagedProductTag,
		Currency:   "USD",
		Price:      10,
		Providers:  []string{"stripe"},
		Properties: nil,
	}
	if _, err := engine.Insert(product, plan); err != nil {
		t.Fatalf("seed legacy plan product: %v", err)
	}
	plan.Price = 20
	if updated, err := UpdatePlan(plan.GetId(), plan); err != nil || !updated {
		t.Fatalf("update legacy plan = (%v, %v)", updated, err)
	}
	stored := &Product{Owner: product.Owner, Name: product.Name}
	if existed, err := engine.Get(stored); err != nil || !existed {
		t.Fatalf("read claimed product = (%v, %v)", existed, err)
	}
	if !isProductManagedByPlan(stored, plan) || stored.Price != plan.Price {
		t.Fatalf("claimed product marker=%#v price=%v", stored.Properties, stored.Price)
	}
}

func TestCerberusSecurityInvalidPlanRoleCreatesNothing(t *testing.T) {
	engine := newGovernanceLifecycleEngine(t)
	seedGovernanceLifecycleOwner(t, engine)

	plan := newGovernanceLifecyclePlan("invalid-role")
	plan.Role = "tenant/missing"
	if added, err := AddPlan(plan); err == nil || added {
		t.Fatalf("invalid-role plan = (%v, %v), want rejection", added, err)
	}
	planCount, err := engine.Count(&Plan{Owner: plan.Owner})
	if err != nil {
		t.Fatalf("count plans: %v", err)
	}
	productCount, err := engine.Count(&Product{Owner: plan.Owner})
	if err != nil {
		t.Fatalf("count products: %v", err)
	}
	if planCount != 0 || productCount != 0 {
		t.Fatalf("invalid-role add left plans=%d products=%d, want zero", planCount, productCount)
	}
}

func newGovernanceLifecycleEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", "file:governance_lifecycle?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	engine.SetMaxOpenConns(4)
	if err = engine.Sync2(
		&Organization{}, &User{}, &Role{}, &Group{}, &Permission{}, &Adapter{}, &Provider{},
		&Plan{}, &Product{}, &Subscription{}, &Application{}, &PrivilegedAccount{}, &PrivilegedRequest{},
		&Key{}, &Resource{}, &Pricing{}, &Coupon{}, &Token{}, &ThirdPartyLink{}, &PasswordHistory{}, &Syncer{},
		&CertLoginTicket{}, &VerificationRecord{}, &MagicLink{},
		&safeCasbinRule{tableName: "permission_rule"}, &safeCasbinRule{tableName: "user_rule"},
	); err != nil {
		_ = engine.Close()
		t.Fatalf("create governance schema: %v", err)
	}
	adapter, err := xormadapter.NewAdapterByEngineWithTableName(engine, "user_rule", "")
	if err != nil {
		_ = engine.Close()
		t.Fatalf("create governance user adapter: %v", err)
	}
	safeAdapter := &SafeAdapter{Adapter: adapter, engine: engine, tableName: "user_rule", sameDatabase: true}
	m, err := model.NewModelFromString(`[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj`)
	if err != nil {
		_ = engine.Close()
		t.Fatalf("create governance user model: %v", err)
	}
	casbinEnforcer, err := casbin.NewSyncedEnforcer(m, safeAdapter)
	if err != nil {
		_ = engine.Close()
		t.Fatalf("create governance user enforcer: %v", err)
	}
	previous := ormer
	previousUserEnforcer := userEnforcer
	ormer = &Ormer{Engine: engine}
	userEnforcer = NewUserGroupEnforcer(casbinEnforcer)
	t.Cleanup(func() {
		ormer = previous
		userEnforcer = previousUserEnforcer
		_ = engine.Close()
	})
	return engine
}

func assertPermissionPolicySubjects(t *testing.T, engine *xorm.Engine, want []string) {
	t.Helper()
	rules := []*safeCasbinRule{}
	if err := engine.Table("permission_rule").Where("ptype = ?", "p").Find(&rules); err != nil {
		t.Fatalf("read permission policies: %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("policy count = %d, want %d", len(rules), len(want))
	}
	for i, subject := range want {
		if rules[i].V0 != subject {
			t.Fatalf("policy[%d] subject = %q, want %q", i, rules[i].V0, subject)
		}
	}
}

func seedGovernanceLifecycleOwner(t *testing.T, engine *xorm.Engine) {
	t.Helper()
	objects := []interface{}{
		&Organization{Owner: "admin", Name: "tenant"},
		&User{Owner: "tenant", Name: "old"},
		&User{Owner: "tenant", Name: "new"},
		&User{Owner: "tenant", Name: "user"},
		&Role{Owner: "tenant", Name: "billing"},
		&Provider{Owner: "tenant", Name: "stripe", Type: "Stripe"},
	}
	for _, object := range objects {
		if _, err := engine.Insert(object); err != nil {
			t.Fatalf("seed %T: %v", object, err)
		}
	}
}

func newGovernanceLifecyclePlan(name string) *Plan {
	return &Plan{
		Owner:            "tenant",
		Name:             name,
		CreatedTime:      "2026-11-15T00:00:00Z",
		Price:            10,
		Currency:         "USD",
		Period:           PeriodMonthly,
		PaymentProviders: []string{"stripe"},
		Role:             "billing",
		IsEnabled:        true,
	}
}
