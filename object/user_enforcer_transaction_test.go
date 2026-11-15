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

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/xorm"
	_ "modernc.org/sqlite"
)

func TestCerberusSecurityUserGroupBindingsFollowCallerTransaction(t *testing.T) {
	engine, enforcer := newTransactionalUserGroupEnforcer(t)
	const userId = "tenant/user"

	rolledBack := engine.NewSession()
	if err := rolledBack.Begin(); err != nil {
		t.Fatalf("begin rollback transaction: %v", err)
	}
	if err := enforcer.replaceGroupsForUserInSession(rolledBack, userId, []string{"tenant/group-a"}); err != nil {
		t.Fatalf("stage rollback binding: %v", err)
	}
	if err := rolledBack.Rollback(); err != nil {
		t.Fatalf("rollback binding: %v", err)
	}
	rolledBack.Close()
	assertStoredUserGroups(t, engine, userId, nil)

	committed := engine.NewSession()
	if err := committed.Begin(); err != nil {
		t.Fatalf("begin commit transaction: %v", err)
	}
	if err := enforcer.replaceGroupsForUserInSession(committed, userId, []string{"tenant/group-a"}); err != nil {
		t.Fatalf("stage committed binding: %v", err)
	}
	if err := committed.Commit(); err != nil {
		t.Fatalf("commit binding: %v", err)
	}
	committed.Close()
	if err := enforcer.publishCommittedGroups(); err != nil {
		t.Fatalf("publish committed binding: %v", err)
	}
	groups, err := enforcer.GetGroupsForUser(userId)
	if err != nil {
		t.Fatalf("read committed binding: %v", err)
	}
	if len(groups) != 1 || groups[0] != "tenant/group-a" {
		t.Fatalf("groups = %v, want [tenant/group-a]", groups)
	}
}

func newTransactionalUserGroupEnforcer(t *testing.T) (*xorm.Engine, *UserGroupEnforcer) {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	const tableName = "casbin_user_rule_test"
	if err = engine.Sync2(&safeCasbinRule{tableName: tableName}); err != nil {
		t.Fatalf("create policy table: %v", err)
	}
	adapter, err := xormadapter.NewAdapterByEngineWithTableName(engine, tableName, "")
	if err != nil {
		t.Fatalf("create xorm adapter: %v", err)
	}
	safeAdapter := &SafeAdapter{Adapter: adapter, engine: engine, tableName: tableName, sameDatabase: true}

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
		t.Fatalf("create RBAC model: %v", err)
	}
	casbinEnforcer, err := casbin.NewSyncedEnforcer(m, safeAdapter)
	if err != nil {
		t.Fatalf("create synced enforcer: %v", err)
	}
	return engine, NewUserGroupEnforcer(casbinEnforcer)
}

func assertStoredUserGroups(t *testing.T, engine *xorm.Engine, userId string, want []string) {
	t.Helper()
	rules := []*safeCasbinRule{}
	if err := engine.Table(&safeCasbinRule{tableName: "casbin_user_rule_test"}).
		Where("ptype = ? AND v0 = ?", "g", userId).Find(&rules); err != nil {
		t.Fatalf("read stored user groups: %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("stored group count = %d, want %d", len(rules), len(want))
	}
}
