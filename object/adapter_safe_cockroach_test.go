//go:build integration

package object

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2/model"
	_ "github.com/lib/pq"
	"github.com/xorm-io/xorm"
)

const (
	cockroachTestIdentity = "casdoor-safe-adapter-crdb"
	cockroachTestDatabase = "casdoor_safe_adapter_test"
	cockroachTestTable    = "casbin_api_rule_integration"
)

func TestSafeAdapterCockroachRepeatedWritesPreserveCustomTable(t *testing.T) {
	dsn := os.Getenv("CASDOOR_COCKROACH_TEST_DSN")
	if os.Getenv("CASDOOR_COCKROACH_TEST_ALLOW_DISPOSABLE") != cockroachTestIdentity || dsn == "" {
		t.Skip("requires explicit opt-in and DSN for the owned disposable CockroachDB test container")
	}

	parsedDSN, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse disposable test DSN: %v", err)
	}
	if parsedDSN.Hostname() != cockroachTestIdentity || parsedDSN.Path != "/"+cockroachTestDatabase || parsedDSN.Query().Get("sslmode") != "disable" {
		t.Fatalf("refusing DSN outside the owned disposable test identity/database")
	}

	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open CockroachDB identity probe: %v", err)
	}
	defer probe.Close()

	var version, database string
	if err := probe.QueryRow("SELECT version(), current_database()").Scan(&version, &database); err != nil {
		t.Fatalf("read disposable CockroachDB identity: %v", err)
	}
	if !strings.Contains(version, "v26.2.7") || database != cockroachTestDatabase {
		t.Fatalf("unexpected disposable database identity: version=%q database=%q", version, database)
	}
	var tableCount int
	if err := probe.QueryRow("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&tableCount); err != nil {
		t.Fatalf("check disposable database is empty: %v", err)
	}
	if tableCount != 0 {
		t.Fatalf("refusing nonempty disposable database: found %d public tables", tableCount)
	}

	engine, err := xorm.NewEngine("postgres", dsn)
	if err != nil {
		t.Fatalf("open CockroachDB Xorm engine: %v", err)
	}
	tableCreated := false
	t.Cleanup(func() {
		if tableCreated {
			if _, err := engine.Exec("DROP TABLE " + cockroachTestTable); err != nil {
				t.Errorf("drop owned integration table: %v", err)
			}
		}
		if err := engine.Close(); err != nil {
			t.Errorf("close CockroachDB Xorm engine: %v", err)
		}
	})

	_, err = engine.Exec(`CREATE TABLE ` + cockroachTestTable + ` (
		id INT8 NOT NULL DEFAULT unique_rowid(),
		ptype STRING NOT NULL DEFAULT '',
		v0 STRING NOT NULL DEFAULT '',
		v1 STRING NOT NULL DEFAULT '',
		v2 STRING NOT NULL DEFAULT '',
		v3 STRING NOT NULL DEFAULT '',
		v4 STRING NOT NULL DEFAULT '',
		v5 STRING NOT NULL DEFAULT '',
		PRIMARY KEY (id)
	)`)
	if err != nil {
		t.Fatalf("create expanded STRING-compatible custom table: %v", err)
	}
	tableCreated = true
	if _, err := engine.Exec("CREATE INDEX casbin_api_rule_integration_marker_idx ON " + cockroachTestTable + " (ptype)"); err != nil {
		t.Fatalf("create marker index: %v", err)
	}

	safeAdapter := &SafeAdapter{engine: engine, tableName: cockroachTestTable}

	firstPolicy := newCockroachPolicyModel(t, [][]string{{"built-in", "*", "*", "*", "*", "*"}})
	if err := safeAdapter.SavePolicy(firstPolicy); err != nil {
		t.Fatalf("first SavePolicy(): %v", err)
	}
	secondPolicy := newCockroachPolicyModel(t, [][]string{
		{"app", "*", "GET", "/api/get-account", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})
	if err := safeAdapter.SavePolicy(secondPolicy); err != nil {
		t.Fatalf("repeated SavePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-account", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})

	if err := safeAdapter.UpdatePolicy("p", "p",
		[]string{"app", "*", "GET", "/api/get-account", "*", "*"},
		[]string{"app", "*", "GET", "/api/get-user", "*", "*"}); err != nil {
		t.Fatalf("UpdatePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-user", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})

	if err := safeAdapter.RemovePolicy("p", "p", []string{"*", "*", "POST", "/api/login", "*", "*"}); err != nil {
		t.Fatalf("RemovePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-user", "*", "*"},
	})

	indexes, err := probe.Query("SHOW INDEXES FROM " + cockroachTestTable)
	if err != nil {
		t.Fatalf("read custom table indexes: %v", err)
	}
	defer indexes.Close()
	indexColumns, err := indexes.Columns()
	if err != nil {
		t.Fatalf("read custom table index columns: %v", err)
	}
	indexNameColumn := -1
	for i, column := range indexColumns {
		if column == "index_name" {
			indexNameColumn = i
			break
		}
	}
	if indexNameColumn == -1 {
		t.Fatalf("SHOW INDEXES result has no index_name column: %v", indexColumns)
	}
	markerIndexFound := false
	for indexes.Next() {
		values := make([]any, len(indexColumns))
		scanArgs := make([]any, len(values))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := indexes.Scan(scanArgs...); err != nil {
			t.Fatalf("scan custom table index: %v", err)
		}
		if fmt.Sprint(values[indexNameColumn]) == "casbin_api_rule_integration_marker_idx" {
			markerIndexFound = true
		}
	}
	if err := indexes.Err(); err != nil {
		t.Fatalf("iterate custom table indexes: %v", err)
	}
	if !markerIndexFound {
		t.Fatal("SavePolicy() removed the custom table marker index")
	}
	columns, err := probe.Query("SHOW COLUMNS FROM " + cockroachTestTable)
	if err != nil {
		t.Fatalf("read expanded STRING-compatible schema: %v", err)
	}
	defer columns.Close()
	columnNames, err := columns.Columns()
	if err != nil {
		t.Fatalf("read custom table column metadata: %v", err)
	}
	columnIndex, typeIndex := -1, -1
	for i, name := range columnNames {
		switch name {
		case "column_name":
			columnIndex = i
		case "data_type":
			typeIndex = i
		}
	}
	if columnIndex == -1 || typeIndex == -1 {
		t.Fatalf("SHOW COLUMNS result lacks column_name or data_type: %v", columnNames)
	}
	policyColumns := map[string]bool{"ptype": false, "v0": false, "v1": false, "v2": false, "v3": false, "v4": false, "v5": false}
	for columns.Next() {
		values := make([]any, len(columnNames))
		scanArgs := make([]any, len(values))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := columns.Scan(scanArgs...); err != nil {
			t.Fatalf("scan custom table column metadata: %v", err)
		}
		name := fmt.Sprint(values[columnIndex])
		if _, isPolicyColumn := policyColumns[name]; !isPolicyColumn {
			continue
		}
		dataType := strings.ToUpper(fmt.Sprint(values[typeIndex]))
		if dataType != "STRING" && dataType != "VARCHAR" && dataType != "CHARACTER VARYING" && dataType != "TEXT" {
			t.Errorf("policy column %s has type %q, want a STRING-compatible type", name, dataType)
		}
		policyColumns[name] = true
	}
	if err := columns.Err(); err != nil {
		t.Fatalf("iterate custom table columns: %v", err)
	}
	for name, found := range policyColumns {
		if !found {
			t.Errorf("custom table is missing STRING-compatible policy column %s", name)
		}
	}

	testCockroachPermissionLifecycle(t, engine)
	testCockroachSubscriptionRetry(t, engine)
}

func testCockroachPermissionLifecycle(t *testing.T, engine *xorm.Engine) {
	t.Helper()
	permissionTables := []string{
		"tenant_permission_rule", "permission_rule", "permission", "adapter", "role", "group", "user", "organization",
		"application", "privileged_account", "privileged_request", "subscription", "key", "resource", "pricing", "coupon",
		"token", "third_party_link", "password_history", "syncer", "cert_login_ticket", "verification_record", "magic_link",
	}
	t.Cleanup(func() {
		for _, table := range permissionTables {
			if _, err := engine.Exec(`DROP TABLE IF EXISTS "` + table + `"`); err != nil {
				t.Errorf("drop owned permission lifecycle table %s: %v", table, err)
			}
		}
	})
	if err := engine.Sync2(
		&Organization{}, &User{}, &Permission{}, &Adapter{}, &Role{}, &Group{}, &Application{},
		&PrivilegedAccount{}, &PrivilegedRequest{}, &Subscription{}, &Key{}, &Resource{}, &Pricing{}, &Coupon{},
		&Token{}, &ThirdPartyLink{}, &PasswordHistory{}, &Syncer{}, &CertLoginTicket{}, &VerificationRecord{}, &MagicLink{},
	); err != nil {
		t.Fatalf("create permission lifecycle schema: %v", err)
	}
	if err := ensurePermissionPolicyTable(engine, "permission_rule"); err != nil {
		t.Fatalf("create permission policy table: %v", err)
	}
	if err := ensurePermissionPolicyTable(engine, "permission_rule"); err != nil {
		t.Fatalf("repeat permission policy startup check: %v", err)
	}
	previousOrmer := ormer
	ormer = &Ormer{Engine: engine}
	t.Cleanup(func() { ormer = previousOrmer })

	for _, object := range []any{
		&Organization{Owner: "admin", Name: "tenant"},
		&User{Owner: "tenant", Name: "old"},
		&User{Owner: "tenant", Name: "fail"},
	} {
		if _, err := engine.Insert(object); err != nil {
			t.Fatalf("seed permission lifecycle %T: %v", object, err)
		}
	}
	permission := &Permission{
		Owner:     "tenant",
		Name:      "cockroach-lifecycle",
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	if added, err := AddPermission(permission); err != nil || !added {
		t.Fatalf("add Cockroach permission = (%v, %v)", added, err)
	}
	assertCockroachPermissionState(t, engine, permission.GetId(), "tenant/old", true)

	if _, err := engine.Exec("ALTER TABLE permission_rule ADD CONSTRAINT reject_failed_policy CHECK (v0 != 'tenant/fail')"); err != nil {
		t.Fatalf("install injected policy failure: %v", err)
	}
	failedUpdate := *permission
	failedUpdate.Users = []string{"tenant/fail"}
	if updated, err := UpdatePermission(permission.GetId(), &failedUpdate); err == nil || updated {
		t.Fatalf("policy-write failure update = (%v, %v), want rollback", updated, err)
	}
	assertCockroachPermissionState(t, engine, permission.GetId(), "tenant/old", true)

	stored := &Permission{Owner: permission.Owner, Name: permission.Name}
	if existed, err := engine.Get(stored); err != nil || !existed {
		t.Fatalf("read Cockroach permission = (%v, %v)", existed, err)
	}
	stored.ExpireTime = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if updated, err := UpdatePermission(stored.GetId(), stored); err != nil || !updated {
		t.Fatalf("set Cockroach permission expiry = (%v, %v)", updated, err)
	}
	if revoked, err := expirePermissionInTransaction(stored, time.Now().UTC()); err != nil || !revoked {
		t.Fatalf("expire Cockroach permission = (%v, %v)", revoked, err)
	}
	assertCockroachPermissionState(t, engine, permission.GetId(), "", false)

	adapter := &Adapter{Owner: "tenant", Name: "custom-permission", Table: "tenant_permission_rule", UseSameDb: true}
	if added, err := AddAdapter(adapter); err != nil || !added {
		t.Fatalf("add Cockroach custom permission adapter = (%v, %v)", added, err)
	}
	if err := ensureStoredPermissionPolicyTables(engine); err != nil {
		t.Fatalf("repeat Cockroach custom table startup provisioning: %v", err)
	}
	customPermission := &Permission{
		Owner:     "tenant",
		Name:      "cockroach-custom-adapter",
		Adapter:   adapter.Name,
		Users:     []string{"tenant/old"},
		Resources: []string{"resource"},
		Actions:   []string{"read"},
		Effect:    "Allow",
		IsEnabled: true,
	}
	if added, err := AddPermission(customPermission); err != nil || !added {
		t.Fatalf("add Cockroach custom-adapter permission = (%v, %v)", added, err)
	}
	customPolicyCount := struct {
		Count int64 `xorm:"count"`
	}{}
	if _, err := engine.SQL("SELECT count(*) AS count FROM tenant_permission_rule WHERE ptype = ? AND v5 = ?", "p", customPermission.GetId()).Get(&customPolicyCount); err != nil {
		t.Fatalf("count Cockroach custom permission policies: %v", err)
	}
	if customPolicyCount.Count != 1 {
		t.Fatalf("Cockroach custom permission policy count = %d, want one", customPolicyCount.Count)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete Cockroach permission-bound user = (%v, %v), want refusal", deleted, err)
	}
	if deleted, err := DeletePermission(customPermission); err != nil || !deleted {
		t.Fatalf("delete Cockroach custom permission = (%v, %v)", deleted, err)
	}
	if deleted, err := DeletePermission(stored); err != nil || !deleted {
		t.Fatalf("delete Cockroach expired permission = (%v, %v)", deleted, err)
	}
	application := &Application{Owner: "admin", Name: "cockroach-external", ExternalUsers: []string{"tenant/reserved"}}
	if _, err := engine.Insert(application); err != nil {
		t.Fatalf("insert Cockroach reserved external identity: %v", err)
	}
	oldUser := &User{Owner: "tenant", Name: "old"}
	if existed, err := engine.Get(oldUser); err != nil || !existed {
		t.Fatalf("read Cockroach rename source = (%v, %v)", existed, err)
	}
	renamed := *oldUser
	renamed.Name = "reserved"
	if updated, err := UpdateUser("tenant/old", &renamed, []string{"name"}, true); err == nil || updated {
		t.Fatalf("rename Cockroach user into reserved identity = (%v, %v), want refusal", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("Cockroach rename source survived refusal = (%v, %v), want true", existed, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "reserved"}); err != nil || existed {
		t.Fatalf("Cockroach reserved rename destination exists = (%v, %v), want false", existed, err)
	}
	rollbackRole := &Role{Owner: "tenant", Name: "cockroach-rollback-role", Users: []string{"tenant/old"}}
	rollbackResource := &Resource{Owner: "tenant", Name: "/cockroach-rollback", User: "old"}
	if _, err := engine.Insert(rollbackRole, rollbackResource); err != nil {
		t.Fatalf("insert Cockroach rename rollback references: %v", err)
	}
	if _, err := engine.Exec(`ALTER TABLE "user" ADD CONSTRAINT reject_blocked_user_rename CHECK (name != 'blocked')`); err != nil {
		t.Fatalf("install Cockroach user rename failure: %v", err)
	}
	blockedRename := *oldUser
	blockedRename.Name = "blocked"
	if updated, err := UpdateUser("tenant/old", &blockedRename, []string{"name"}, true); err == nil || updated {
		t.Fatalf("injected-failure Cockroach rename = (%v, %v), want rollback", updated, err)
	}
	if existed, err := engine.Get(&User{Owner: "tenant", Name: "old"}); err != nil || !existed {
		t.Fatalf("Cockroach rename source after rollback = (%v, %v), want true", existed, err)
	}
	storedRollbackRole := &Role{Owner: rollbackRole.Owner, Name: rollbackRole.Name}
	if existed, err := engine.Get(storedRollbackRole); err != nil || !existed {
		t.Fatalf("read Cockroach role after rename rollback = (%v, %v)", existed, err)
	}
	if len(storedRollbackRole.Users) != 1 || storedRollbackRole.Users[0] != "tenant/old" {
		t.Fatalf("Cockroach role users after rename rollback = %v, want [tenant/old]", storedRollbackRole.Users)
	}
	storedRollbackResource := &Resource{Owner: rollbackResource.Owner, Name: rollbackResource.Name}
	if existed, err := engine.Get(storedRollbackResource); err != nil || !existed {
		t.Fatalf("read Cockroach resource after rename rollback = (%v, %v)", existed, err)
	}
	if storedRollbackResource.User != "old" {
		t.Fatalf("Cockroach resource user after rename rollback = %q, want old", storedRollbackResource.User)
	}
	if _, err := engine.Delete(rollbackRole); err != nil {
		t.Fatalf("delete Cockroach rollback role: %v", err)
	}
	if _, err := engine.Delete(rollbackResource); err != nil {
		t.Fatalf("delete Cockroach rollback resource: %v", err)
	}
	role := &Role{Owner: "tenant", Name: "cockroach-role", Users: []string{"tenant/old"}}
	if _, err := engine.Insert(role); err != nil {
		t.Fatalf("insert Cockroach user role: %v", err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete Cockroach role-bound user = (%v, %v), want refusal", deleted, err)
	}
	if _, err := engine.Delete(role); err != nil {
		t.Fatalf("delete Cockroach user role: %v", err)
	}
	subscription := &Subscription{Owner: "tenant", Name: "cockroach-subscription", User: "old", State: SubStateExpired}
	if _, err := engine.Insert(subscription); err != nil {
		t.Fatalf("insert Cockroach user subscription: %v", err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err == nil || deleted {
		t.Fatalf("delete Cockroach subscription-bound user = (%v, %v), want refusal", deleted, err)
	}
	if _, err := engine.Delete(subscription); err != nil {
		t.Fatalf("delete Cockroach user subscription: %v", err)
	}
	if deleted, err := deleteUser(&User{Owner: "tenant", Name: "old"}); err != nil || !deleted {
		t.Fatalf("delete Cockroach unbound user = (%v, %v), want success", deleted, err)
	}
	if _, err := engine.Insert(&User{Owner: "tenant", Name: "old"}); err != nil {
		t.Fatalf("recreate Cockroach unbound user: %v", err)
	}
}

func assertCockroachPermissionState(t *testing.T, engine *xorm.Engine, permissionId string, policySubject string, enabled bool) {
	t.Helper()
	stored := &Permission{Owner: "tenant", Name: "cockroach-lifecycle"}
	existed, err := engine.Get(stored)
	if err != nil || !existed {
		t.Fatalf("read permission state = (%v, %v)", existed, err)
	}
	if stored.IsEnabled != enabled {
		t.Fatalf("permission enabled = %v, want %v", stored.IsEnabled, enabled)
	}
	if enabled && (len(stored.Users) != 1 || stored.Users[0] != policySubject) {
		t.Fatalf("permission users = %v, want [%s]", stored.Users, policySubject)
	}
	rules := []*safeCasbinRule{}
	if err := engine.Table("permission_rule").Where("ptype = ? AND v5 = ?", "p", permissionId).Find(&rules); err != nil {
		t.Fatalf("read permission policy state: %v", err)
	}
	if policySubject == "" {
		if len(rules) != 0 {
			t.Fatalf("expired permission retained policies: %#v", rules)
		}
		return
	}
	if len(rules) != 1 || rules[0].V0 != policySubject {
		t.Fatalf("permission policy rows = %#v, want one subject %s", rules, policySubject)
	}
}

func testCockroachSubscriptionRetry(t *testing.T, engine *xorm.Engine) {
	t.Helper()
	const tableName = "subscription_retry_probe"
	if _, err := engine.Exec("CREATE TABLE " + tableName + " (id INT8 PRIMARY KEY, value INT8 NOT NULL)"); err != nil {
		t.Fatalf("create Cockroach retry probe: %v", err)
	}
	t.Cleanup(func() {
		if _, err := engine.Exec("DROP TABLE IF EXISTS " + tableName); err != nil {
			t.Errorf("drop Cockroach retry probe: %v", err)
		}
	})
	if _, err := engine.Exec("INSERT INTO " + tableName + " (id, value) VALUES (1, 0)"); err != nil {
		t.Fatalf("seed Cockroach retry probe: %v", err)
	}

	attempts := 0
	err := retrySubscriptionTransaction(func() error {
		attempts++
		session := engine.NewSession()
		defer session.Close()
		if err := session.Begin(); err != nil {
			return err
		}
		rows, err := session.QueryString("SELECT value FROM " + tableName + " WHERE id = 1")
		if err != nil {
			_ = session.Rollback()
			return err
		}
		if len(rows) != 1 {
			_ = session.Rollback()
			return fmt.Errorf("retry probe returned %d rows", len(rows))
		}
		value, err := strconv.ParseInt(rows[0]["value"], 10, 64)
		if err != nil {
			_ = session.Rollback()
			return err
		}
		if attempts == 1 {
			if _, err = engine.Exec("UPDATE " + tableName + " SET value = value + 1 WHERE id = 1"); err != nil {
				_ = session.Rollback()
				return err
			}
		}
		if _, err = session.Exec("UPDATE "+tableName+" SET value = ? WHERE id = 1", value+10); err != nil {
			_ = session.Rollback()
			return err
		}
		if err = session.Commit(); err != nil {
			_ = session.Rollback()
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry genuine Cockroach serialization failure after %d attempts: %v", attempts, err)
	}
	if attempts != 2 {
		t.Fatalf("genuine Cockroach retry attempts = %d, want 2", attempts)
	}
	result := struct {
		Value int64 `xorm:"value"`
	}{}
	if _, err := engine.SQL("SELECT value FROM " + tableName + " WHERE id = 1").Get(&result); err != nil {
		t.Fatalf("read Cockroach retry result: %v", err)
	}
	if result.Value != 11 {
		t.Fatalf("Cockroach retry result = %d, want 11", result.Value)
	}
}

func newCockroachPolicyModel(t *testing.T, policies [][]string) model.Model {
	t.Helper()
	m, err := model.NewModelFromString(`[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.subOwner == p.subOwner && r.subName == p.subName && r.method == p.method && r.urlPath == p.urlPath && r.objOwner == p.objOwner && r.objName == p.objName`)
	if err != nil {
		t.Fatalf("parse policy model: %v", err)
	}
	for _, policy := range policies {
		m["p"]["p"].Policy = append(m["p"]["p"].Policy, policy)
	}
	return m
}

func assertCockroachPolicyRows(t *testing.T, adapter *SafeAdapter, want [][]string) {
	t.Helper()
	rules, err := adapter.GetRules()
	if err != nil {
		t.Fatalf("GetRules(): %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("GetRules() returned %d rows, want %d: %#v", len(rules), len(want), rules)
	}
	for _, policy := range want {
		found := false
		for _, rule := range rules {
			if rule.Ptype == "p" && rule.V0 == policy[0] && rule.V1 == policy[1] && rule.V2 == policy[2] && rule.V3 == policy[3] && rule.V4 == policy[4] && rule.V5 == policy[5] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("policy %v missing from CockroachDB rows %#v", policy, rules)
		}
	}
}
