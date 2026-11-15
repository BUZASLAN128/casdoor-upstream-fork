package object

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/xorm"
)

type SafeAdapter struct {
	*xormadapter.Adapter
	engine       *xorm.Engine
	tableName    string
	sameDatabase bool
	isFiltered   bool
}

func (a *SafeAdapter) LoadPolicy(m model.Model) error {
	return a.loadFilteredPolicy(m, xormadapter.Filter{}, false)
}

func (a *SafeAdapter) LoadFilteredPolicy(m model.Model, filter interface{}) error {
	filterValue, ok := filter.(xormadapter.Filter)
	if !ok {
		return fmt.Errorf("invalid permission policy filter type %T", filter)
	}

	return a.loadFilteredPolicy(m, filterValue, true)
}

func (a *SafeAdapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *SafeAdapter) loadFilteredPolicy(m model.Model, filter xormadapter.Filter, filtered bool) error {
	rules := []*safeCasbinRule{}
	session := a.engine.NewSession()
	defer session.Close()
	session = safeRuleFilterQuery(session, filter)

	err := session.Table(&safeCasbinRule{tableName: a.policyTableName()}).Find(&rules)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if err = persist.LoadPolicyArray(rule.policyFields(), m); err != nil {
			return err
		}
	}

	a.isFiltered = filtered
	return nil
}

func safeRuleFilterQuery(session *xorm.Session, filter xormadapter.Filter) *xorm.Session {
	fields := []struct {
		column string
		values []string
	}{
		{"ptype", filter.Ptype},
		{"v0", filter.V0},
		{"v1", filter.V1},
		{"v2", filter.V2},
		{"v3", filter.V3},
		{"v4", filter.V4},
		{"v5", filter.V5},
	}
	for _, field := range fields {
		switch len(field.values) {
		case 0:
			continue
		case 1:
			session = session.And(field.column+" = ?", field.values[0])
		default:
			session = session.In(field.column, field.values)
		}
	}
	return session
}

func (rule *safeCasbinRule) policyFields() []string {
	fields := []string{rule.Ptype, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}
	last := len(fields) - 1
	for last > 0 && fields[last] == "" {
		last--
	}
	return fields[:last+1]
}

type safeCasbinRule struct {
	Id    int64  `xorm:"pk autoincr"`
	Ptype string `xorm:"varchar(100) index not null default ''"`
	V0    string `xorm:"varchar(100) index not null default ''"`
	V1    string `xorm:"varchar(100) index not null default ''"`
	V2    string `xorm:"varchar(100) index not null default ''"`
	V3    string `xorm:"varchar(100) index not null default ''"`
	V4    string `xorm:"varchar(100) index not null default ''"`
	V5    string `xorm:"varchar(100) index not null default ''"`

	tableName string `xorm:"-"`
}

func ensurePermissionPolicyTable(engine *xorm.Engine, tableName string) error {
	if !util.FilterSQLIdentifier(tableName) {
		return fmt.Errorf("invalid permission policy table name: %s", tableName)
	}
	exists, err := engine.IsTableExist(tableName)
	if err != nil {
		return err
	}
	if exists {
		rows, err := engine.DB().QueryContext(context.Background(), fmt.Sprintf("SELECT * FROM %s WHERE 1 = 0", engine.Quote(tableName)))
		if err != nil {
			return err
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			return err
		}
		if !isCasbinRuleColumns(columns) {
			return fmt.Errorf("the permission policy table has an incompatible schema: %s (%v)", tableName, columns)
		}
		return nil
	}
	return engine.Sync2(&safeCasbinRule{tableName: tableName})
}

func ensurePermissionPolicyTableForAdapter(engine *xorm.Engine, adapter *Adapter) error {
	if adapter == nil || adapter.Table == "" || (!adapter.UseSameDb && !adapter.isBuiltIn()) {
		return nil
	}
	return ensurePermissionPolicyTable(engine, conf.GetConfigString("tableNamePrefix")+adapter.Table)
}

func ensureStoredPermissionPolicyTables(engine *xorm.Engine) error {
	adapters := []*Adapter{}
	if err := engine.Find(&adapters); err != nil {
		return err
	}
	for _, adapter := range adapters {
		if err := ensurePermissionPolicyTableForAdapter(engine, adapter); err != nil {
			return fmt.Errorf("provision permission policy table for adapter %s: %w", adapter.GetId(), err)
		}
	}
	return nil
}

func (rule *safeCasbinRule) TableName() string {
	if rule.tableName == "" {
		return "casbin_rule"
	}
	return rule.tableName
}

func NewSafeAdapter(a *Adapter) *SafeAdapter {
	if a == nil || a.Adapter == nil || a.engine == nil {
		return nil
	}

	return &SafeAdapter{
		Adapter:      a.Adapter,
		engine:       a.engine,
		tableName:    a.Table,
		sameDatabase: a.UseSameDb || a.isBuiltIn(),
	}
}

func (a *SafeAdapter) SavePolicy(model model.Model) error {
	lines := make([]*safeCasbinRule, 0, 64)

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.buildCasbinRule(ptype, rule))
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.buildCasbinRule(ptype, rule))
		}
	}

	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		_, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE ptype IS NOT NULL", a.quotedPolicyTableName()))
		if err != nil {
			return nil, err
		}

		for _, line := range lines {
			if err = a.insertRule(tx, line); err != nil {
				return nil, err
			}
		}

		return nil, nil
	})
	return err
}

func (a *SafeAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	session := a.engine.NewSession()
	defer session.Close()
	return a.insertRule(session, a.buildCasbinRule(ptype, rule))
}

func (a *SafeAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for _, rule := range rules {
			if err := a.insertRule(tx, a.buildCasbinRule(ptype, rule)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (a *SafeAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := a.buildCasbinRule(ptype, rule)

	session := a.engine.NewSession()
	defer session.Close()
	return a.deleteRule(session, line)
}

func (a *SafeAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for _, rule := range rules {
			if err := a.deleteRule(tx, a.buildCasbinRule(ptype, rule)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (a *SafeAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	if fieldIndex < 0 || fieldIndex > 5 || fieldIndex+len(fieldValues) > 6 {
		return fmt.Errorf("invalid filtered policy range: index=%d values=%d", fieldIndex, len(fieldValues))
	}

	conditions := []string{"ptype = ?"}
	args := []any{ptype}
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		conditions = append(conditions, fmt.Sprintf("v%d = ?", fieldIndex+i))
		args = append(args, value)
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE %s", a.quotedPolicyTableName(), strings.Join(conditions, " AND "))
	_, err := a.engine.Exec(append([]any{query}, args...)...)
	return err
}

func (a *SafeAdapter) UpdatePolicy(sec string, ptype string, oldRule []string, newRule []string) error {
	oldLine := a.buildCasbinRule(ptype, oldRule)
	newLine := a.buildCasbinRule(ptype, newRule)

	session := a.engine.NewSession()
	defer session.Close()
	_, err := session.Exec(fmt.Sprintf("UPDATE %s SET ptype = ?, v0 = ?, v1 = ?, v2 = ?, v3 = ?, v4 = ?, v5 = ? WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?", a.quotedPolicyTableName()),
		newLine.Ptype, newLine.V0, newLine.V1, newLine.V2, newLine.V3, newLine.V4, newLine.V5,
		oldLine.Ptype, oldLine.V0, oldLine.V1, oldLine.V2, oldLine.V3, oldLine.V4, oldLine.V5)
	return err
}

func (a *SafeAdapter) UpdatePolicies(sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return fmt.Errorf("old and new policy counts differ: %d != %d", len(oldRules), len(newRules))
	}
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for i, oldRule := range oldRules {
			oldLine := a.buildCasbinRule(ptype, oldRule)
			newLine := a.buildCasbinRule(ptype, newRules[i])

			_, err := tx.Exec(fmt.Sprintf("UPDATE %s SET ptype = ?, v0 = ?, v1 = ?, v2 = ?, v3 = ?, v4 = ?, v5 = ? WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?", a.quotedPolicyTableName()),
				newLine.Ptype, newLine.V0, newLine.V1, newLine.V2, newLine.V3, newLine.V4, newLine.V5,
				oldLine.Ptype, oldLine.V0, oldLine.V1, oldLine.V2, oldLine.V3, oldLine.V4, oldLine.V5)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (a *SafeAdapter) GetRules() ([]*xormadapter.CasbinRule, error) {
	rules := []*safeCasbinRule{}
	session := a.engine.NewSession()
	defer session.Close()

	err := session.Table(&safeCasbinRule{tableName: a.policyTableName()}).Find(&rules)
	if err != nil {
		return nil, err
	}

	res := make([]*xormadapter.CasbinRule, 0, len(rules))
	for _, rule := range rules {
		res = append(res, rule.toXormCasbinRule())
	}
	return res, nil
}

func (a *SafeAdapter) policyTableName() string {
	if a.tableName == "" {
		return "casbin_rule"
	}
	return a.tableName
}

func (a *SafeAdapter) quotedPolicyTableName() string {
	return a.engine.Quote(a.policyTableName())
}

func (a *SafeAdapter) insertRule(session *xorm.Session, line *safeCasbinRule) error {
	_, err := session.Exec(fmt.Sprintf("INSERT INTO %s (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", a.quotedPolicyTableName()),
		line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	return err
}

func (a *SafeAdapter) deleteRule(session *xorm.Session, line *safeCasbinRule) error {
	_, err := session.Exec(fmt.Sprintf("DELETE FROM %s WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?", a.quotedPolicyTableName()),
		line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	return err
}

func (a *SafeAdapter) buildCasbinRule(ptype string, rule []string) *safeCasbinRule {
	line := safeCasbinRule{Ptype: ptype, tableName: a.policyTableName()}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	return &line
}

func (rule *safeCasbinRule) toXormCasbinRule() *xormadapter.CasbinRule {
	return &xormadapter.CasbinRule{
		Id:    rule.Id,
		Ptype: rule.Ptype,
		V0:    rule.V0,
		V1:    rule.V1,
		V2:    rule.V2,
		V3:    rule.V3,
		V4:    rule.V4,
		V5:    rule.V5,
	}
}
