// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type Permission struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"mediumtext" json:"description"`

	Users   []string `xorm:"mediumtext" json:"users"`
	Groups  []string `xorm:"mediumtext" json:"groups"`
	Roles   []string `xorm:"mediumtext" json:"roles"`
	Domains []string `xorm:"mediumtext" json:"domains"`
	// Agents and Conditions are for the "MCP tool" permissions of the MCP gateway
	Agents     []string               `xorm:"mediumtext" json:"agents"`
	Conditions []*PermissionCondition `xorm:"mediumtext" json:"conditions"`

	// SourceGroups and SourceRoles are only set when the permission is resolved for a user, both being empty means it was assigned directly
	SourceGroups []string `xorm:"-" json:"sourceGroups,omitempty"`
	SourceRoles  []string `xorm:"-" json:"sourceRoles,omitempty"`

	Model        string   `xorm:"varchar(100)" json:"model"`
	Adapter      string   `xorm:"varchar(100)" json:"adapter"`
	ResourceType string   `xorm:"varchar(100)" json:"resourceType"`
	Resources    []string `xorm:"mediumtext" json:"resources"`
	Actions      []string `xorm:"mediumtext" json:"actions"`
	Effect       string   `xorm:"varchar(100)" json:"effect"`
	IsEnabled    bool     `json:"isEnabled"`

	// ExpireTime is an optional RFC3339 timestamp. When set and reached, the permission
	// is automatically revoked (its Casbin policies are removed and it is disabled) by the
	// permission expiration job, providing time-limited access as required by standards
	// such as ISO/IEC 27001 control 5.18. An empty value means the permission never expires.
	ExpireTime string `xorm:"varchar(100)" json:"expireTime"`

	Submitter   string `xorm:"varchar(100)" json:"submitter"`
	Approver    string `xorm:"varchar(100)" json:"approver"`
	ApproveTime string `xorm:"varchar(100)" json:"approveTime"`
	State       string `xorm:"varchar(100)" json:"state"`
}

const builtInMaxFields = 6 // Casdoor built-in adapter, use V5 to filter permission, so has 6 max field

func GetPermissionCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Permission{})
}

func GetPermissions(owner string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPaginationPermissions(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Permission, error) {
	permissions := []*Permission{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&permissions)
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func getPermission(owner string, name string) (*Permission, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	permission := Permission{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&permission)
	if err != nil {
		return &permission, err
	}

	if existed {
		return &permission, nil
	} else {
		return nil, nil
	}
}

func GetPermission(id string) (*Permission, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getPermission(owner, name)
}

// checkPermissionValid verifies if the permission is valid
func checkPermissionValid(permission *Permission) error {
	enforcer, err := getPermissionEnforcer(permission)
	if err != nil {
		return err
	}

	enforcer.EnableAutoSave(false)

	policies := getPolicies(permission)
	_, err = enforcer.AddPolicies(policies)
	if err != nil {
		return err
	}

	if !HasRoleDefinition(enforcer.GetModel()) {
		permission.Roles = []string{}
	}

	if !HasDomainDefinition(enforcer.GetModel()) {
		permission.Domains = []string{}
	}

	return nil
}

// checkPermissionModel verifies that the model referenced by an "Application" permission exists and is valid.
func checkPermissionModel(permission *Permission) error {
	if permission.ResourceType == "Application" && permission.Model != "" {
		model, err := getModelEx(permission.Model)
		if err != nil {
			return err
		} else if model == nil {
			return fmt.Errorf("the model: %s for permission: %s is not found", permission.Model, permission.GetId())
		}

		modelCfg, err := getModelCfg(model)
		if err != nil {
			return err
		}

		if len(strings.Split(modelCfg["p"], ",")) != 3 {
			return fmt.Errorf("the model: %s for permission: %s is not valid, Casbin model's [policy_defination] section should have 3 elements", permission.Model, permission.GetId())
		}
	}

	return nil
}

func permissionGovernanceOwners(permission *Permission) ([]string, error) {
	owners := []string{permission.Owner}
	references := append([]string{}, permission.Users...)
	references = append(references, permission.Groups...)
	references = append(references, permission.Roles...)
	for _, reference := range references {
		if reference == "*" {
			continue
		}
		owner, _, err := util.GetOwnerAndNameFromIdWithError(reference)
		if err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	return owners, nil
}

func lockPermissionGovernance(session *xorm.Session, permissions ...*Permission) error {
	owners := []string{}
	for _, permission := range permissions {
		if permission == nil {
			continue
		}
		permissionOwners, err := permissionGovernanceOwners(permission)
		if err != nil {
			return err
		}
		owners = append(owners, permissionOwners...)
	}
	return lockGovernanceScopes(session, owners...)
}

func permissionGovernanceLocksCover(candidates []*Permission, current *Permission) (bool, error) {
	lockedOwners := map[string]bool{}
	for _, candidate := range candidates {
		owners, err := permissionGovernanceOwners(candidate)
		if err != nil {
			return false, err
		}
		for _, owner := range owners {
			lockedOwners[owner] = true
		}
	}
	currentOwners, err := permissionGovernanceOwners(current)
	if err != nil {
		return false, err
	}
	for _, owner := range currentOwners {
		if !lockedOwners[owner] {
			return false, nil
		}
	}
	return true, nil
}

func validatePermissionReferencesInSession(session *xorm.Session, permission *Permission) error {
	for _, userId := range permission.Users {
		if userId == "*" {
			continue
		}
		userOwner, userName, err := util.GetOwnerAndNameFromIdWithError(userId)
		if err != nil {
			return err
		}
		if userName == "*" {
			continue
		}
		existed, err := session.ID(core.PK{userOwner, userName}).Exist(&User{})
		if err != nil {
			return err
		}
		if !existed {
			return fmt.Errorf("the permission user does not exist: %s", userId)
		}
	}
	for _, groupId := range permission.Groups {
		groupId = getPermissionGroupId(permission.Owner, groupId)
		groupOwner, groupName, err := util.GetOwnerAndNameFromIdWithError(groupId)
		if err != nil {
			return err
		}
		if groupName == "*" {
			continue
		}
		existed, err := session.ID(core.PK{groupOwner, groupName}).Exist(&Group{})
		if err != nil {
			return err
		}
		if !existed {
			return fmt.Errorf("the permission group does not exist: %s", groupId)
		}
	}
	for _, roleId := range permission.Roles {
		if roleId == "*" {
			roleId = util.GetId(permission.Owner, "*")
		}
		roleOwner, roleName, err := util.GetOwnerAndNameFromIdWithError(roleId)
		if err != nil {
			return err
		}
		if roleName == "*" {
			continue
		}
		existed, err := session.ID(core.PK{roleOwner, roleName}).Exist(&Role{})
		if err != nil {
			return err
		}
		if !existed {
			return fmt.Errorf("the permission role does not exist: %s", roleId)
		}
	}
	return nil
}

func permissionPolicyTableName(session *xorm.Session, permission *Permission) (string, error) {
	return resolvePermissionPolicyTableName(session, permission, true)
}

func resolvePermissionPolicyTableName(session *xorm.Session, permission *Permission, lock bool) (string, error) {
	tableName := "permission_rule"
	if permission.Adapter != "" {
		adapter := &Adapter{Owner: permission.Owner, Name: permission.Adapter}
		query := session
		if lock {
			query = query.ForUpdate()
		}
		existed, err := query.Get(adapter)
		if err != nil {
			return "", err
		}
		if !existed {
			return "", fmt.Errorf("the permission adapter does not exist: %s/%s", permission.Owner, permission.Adapter)
		}
		if !adapter.UseSameDb && !adapter.isBuiltIn() {
			return "", fmt.Errorf("the permission adapter must use Casdoor's database: %s", adapter.GetId())
		}
		if adapter.Table != "" {
			tableName = adapter.Table
		}
	}
	tableName = conf.GetConfigString("tableNamePrefix") + tableName
	if !util.FilterSQLIdentifier(tableName) {
		return "", fmt.Errorf("the permission policy table name is invalid: %s", tableName)
	}
	return tableName, nil
}

func removePermissionPoliciesInSession(session *xorm.Session, permission *Permission) error {
	tableName, err := permissionPolicyTableName(session, permission)
	if err != nil {
		return err
	}
	_, err = session.Exec(fmt.Sprintf("DELETE FROM %s WHERE ptype = ? AND v5 = ?", ormer.Engine.Quote(tableName)), "p", permission.GetId())
	return err
}

func addPermissionPoliciesInSession(session *xorm.Session, permission *Permission) error {
	tableName, err := permissionPolicyTableName(session, permission)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, policy := range getPolicies(permission) {
		key := getPolicyKey(policy)
		if seen[key] {
			continue
		}
		seen[key] = true
		rule := &safeCasbinRule{Ptype: "p"}
		if len(policy) > 0 {
			rule.V0 = policy[0]
		}
		if len(policy) > 1 {
			rule.V1 = policy[1]
		}
		if len(policy) > 2 {
			rule.V2 = policy[2]
		}
		if len(policy) > 3 {
			rule.V3 = policy[3]
		}
		if len(policy) > 4 {
			rule.V4 = policy[4]
		}
		if len(policy) > 5 {
			rule.V5 = policy[5]
		}
		query := fmt.Sprintf("INSERT INTO %s (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", ormer.Engine.Quote(tableName))
		if _, err = session.Exec(query, rule.Ptype, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5); err != nil {
			return err
		}
	}
	return nil
}

func replacePermissionPoliciesInSession(session *xorm.Session, oldPermission *Permission, newPermission *Permission) error {
	if err := removePermissionPoliciesInSession(session, oldPermission); err != nil {
		return err
	}
	return addPermissionPoliciesInSession(session, newPermission)
}

func UpdatePermission(id string, permission *Permission) (bool, error) {
	err := checkPermissionValid(permission)
	if err != nil {
		return false, err
	}

	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldPermission, err := getPermission(owner, name)
	if err != nil {
		return false, err
	}
	if oldPermission == nil {
		return false, nil
	}
	updated := *permission
	updated.Owner = owner
	updated.Name = name
	err = checkPermissionModel(&updated)
	if err != nil {
		return false, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err = lockPermissionGovernance(session, oldPermission, &updated); err != nil {
		return rollback(err)
	}
	lockedOld := &Permission{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(lockedOld)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	covered, err := permissionGovernanceLocksCover([]*Permission{oldPermission, &updated}, lockedOld)
	if err != nil {
		return rollback(err)
	}
	if !covered {
		return rollback(fmt.Errorf("the permission governance references changed while updating it: %s", lockedOld.GetId()))
	}
	if err = validatePermissionReferencesInSession(session, &updated); err != nil {
		return rollback(err)
	}
	affected, err := session.ID(core.PK{owner, name}).AllCols().Update(&updated)
	if err != nil {
		return rollback(err)
	}
	if affected != 0 {
		if err = replacePermissionPoliciesInSession(session, lockedOld, &updated); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	*permission = updated
	return affected != 0, nil
}

// UpdatePermissions commits each permission row and its persisted Casbin policy rows in one
// transaction, while governance locks serialize changes to referenced groups and roles.
func UpdatePermissions(permissions []*Permission) (bool, error) {
	if len(permissions) == 0 {
		return false, nil
	}

	lockCandidates := make([]*Permission, 0, len(permissions)*2)
	updatedPermissions := make([]*Permission, 0, len(permissions))
	for _, permission := range permissions {
		err := checkPermissionValid(permission)
		if err != nil {
			return false, err
		}
		owner, name := util.GetOwnerAndNameFromIdNoCheck(permission.GetId())
		oldPermission, err := getPermission(owner, name)
		if err != nil {
			return false, err
		}
		if oldPermission == nil {
			continue
		}
		updated := *permission
		updated.Owner = owner
		updated.Name = name
		err = checkPermissionModel(&updated)
		if err != nil {
			return false, err
		}
		updatedPermissions = append(updatedPermissions, &updated)
		lockCandidates = append(lockCandidates, oldPermission, &updated)
	}
	if len(updatedPermissions) == 0 {
		return false, nil
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockPermissionGovernance(session, lockCandidates...); err != nil {
		return rollback(err)
	}
	newPermissions := make([]*Permission, 0, len(updatedPermissions))
	for _, updated := range updatedPermissions {
		lockedOld := &Permission{Owner: updated.Owner, Name: updated.Name}
		existed, err := session.ForUpdate().Get(lockedOld)
		if err != nil {
			return rollback(err)
		}
		if !existed {
			continue
		}
		covered, err := permissionGovernanceLocksCover(lockCandidates, lockedOld)
		if err != nil {
			return rollback(err)
		}
		if !covered {
			return rollback(fmt.Errorf("the permission governance references changed while updating it: %s", lockedOld.GetId()))
		}
		if err = validatePermissionReferencesInSession(session, updated); err != nil {
			return rollback(err)
		}
		affected, err := session.ID(core.PK{updated.Owner, updated.Name}).AllCols().Update(updated)
		if err != nil {
			return rollback(err)
		}
		if affected != 0 {
			if err = replacePermissionPoliciesInSession(session, lockedOld, updated); err != nil {
				return rollback(err)
			}
			newPermissions = append(newPermissions, updated)
		}
	}
	if err := session.Commit(); err != nil {
		return rollback(err)
	}
	if len(newPermissions) == 0 {
		return false, nil
	}
	return true, nil
}

// AddPermissionWithCheck also validates the permission's model, the same way UpdatePermission()
// does it. AddPermission() itself cannot do this because it is used to create the built-in
// permission before the built-in model exists.
func AddPermissionWithCheck(permission *Permission) (bool, error) {
	err := checkPermissionModel(permission)
	if err != nil {
		return false, err
	}

	return AddPermission(permission)
}

func AddPermission(permission *Permission) (bool, error) {
	err := checkPermissionValid(permission)
	if err != nil {
		return false, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err = lockPermissionGovernance(session, permission); err != nil {
		return rollback(err)
	}
	if err = validatePermissionReferencesInSession(session, permission); err != nil {
		return rollback(err)
	}
	affected, err := session.Insert(permission)
	if err != nil {
		return rollback(err)
	}
	if affected != 0 {
		if err = addPermissionPoliciesInSession(session, permission); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}

	return affected != 0, nil
}

func AddPermissions(permissions []*Permission) (bool, error) {
	if len(permissions) == 0 {
		return false, nil
	}
	for _, permission := range permissions {
		if err := checkPermissionValid(permission); err != nil {
			return false, err
		}
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockPermissionGovernance(session, permissions...); err != nil {
		return rollback(err)
	}
	for _, permission := range permissions {
		if err := validatePermissionReferencesInSession(session, permission); err != nil {
			return rollback(err)
		}
	}
	affected, err := session.Insert(permissions)
	if err != nil {
		_ = session.Rollback()
		if strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return false, nil
		}
		return false, err
	}
	if affected != 0 {
		for _, permission := range permissions {
			if err = addPermissionPoliciesInSession(session, permission); err != nil {
				return rollback(err)
			}
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}

func AddPermissionsInBatch(permissions []*Permission) (bool, error) {
	batchSize := conf.GetConfigBatchSize()

	if len(permissions) == 0 {
		return false, nil
	}

	affected := false
	for i := 0; i < len(permissions); i += batchSize {
		start := i
		end := i + batchSize
		if end > len(permissions) {
			end = len(permissions)
		}

		tmp := permissions[start:end]
		fmt.Printf("The syncer adds permissions: [%d - %d]\n", start, end)

		b, err := AddPermissions(tmp)
		if err != nil {
			return false, err
		}

		if b {
			affected = true
		}
	}

	return affected, nil
}

func deletePermission(permission *Permission) (bool, error) {
	affected, _, err := deletePermissionRecord(permission)
	return affected, err
}

func deletePermissionRecord(permission *Permission) (bool, *Permission, error) {
	snapshot, err := getPermission(permission.Owner, permission.Name)
	if err != nil {
		return false, nil, err
	}
	if snapshot == nil {
		return false, nil, nil
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, nil, err
	}
	rollback := func(err error) (bool, *Permission, error) {
		_ = session.Rollback()
		return false, nil, err
	}
	if err := lockPermissionGovernance(session, snapshot); err != nil {
		return rollback(err)
	}
	stored := &Permission{Owner: permission.Owner, Name: permission.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil, nil
	}
	covered, err := permissionGovernanceLocksCover([]*Permission{snapshot}, stored)
	if err != nil {
		return rollback(err)
	}
	if !covered {
		return rollback(fmt.Errorf("the permission governance references changed while deleting it: %s", stored.GetId()))
	}
	if err = removePermissionPoliciesInSession(session, stored); err != nil {
		return rollback(err)
	}
	affected, err := session.ID(core.PK{stored.Owner, stored.Name}).Delete(&Permission{})
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, stored, nil
}

func DeletePermission(permission *Permission) (bool, error) {
	affected, _, err := deletePermissionRecord(permission)
	if err != nil {
		return false, err
	}
	return affected, nil
}

func getPermissionsByUser(userId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Where("users like ?", "%"+userId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	res := []*Permission{}
	for _, permission := range permissions {
		if util.InSlice(permission.Users, userId) {
			res = append(res, permission)
		}
	}

	return res, nil
}

func getPermissionsByGroup(groupId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Where("`groups` like ?", "%"+groupId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	res := []*Permission{}
	for _, permission := range permissions {
		if util.InSlice(permission.Groups, groupId) {
			res = append(res, permission)
		}
	}

	return res, nil
}

func GetPermissionsByRole(roleId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Where("roles like ?", "%"+roleId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	res := []*Permission{}
	for _, permission := range permissions {
		if util.InSlice(permission.Roles, roleId) {
			res = append(res, permission)
		}
	}

	return res, nil
}

func GetPermissionsByResource(resourceId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Where("resources like ?", "%"+resourceId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	res := []*Permission{}
	for _, permission := range permissions {
		if util.InSlice(permission.Resources, resourceId) {
			res = append(res, permission)
		}
	}

	return res, nil
}

func getPermissionsAndRolesByUser(userId string) ([]*Permission, []*Role, error) {
	permissions, err := getPermissionsByUser(userId)
	if err != nil {
		return nil, nil, err
	}

	existedPerms := map[string]*Permission{}
	directPerms := map[string]bool{}

	for _, perm := range permissions {
		perm.Users = nil

		if _, ok := existedPerms[perm.Name]; !ok {
			existedPerms[perm.Name] = perm
		}
		directPerms[perm.Name] = true
	}

	addPermission := func(perm *Permission) *Permission {
		perm.Users = nil

		existedPerm, ok := existedPerms[perm.Name]
		if !ok {
			existedPerms[perm.Name] = perm
			permissions = append(permissions, perm)
			return perm
		}
		return existedPerm
	}

	user, err := GetUser(userId)
	if err != nil {
		return nil, nil, err
	}
	if user != nil {
		groupIds := append([]string{}, user.Groups...)
		if len(user.Groups) > 0 {
			groupIds = append(groupIds, "*", util.GetId(user.Owner, "*"))
		}

		for _, groupId := range groupIds {
			perms, err := getPermissionsByGroup(groupId)
			if err != nil {
				return nil, nil, err
			}
			for _, perm := range perms {
				existedPerm := addPermission(perm)
				if !util.InSlice(existedPerm.SourceGroups, groupId) {
					existedPerm.SourceGroups = append(existedPerm.SourceGroups, groupId)
				}
			}
		}
	}

	roles, err := getRolesByUser(userId)
	if err != nil {
		return nil, nil, err
	}

	for _, role := range roles {
		roleId := role.GetId()
		perms, err := GetPermissionsByRole(roleId)
		if err != nil {
			return nil, nil, err
		}
		for _, perm := range perms {
			existedPerm := addPermission(perm)
			if !util.InSlice(existedPerm.SourceRoles, roleId) {
				existedPerm.SourceRoles = append(existedPerm.SourceRoles, roleId)
			}
		}
	}

	for _, perm := range permissions {
		if directPerms[perm.Name] {
			perm.SourceGroups = nil
			perm.SourceRoles = nil
		}
	}

	return permissions, roles, nil
}

func GetPermissionsBySubmitter(owner string, submitter string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner, Submitter: submitter})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPermissionsByModel(owner string, model string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := ormer.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner, Model: model})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetMaskedPermissions(permissions []*Permission) []*Permission {
	for _, permission := range permissions {
		permission.Users = nil
		permission.Submitter = ""
	}

	return permissions
}

// GroupPermissionsByModelAdapter group permissions by model and adapter.
// Every model and adapter will be a key, and the value is a list of permission ids.
// With each list of permission ids have the same key, we just need to init the
// enforcer and do the enforce/batch-enforce once (with list of permission ids
// as the policyFilter when the enforcer load policy).
func GroupPermissionsByModelAdapter(permissions []*Permission) map[string][]string {
	m := make(map[string][]string)
	for _, permission := range permissions {
		key := permission.GetModelAndAdapter()
		permissionIds, ok := m[key]
		if !ok {
			m[key] = []string{permission.GetId()}
		} else {
			m[key] = append(permissionIds, permission.GetId())
		}
	}

	return m
}

func (p *Permission) GetId() string {
	return util.GetId(p.Owner, p.Name)
}

func (p *Permission) GetModelAndAdapter() string {
	return util.GetId(p.Model, p.Adapter)
}

func (p *Permission) isUserHit(name string) bool {
	targetOrg, targetName, err := util.GetOwnerAndNameFromIdWithError(name)
	if err != nil {
		return false
	}
	for _, user := range p.Users {
		if user == "*" {
			return true
		}

		userOrg, userName, err := util.GetOwnerAndNameFromIdWithError(user)
		if err != nil {
			continue
		}
		if userOrg == targetOrg && (userName == "*" || userName == targetName) {
			return true
		}
	}
	return false
}

func (p *Permission) isGroupHit(userId string) bool {
	user, err := GetUser(userId)
	if err != nil || user == nil {
		return false
	}
	return len(p.getGroupSubjectsForUser(user)) > 0
}

// Keep the exact policy subjects rather than just a boolean. A user being
// created by signup is not in the database yet, so the permission enforcer's
// runtime grouping policies cannot contain it. Evaluating the matching group
// subjects directly preserves the same policy before the account is written.
func (p *Permission) getGroupSubjectsForUser(user *User) []string {
	if user == nil {
		return nil
	}

	res := []string{}
	for _, group := range p.Groups {
		if (group == "*" || group == util.GetId(p.Owner, "*")) && len(user.Groups) > 0 {
			res = append(res, getPermissionGroupSubject(p.Owner, group))
			continue
		}

		if util.InSlice(user.Groups, group) {
			res = append(res, getPermissionGroupSubject(p.Owner, group))
		}
	}
	return res
}

func (p *Permission) isRoleHit(userId string) bool {
	targetRoles, err := getRolesByUser(userId)
	if err != nil {
		return false
	}

	for _, role := range p.Roles {
		if role == "*" {
			return true
		}

		for _, targetRole := range targetRoles {
			if role == targetRole.GetId() {
				return true
			}
		}
	}
	return false
}

func (p *Permission) isResourceHit(name string) bool {
	for _, resource := range p.Resources {
		if resource == "*" || resource == name {
			return true
		}
	}
	return false
}
