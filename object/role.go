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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type Role struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"mediumtext" json:"description"`

	Users     []string `xorm:"mediumtext" json:"users"`
	Groups    []string `xorm:"mediumtext" json:"groups"`
	Roles     []string `xorm:"mediumtext" json:"roles"`
	Domains   []string `xorm:"mediumtext" json:"domains"`
	IsEnabled bool     `json:"isEnabled"`

	// SourceGroups is only set when the role is resolved for a user, empty means it was assigned directly
	SourceGroups []string `xorm:"-" json:"sourceGroups,omitempty"`
}

func GetRoleCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Role{})
}

func GetRoles(owner string) ([]*Role, error) {
	roles := []*Role{}
	err := ormer.Engine.Desc("created_time").Find(&roles, &Role{Owner: owner})
	if err != nil {
		return roles, err
	}

	return roles, nil
}

func GetPaginationRoles(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Role, error) {
	roles := []*Role{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&roles)
	if err != nil {
		return roles, err
	}

	return roles, nil
}

func getRole(owner string, name string) (*Role, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	role := Role{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&role)
	if err != nil {
		return &role, err
	}

	if existed {
		return &role, nil
	} else {
		return nil, nil
	}
}

func GetRole(id string) (*Role, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getRole(owner, name)
}

func UpdateRole(id string, role *Role, isGlobalAdmin bool, lang string) (bool, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, owner); err != nil {
		return rollback(err)
	}

	oldRole := &Role{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(oldRole)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}

	if !isGlobalAdmin && oldRole.Owner != role.Owner {
		return rollback(errors.New(i18n.Translate(lang, "auth:Unauthorized operation")))
	}
	updated := *role
	updated.Owner = owner
	renameRole := name != updated.Name
	if renameRole {
		target := &Role{Owner: owner, Name: updated.Name}
		targetExists, targetErr := session.ForUpdate().Get(target)
		if targetErr != nil {
			return rollback(targetErr)
		}
		if targetExists {
			return rollback(fmt.Errorf("the target role already exists: %s", target.GetId()))
		}
		usedByPlan, checkErr := hasPlanUsingRoleInSession(session, owner, util.GetId(owner, name))
		if checkErr != nil {
			return rollback(checkErr)
		}
		if usedByPlan {
			return rollback(fmt.Errorf("the role cannot be renamed while a plan depends on it: %s", id))
		}
		usedByPam, checkErr := hasPamRoleDependencyInSession(session, owner, name)
		if checkErr != nil {
			return rollback(checkErr)
		}
		if usedByPam {
			return rollback(fmt.Errorf("the role cannot be renamed while privileged access depends on it: %s", id))
		}
		updated.Roles = util.ReplaceVal(updated.Roles, util.GetId(owner, name), util.GetId(owner, updated.Name))
	}
	if err = CheckRoleSodChangeInSession(session, name, &updated, lang); err != nil {
		return rollback(err)
	}

	oldPermissions := []*Permission{}
	newPermissions := []*Permission{}
	if renameRole {
		oldPermissions, newPermissions, err = roleChangeReferencesInSession(session, owner, name, updated.Name)
		if err != nil {
			return rollback(err)
		}
	}

	affected, err := session.ID(core.PK{owner, name}).AllCols().Update(&updated)
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	*role = updated

	if renameRole && affected != 0 {
		for _, permission := range oldPermissions {
			if err = removePolicies(permission); err != nil {
				return true, fmt.Errorf("the role was renamed but removing its old permission policy failed: %w", err)
			}
		}
		for _, permission := range newPermissions {
			if err = addPolicies(permission); err != nil {
				return true, fmt.Errorf("the role was renamed but adding its new permission policy failed: %w", err)
			}
		}
	}

	return affected != 0, nil
}

func AddRole(role *Role) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, role.Owner); err != nil {
		return rollback(err)
	}
	if err := CheckRoleSodInSession(session, role, ""); err != nil {
		return rollback(err)
	}
	affected, err := session.Insert(role)
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}

	return affected != 0, nil
}

func AddRoles(roles []*Role) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	owners := map[string]bool{}
	for _, role := range roles {
		owners[role.Owner] = true
	}
	ownerNames := make([]string, 0, len(owners))
	for owner := range owners {
		ownerNames = append(ownerNames, owner)
	}
	sort.Strings(ownerNames)
	for _, owner := range ownerNames {
		if err := lockGovernanceScope(session, owner); err != nil {
			_ = session.Rollback()
			return false, err
		}
	}
	affected := int64(0)
	for _, role := range roles {
		if err := CheckRoleSodInSession(session, role, ""); err != nil {
			_ = session.Rollback()
			return false, err
		}
		inserted, err := session.Insert(role)
		if err != nil {
			_ = session.Rollback()
			if !strings.Contains(err.Error(), "Duplicate entry") {
				return false, err
			}
			return false, nil
		}
		affected += inserted
	}
	if err := session.Commit(); err != nil {
		_ = session.Rollback()
		return false, err
	}
	return affected != 0, nil
}

func AddRolesInBatch(roles []*Role) (bool, error) {
	batchSize := conf.GetConfigBatchSize()

	if len(roles) == 0 {
		return false, nil
	}

	affected := false
	for i := 0; i < len(roles); i += batchSize {
		start := i
		end := i + batchSize
		if end > len(roles) {
			end = len(roles)
		}

		tmp := roles[start:end]
		fmt.Printf("The syncer adds roles: [%d - %d]\n", start, end)
		ok, err := AddRoles(tmp)
		if err != nil {
			return false, err
		}
		if ok {
			affected = true
		}
	}

	return affected, nil
}

func deleteRole(role *Role) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{role.Owner, role.Name}).Delete(&Role{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteRole(role *Role) (bool, error) {
	roleId := role.GetId()
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, role.Owner); err != nil {
		return rollback(err)
	}
	stored := &Role{Owner: role.Owner, Name: role.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	usedByPlan, err := hasPlanUsingRoleInSession(session, role.Owner, roleId)
	if err != nil {
		return rollback(err)
	}
	if usedByPlan {
		return rollback(fmt.Errorf("the role cannot be deleted while a plan depends on it: %s", roleId))
	}
	usedByPam, err := hasPamRoleDependencyInSession(session, role.Owner, role.Name)
	if err != nil {
		return rollback(err)
	}
	if usedByPam {
		return rollback(fmt.Errorf("the role cannot be deleted while privileged access depends on it: %s", roleId))
	}

	permissions, err := GetPermissionsByRole(roleId)
	if err != nil {
		return rollback(err)
	}

	for _, permission := range permissions {
		permission.Roles = util.DeleteVal(permission.Roles, roleId)
		_, err := UpdatePermission(permission.GetId(), permission)
		if err != nil {
			return rollback(err)
		}
	}

	affected, err := session.ID(core.PK{role.Owner, role.Name}).Delete(&Role{})
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}

func hasPamRoleDependencyInSession(session *xorm.Session, owner string, roleName string) (bool, error) {
	accountCount, err := session.Where("owner = ? and type = ? and role = ?", owner, PamTypeRole, roleName).Count(&PrivilegedAccount{})
	if err != nil {
		return false, err
	}
	if accountCount != 0 {
		return true, nil
	}
	requestCount, err := session.Where("owner = ? and role = ? and role_added = ?", owner, roleName, true).Count(&PrivilegedRequest{})
	if err != nil {
		return false, err
	}
	return requestCount != 0, nil
}

func (role *Role) GetId() string {
	return fmt.Sprintf("%s/%s", role.Owner, role.Name)
}

func getRolesByUserInternal(userId string) ([]*Role, map[string][]string, error) {
	user, err := GetUser(userId)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, fmt.Errorf("The user: %s doesn't exist", userId)
	}
	return getRolesBySuppliedUserInternal(userId, user)
}

// getRolesBySuppliedUserInternal resolves direct and group role assignments
// from the supplied user. Signup uses this before the account is persisted, so
// role policies cannot be bypassed merely because GetUser cannot find it yet.
func getRolesBySuppliedUserInternal(userId string, user *User) ([]*Role, map[string][]string, error) {
	if user == nil {
		return nil, nil, fmt.Errorf("The user: %s doesn't exist", userId)
	}

	query := ormer.Engine.Alias("r").Where("r.users like ?", fmt.Sprintf("%%%s%%", userId))
	for _, group := range user.Groups {
		query = query.Or("r.groups like ?", fmt.Sprintf("%%%s%%", group))
	}

	roles := []*Role{}
	err := query.Find(&roles)
	if err != nil {
		return nil, nil, err
	}

	res := []*Role{}
	// a source is the group that granted the role, "" means it was assigned directly
	sources := map[string][]string{}
	for _, role := range roles {
		roleSources := getRoleSourcesForSuppliedUser(role, userId, user)
		if len(roleSources) != 0 {
			res = append(res, role)
			sources[role.GetId()] = roleSources
		}
	}
	return res, sources, nil
}

func getRoleSourcesForSuppliedUser(role *Role, userId string, user *User) []string {
	if role == nil || user == nil {
		return nil
	}

	roleSources := []string{}
	if util.InSlice(role.Users, userId) {
		roleSources = append(roleSources, "")
	}
	for _, group := range role.Groups {
		if util.InSlice(user.Groups, group) {
			roleSources = append(roleSources, group)
		}
	}
	return roleSources
}

func fillSourceGroups(roles []*Role, sources map[string][]string) {
	resolved := map[string]map[string]bool{}
	for _, role := range roles {
		roleId := role.GetId()
		resolved[roleId] = map[string]bool{}
		for _, source := range sources[roleId] {
			resolved[roleId][source] = true
		}
	}

	for changed := true; changed; {
		changed = false
		for _, role := range roles {
			roleId := role.GetId()
			for _, subRoleId := range role.Roles {
				for source := range resolved[subRoleId] {
					if !resolved[roleId][source] {
						resolved[roleId][source] = true
						changed = true
					}
				}
			}
		}
	}

	for _, role := range roles {
		roleSources := resolved[role.GetId()]
		if roleSources[""] {
			role.SourceGroups = nil
			continue
		}

		sourceGroups := []string{}
		for source := range roleSources {
			sourceGroups = append(sourceGroups, source)
		}
		sort.Strings(sourceGroups)
		role.SourceGroups = sourceGroups
	}
}

func expandRolesByUserSources(roles []*Role, sources map[string][]string) ([]*Role, error) {
	if len(roles) == 0 {
		return []*Role{}, nil
	}

	allRolesIds := []string{}
	for _, role := range roles {
		allRolesIds = append(allRolesIds, role.GetId())
	}

	allRoles, err := GetAncestorRoles(allRolesIds...)
	if err != nil {
		return nil, err
	}

	fillSourceGroups(allRoles, sources)

	for i := range allRoles {
		allRoles[i].Users = nil
	}

	return allRoles, nil
}

func getRolesBySuppliedUser(userId string, user *User) ([]*Role, error) {
	roles, sources, err := getRolesBySuppliedUserInternal(userId, user)
	if err != nil {
		return nil, err
	}
	return expandRolesByUserSources(roles, sources)
}

func getRolesByUser(userId string) ([]*Role, error) {
	roles, sources, err := getRolesByUserInternal(userId)
	if err != nil {
		return nil, err
	}
	return expandRolesByUserSources(roles, sources)
}

func roleChangeTrigger(owner string, oldName string, newName string) error {
	role, err := getRole(owner, oldName)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("the role does not exist: %s/%s", owner, oldName)
	}
	role.Name = newName
	_, err = UpdateRole(util.GetId(owner, oldName), role, true, "")
	return err
}

func roleChangeReferencesInSession(session *xorm.Session, owner string, oldName string, newName string) ([]*Permission, []*Permission, error) {
	oldRoleId := util.GetId(owner, oldName)
	newRoleId := util.GetId(owner, newName)
	var roles []*Role
	if err := session.Find(&roles); err != nil {
		return nil, nil, err
	}
	for _, role := range roles {
		if !util.InSlice(role.Roles, oldRoleId) {
			continue
		}
		if role.Owner != owner {
			return nil, nil, fmt.Errorf("the role cannot be renamed while another organization depends on it: %s", role.GetId())
		}
		if role.Name == oldName {
			continue
		}
		role.Roles = util.ReplaceVal(role.Roles, oldRoleId, newRoleId)
		if _, err := session.ID(core.PK{role.Owner, role.Name}).Cols("roles").Update(role); err != nil {
			return nil, nil, err
		}
	}

	var permissions []*Permission
	if err := session.Find(&permissions); err != nil {
		return nil, nil, err
	}
	oldPermissions := []*Permission{}
	newPermissions := []*Permission{}
	for _, permission := range permissions {
		if !util.InSlice(permission.Roles, oldRoleId) {
			continue
		}
		if permission.Owner != owner {
			return nil, nil, fmt.Errorf("the role cannot be renamed while another organization's permission depends on it: %s", permission.GetId())
		}
		oldPermission := *permission
		oldPermission.Roles = append([]string{}, permission.Roles...)
		permission.Roles = util.ReplaceVal(permission.Roles, oldRoleId, newRoleId)
		if _, err := session.ID(core.PK{permission.Owner, permission.Name}).Cols("roles").Update(permission); err != nil {
			return nil, nil, err
		}
		oldPermissions = append(oldPermissions, &oldPermission)
		newPermissions = append(newPermissions, permission)
	}
	return oldPermissions, newPermissions, nil
}

func GetMaskedRoles(roles []*Role) []*Role {
	for _, role := range roles {
		role.Users = nil
	}

	return roles
}

// GetAncestorRoles returns a list of roles that contain the given roleIds
func GetAncestorRoles(roleIds ...string) ([]*Role, error) {
	if len(roleIds) == 0 {
		return []*Role{}, nil
	}

	visited := map[string]bool{}
	for _, roleId := range roleIds {
		visited[roleId] = true
	}

	owner, _ := util.GetOwnerAndNameFromIdNoCheck(roleIds[0])

	allRoles, err := GetRoles(owner)
	if err != nil {
		return nil, err
	}

	roleMap := map[string]*Role{}
	for _, r := range allRoles {
		roleMap[r.GetId()] = r
	}

	// find all the roles that contain father roles
	res := []*Role{}
	for _, r := range allRoles {
		isContain, ok := visited[r.GetId()]
		if isContain {
			res = append(res, r)
		} else if !ok {
			rId := r.GetId()
			visited[rId] = containsRole(r, roleMap, visited, roleIds...)
			if visited[rId] {
				res = append(res, r)
			}
		}
	}
	return res, nil
}

// containsRole is a helper function to check if a roles is related to any role in the given list roles
func containsRole(role *Role, roleMap map[string]*Role, visited map[string]bool, roleIds ...string) bool {
	roleId := role.GetId()
	if isContain, ok := visited[roleId]; ok {
		return isContain
	}

	visited[role.GetId()] = false

	for _, subRole := range role.Roles {
		if util.HasString(roleIds, subRole) {
			return true
		}

		r, ok := roleMap[subRole]
		if ok && containsRole(r, roleMap, visited, roleIds...) {
			return true
		}
	}

	return false
}
