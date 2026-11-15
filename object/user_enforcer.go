package object

import (
	errors2 "errors"
	"fmt"

	"github.com/casbin/casbin/v2/errors"

	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/xorm"
)

type UserGroupEnforcer struct {
	// use rbac model implement use group, the enforcer can also implement user role
	enforcer *casbin.SyncedEnforcer
}

// replaceGroupsForUserInSession persists the canonical user-group bindings in
// the caller's transaction. The built-in user enforcer is deliberately backed
// by Casdoor's own database, so its policy rows and the User.Groups column can
// commit or roll back together.
func (e *UserGroupEnforcer) replaceGroupsForUserInSession(session *xorm.Session, user string, groups []string) error {
	adapter, ok := e.enforcer.GetAdapter().(*SafeAdapter)
	if !ok || adapter == nil || !adapter.sameDatabase {
		return fmt.Errorf("the user-group adapter is not backed by Casdoor's database")
	}
	tableName := adapter.policyTableName()
	if _, err := session.Where("ptype = ? AND v0 = ?", "g", user).Delete(&safeCasbinRule{tableName: tableName}); err != nil {
		return err
	}

	seen := map[string]bool{}
	for _, group := range groups {
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		rule := &safeCasbinRule{Ptype: "g", V0: user, V1: GetGroupWithPrefix(group), tableName: tableName}
		if _, err := session.InsertOne(rule); err != nil {
			return err
		}
	}
	return nil
}

func (e *UserGroupEnforcer) deleteGroupBindingsInSession(session *xorm.Session, group string) error {
	adapter, ok := e.enforcer.GetAdapter().(*SafeAdapter)
	if !ok || adapter == nil || !adapter.sameDatabase {
		return fmt.Errorf("the user-group adapter is not backed by Casdoor's database")
	}
	_, err := session.Where("ptype = ? AND v1 = ?", "g", GetGroupWithPrefix(group)).
		Delete(&safeCasbinRule{tableName: adapter.policyTableName()})
	return err
}

// publishCommittedGroups refreshes the synchronized in-memory model only after
// the database transaction has committed. If reload fails, clear the model so
// stale allow bindings cannot outlive the authoritative database state.
func (e *UserGroupEnforcer) publishCommittedGroups() error {
	if err := e.LoadPolicy(); err != nil {
		e.enforcer.ClearPolicy()
		return fmt.Errorf("reload committed user-group policy: %w", err)
	}
	return nil
}

func NewUserGroupEnforcer(enforcer *casbin.SyncedEnforcer) *UserGroupEnforcer {
	return &UserGroupEnforcer{
		enforcer: enforcer,
	}
}

func (e *UserGroupEnforcer) checkModel() error {
	if _, ok := e.enforcer.GetModel()["g"]; !ok {
		return fmt.Errorf("The Casbin model used by enforcer doesn't support RBAC (\"[role_definition]\" section not found), please use a RBAC enabled Casbin model for the enforcer")
	}
	return nil
}

func (e *UserGroupEnforcer) AddGroupForUser(user string, group string) (bool, error) {
	err := e.checkModel()
	if err != nil {
		return false, err
	}

	return e.enforcer.AddRoleForUser(user, GetGroupWithPrefix(group))
}

func (e *UserGroupEnforcer) AddGroupsForUser(user string, groups []string) (bool, error) {
	err := e.checkModel()
	if err != nil {
		return false, err
	}

	g := make([]string, len(groups))
	for i, group := range groups {
		g[i] = GetGroupWithPrefix(group)
	}
	return e.enforcer.AddRolesForUser(user, g)
}

func (e *UserGroupEnforcer) DeleteGroupForUser(user string, group string) (bool, error) {
	err := e.checkModel()
	if err != nil {
		return false, err
	}

	return e.enforcer.DeleteRoleForUser(user, GetGroupWithPrefix(group))
}

func (e *UserGroupEnforcer) DeleteGroupsForUser(user string) (bool, error) {
	err := e.checkModel()
	if err != nil {
		return false, err
	}

	return e.enforcer.DeleteRolesForUser(user)
}

func (e *UserGroupEnforcer) GetGroupsForUser(user string) ([]string, error) {
	err := e.checkModel()
	if err != nil {
		return nil, err
	}

	if err = e.enforcer.LoadPolicy(); err != nil {
		return nil, err
	}

	groups, err := e.enforcer.GetRolesForUser(user)
	for i, group := range groups {
		groups[i] = GetGroupWithoutPrefix(group)
	}
	return groups, err
}

// LoadPolicy reads the whole policy from the storage. It's exposed so that a
// caller which looks up many groups can load the policy once instead of once
// per group.
func (e *UserGroupEnforcer) LoadPolicy() error {
	err := e.checkModel()
	if err != nil {
		return err
	}

	return e.enforcer.LoadPolicy()
}

// getAllUsersByGroup reads the members of a group from the policy that is
// already in memory, the caller is responsible for loading it.
func (e *UserGroupEnforcer) getAllUsersByGroup(group string) ([]string, error) {
	users, err := e.enforcer.GetUsersForRole(GetGroupWithPrefix(group))
	if err != nil {
		if errors2.Is(err, errors.ErrNameNotFound) {
			return []string{}, nil
		}
		return nil, err
	}
	return users, nil
}

func (e *UserGroupEnforcer) GetAllUsersByGroup(group string) ([]string, error) {
	err := e.LoadPolicy()
	if err != nil {
		return nil, err
	}

	return e.getAllUsersByGroup(group)
}

func GetGroupWithPrefix(group string) string {
	return "group:" + group
}

func GetGroupWithoutPrefix(group string) string {
	return group[len("group:"):]
}

func (e *UserGroupEnforcer) GetUserNamesByGroupName(groupName string) ([]string, error) {
	err := e.checkModel()
	if err != nil {
		return nil, err
	}

	userIds, err := e.GetAllUsersByGroup(groupName)
	if err != nil {
		return nil, err
	}

	names := []string{}
	for _, userId := range userIds {
		_, name := util.GetOwnerAndNameFromIdNoCheck(userId)
		names = append(names, name)
	}

	return names, nil
}

func (e *UserGroupEnforcer) UpdateGroupsForUser(user string, groups []string) (bool, error) {
	err := e.checkModel()
	if err != nil {
		return false, err
	}

	_, err = e.DeleteGroupsForUser(user)
	if err != nil {
		return false, err
	}

	affected, err := e.AddGroupsForUser(user, groups)
	if err != nil {
		return false, err
	}

	return affected, nil
}

// RenameUser moves the group bindings of a user from the old user ID to the new one.
// The group APIs read the members of a group from these bindings, so a rename that
// doesn't move them would keep the old ID inside every group the user belonged to.
func (e *UserGroupEnforcer) RenameUser(oldUser string, newUser string) error {
	groups, err := e.GetGroupsForUser(oldUser)
	if err != nil {
		return err
	}

	if len(groups) == 0 {
		return nil
	}

	_, err = e.DeleteGroupsForUser(oldUser)
	if err != nil {
		return err
	}

	_, err = e.UpdateGroupsForUser(newUser, groups)
	if err != nil {
		return err
	}

	return nil
}
