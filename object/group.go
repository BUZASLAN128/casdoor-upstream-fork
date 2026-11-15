// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type Group struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk index" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	DisplayName  string   `xorm:"varchar(100)" json:"displayName"`
	Manager      string   `xorm:"varchar(100)" json:"manager"`
	ContactEmail string   `xorm:"varchar(100)" json:"contactEmail"`
	Type         string   `xorm:"varchar(100)" json:"type"`
	ParentId     string   `xorm:"varchar(100)" json:"parentId"`
	ParentName   string   `xorm:"-" json:"parentName"`
	IsTopGroup   bool     `xorm:"bool" json:"isTopGroup"`
	Users        []string `xorm:"-" json:"users"`

	Title        string   `json:"title,omitempty"`
	Key          string   `json:"key,omitempty"`
	HaveChildren bool     `xorm:"-" json:"haveChildren"`
	Children     []*Group `json:"children,omitempty"`

	IsEnabled bool `json:"isEnabled"`
	// GidNumber is the POSIX gid published by the built-in LDAP server, 0 when unassigned.
	GidNumber  int               `xorm:"index" json:"gidNumber"`
	Properties map[string]string `xorm:"mediumtext" json:"properties"`
}

type GroupNode struct{}

func GetGroupCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	count, err := session.Count(&Group{})
	if err != nil {
		return 0, err
	}

	return count, nil
}

func GetGroups(owner string) ([]*Group, error) {
	groups := []*Group{}
	err := ormer.Engine.Desc("created_time").Find(&groups, &Group{Owner: owner})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func GetGlobalGroups() ([]*Group, error) {
	groups := []*Group{}
	err := ormer.Engine.Desc("created_time").Find(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func GetPaginationGroups(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Group, error) {
	groups := []*Group{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func GetGroupCountWithFilter(owner string, cond builder.Cond) (int64, error) {
	session := GetSession(owner, -1, -1, "", "", "", "")
	return session.And(cond).Count(&Group{})
}

func GetPaginationGroupsWithFilter(owner string, offset, limit int, cond builder.Cond) ([]*Group, error) {
	groups := []*Group{}
	session := GetSession(owner, offset, limit, "", "", "", "")
	err := session.And(cond).Find(&groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// GetGroupsParentMap returns the parent group of each given group, keyed by the parent's ID.
func GetGroupsParentMap(groups []*Group) (map[string]*Group, error) {
	resultMap := make(map[string]*Group)

	groupNames := []string{}
	for _, group := range groups {
		if !group.IsTopGroup {
			groupNames = append(groupNames, group.ParentId)
		}
	}
	if len(groupNames) == 0 {
		return resultMap, nil
	}

	parentGroups := []*Group{}
	err := ormer.Engine.Cols("owner", "name", "parent_id", "display_name").In("name", groupNames).Find(&parentGroups)
	if err != nil {
		return nil, err
	}

	for _, group := range parentGroups {
		resultMap[group.GetId()] = group
	}
	return resultMap, nil
}

// GetGroupIdsHaveChildren returns the IDs of the given groups that have at least one subgroup.
func GetGroupIdsHaveChildren(groups []*Group) (map[string]bool, error) {
	resultMap := make(map[string]bool)

	groupNames := []string{}
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	if len(groupNames) == 0 {
		return resultMap, nil
	}

	childGroups := []*Group{}
	err := ormer.Engine.Cols("owner", "parent_id").In("parent_id", groupNames).Find(&childGroups)
	if err != nil {
		return nil, err
	}

	for _, group := range childGroups {
		resultMap[fmt.Sprintf("%s/%s", group.Owner, group.ParentId)] = true
	}
	return resultMap, nil
}

func getGroup(owner string, name string) (*Group, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	group := Group{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&group)
	if err != nil {
		return nil, err
	}

	if existed {
		return &group, nil
	} else {
		return nil, nil
	}
}

func GetGroup(id string) (*Group, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getGroup(owner, name)
}

func UpdateGroup(id string, group *Group, isGlobalAdmin bool, lang string) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldGroup, err := getGroup(owner, name)
	if oldGroup == nil {
		return false, err
	}

	if !isGlobalAdmin && oldGroup.Owner != group.Owner {
		return false, errors.New(i18n.Translate(lang, "auth:Unauthorized operation"))
	}

	err = checkGroupName(group.Name)
	if err != nil {
		return false, err
	}

	return updateGroupWithGovernance(owner, name, group)
}

func updateGroupWithGovernance(owner string, name string, group *Group) (bool, error) {
	updated := *group
	updated.Owner = owner
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
	stored := &Group{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}

	rename := name != updated.Name
	if rename {
		target := &Group{Owner: owner, Name: updated.Name}
		targetExists, targetErr := session.ForUpdate().Get(target)
		if targetErr != nil {
			return rollback(targetErr)
		}
		if targetExists {
			return rollback(fmt.Errorf("the target group already exists: %s", target.GetId()))
		}
		if err = groupChangeInSession(session, owner, name, updated.Name); err != nil {
			return rollback(err)
		}
	}

	affected, err := session.ID(core.PK{owner, name}).AllCols().Update(&updated)
	if err != nil {
		return rollback(err)
	}
	if affected != 1 {
		return rollback(fmt.Errorf("the group changed while updating it: %s/%s", owner, name))
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	*group = updated
	if rename {
		if err = userEnforcer.publishCommittedGroups(); err != nil {
			return false, err
		}
	}
	return true, nil
}

func AddGroup(group *Group) (bool, error) {
	err := checkGroupName(group.Name)
	if err != nil {
		return false, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return false, err
	}
	if err = lockGovernanceScope(session, group.Owner); err != nil {
		_ = session.Rollback()
		return false, err
	}
	affected, err := session.Insert(group)
	if err != nil {
		_ = session.Rollback()
		return false, err
	}
	if err = session.Commit(); err != nil {
		_ = session.Rollback()
		return false, err
	}
	return affected != 0, nil
}

func AddGroups(groups []*Group) (bool, error) {
	if len(groups) == 0 {
		return false, nil
	}
	owners := map[string]bool{}
	for _, group := range groups {
		if err := checkGroupName(group.Name); err != nil {
			return false, err
		}
		owners[group.Owner] = true
	}
	ownerNames := make([]string, 0, len(owners))
	for owner := range owners {
		ownerNames = append(ownerNames, owner)
	}
	sort.Strings(ownerNames)

	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	for _, owner := range ownerNames {
		if err := lockGovernanceScope(session, owner); err != nil {
			_ = session.Rollback()
			return false, err
		}
	}
	affected, err := session.Insert(groups)
	if err != nil {
		_ = session.Rollback()
		return false, err
	}
	if err = session.Commit(); err != nil {
		_ = session.Rollback()
		return false, err
	}
	return affected != 0, nil
}

func AddGroupsInBatch(groups []*Group) (bool, error) {
	if len(groups) == 0 {
		return false, nil
	}

	session := ormer.Engine.NewSession()
	defer session.Close()
	err := session.Begin()
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		err = checkGroupName(group.Name)
		if err != nil {
			return false, err
		}

		affected, err := session.Insert(group)
		if err != nil {
			return false, err
		}
		if affected == 0 {
			return false, nil
		}
	}

	err = session.Commit()
	if err != nil {
		return false, err
	}

	return true, nil
}

func deleteGroup(group *Group) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{group.Owner, group.Name}).Delete(&Group{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteGroup(group *Group) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, group.Owner); err != nil {
		return rollback(err)
	}
	stored := &Group{Owner: group.Owner, Name: group.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}

	if count, err := session.Where("owner = ?", group.Owner).And("parent_id = ?", group.Name).Count(&Group{}); err != nil {
		return rollback(err)
	} else if count > 0 {
		return rollback(errors.New("group has children group"))
	}

	groupId := group.GetId()
	users := []*User{}
	if err = session.Cols("groups").Where("owner = ?", group.Owner).Find(&users); err != nil {
		return rollback(err)
	}
	for _, user := range users {
		if util.InSlice(user.Groups, groupId) {
			return rollback(errors.New("group has users"))
		}
	}
	if count, err := GetGroupUserCount(groupId, "", ""); err != nil {
		return rollback(err)
	} else if count > 0 {
		return rollback(errors.New("group has users"))
	}

	roles := []*Role{}
	if err = session.Where("owner = ?", group.Owner).Find(&roles); err != nil {
		return rollback(err)
	}
	for _, role := range roles {
		if util.InSlice(role.Groups, groupId) {
			return rollback(fmt.Errorf("the group cannot be deleted while a role depends on it: %s", groupId))
		}
	}
	count, err := session.Where("owner = ?", group.Owner).And(fmt.Sprintf("%s = ?", quoteColumn("group")), group.Name).Count(&Subscription{})
	if err != nil {
		return rollback(err)
	}
	if count != 0 {
		return rollback(fmt.Errorf("the group cannot be deleted while a subscription depends on it: %s", groupId))
	}

	affected, err := session.ID(core.PK{group.Owner, group.Name}).Delete(&Group{})
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}

func checkGroupName(name string) error {
	if name == "" {
		return errors.New("group name can't be empty")
	}
	if strings.Contains(name, "/") {
		return errors.New("group name can't contain \"/\"")
	}
	exist, err := ormer.Engine.Exist(&Organization{Owner: "admin", Name: name})
	if err != nil {
		return err
	}
	if exist {
		return errors.New("group name can't be same as the organization name")
	}
	return nil
}

func (group *Group) GetId() string {
	return fmt.Sprintf("%s/%s", group.Owner, group.Name)
}

func ConvertToTreeData(groups []*Group, parentId string) []*Group {
	treeData := []*Group{}

	for _, group := range groups {
		if group.ParentId == parentId {
			node := &Group{
				Title:       group.DisplayName,
				Key:         group.Name,
				Type:        group.Type,
				Owner:       group.Owner,
				Name:        group.Name,
				DisplayName: group.DisplayName,
			}
			children := ConvertToTreeData(groups, group.Name)
			if len(children) > 0 {
				node.Children = children
			}
			treeData = append(treeData, node)
		}
	}
	return treeData
}

func GetGroupUserCount(groupId string, field, value string) (int64, error) {
	owner, _, err := util.GetOwnerAndNameFromIdWithError(groupId)
	if err != nil {
		return 0, err
	}
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)
	if err != nil {
		return 0, err
	}

	if field == "" && value == "" {
		return int64(len(names)), nil
	} else {
		tableNamePrefix := conf.GetConfigString("tableNamePrefix")
		session := ormer.Engine.Table(tableNamePrefix+"user").
			Where("owner = ?", owner).In("name", names)
		if util.FilterField(field) {
			session = session.And(fmt.Sprintf("user.%s like ?", util.CamelToSnakeCase(field)), "%"+value+"%")
		}
		return session.Count()
	}
}

func GetPaginationGroupUsers(groupId string, offset, limit int, field, value, sortField, sortOrder string) ([]*User, error) {
	users := []*User{}
	owner, _, err := util.GetOwnerAndNameFromIdWithError(groupId)
	if err != nil {
		return nil, err
	}
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)
	if err != nil {
		return nil, err
	}

	tableNamePrefix := conf.GetConfigString("tableNamePrefix")
	prefixedUserTable := tableNamePrefix + "user"
	session := ormer.Engine.Table(prefixedUserTable).
		Where("owner = ?", owner).In("name", names)

	if offset != -1 && limit != -1 {
		session.Limit(limit, offset)
	}

	if field != "" && value != "" && util.FilterField(field) {
		session = session.And(fmt.Sprintf("%s.%s like ?", prefixedUserTable, util.CamelToSnakeCase(field)), "%"+value+"%")
	}

	if sortField == "" || sortOrder == "" || !util.FilterField(sortField) {
		sortField = "created_time"
	}

	orderQuery := fmt.Sprintf("%s.%s", prefixedUserTable, util.CamelToSnakeCase(sortField))

	if sortOrder == "ascend" {
		session = session.Asc(orderQuery)
	} else {
		session = session.Desc(orderQuery)
	}

	err = session.Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetGroupUsers(groupId string) ([]*User, error) {
	users := []*User{}
	owner, _, err := util.GetOwnerAndNameFromIdWithError(groupId)
	if err != nil {
		return nil, err
	}
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)
	if err != nil {
		return nil, err
	}
	err = ormer.Engine.Where("owner = ?", owner).In("name", names).Find(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func GetGroupUsersWithoutError(groupId string) []*User {
	users, _ := GetGroupUsers(groupId)
	return users
}

func ExtendGroupWithUsers(group *Group) error {
	if group == nil {
		return nil
	}

	groupId := group.GetId()
	userIds := []string{}
	userIds, err := userEnforcer.GetAllUsersByGroup(groupId)
	if err != nil {
		return err
	}

	group.Users = userIds
	return nil
}

func ExtendGroupsWithUsers(groups []*Group) error {
	if len(groups) == 0 {
		return nil
	}

	// Load the policy once for the whole page, GetAllUsersByGroup() would
	// otherwise read the entire policy table again for every group.
	err := userEnforcer.LoadPolicy()
	if err != nil {
		return err
	}

	for _, group := range groups {
		users, err := userEnforcer.getAllUsersByGroup(group.GetId())
		if err != nil {
			return err
		}

		group.Users = users
	}
	return nil
}

func GroupChangeTrigger(owner string, oldName string, newName string) error {
	group, err := getGroup(owner, oldName)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("the group does not exist: %s/%s", owner, oldName)
	}
	group.Name = newName
	_, err = updateGroupWithGovernance(owner, oldName, group)
	return err
}

func groupChangeInSession(session *xorm.Session, owner string, oldName string, newName string) error {
	oldGroupId := util.GetId(owner, oldName)
	newGroupId := util.GetId(owner, newName)
	if err := userEnforcer.deleteGroupBindingsInSession(session, oldGroupId); err != nil {
		return err
	}

	users := []*User{}
	if err := session.Where("owner = ?", owner).Find(&users); err != nil {
		return err
	}
	changedUsers := []*User{}
	for _, user := range users {
		if !util.InSlice(user.Groups, oldGroupId) {
			continue
		}
		oldUser := *user
		oldUser.Groups = append([]string{}, user.Groups...)
		user.Groups = util.ReplaceVal(user.Groups, oldGroupId, newGroupId)
		if err := user.UpdateUserHash(); err != nil {
			return err
		}
		if _, err := session.ID(core.PK{oldUser.Owner, oldUser.Name}).Cols("groups", "hash").Update(user); err != nil {
			return err
		}
		if err := userEnforcer.replaceGroupsForUserInSession(session, user.GetId(), user.Groups); err != nil {
			return err
		}
		changedUsers = append(changedUsers, user)
	}

	roles := []*Role{}
	if err := session.Where("owner = ?", owner).Find(&roles); err != nil {
		return err
	}
	for _, role := range roles {
		if !util.InSlice(role.Groups, oldGroupId) {
			continue
		}
		role.Groups = util.ReplaceVal(role.Groups, oldGroupId, newGroupId)
		if _, err := session.ID(core.PK{role.Owner, role.Name}).Cols("groups").Update(role); err != nil {
			return err
		}
	}
	// Validate against the complete post-rename snapshot. Checking before role
	// references move can temporarily hide the source group's grants and miss a
	// conflict with roles that already point at the destination ID.
	for _, user := range changedUsers {
		if err := CheckUserSodInSession(session, nil, user, ""); err != nil {
			return err
		}
	}

	groups := []*Group{}
	if err := session.Where("owner = ?", owner).And("parent_id = ?", oldName).Find(&groups); err != nil {
		return err
	}
	for _, group := range groups {
		group.ParentId = newName
		if _, err := session.ID(core.PK{group.Owner, group.Name}).Cols("parent_id").Update(group); err != nil {
			return err
		}
	}

	subscriptions := []*Subscription{}
	if err := session.Where("owner = ?", owner).And(fmt.Sprintf("%s = ?", quoteColumn("group")), oldName).Find(&subscriptions); err != nil {
		return err
	}
	for _, subscription := range subscriptions {
		subscription.Group = newName
		if _, err := session.ID(core.PK{subscription.Owner, subscription.Name}).Cols("group").Update(subscription); err != nil {
			return err
		}
	}
	return nil
}
