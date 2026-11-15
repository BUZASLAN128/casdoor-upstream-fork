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
	"fmt"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/robfig/cron/v3"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

func (sub *Subscription) isActiveAt(now time.Time) bool {
	if sub.State != SubStateActive && sub.State != SubStateUpcoming && sub.State != SubStateExpired {
		return false
	}

	startTime, err := time.Parse(time.RFC3339, sub.StartTime)
	if err != nil {
		return false
	}

	endTime, err := time.Parse(time.RFC3339, sub.EndTime)
	if err != nil {
		return false
	}

	return !startTime.After(now) && !endTime.Before(now)
}

func getPlanRoleIdInSession(session *xorm.Session, owner string, planName string) (string, error) {
	if owner == "" || planName == "" {
		return "", fmt.Errorf("the subscription plan identity is empty")
	}
	plan := &Plan{}
	existed, err := session.ID(core.PK{owner, planName}).Get(plan)
	if err != nil {
		return "", err
	}
	if !existed {
		return "", fmt.Errorf("the plan does not exist: %s/%s", owner, planName)
	}
	return plan.GetRoleId(), nil
}

// syncSubscriptionRole gives the plan's role to the user or group only while one of their subscriptions to it is active
func syncSubscriptionRole(sub *Subscription) error {
	if sub == nil {
		return nil
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return err
	}
	if err := lockGovernanceScope(session, sub.Owner); err != nil {
		_ = session.Rollback()
		return err
	}
	if err := syncSubscriptionRoleInSession(session, sub); err != nil {
		_ = session.Rollback()
		return err
	}
	if err := session.Commit(); err != nil {
		_ = session.Rollback()
		return err
	}
	return nil
}

func syncSubscriptionRoleInSession(session *xorm.Session, sub *Subscription) error {
	if sub == nil {
		return nil
	}
	if err := lockGovernanceScope(session, sub.Owner); err != nil {
		return err
	}
	roleId, err := getPlanRoleIdInSession(session, sub.Owner, sub.Plan)
	if err != nil || roleId == "" {
		return err
	}

	if sub.User != "" {
		err = syncSubscriptionRoleMemberInSession(session, sub.Owner, roleId, "user", sub.User)
		if err != nil {
			return err
		}
	}

	if sub.Group != "" {
		err = syncSubscriptionRoleMemberInSession(session, sub.Owner, roleId, "group", sub.Group)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncSubscriptionRoleMemberInSession(session *xorm.Session, owner string, roleId string, column string, memberName string) error {
	roleOwner, roleName, err := util.GetOwnerAndNameFromIdWithError(roleId)
	if err != nil {
		return err
	}
	if roleOwner != owner {
		return fmt.Errorf("the subscription role is outside its organization: %s", roleId)
	}
	role := &Role{Owner: roleOwner, Name: roleName}
	existed, err := session.ForUpdate().Get(role)
	if err != nil {
		return err
	}
	if !existed {
		return fmt.Errorf("the subscription role does not exist: %s", roleId)
	}

	subscriptions := []*Subscription{}
	err = session.Where("owner = ?", owner).And(fmt.Sprintf("%s = ?", quoteColumn(column)), memberName).Find(&subscriptions)
	if err != nil {
		return err
	}

	isActive := false
	now := time.Now()
	for _, sub := range subscriptions {
		if !sub.isActiveAt(now) {
			continue
		}

		subRoleId, err := getPlanRoleIdInSession(session, sub.Owner, sub.Plan)
		if err != nil {
			return err
		}
		if subRoleId == roleId {
			isActive = true
			break
		}
	}

	memberId := util.GetId(owner, memberName)
	members, roleColumn := role.Users, "users"
	if column == "group" {
		members, roleColumn = role.Groups, "groups"
	}
	members, changed := getSubscriptionRoleMembersAfterMutation(members, memberId, isActive)
	if !changed {
		return nil
	}

	if column == "group" {
		role.Groups = members
	} else {
		role.Users = members
	}
	if isActive {
		if err = CheckRoleSodInSession(session, role, ""); err != nil {
			return err
		}
	}

	affected, err := session.ID(core.PK{role.Owner, role.Name}).Cols(roleColumn).Update(role)
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("the subscription role changed while updating membership: %s", roleId)
	}
	return nil
}

func getSubscriptionRoleMembersAfterMutation(members []string, memberId string, isActive bool) ([]string, bool) {
	if util.InSlice(members, memberId) == isActive {
		return members, false
	}
	if isActive {
		return append(members, memberId), true
	}
	return util.DeleteVal(members, memberId), true
}

func updatePaymentSubscriptions(payment *Payment) error {
	subscriptions := []*Subscription{}
	err := ormer.Engine.Where("owner = ? and payment = ?", payment.Owner, payment.Name).Find(&subscriptions)
	if err != nil {
		return err
	}

	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return err
		}
	}

	return nil
}

// UpdateSubscriptionStates refreshes the unfinished subscriptions so that their plans' roles are granted and taken back on time, and renews the ones about to end
func UpdateSubscriptionStates() error {
	subscriptions := []*Subscription{}
	err := ormer.Engine.In("state", string(SubStatePending), string(SubStateUpcoming), string(SubStateActive)).Find(&subscriptions)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			fmt.Printf("UpdateSubscriptionStates() error for subscription %s: %v\n", sub.GetId(), err)
			continue
		}

		if sub.State == SubStateActive {
			err = syncSubscriptionRole(sub)
			if err != nil {
				fmt.Printf("UpdateSubscriptionStates() error for subscription %s: %v\n", sub.GetId(), err)
			}
		}

		if sub.needsRenewal(now) {
			err = renewSubscription(sub)
			if err != nil {
				fmt.Printf("UpdateSubscriptionStates() error renewing subscription %s: %v\n", sub.GetId(), err)
			}
		}
	}

	return nil
}

func InitUpdateSubscriptionStates() {
	go func() {
		if err := UpdateSubscriptionStates(); err != nil {
			fmt.Printf("Error updating subscription states at startup: %v\n", err)
		}
	}()

	cronJob := cron.New()
	_, err := cronJob.AddFunc("0 * * * *", func() {
		if err := UpdateSubscriptionStates(); err != nil {
			fmt.Printf("Error updating subscription states: %v\n", err)
		}
	})
	if err != nil {
		fmt.Printf("Error scheduling subscription state updates: %v\n", err)
		return
	}
	cronJob.Start()
}
