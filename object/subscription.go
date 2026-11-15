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
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/pp"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type SubscriptionState string

const (
	SubStatePending   SubscriptionState = "Pending"
	SubStateError     SubscriptionState = "Error"
	SubStateSuspended SubscriptionState = "Suspended" // suspended by the admin

	SubStateActive   SubscriptionState = "Active"
	SubStateUpcoming SubscriptionState = "Upcoming"
	SubStateExpired  SubscriptionState = "Expired"
)

type Subscription struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	Description string `xorm:"mediumtext" json:"description"`

	User    string `xorm:"varchar(100)" json:"user"`
	Group   string `xorm:"varchar(100)" json:"group"`
	Pricing string `xorm:"varchar(100)" json:"pricing"`
	Plan    string `xorm:"varchar(100)" json:"plan"`
	Payment string `xorm:"varchar(100)" json:"payment"`

	StartTime string            `xorm:"varchar(100)" json:"startTime"`
	EndTime   string            `xorm:"varchar(100)" json:"endTime"`
	Period    string            `xorm:"varchar(100)" json:"period"`
	State     SubscriptionState `xorm:"varchar(100)" json:"state"`

	AutoRenew           bool   `json:"autoRenew"`
	RenewalState        string `xorm:"mediumtext" json:"renewalState"`
	RenewalSubscription string `xorm:"mediumtext" json:"renewalSubscription"`
	RenewalMessage      string `xorm:"mediumtext" json:"renewalMessage"`
	PaymentType         string `xorm:"-" json:"paymentType"`
}

func (sub *Subscription) GetId() string {
	return fmt.Sprintf("%s/%s", sub.Owner, sub.Name)
}

func (sub *Subscription) UpdateState() error {
	now := time.Now()
	probe := *sub
	probeSession := ormer.Engine.NewSession()
	err := calculateSubscriptionStateInSession(probeSession, &probe, now)
	probeSession.Close()
	if err != nil {
		return err
	}
	if probe.State == sub.State {
		return nil
	}
	return updateSubscriptionStateAndRole(sub, now)
}

func updateSubscriptionStateAndRole(sub *Subscription, now time.Time) error {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return err
	}
	rollback := func(err error) error {
		_ = session.Rollback()
		return err
	}
	if err := lockGovernanceScope(session, sub.Owner); err != nil {
		return rollback(err)
	}

	stored := &Subscription{Owner: sub.Owner, Name: sub.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		return rollback(fmt.Errorf("the subscription does not exist: %s", sub.GetId()))
	}
	candidate := *stored
	preState := candidate.State
	if err = calculateSubscriptionStateInSession(session, &candidate, now); err != nil {
		return rollback(err)
	}
	if preState == candidate.State {
		_ = session.Rollback()
		sub.State = candidate.State
		sub.Description = candidate.Description
		return nil
	}

	stored.State = candidate.State
	stored.Description = candidate.Description
	affected, err := session.ID(core.PK{stored.Owner, stored.Name}).Cols("state", "description").Update(stored)
	if err != nil {
		return rollback(err)
	}
	if affected != 1 {
		return rollback(fmt.Errorf("the subscription state was not updated: %s", candidate.GetId()))
	}
	if err = syncSubscriptionRoleInSession(session, stored); err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	sub.State = candidate.State
	sub.Description = candidate.Description
	return nil
}

func calculateSubscriptionStateInSession(session *xorm.Session, candidate *Subscription, now time.Time) error {
	// update subscription state by payment state
	if candidate.State == SubStatePending {
		if candidate.Payment == "" {
			return nil
		}
		paymentOwner, paymentName, err := util.GetOwnerAndNameFromIdWithError(util.GetId(candidate.Owner, candidate.Payment))
		if err != nil {
			return err
		}
		payment := &Payment{Owner: paymentOwner, Name: paymentName}
		existed, err := session.Get(payment)
		if err != nil {
			return err
		}
		if !existed {
			candidate.Description = fmt.Sprintf("payment: %s does not exist", candidate.Payment)
			candidate.State = SubStateError
		} else {
			if payment.State == pp.PaymentStatePaid {
				candidate.State = SubStateActive
			} else if payment.State != pp.PaymentStateCreated {
				// other states: Canceled, Timeout, Error
				candidate.Description = fmt.Sprintf("payment: %s state is %v", candidate.Payment, payment.State)
				candidate.State = SubStateError
			}
		}
	}

	if candidate.State == SubStateActive || candidate.State == SubStateUpcoming || candidate.State == SubStateExpired {
		startTime, err := time.Parse(time.RFC3339, candidate.StartTime)
		if err != nil {
			return err
		}

		endTime, err := time.Parse(time.RFC3339, candidate.EndTime)
		if err != nil {
			return err
		}

		if endTime.Before(now) {
			candidate.State = SubStateExpired
		} else if startTime.After(now) {
			candidate.State = SubStateUpcoming
		} else {
			candidate.State = SubStateActive
		}
	}

	return nil
}

func NewSubscription(owner, userName, planName, paymentName, period string) (*Subscription, error) {
	return newSubscriptionFrom(owner, userName, planName, paymentName, period, time.Now())
}

func newSubscriptionFrom(owner, userName, planName, paymentName, period string, start time.Time) (*Subscription, error) {
	startTime, endTime, err := getDurationFrom(period, start)
	if err != nil {
		return nil, err
	}

	id := util.GenerateId()[:6]

	res := &Subscription{
		Owner:       owner,
		Name:        "sub_" + id,
		DisplayName: "New Subscription - " + id,
		CreatedTime: util.GetCurrentTime(),

		User:    userName,
		Plan:    planName,
		Payment: paymentName,

		StartTime: startTime,
		EndTime:   endTime,
		Period:    period,
		State:     SubStatePending, // waiting for payment complete
	}
	return res, nil
}

func GetSubscriptionCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Subscription{})
}

func GetSubscriptions(owner string) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := ormer.Engine.Desc("created_time").Find(&subscriptions, &Subscription{Owner: owner})
	if err != nil {
		return subscriptions, err
	}
	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return nil, err
		}
	}
	err = extendSubscriptionsWithPaymentType(subscriptions)
	if err != nil {
		return nil, err
	}
	return subscriptions, nil
}

// getUserSubscriptionGroups returns the groups a user inherits subscriptions from:
// the ones they belong to plus all of their ancestors, since a subscription bought
// for a parent group covers its subgroups too.
func getUserSubscriptionGroups(owner string, userName string) ([]string, error) {
	user, err := getUser(owner, userName)
	if err != nil {
		return nil, err
	}
	if user == nil || len(user.Groups) == 0 {
		return nil, nil
	}

	groups, err := GetGroups(owner)
	if err != nil {
		return nil, err
	}

	groupMap := map[string]*Group{}
	for _, group := range groups {
		groupMap[group.Name] = group
	}

	groupNames := []string{}
	visited := map[string]bool{}
	for _, groupId := range user.Groups {
		groupOwner, groupName := util.GetOwnerAndNameFromIdNoCheck(groupId)
		if groupOwner != owner {
			continue
		}

		for {
			group, ok := groupMap[groupName]
			if !ok || visited[groupName] {
				break
			}
			visited[groupName] = true
			groupNames = append(groupNames, groupName)
			if group.IsTopGroup {
				break
			}
			groupName = group.ParentId
		}
	}
	return groupNames, nil
}

// getSubscriptionUserCond builds the condition matching the subscriptions a user
// benefits from: the ones bought for them and the ones bought for their groups.
func getSubscriptionUserCond(owner string, userName string) (string, []interface{}, error) {
	groupNames, err := getUserSubscriptionGroups(owner, userName)
	if err != nil {
		return "", nil, err
	}

	cond := fmt.Sprintf("%s = ?", quoteColumn("user"))
	args := []interface{}{userName}
	if len(groupNames) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(groupNames)), ", ")
		cond = fmt.Sprintf("(%s or %s in (%s))", cond, quoteColumn("group"), placeholders)
		for _, groupName := range groupNames {
			args = append(args, groupName)
		}
	}
	return cond, args, nil
}

func GetSubscriptionsByUser(owner, userName string) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	cond, args, err := getSubscriptionUserCond(owner, userName)
	if err != nil {
		return subscriptions, err
	}

	err = ormer.Engine.Desc("created_time").Where("owner = ?", owner).And(cond, args...).Find(&subscriptions)
	if err != nil {
		return subscriptions, err
	}
	// update subscription state
	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return subscriptions, err
		}
	}
	err = extendSubscriptionsWithPaymentType(subscriptions)
	if err != nil {
		return subscriptions, err
	}
	return subscriptions, nil
}

func GetSubscriptionCountByUser(owner, userName, field, value string) (int64, error) {
	cond, args, err := getSubscriptionUserCond(owner, userName)
	if err != nil {
		return 0, err
	}

	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.And(cond, args...).Count(&Subscription{})
}

func GetPaginationSubscriptionsByUser(owner, userName string, offset, limit int, field, value, sortField, sortOrder string) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	cond, args, err := getSubscriptionUserCond(owner, userName)
	if err != nil {
		return subscriptions, err
	}

	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err = session.And(cond, args...).Find(&subscriptions)
	if err != nil {
		return subscriptions, err
	}
	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return nil, err
		}
	}
	err = extendSubscriptionsWithPaymentType(subscriptions)
	if err != nil {
		return nil, err
	}
	return subscriptions, nil
}

func GetPaginationSubscriptions(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&subscriptions)
	if err != nil {
		return subscriptions, err
	}
	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return nil, err
		}
	}
	err = extendSubscriptionsWithPaymentType(subscriptions)
	if err != nil {
		return nil, err
	}
	return subscriptions, nil
}

func getSubscription(owner string, name string) (*Subscription, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	subscription := Subscription{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&subscription)
	if err != nil {
		return nil, err
	}

	if existed {
		return &subscription, nil
	} else {
		return nil, nil
	}
}

func GetSubscription(id string) (*Subscription, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}

	subscription, err := getSubscription(owner, name)
	if err != nil || subscription == nil {
		return subscription, err
	}

	err = extendSubscriptionsWithPaymentType([]*Subscription{subscription})
	if err != nil {
		return nil, err
	}
	return subscription, nil
}

func hasActiveSubscriptionForPlan(owner, planName, cond string, args []interface{}) (bool, error) {
	subscriptions := []*Subscription{}
	err := ormer.Engine.Where("owner = ? and plan = ?", owner, planName).And(cond, args...).Find(&subscriptions)
	if err != nil {
		return false, err
	}

	for _, sub := range subscriptions {
		err = sub.UpdateState()
		if err != nil {
			return false, err
		}
		// Check if subscription is active, upcoming, or pending (not expired, error, or suspended)
		if sub.State == SubStateActive || sub.State == SubStateUpcoming || sub.State == SubStatePending {
			return true, nil
		}
	}
	return false, nil
}

// HasActiveSubscriptionForPlan reports whether the user is already covered by the
// plan, either directly or through one of their groups.
func HasActiveSubscriptionForPlan(owner, userName, planName string) (bool, error) {
	cond, args, err := getSubscriptionUserCond(owner, userName)
	if err != nil {
		return false, err
	}
	return hasActiveSubscriptionForPlan(owner, planName, cond, args)
}

func HasActiveSubscriptionForPlanByGroup(owner, groupName, planName string) (bool, error) {
	cond := fmt.Sprintf("%s = ?", quoteColumn("group"))
	return hasActiveSubscriptionForPlan(owner, planName, cond, []interface{}{groupName})
}

func UpdateSubscription(id string, subscription *Subscription) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	preUpdate, err := getSubscription(owner, name)
	if err != nil {
		return false, err
	}
	if preUpdate == nil {
		return false, nil
	}
	updated := *subscription
	updated.Owner = owner
	updated.Name = name
	if updated.AutoRenew && !preUpdate.AutoRenew {
		if err = checkSubscriptionAutoRenew(&updated); err != nil {
			return false, err
		}
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
	if err = lockGovernanceScope(session, owner); err != nil {
		return rollback(err)
	}

	oldSubscription := &Subscription{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(oldSubscription)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	if oldSubscription.AutoRenew != preUpdate.AutoRenew {
		return rollback(fmt.Errorf("the subscription changed concurrently: %s", id))
	}

	affected, err := session.ID(core.PK{owner, name}).AllCols().Omit("renewal_state", "renewal_subscription", "renewal_message").Update(&updated)
	if err != nil {
		return rollback(err)
	}
	if affected != 0 {
		if err = syncSubscriptionRoleInSession(session, oldSubscription); err != nil {
			return rollback(err)
		}
		if err = syncSubscriptionRoleInSession(session, &updated); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	*subscription = updated
	return affected != 0, nil
}

func AddSubscription(subscription *Subscription) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, subscription.Owner); err != nil {
		return rollback(err)
	}

	affected, err := session.Insert(subscription)
	if err != nil {
		return rollback(err)
	}
	if affected != 0 {
		if err = syncSubscriptionRoleInSession(session, subscription); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}

func DeleteSubscription(subscription *Subscription) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, subscription.Owner); err != nil {
		return rollback(err)
	}

	oldSubscription := &Subscription{Owner: subscription.Owner, Name: subscription.Name}
	existed, err := session.ForUpdate().Get(oldSubscription)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}

	affected, err := session.ID(core.PK{subscription.Owner, subscription.Name}).Delete(&Subscription{})
	if err != nil {
		return rollback(err)
	}
	if affected != 0 {
		if err = syncSubscriptionRoleInSession(session, oldSubscription); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}
