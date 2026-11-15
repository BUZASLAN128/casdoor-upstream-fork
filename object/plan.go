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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type Plan struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"mediumtext" json:"description"`

	Price            float64  `json:"price"`
	Currency         string   `xorm:"varchar(100)" json:"currency"`
	Period           string   `xorm:"varchar(100)" json:"period"`
	Product          string   `xorm:"varchar(100)" json:"product"`
	PaymentProviders []string `xorm:"varchar(100)" json:"paymentProviders"` // payment providers for related product
	IsEnabled        bool     `json:"isEnabled"`
	IsExclusive      bool     `json:"isExclusive"` // if true, a user can only have at most one subscription of this plan
	AutoRenew        bool     `json:"autoRenew"`

	Role    string   `xorm:"varchar(100)" json:"role"`
	Options []string `xorm:"-" json:"options"`
}

const (
	PeriodMonthly = "Monthly"
	PeriodYearly  = "Yearly"
)

func (plan *Plan) GetId() string {
	return fmt.Sprintf("%s/%s", plan.Owner, plan.Name)
}

func (plan *Plan) GetRoleId() string {
	if plan.Role == "" || strings.Contains(plan.Role, "/") {
		return plan.Role
	}
	return util.GetId(plan.Owner, plan.Role)
}

func hasPlanUsingRoleInSession(session *xorm.Session, owner string, roleId string) (bool, error) {
	plans := []*Plan{}
	if err := session.Where("owner = ?", owner).Find(&plans); err != nil {
		return false, err
	}
	for _, plan := range plans {
		if plan.GetRoleId() == roleId {
			return true, nil
		}
	}
	return false, nil
}

func getDurationFrom(period string, startTime time.Time) (string, string, error) {
	var endTime time.Time

	if period == PeriodYearly {
		endTime = startTime.AddDate(1, 0, 0)
	} else if period == PeriodMonthly {
		endTime = startTime.AddDate(0, 1, 0)
	} else {
		return "", "", fmt.Errorf("invalid period: %s", period)
	}

	startTimeString := startTime.Format(time.RFC3339)
	endTimeString := endTime.Format(time.RFC3339)
	return startTimeString, endTimeString, nil
}

func GetPlanCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Plan{})
}

func GetPlans(owner string) ([]*Plan, error) {
	plans := []*Plan{}
	err := ormer.Engine.Desc("created_time").Find(&plans, &Plan{Owner: owner})
	if err != nil {
		return plans, err
	}
	return plans, nil
}

func GetPaginatedPlans(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Plan, error) {
	plans := []*Plan{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&plans)
	if err != nil {
		return plans, err
	}
	return plans, nil
}

func getPlan(owner, name string) (*Plan, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	plan := Plan{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&plan)
	if err != nil {
		return &plan, err
	}
	if existed {
		return &plan, nil
	} else {
		return nil, nil
	}
}

func GetPlan(id string) (*Plan, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getPlan(owner, name)
}

func UpdatePlan(id string, plan *Plan) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
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
	if err = lockGovernanceScope(session, owner); err != nil {
		return rollback(err)
	}

	oldPlan := &Plan{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(oldPlan)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	updated := *plan
	updated.Owner = owner
	updated.Name = name
	if oldPlan.GetRoleId() != updated.GetRoleId() {
		count, countErr := session.Where("owner = ? and plan = ?", owner, name).Count(&Subscription{})
		if countErr != nil {
			return rollback(countErr)
		}
		if count != 0 {
			return rollback(fmt.Errorf("the plan role cannot change while subscriptions depend on it: %s", id))
		}
	}
	if updated.Product != "" {
		product := &Product{Owner: owner, Name: updated.Product}
		productExists, productErr := session.ForUpdate().Get(product)
		if productErr != nil {
			return rollback(productErr)
		}
		if productExists {
			UpdateProductForPlan(&updated, product)
			if productErr = checkProduct(product); productErr != nil {
				return rollback(productErr)
			}
			if _, productErr = session.ID(core.PK{product.Owner, product.Name}).AllCols().Update(product); productErr != nil {
				return rollback(productErr)
			}
		}
	}

	affected, err := session.ID(core.PK{owner, name}).AllCols().Update(&updated)
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	*plan = updated
	return affected != 0, nil
}

func AddPlan(plan *Plan) (bool, error) {
	affected, err := ormer.Engine.Insert(plan)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func DeletePlan(plan *Plan) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, plan.Owner); err != nil {
		return rollback(err)
	}

	stored := &Plan{Owner: plan.Owner, Name: plan.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	count, err := session.Where("owner = ? and plan = ?", plan.Owner, plan.Name).Count(&Subscription{})
	if err != nil {
		return rollback(err)
	}
	if count != 0 {
		return rollback(fmt.Errorf("the plan cannot be deleted while subscriptions depend on it: %s", plan.GetId()))
	}

	if stored.Product != "" {
		if _, err = session.ID(core.PK{stored.Owner, stored.Product}).Delete(&Product{}); err != nil {
			return rollback(err)
		}
	}
	affected, err := session.ID(core.PK{plan.Owner, plan.Name}).Delete(Plan{})
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return affected != 0, nil
}
