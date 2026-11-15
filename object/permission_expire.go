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
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/xorm-io/core"
)

// isPermissionExpired reports whether the permission has a configured expiration
// time that has already passed relative to now. Permissions with an empty
// ExpireTime never expire.
func isPermissionExpired(permission *Permission, now time.Time) bool {
	if permission.ExpireTime == "" {
		return false
	}

	expireTime, err := time.Parse(time.RFC3339, permission.ExpireTime)
	if err != nil {
		fmt.Printf("isPermissionExpired() error, invalid expireTime %q for permission %s: %v\n", permission.ExpireTime, permission.GetId(), err)
		return false
	}

	return now.After(expireTime)
}

// ExpirePermissions revokes every enabled permission whose expiration time has
// passed. Revocation removes the permission's Casbin policies (so it stops being
// enforced) and disables the permission, implementing the automatic revocation of
// time-limited access required by standards such as ISO/IEC 27001 control 5.18.
func ExpirePermissions() error {
	now := time.Now()

	// Only enabled permissions that carry an expiration time are candidates. Rows with a
	// NULL/empty expire_time (e.g. permissions created before this feature) are excluded by
	// the query and thus never affected.
	permissions := []*Permission{}
	err := ormer.Engine.Where("expire_time is not null and expire_time != ? and is_enabled = ?", "", true).Find(&permissions)
	if err != nil {
		return fmt.Errorf("failed to query permissions for expiration: %w", err)
	}

	revokedCount := 0
	revocationErrors := []error{}
	for _, permission := range permissions {
		if !isPermissionExpired(permission, now) {
			continue
		}
		revoked, revokeErr := expirePermissionInTransaction(permission, now)
		if revokeErr != nil {
			revocationErrors = append(revocationErrors, fmt.Errorf("failed to revoke expired permission %s: %w", permission.GetId(), revokeErr))
			continue
		}
		if !revoked {
			continue
		}
		permission.IsEnabled = false
		fmt.Printf("[%d] Revoked expired permission: %s | ExpireTime: %s\n", revokedCount, permission.GetId(), permission.ExpireTime)
		revokedCount++
	}

	return errors.Join(revocationErrors...)
}

func expirePermissionInTransaction(permission *Permission, now time.Time) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockPermissionGovernance(session, permission); err != nil {
		return rollback(err)
	}
	stored := &Permission{Owner: permission.Owner, Name: permission.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed || !stored.IsEnabled || !isPermissionExpired(stored, now) {
		_ = session.Rollback()
		return false, nil
	}
	covered, err := permissionGovernanceLocksCover([]*Permission{permission}, stored)
	if err != nil {
		return rollback(err)
	}
	if !covered {
		return rollback(fmt.Errorf("the permission governance references changed while expiring it: %s", stored.GetId()))
	}
	if err = removePermissionPoliciesInSession(session, stored); err != nil {
		return rollback(err)
	}
	stored.IsEnabled = false
	affected, err := session.ID(core.PK{stored.Owner, stored.Name}).Cols("is_enabled").Update(stored)
	if err != nil {
		return rollback(err)
	}
	if affected != 1 {
		return rollback(fmt.Errorf("the permission changed while expiring it: %s", stored.GetId()))
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	return true, nil
}

// InitExpirePermissions runs the permission expiration job once at startup and then
// hourly, so that expired permissions are revoked promptly without requiring manual
// intervention.
func InitExpirePermissions() {
	schedule := "0 * * * *"

	go func() {
		if err := ExpirePermissions(); err != nil {
			fmt.Printf("Error revoking expired permissions at startup: %v\n", err)
		}
	}()

	cronJob := cron.New()
	_, err := cronJob.AddFunc(schedule, func() {
		if err := ExpirePermissions(); err != nil {
			fmt.Printf("Error revoking expired permissions: %v\n", err)
		}
	})
	if err != nil {
		fmt.Printf("Error scheduling permission expiration: %v\n", err)
		return
	}
	cronJob.Start()
}
