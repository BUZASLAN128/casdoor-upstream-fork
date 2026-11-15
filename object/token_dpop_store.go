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
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/redis/go-redis/v9"
)

type dpopProofReplayStore interface {
	MarkUsed(id string, ttl time.Duration) (bool, error)
}

const dpopProofRedisPrefix = "casdoor:dpop_proof:"

var DPoPProofReplayStore dpopProofReplayStore = &memoryDPoPProofReplayStore{expiries: map[string]time.Time{}}

// InitDPoPProofReplayStore uses Redis when configured, so proof replay detection
// remains atomic across Casdoor replicas. Single-replica deployments use the
// in-memory store.
func InitDPoPProofReplayStore() {
	config := conf.GetRedisConfig()
	if config == nil {
		return
	}

	addrs := strings.Join(config.Addrs, ";")
	store, err := newDPoPProofReplayStore(config, newRedisClient)
	DPoPProofReplayStore = store
	if err != nil {
		logs.Error("dpop_proof_store: failed to connect to configured Redis (%s); DPoP validation will fail closed: %v", addrs, err)
		return
	}

	logs.Info("dpop_proof_store: using Redis backend at %s", addrs)
}

func newDPoPProofReplayStore(config *conf.RedisConfig, connect func(*conf.RedisConfig) (redis.Cmdable, error)) (dpopProofReplayStore, error) {
	client, err := connect(config)
	if err != nil {
		wrapped := fmt.Errorf("configured Redis replay store is unavailable: %w", err)
		return &unavailableDPoPProofReplayStore{err: wrapped}, wrapped
	}
	return &redisDPoPProofReplayStore{client: client}, nil
}

type memoryDPoPProofReplayStore struct {
	mu       sync.Mutex
	expiries map[string]time.Time
	now      func() time.Time
}

func (s *memoryDPoPProofReplayStore) MarkUsed(id string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	for usedId, expiry := range s.expiries {
		if !now.Before(expiry) {
			delete(s.expiries, usedId)
		}
	}
	if _, ok := s.expiries[id]; ok {
		return true, nil
	}
	s.expiries[id] = now.Add(ttl)
	return false, nil
}

type unavailableDPoPProofReplayStore struct {
	err error
}

func (s *unavailableDPoPProofReplayStore) MarkUsed(_ string, _ time.Duration) (bool, error) {
	return false, s.err
}

type redisDPoPProofReplayStore struct {
	client redis.Cmdable
}

func (s *redisDPoPProofReplayStore) MarkUsed(id string, ttl time.Duration) (bool, error) {
	isNew, err := s.client.SetNX(context.Background(), dpopProofRedisPrefix+id, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return !isNew, nil
}
