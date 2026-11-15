package object

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

func makeCerberusSecurityDPoPProof(t *testing.T, key *rsa.PrivateKey, jti string) string {
	return makeCerberusSecurityDPoPProofAt(t, key, jti, time.Now())
}

func makeCerberusSecurityDPoPProofAt(t *testing.T, key *rsa.PrivateKey, jti string, issuedAt time.Time) string {
	t.Helper()
	claims := &DPoPProofClaims{
		Jti: "proof-" + jti,
		Htm: "GET",
		Htu: "https://example.test/api/resource",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = jose.JSONWebKey{Key: &key.PublicKey}
	signed, err := proof.SignedString(key)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	return signed
}

func TestCerberusSecurityDPoPReplayRetentionCoversFutureDatedProof(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	now := base
	oldStore := DPoPProofReplayStore
	DPoPProofReplayStore = &memoryDPoPProofReplayStore{
		expiries: map[string]time.Time{},
		now:      func() time.Time { return now },
	}
	defer func() { DPoPProofReplayStore = oldStore }()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	proof := makeCerberusSecurityDPoPProofAt(t, key, "future", base.Add(240*time.Second))
	if _, err = validateDPoPProofAt(proof, "GET", "https://example.test/api/resource", "", now); err != nil {
		t.Fatalf("first future-dated proof validation: %v", err)
	}

	now = base.Add(301 * time.Second)
	if _, err = validateDPoPProofAt(proof, "GET", "https://example.test/api/resource", "", now); err == nil {
		t.Fatal("future-dated proof replay was accepted after the old fixed TTL")
	}

	now = base.Add(540 * time.Second)
	if _, err = validateDPoPProofAt(proof, "GET", "https://example.test/api/resource", "", now); err == nil {
		t.Fatal("proof replay was accepted at the inclusive max-age boundary")
	}
}

func TestCerberusSecurityDPoPUnavailableConfiguredStoreFailsClosed(t *testing.T) {
	store, initErr := newDPoPProofReplayStore(
		&conf.RedisConfig{Addrs: []string{"redis.example.test:6379"}},
		func(*conf.RedisConfig) (redis.Cmdable, error) {
			return nil, fmt.Errorf("configured Redis unavailable")
		},
	)
	if initErr == nil {
		t.Fatal("configured Redis initialization unexpectedly succeeded")
	}
	if replayed, err := store.MarkUsed("proof", time.Minute); err == nil || replayed {
		t.Fatalf("MarkUsed() = (%v, %v), want fail-closed error", replayed, err)
	}
}

func TestCerberusSecurityDPoPProofIdentifiersAreSingleUse(t *testing.T) {
	oldStore := DPoPProofReplayStore
	DPoPProofReplayStore = &memoryDPoPProofReplayStore{expiries: map[string]time.Time{}}
	defer func() { DPoPProofReplayStore = oldStore }()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	proof := makeCerberusSecurityDPoPProof(t, key, "one")
	if _, err = ValidateDPoPProof(proof, "GET", "https://example.test/api/resource", ""); err != nil {
		t.Fatalf("first proof validation: %v", err)
	}
	if _, err = ValidateDPoPProof(proof, "GET", "https://example.test/api/resource", ""); err == nil {
		t.Fatal("replayed proof was accepted")
	}
	secondProof := makeCerberusSecurityDPoPProof(t, key, "two")
	if _, err = ValidateDPoPProof(secondProof, "GET", "https://example.test/api/resource", ""); err != nil {
		t.Fatalf("fresh proof validation: %v", err)
	}
}
