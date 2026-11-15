package object

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func makeCerberusSecurityDPoPProof(t *testing.T, key *rsa.PrivateKey, jti string) string {
	t.Helper()
	claims := &DPoPProofClaims{
		Jti: "proof-" + jti,
		Htm: "GET",
		Htu: "https://example.test/api/resource",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
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
