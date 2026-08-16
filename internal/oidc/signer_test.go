package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "http://eksuvia:4566/id/ABC123"

func TestNewSignerProducesUsableKeys(t *testing.T) {
	s, err := NewSigner(testIssuer)
	if err != nil {
		t.Fatalf("NewSigner returned unexpected error: %v", err)
	}

	// The private key is handed to the API server as its service-account signing
	// key, so it must be a parseable PKCS#1 PEM.
	block, _ := pem.Decode(s.PrivateKeyPEM())
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PrivateKeyPEM did not produce an RSA PRIVATE KEY block")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("private key is not valid PKCS#1: %v", err)
	}

	pubPEM, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM returned unexpected error: %v", err)
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatal("PublicKeyPEM did not produce a PUBLIC KEY block")
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		t.Fatalf("public key is not valid PKIX: %v", err)
	}
}

func TestKeyIDMatchesKubernetesDerivation(t *testing.T) {
	s, err := NewSigner(testIssuer)
	if err != nil {
		t.Fatalf("NewSigner returned unexpected error: %v", err)
	}

	// Recompute the way Kubernetes does: base64url of the SHA-256 of the DER
	// PKIX public key. If these ever diverge, the API server stamps a kid into
	// projected tokens that our JWKS does not advertise and every IRSA
	// verification fails with an unhelpful "key not found".
	pubPEM, _ := s.PublicKeyPEM()
	block, _ := pem.Decode(pubPEM)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing public key: %v", err)
	}
	want, err := keyIDFromPublicKey(parsed)
	if err != nil {
		t.Fatalf("keyIDFromPublicKey: %v", err)
	}
	if s.KeyID != want {
		t.Errorf("KeyID = %q, want %q", s.KeyID, want)
	}
	if s.KeyID == "" {
		t.Error("KeyID must not be empty")
	}
}

func TestJWKSAdvertisesTheSigningKey(t *testing.T) {
	s, _ := NewSigner(testIssuer)
	jwks := s.JWKS()

	if len(jwks.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kid != s.KeyID {
		t.Errorf("kid = %q, want %q", key.Kid, s.KeyID)
	}
	if key.Alg != "RS256" || key.Kty != "RSA" || key.Use != "sig" {
		t.Errorf("unexpected JWK header: %+v", key)
	}

	// Reconstruct the public key from n/e and confirm it matches, since that is
	// exactly what STS will do before trusting a projected token.
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("decoding modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		t.Fatalf("decoding exponent: %v", err)
	}
	rebuilt := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	if rebuilt.N.Cmp(s.private.N) != 0 || rebuilt.E != s.private.E {
		t.Error("JWKS does not round-trip to the actual signing key")
	}
}

func TestDiscoveryDocument(t *testing.T) {
	s, _ := NewSigner(testIssuer)
	doc := s.Discovery()

	// STS requires the issuer in the document to match the URL it was fetched
	// from, and refuses providers that do not advertise RS256.
	if doc.Issuer != testIssuer {
		t.Errorf("issuer = %q, want %q", doc.Issuer, testIssuer)
	}
	if doc.JWKSURI != testIssuer+"/keys" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) != 1 || doc.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Errorf("signing algs = %v, want [RS256]", doc.IDTokenSigningAlgValuesSupported)
	}
}

func TestMintServiceAccountToken(t *testing.T) {
	s, _ := NewSigner(testIssuer)

	raw, err := s.MintServiceAccountToken("my-ns", "my-sa", "", time.Hour)
	if err != nil {
		t.Fatalf("MintServiceAccountToken returned unexpected error: %v", err)
	}

	parsed, err := jwt.Parse(raw, func(tok *jwt.Token) (any, error) {
		return &s.private.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("minted token does not verify against its own key: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != s.KeyID {
		t.Errorf("token kid = %q, want %q", kid, s.KeyID)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	if sub, _ := claims["sub"].(string); sub != "system:serviceaccount:my-ns:my-sa" {
		t.Errorf("sub = %q, want system:serviceaccount:my-ns:my-sa", sub)
	}
	if iss, _ := claims["iss"].(string); iss != testIssuer {
		t.Errorf("iss = %q, want %q", iss, testIssuer)
	}
	// The default audience must be the one AWS SDKs request.
	aud, err := claims.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != DefaultAudience {
		t.Errorf("aud = %v, want [%s]", aud, DefaultAudience)
	}
}

func TestMintServiceAccountTokenRequiresIdentity(t *testing.T) {
	s, _ := NewSigner(testIssuer)
	if _, err := s.MintServiceAccountToken("", "my-sa", "", time.Hour); err == nil {
		t.Error("expected an error when the namespace is empty")
	}
	if _, err := s.MintServiceAccountToken("my-ns", "", "", time.Hour); err == nil {
		t.Error("expected an error when the service account is empty")
	}
}

func TestIssuerIDShapeMatchesEKS(t *testing.T) {
	id := IssuerID("my-cluster", "000000000000")

	// Real EKS issuer IDs are 32 uppercase hex characters. Matching the shape
	// keeps generated trust policies visually identical to production.
	if len(id) != 32 {
		t.Errorf("length = %d, want 32", len(id))
	}
	if id != strings.ToUpper(id) {
		t.Errorf("id %q should be uppercase", id)
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789ABCDEF", c) {
			t.Fatalf("id %q contains non-hex character %q", id, c)
		}
	}

	if IssuerID("my-cluster", "000000000000") != id {
		t.Error("IssuerID must be deterministic")
	}
	if IssuerID("other-cluster", "000000000000") == id {
		t.Error("different clusters must get different issuer IDs")
	}
}
