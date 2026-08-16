// Package oidc implements the per-cluster OIDC identity provider that backs
// IAM Roles for Service Accounts.
//
// The design here is what separates eksuvia from a mock. Rather than minting
// service-account tokens out of band, eksuvia generates an RSA keypair per
// cluster and hands the private key to kind's kube-apiserver as its
// service-account signing key, with --service-account-issuer pointed at the
// discovery document served from this package.
//
// The consequence is that the *real kubelet* projects *real* service-account
// tokens, signed by a key whose public half is published at a JWKS endpoint
// that STS can actually dereference. A pod running an unmodified AWS SDK
// performs the genuine AssumeRoleWithWebIdentity flow. Nothing in the path is
// stubbed, which is precisely the flow that cannot be exercised against an
// emulator with no kubelet.
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer is one cluster's OIDC identity provider.
type Signer struct {
	// Issuer is the iss claim and the base URL of the discovery document.
	Issuer string
	// KeyID is the JWKS kid, derived exactly as Kubernetes derives it so that
	// tokens minted by the apiserver carry a kid we publish.
	KeyID string

	private *rsa.PrivateKey
}

// DefaultAudience is the audience AWS SDKs request for IRSA.
const DefaultAudience = "sts.amazonaws.com"

// NewSigner generates a fresh 2048-bit keypair and derives its key ID.
func NewSigner(issuer string) (*Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidc: generating signing key: %w", err)
	}
	kid, err := keyIDFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{Issuer: issuer, KeyID: kid, private: key}, nil
}

// keyIDFromPublicKey reproduces Kubernetes' key ID derivation: the base64url
// encoding of the SHA-256 of the DER-encoded PKIX public key.
//
// This must match upstream exactly. If it does not, the apiserver stamps a kid
// into projected tokens that our JWKS does not advertise, and every IRSA
// verification fails with an unhelpful "key not found".
func keyIDFromPublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("oidc: marshalling public key: %w", err)
	}
	h := crypto.SHA256.New()
	h.Write(der)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// PrivateKeyPEM returns the PKCS#1 PEM handed to the apiserver as its
// service-account signing key.
func (s *Signer) PrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(s.private),
	})
}

// PublicKeyPEM returns the PKIX PEM handed to the apiserver as its
// service-account key file, used to verify tokens it did not mint itself.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&s.private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("oidc: marshalling public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// DiscoveryDocument is the /.well-known/openid-configuration payload.
//
// The field set matches what real EKS publishes. STS is strict about
// id_token_signing_alg_values_supported and about issuer matching the URL the
// document was fetched from, so neither is optional.
type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// Discovery builds the discovery document for this cluster.
func (s *Signer) Discovery() DiscoveryDocument {
	return DiscoveryDocument{
		Issuer:  s.Issuer,
		JWKSURI: strings.TrimSuffix(s.Issuer, "/") + "/keys",
		// EKS publishes an unusable authorization endpoint because the field is
		// required by the spec and the implicit flow is never exercised.
		AuthorizationEndpoint:            "urn:kubernetes:programmatic_authorization",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported:                  []string{"sub", "iss"},
	}
}

// JWK is one key in the JWKS.
type JWK struct {
	Use string `json:"use"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the key set served at the jwks_uri.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS renders the public key in JWK form.
func (s *Signer) JWKS() JWKS {
	pub := s.private.PublicKey
	return JWKS{Keys: []JWK{{
		Use: "sig",
		Kty: "RSA",
		Kid: s.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// ServiceAccountClaims is the claim set Kubernetes puts in a projected token.
type ServiceAccountClaims struct {
	jwt.RegisteredClaims
	Kubernetes KubernetesClaim `json:"kubernetes.io"`
}

// KubernetesClaim is the kubernetes.io claim block.
type KubernetesClaim struct {
	Namespace      string        `json:"namespace"`
	ServiceAccount SANameAndUID  `json:"serviceaccount"`
	Pod            *SANameAndUID `json:"pod,omitempty"`
}

// SANameAndUID identifies a service account or pod.
type SANameAndUID struct {
	Name string `json:"name"`
	UID  string `json:"uid,omitempty"`
}

// MintServiceAccountToken issues a token shaped like one the kubelet would
// project.
//
// In normal operation this is not on the IRSA path -- the apiserver mints those
// itself using the same key. It exists so `eksuvia irsa token` can hand a
// developer a valid token for a service account without deploying a pod, which
// is the one genuinely useful thing an emulator can offer over real EKS.
func (s *Signer) MintServiceAccountToken(namespace, serviceAccount, audience string, ttl time.Duration) (string, error) {
	if namespace == "" || serviceAccount == "" {
		return "", fmt.Errorf("oidc: namespace and service account are required")
	}
	if audience == "" {
		audience = DefaultAudience
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	claims := ServiceAccountClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Kubernetes: KubernetesClaim{
			Namespace:      namespace,
			ServiceAccount: SANameAndUID{Name: serviceAccount},
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.KeyID
	return tok.SignedString(s.private)
}

// IssuerID derives the opaque identifier EKS puts in an issuer URL.
//
// Real EKS uses a 32-character uppercase hex string. Matching that shape keeps
// generated trust policies and Terraform output visually identical to
// production, which matters when the emulator is used to author IAM policy that
// will later be applied for real.
func IssuerID(clusterName, seed string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(clusterName + "|" + seed))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))[:32])
}
