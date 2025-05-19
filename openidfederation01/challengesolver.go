package openidfederation01

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/go-jose/go-jose/v4"

	"github.com/tgeoghegan/oidf-box/errors"
)

const (
	SignedChallengeHeaderType = "signed-acme-challenge+jwt"
)

// ChallengeSolver solves ACME OpenIDFederation challenges over HTTP
type ChallengeSolver struct {
	EntityIdentifier string
	// challengeSigningKeys is a set of keys that may be used to solve ACME challenges.
	challengeSigningKeys jose.JSONWebKeySet

	// listener may be a bound port on which requests for OpenID Federation API (i.e. entity
	// configurations or other federation endpoints) are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

// NewSolver generates keys and creates a ChallengeSolver.
func NewSolver(identifier string) (*ChallengeSolver, error) {
	challengeSigningKeys, err := GenerateACMEChallengeSigningKeys()
	if err != nil {
		return nil, err
	}

	return &ChallengeSolver{
		EntityIdentifier:     identifier,
		challengeSigningKeys: *challengeSigningKeys,
	}, nil
}

// ChallengeSigningPublicKeys returns a JSONWebKeySet containing only the public portion of the
// solver's challenge signing keys.
func (s *ChallengeSolver) ChallengeSigningPublicKeys() *jose.JSONWebKeySet {
	publicKeys := publicJWKS(&s.challengeSigningKeys)
	return &publicKeys
}

// Solve constructs a JWS containing a signature over token using one of the entity's acme_requestor
// keys.
func (s *ChallengeSolver) Solve(token string) (*ChallengeResponse, error) {
	challengeSigner, err := jose.NewSigner(
		jose.SigningKey{
			// TODO: probably should validate that the Algorithm field is valid somehow
			Algorithm: jose.SignatureAlgorithm(s.challengeSigningKeys.Keys[0].Algorithm),
			Key:       s.challengeSigningKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{
				// kid is REQUIRED by acme-openid-fed, but it doesn't say anything about typ here. I
				// suspect we should set one to avoid token confusion.
				// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5-7
				jose.HeaderType: SignedChallengeHeaderType,
				"kid":           s.challengeSigningKeys.Keys[0].KeyID,
			},
		},
	)
	if err != nil {
		return nil, errors.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := challengeSigner.Sign([]byte(token))
	if err != nil {
		return nil, errors.Errorf("Failed to sign challenge: %w", err)
	}

	compactSignedToken, err := signed.CompactSerialize()
	if err != nil {
		return nil, errors.Errorf("failed to compact serialize JWS: %w", err)
	}

	return &ChallengeResponse{Sig: compactSignedToken}, nil
}

// publicJWKS returns a JSONWebKeySet containing only the public portion of jwks.
func publicJWKS(jwks *jose.JSONWebKeySet) jose.JSONWebKeySet {
	publicJWKS := jose.JSONWebKeySet{}
	for _, jsonWebKey := range jwks.Keys {
		publicJWKS.Keys = append(publicJWKS.Keys, jsonWebKey.Public())
	}

	return publicJWKS
}

// privateJWKS returns a JSONWebKeySet containing the public and private portions of provided keys
func privateJWKS(keys []any) (jose.JSONWebKeySet, error) {
	privateJWKS := jose.JSONWebKeySet{}
	for _, key := range keys {
		jsonWebKey := jose.JSONWebKey{Key: key}

		thumbprint, err := jsonWebKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return jose.JSONWebKeySet{}, errors.Errorf("failed to compute thumbprint: %w", err)
		}
		kid := base64.URLEncoding.EncodeToString(thumbprint)
		jsonWebKey.KeyID = kid

		// Gross, but I'm not sure how else to get at the `alg` value for a JSONWebKey in go-jose
		var alg jose.SignatureAlgorithm
		switch k := key.(type) {
		case *rsa.PrivateKey:
			alg = jose.RS256
		case *ecdsa.PrivateKey:
			if k.Curve == elliptic.P256() {
				alg = jose.ES256
			} else if k.Curve == elliptic.P384() {
				alg = jose.ES384
			}
		}
		jsonWebKey.Algorithm = string(alg)

		privateJWKS.Keys = append(privateJWKS.Keys, jsonWebKey)
	}

	return privateJWKS, nil
}

// GenerateACMEChallengeSigningKeys generates some keys that can be used to satisfy ACME OpenID
// Federation challenges.Hard codeed to generate one RSA key, one EC key.
func GenerateACMEChallengeSigningKeys() (*jose.JSONWebKeySet, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Errorf("failed to generate RSA key for challenge signing: %w", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Errorf("failed to generate P256 key for challenge signing: %w", err)
	}

	keys, err := privateJWKS([]any{rsaKey, ecKey})
	if err != nil {
		return nil, fmt.Errorf("failed to construct JWKS for challenge signing keys: %w", err)
	}

	return &keys, err
}
