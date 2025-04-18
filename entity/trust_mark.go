package entity

import (
	_ "encoding/json"
	_ "fmt"
	_ "maps"
	_ "slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/errors"
)

const (
	TrustMarkHeaderType           = "trust-mark+jwt"
	TrustMarkDelegationHeaderType = "trust-mark-delegation+jwt"
)

// TrustMarkIdentifier identifies a trust mark.
type TrustMarkIdentifier string

// TrustMark is an OpenID Federation trust mark, defined in
// https://openid.net/specs/openid-federation-1_0-41.html#section-7
type TrustMark struct {
	// Issuer is the issuer of this trust mark.
	Issuer Identifier `json:"iss"`
	// Subject is the subject of this trust mark.
	Subject Identifier `json:"sub"`
	// IssuedAt is the time at which the trust mark was issued.
	IssuedAt int64 `json:"iat"`
	// Expiration is the time past which the trust mark should no longer be trusted.
	Expiration int64 `json:"exp,omitempty"`
	// Identifier is the identifier of the trust mark.
	Identifier string `json:"id"`
	// Delegation is the delegation claim for this trust mark.
	Delegation *jose.JSONWebSignature `json:"delegation,omitempty"`
	// TODO: human-facing fields like logo_uri or ref
}

// ValidateTrustMark validates that the provided signature is a well formed JSON web signature
// whose payload is a well formed OpenID Federation trust mark. The JWS signature is validated
// using XXX what key?
func ValidateTrustMark(signature string, trustAnchor Identifier) (*TrustMark, error) {
	// untrusted parse the trust mark <-- unforunate we have to keep parsing untrusted stuff
	// validate signature
	// fetch trust anchor EC
	// look up the trust mark identifier in the TA's trust_mark_owners and/or _issuers
	// fetch EC for that entity, build chain back to trust anchor
	// check that the trust mark JWT is signed with one of the issuer's JWKS
	return nil, errors.Errorf("not yet implemented")
}

// TrustMarkDelegation is a JWT identifying a legitimate delegated issuer of trust marks with a
// particular identifier.
// https://openid.net/specs/openid-federation-1_0-41.html#section-7.2.1
type TrustMarkDelegation struct {
	// Issuer is the issuer of this trust mark delegation.
	Issuer Identifier `json:"iss"`
	// Subject is the subject of this trust mark delegation.
	Subject Identifier `json:"sub"`
	// IssuedAt is the time at which the trust mark delegation was issued.
	IssuedAt int64 `json:"iat"`
	// Expiration is the time past which the trust mark delegation should no longer be trusted.
	Expiration int64 `json:"exp,omitempty"`
	// Identifier is the identifier of the delegated trust mark.
	Identifier string `json:"id"`
}
