package entity

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/go-jose/go-jose/v4"
)

const (
	// Entity Type Identifiers
	// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1
	FederationEntity EntityTypeIdentifier = "federation_entity"
	ACMERequestor    EntityTypeIdentifier = "acme_requestor"
	ACMEIssuer       EntityTypeIdentifier = "acme_issuer"
)

// EntityStatement is an OIDF Entity Statement
// https://openid.net/specs/openid-federation-1_0-41.html#section-3
type EntityStatement struct {
	Issuer               Identifier                           `json:"iss"`
	Subject              Identifier                           `json:"sub"`
	IssuedAt             int64                                `json:"iat"`
	Expiration           int64                                `json:"exp"`
	FederationEntityKeys jose.JSONWebKeySet                   `json:"jwks"`
	AuthorityHints       []Identifier                         `json:"authority_hints,omitempty"`
	Metadata             map[EntityTypeIdentifier]interface{} `json:"metadata,omitempty"`
	// TODO(timg): constraints, crit, trust marks
}

// ValidateEntityStatement validates that the provided signature is a well formed JSON web signature
// whose payload is a well formed OpenID Federation entity statement. The JWS signature is validated
// using one of the keys in the provided JWKS, or with a key inside the payload (in which case the
// payload is an entity configuration).
func ValidateEntityStatement(signature string, keys *jose.JSONWebKeySet) (*EntityStatement, error) {
	// The JWS header indicates what algorithm it's signed with, but jose requires us to provide a
	// list of acceptable signing algorithms.
	// TODO(timg): For now, we'll allow a variety of RSA PKCS1.5 and ECDSA algorithms but this
	// should be configurable somehow.
	jws, err := jose.ParseSigned(signature, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWS signature: %w", err)
	}

	if len(jws.Signatures) > 1 {
		return nil, fmt.Errorf("unexpected multi-signature JWS")
	}

	headerType, ok := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType]
	if !ok || headerType != EntityStatementHeaderType {
		return nil, fmt.Errorf("wrong or no type in JWS header: %+v", jws.Signatures[0])
	}

	if jws.Signatures[0].Header.KeyID == "" {
		return nil, fmt.Errorf("JWS header must contain kid")
	}

	if keys == nil {
		// This is an Entity *Configuration*, so to verify the signature, we have to find the signature
		// kid in the payload's JWKS, so we have to parse it untrusted.
		var untrustedEntityConfiguration EntityStatement
		if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &untrustedEntityConfiguration); err != nil {
			return nil, fmt.Errorf("could not unmarshal JWS payload: %w", err)
		}

		// We should probably not examine anything in the payload until the signature is validated
		// but it's convenient to do this now.
		if untrustedEntityConfiguration.Issuer != untrustedEntityConfiguration.Subject {
			return nil, fmt.Errorf("iss and sub MUST be identical in entity configuration")
		}

		keys = &untrustedEntityConfiguration.FederationEntityKeys
	}

	verificationKeys := keys.Key(jws.Signatures[0].Header.KeyID)

	if len(verificationKeys) != 1 {
		return nil, fmt.Errorf("found no or multiple keys in JWKS matching header kid")
	}

	entityStatementBytes, err := jws.Verify(verificationKeys[0])
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWS signature: %w", err)
	}

	var trustedEntityStatement EntityStatement
	if err := json.Unmarshal(entityStatementBytes, &trustedEntityStatement); err != nil {
		return nil, fmt.Errorf("could not unmarshal JWS payload %s: %w", string(entityStatementBytes), err)
	}

	return &trustedEntityStatement, nil
}

// FindMetadata finds metadata for the specified entity type in the EntityStatement and decodes it
// into the provided metadata unmarshaler.
func (ec *EntityStatement) FindMetadata(entityType EntityTypeIdentifier, metadata interface{}) error {
	metadataMap, ok := ec.Metadata[entityType]
	if !ok {
		return fmt.Errorf("could not find metadata for entity %s", entityType)
	}

	// Go will deserialize each metadata into a map[string]interface{}. This is stupid and there may
	// be a nicer way to do this with generics, but we encode that back to JSON, then decode it into
	// the provided struct so we can use RTTI to give the caller a richer representation.
	jsonMetadata, err := json.Marshal(metadataMap)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return json.Unmarshal(jsonMetadata, metadata)
}

// EntityTypes returns the OpenID Federation entity types advertised by this entity statement.
func (ec *EntityStatement) EntityTypes() []EntityTypeIdentifier {
	return slices.Collect(maps.Keys(ec.Metadata))
}

// FederationEntityMetadata is the metadata for an OpenID Federation entity
// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1.1
type FederationEntityMetadata struct {
	FetchEndpoint         string `json:"federation_fetch_endpoint"`
	ListEndpoint          string `json:"federation_list_endpoint"`
	ResolveEndpoint       string `json:"federation_resolve_endpoint"`
	SubordinationEndpoint string `json:"federation_subordination_endpoint"`
	// TODO(timg): various other endpoints
}

// ACMEIssuerMetadata describes an ACME issuer entity in an OpenID Federation
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.4.1
type ACMEIssuerMetadata struct {
	// The current draft requires that the entire ACME directory appear here, but I argue in the
	// issue below that it makes more sense to put the directory URI. That's also easier to
	// implement.
	// Ideally this would be a url.URL but serializing url.URL sucks!
	// https://github.com/peppelinux/draft-demarco-acme-openid-federation/issues/60
	Directory string `json:"directory"`
}

// ACMERequestorMetadata
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.4.2
type ACMERequestorMetadata struct {
	CertifiableKeys *jose.JSONWebKeySet `json:"jwks"`
}
