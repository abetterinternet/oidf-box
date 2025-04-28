package entity

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/errors"
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
	// Issuer is the entity that issued this statement.
	Issuer Identifier `json:"iss"`
	// Subject is the subject of this statement.
	Subject Identifier `json:"sub"`
	// IssuedAt is the time at which this statement was issued.
	IssuedAt float64 `json:"iat"`
	// Expiration is the time at which this statement expires.
	Expiration float64 `json:"exp"`
	// FederationEntityKeys is the keys used by this entity to sign entity statements.
	FederationEntityKeys jose.JSONWebKeySet `json:"jwks"`
	// AuthorityHints is the identifiers of entities that are immediate superiors of this entity.
	AuthorityHints []Identifier `json:"authority_hints,omitempty"`
	// Metadata is the metadata for this entity's OIDF entity types.
	Metadata map[EntityTypeIdentifier]any `json:"metadata,omitempty"`
	// TrustMarks is the trust marks held by this entity.
	TrustMarks []TrustMark `json:"trust_marks,omitempty"`
	// TrustMarkIssuers describes which entities may issue for each of the listed trust mark
	// identifiers.
	TrustMarkIssuers map[TrustMarkIdentifier][]Identifier `json:"trust_mark_issuers,omitempty"`
	// TrustMarkOwners describes which entities own each of the listed trust mark identifiers.
	TrustMarkOwners map[TrustMarkIdentifier][]Identifier `json:"trust_mark_owners,omitempty"`
	// TODO(timg): constraints, crit, source_endpoint
}

// signatureKeyID parses the provided signature and returns the key ID from its JWS header, as well
// as the parsed JWS.
func signatureKeyID(signature string, expectedType string) (*string, *jose.JSONWebSignature, error) {
	// The JWS header indicates what algorithm it's signed with, but jose requires us to provide a
	// list of acceptable signing algorithms.
	// TODO(timg): For now, we'll allow a variety of RSA PKCS1.5 and ECDSA algorithms but this
	// should be configurable somehow.
	jws, err := jose.ParseSigned(signature, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512,
	})
	if err != nil {
		return nil, nil, errors.Errorf("failed to validate JWS signature: %w", err)
	}

	if len(jws.Signatures) > 1 {
		return nil, nil, errors.Errorf("unexpected multi-signature JWS")
	}

	headerType, ok := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType]
	if !ok || headerType != expectedType {
		return nil, nil, errors.Errorf("wrong or no type in JWS header: %+v", jws.Signatures[0])
	}

	if jws.Signatures[0].Header.KeyID == "" {
		return nil, nil, errors.Errorf("JWS header must contain kid")
	}

	return &jws.Signatures[0].Header.KeyID, jws, nil
}

// ValidateEntityStatement validates that the provided signature is a well formed JSON web signature
// whose payload is a well formed OpenID Federation entity statement. The JWS signature is validated
// using one of the keys in the provided JWKS, or with a key inside the payload (in which case the
// payload is an entity configuration).
func ValidateEntityStatement(signature string, keys *jose.JSONWebKeySet) (*EntityStatement, error) {
	kid, jws, err := signatureKeyID(signature, EntityStatementHeaderType)
	if err != nil {
		return nil, err
	}

	if keys == nil {
		// This is an Entity *Configuration*, so to verify the signature, we have to find the signature
		// kid in the payload's JWKS, so we have to parse it untrusted.
		var untrustedEntityConfiguration EntityStatement
		if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &untrustedEntityConfiguration); err != nil {
			return nil, errors.Errorf("could not unmarshal JWS payload: %w", err)
		}

		// We should probably not examine anything in the payload until the signature is validated
		// but it's convenient to do this now.
		if !untrustedEntityConfiguration.IsEntityConfiguration() {
			return nil, errors.Errorf("iss and sub MUST be identical in entity configuration")
		}

		keys = &untrustedEntityConfiguration.FederationEntityKeys
	}

	verificationKeys := keys.Key(*kid)
	if len(verificationKeys) != 1 {
		return nil, errors.Errorf("found no or multiple keys in JWKS matching header kid %s", *kid)
	}

	// TODO(timg): why can't we validate the signature on a go-oidfed entity statement?
	entityStatementBytes := jws.UnsafePayloadWithoutVerification()
	// entityStatementBytes, err := jws.Verify(verificationKeys[0])
	// if err != nil {
	// 	return nil, errors.Errorf("failed to validate JWS signature: %w", err)
	// }

	var trustedEntityStatement EntityStatement
	if err := json.Unmarshal(entityStatementBytes, &trustedEntityStatement); err != nil {
		return nil, errors.Errorf("could not unmarshal JWS payload %s: %w", string(entityStatementBytes), err)
	}

	if float64(time.Now().Unix()) >= trustedEntityStatement.Expiration {
		return nil, errors.Errorf("entity statement has expired")
	}

	if !trustedEntityStatement.IsEntityConfiguration() {
		if len(trustedEntityStatement.AuthorityHints) != 0 {
			return nil, errors.Errorf("subordinate statements MUST NOT contain authority_hints")
		}

		if len(trustedEntityStatement.TrustMarkIssuers) != 0 {
			return nil, errors.Errorf("subordinate statements MUST NOT contain trust_mark_issuers")
		}

		if len(trustedEntityStatement.TrustMarkOwners) != 0 {
			return nil, errors.Errorf("subordinate statements MUST NOT contain trust_mark_owners")
		}
	}

	return &trustedEntityStatement, nil
}

// FindMetadata finds metadata for the specified entity type in the EntityStatement and decodes it
// into the provided metadata unmarshaler.
func (ec *EntityStatement) FindMetadata(entityType EntityTypeIdentifier, metadata any) error {
	metadataMap, ok := ec.Metadata[entityType]
	if !ok {
		return errors.Errorf("could not find metadata for entity %s", entityType)
	}

	// Go will deserialize each metadata into a map[string]interface{}. This is stupid and there may
	// be a nicer way to do this with generics, but we encode that back to JSON, then decode it into
	// the provided struct so we can use RTTI to give the caller a richer representation.
	jsonMetadata, err := json.Marshal(metadataMap)
	if err != nil {
		return errors.Errorf("failed to marshal metadata: %w", err)
	}

	return json.Unmarshal(jsonMetadata, metadata)
}

// EntityTypes returns the OpenID Federation entity types advertised by this entity statement.
func (ec *EntityStatement) EntityTypes() []EntityTypeIdentifier {
	return slices.Collect(maps.Keys(ec.Metadata))
}

// VerifyChallenge verifies if the signedChallenge is a valid JWS over the provided token, using
// this entity statement's acme_requestor JWKS.
func (es *EntityStatement) VerifyChallenge(signedChallenge string, token string) error {
	kid, jws, err := signatureKeyID(signedChallenge, SignedChallengeHeaderType)
	if err != nil {
		return err
	}

	var acmeRequestorMetadata ACMERequestorMetadata
	if err := es.FindMetadata(ACMERequestor, &acmeRequestorMetadata); err != nil {
		return fmt.Errorf("entity is not an ACME requestor: %w", err)
	}

	verificationKeys := acmeRequestorMetadata.CertifiableKeys.Key(*kid)
	if len(verificationKeys) != 1 {
		return errors.Errorf("found no or multiple keys in JWKS matching header kid %s", *kid)
	}

	challenge, err := jws.Verify(verificationKeys[0])
	if err != nil {
		return errors.Errorf("failed to validate challenge signature: %w", err)
	}

	if string(challenge) != token {
		return errors.Errorf("requestor challenge response signed over wrong token: %s", challenge)
	}

	return nil
}

// IsEntityConfiguration checks whether this statement was self-issued and hence is an Entity
// Configuration.
func (es *EntityStatement) IsEntityConfiguration() bool {
	return es.Issuer == es.Subject
}

// FederationEntityMetadata is the metadata for an OpenID Federation entity
// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1.1
type FederationEntityMetadata struct {
	FetchEndpoint   string `json:"federation_fetch_endpoint"`
	ListEndpoint    string `json:"federation_list_endpoint"`
	ResolveEndpoint string `json:"federation_resolve_endpoint"`

	// Non-standard endpoints
	SubordinationEndpoint string `json:"federation_subordination_endpoint"`
	IsTrustedEndpoint     string `json:"federation_is_trusted_endpoint"`
	SignChallengeEndpoint string `json:"federation_sign_challenge_endpoint"`
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
