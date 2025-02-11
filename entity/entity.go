package entity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/httpclient"
)

const (
	EntityStatementHeaderType = "entity-statement+jwt"

	// https://openid.net/specs/openid-federation-1_0-41.html#name-obtaining-federation-entity
	EntityConfigurationPath    = "/.well-known/openid-federation"
	EntityStatementContentType = "application/entity-statement+jwt"

	// Federation entity endpoints
	// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1.1
	FederationFetchEndpoint = "/federation-fetch"
	FederationListEndpoint  = "/federation-list"
	// TODO(timg) Trust mark related endpoints

	// Entity Type Identifiers
	// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1
	FederationEntity EntityTypeIdentifier = "federation_entity"
	ACMERequestor    EntityTypeIdentifier = "acme_requestor"
	ACMEIssuer       EntityTypeIdentifier = "acme_issuer"
)

type EntityTypeIdentifier string

// Identifier identifies an entity in an OpenID Federation.
// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.4
type Identifier struct {
	url url.URL
}

// NewIdentifier returns an EntityIdentifier if it the provided identifier is a valid OpenID
// Federation entity identifier.
func NewIdentifier(identifier string) (Identifier, error) {
	entityURL, err := url.Parse(identifier)
	if err != nil {
		return Identifier{}, fmt.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: %w",
			identifier, err)
	}

	// TODO(timg): https is required by OpenID Federation, but requiring https identifiers is a
	// hassle in testing here I want to use a bunch of entities like http://localhost:8000
	// if entityURL.Scheme != "https" {
	// 	return Identifier{}, fmt.Errorf(
	// 		"identifier '%s' is not a valid OIDF entity identifier: scheme must be https",
	// 		identifier)
	// }

	if entityURL.Fragment != "" {
		return Identifier{}, fmt.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: has fragment", identifier)
	}

	if len(entityURL.Query()) > 0 {
		return Identifier{}, fmt.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: has query", identifier)
	}

	return Identifier{url: *entityURL}, nil
}

func (i *Identifier) Equals(other *Identifier) bool {
	if i == other {
		return true
	}

	if (i == nil) != (other == nil) {
		return false
	}

	return i.url.String() == other.url.String()
}

func (i *Identifier) String() string {
	return i.url.String()
}

func (i Identifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

func (i *Identifier) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	identifier, err := NewIdentifier(s)
	if err != nil {
		return err
	}

	*i = identifier

	return nil
}

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

// ValidateEntityConfiguration validates that the provided JWS is a valid OIDF Entity Configuration.
func ValidateEntityConfiguration(signature string) (*EntityStatement, error) {
	// The JWS header indicates what algorithm it's signed with, but jose requires us to provide a
	// list of acceptable signing algorithms. For now, we'll allow a variety of RSA PKCS1.5 and
	// ECDSA but this should be configurable somehow.
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

	// This is an Entity *Configuration*, so to verify the signature, we have to find the signature
	// kid in the payload's JWKS, so we have to parse it untrusted.
	var untrustedEntityConfiguration EntityStatement
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &untrustedEntityConfiguration); err != nil {
		return nil, fmt.Errorf("could not unmarshal JWS payload: %w", err)
	}

	verificationKeys := untrustedEntityConfiguration.FederationEntityKeys.Key(jws.Signatures[0].Header.KeyID)

	if len(verificationKeys) != 1 {
		return nil, fmt.Errorf("found no or multiple keys in JWKS matching header kid")
	}

	entityConfigurationBytes, err := jws.Verify(verificationKeys[0])
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWS signature: %w", err)
	}

	var trustedEntityConfiguration EntityStatement
	if err := json.Unmarshal(entityConfigurationBytes, &trustedEntityConfiguration); err != nil {
		return nil, fmt.Errorf("could not unmarshal JWS payload %s: %w", string(entityConfigurationBytes), err)
	}

	return &trustedEntityConfiguration, nil
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

// FederationEntityMetadata is the metadata for an OpenID Federation entity
// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1.1
type FederationEntityMetadata struct {
	FetchEndpoint   string `json:"federation_fetch_endpoint"`
	ListEndpoint    string `json:"federation_list_endpoint"`
	ResolveEndpoint string `json:"federation_resolve_endpoint"`
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

// EntityOptions are options for constructing an Entity.
type EntityOptions struct {
	// If true, metadata for the acme_requestor entity type will be constructed and advertised.
	IsACMERequestor bool
	// If set, the entity will advertise acme_issuer metadata using the provided URL.
	ACMEIssuer *url.URL
	// Trust anchors trusted by this entity.
	TrustAnchors []string
}

// Entity represents an OpenID Federation Entity.
type Entity struct {
	// Identifier for the OpenID Federation Entity.
	Identifier Identifier
	// identifiers for the trust anchors trusted by this entity.
	trustAnchors []Identifier
	// federationEntityKey is this entity's keys
	// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.44
	federationEntityKeys jose.JSONWebKeySet
	// acmeRequestorKeys is the set of keys that this entity MAY request X.509 certificates for. If
	// non-empty, this entity has the type acme_requestor (possibly alongside other entity types).
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-requestor-metadata
	acmeRequestorKeys jose.JSONWebKeySet
	// acmeDirectory is where an ACME server directory may be found. If non-nil, this entity has the
	// type acme_issuer (possibly alongside other entity types).
	acmeDirectory *url.URL
	// subordinates is this entity's federation subordinates
	// TODO(timg): locking on this and superiors since they can be read by HTTP handlers
	subordinates map[Identifier]EntityStatement
	// superiors is the federation entities known to have emitted entity statements about this
	// entity
	// TODO(timg): this should be a set, or failing that map[Identifier]struct{}
	superiors []Identifier

	// client is used for HTTP requests
	client httpclient.Client
	// listener may be a bound port on which requests for OpenID Federation API (i.e. entity
	// configurations or other federation endpoints) are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

// New constructs a new Entity, generating keys as needed.
func New(identifier string, options EntityOptions) (Entity, error) {
	parsedIdentifier, err := NewIdentifier(identifier)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to parse identifier '%s': %w", identifier, err)
	}

	var trustAnchors []Identifier
	for _, trustAnchor := range options.TrustAnchors {
		parsedTrustAnchor, err := NewIdentifier(trustAnchor)
		if err != nil {
			return Entity{}, fmt.Errorf("invalid trust anchor identifier %s", trustAnchor)
		}

		trustAnchors = append(trustAnchors, parsedTrustAnchor)
	}

	// Generate the federation entity keys. Hard code a single 2048 bit RSA key for now.
	federationEntityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to generate key: %w", err)
	}
	federationEntityKeys, err := privateJWKS([]interface{}{federationEntityKey})
	if err != nil {
		return Entity{}, fmt.Errorf("failed to construct JWKS for federation entity: %w", err)
	}

	entity := Entity{
		Identifier:           parsedIdentifier,
		trustAnchors:         trustAnchors,
		federationEntityKeys: federationEntityKeys,
		acmeDirectory:        options.ACMEIssuer,
		client:               httpclient.New(),
		subordinates:         make(map[Identifier]EntityStatement),
		superiors:            []Identifier{},
	}

	if options.IsACMERequestor {
		// Generate the keys this entity may certify. Hard code one RSA key, one EC key.
		rsaACMERequestorKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return Entity{}, fmt.Errorf("failed to generate RSA key to certify: %w", err)
		}

		ecACMERequestorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Entity{}, fmt.Errorf("failed to generate P256 key to certify: %w", err)
		}

		acmeRequestorKeys, err := privateJWKS([]interface{}{rsaACMERequestorKey, ecACMERequestorKey})
		if err != nil {
			return Entity{}, fmt.Errorf("failed to construct JWKS for keys to certify: %w", err)
		}

		entity.acmeRequestorKeys = acmeRequestorKeys
	}

	return entity, nil
}

// signEntityStatement signs an entity statement using this entity's federation entity keys.
func (e *Entity) signEntityStatement(entityStatement EntityStatement) (*jose.JSONWebSignature, error) {
	payload, err := json.Marshal(entityStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity statement to JSON: %w", err)
	}

	if e.federationEntityKeys.Keys[0].KeyID == "" {
		panic("federation entity key KID should be set")
	}

	if e.federationEntityKeys.Keys[0].Algorithm == "" {
		panic("federation entity key alg should be set")
	}

	entityConfigurationSigner, err := jose.NewSigner(
		jose.SigningKey{
			// TODO(timg): don't hard code algorithm, but it's annoying to go from jose.JSONWebKey
			// to jose.Algorithm for some reason
			Algorithm: jose.RS256,
			Key:       e.federationEntityKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				// "typ" required by OIDF
				jose.HeaderType: "entity-statement+jwt",
				// "kid" required by OIDF
				"kid": e.federationEntityKeys.Keys[0].KeyID,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := entityConfigurationSigner.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign entity statement: %w", err)
	}

	return signed, nil
}

// entityConfiguration constructs an entity configuration for this entity
func (e *Entity) entityConfiguration() EntityStatement {
	metadata := map[EntityTypeIdentifier]interface{}{
		FederationEntity: FederationEntityMetadata{
			FetchEndpoint: FederationFetchEndpoint,
			ListEndpoint:  FederationListEndpoint,
			// TODO(timg): informational metadata
			// https://openid.net/specs/openid-federation-1_0-41.html#section-5.2.2
		},
	}

	if len(e.acmeRequestorKeys.Keys) > 0 {
		metadata[ACMERequestor] = ACMERequestorMetadata{
			CertifiableKeys: &e.acmeRequestorKeys,
		}
	}

	if e.acmeDirectory != nil {
		metadata[ACMEIssuer] = ACMEIssuerMetadata{
			Directory: e.acmeDirectory.String(),
		}
	}

	return EntityStatement{
		Issuer:               e.Identifier,
		Subject:              e.Identifier,
		IssuedAt:             time.Now().Unix(),
		Expiration:           time.Now().Unix() + 3600, // valid for 1 hour
		FederationEntityKeys: publicJWKS(&e.federationEntityKeys),
		Metadata:             metadata,
		AuthorityHints:       e.superiors,
	}
}

// SignedEntityConfiguration constructs and signs an Entity Configuration for this Entity
func (e *Entity) SignedEntityConfiguration() (*jose.JSONWebSignature, error) {
	return e.signEntityStatement(e.entityConfiguration())
}

// FetchEntityConfiguration obtains an entity configuration for the provided identifier per
// https://openid.net/specs/openid-federation-1_0-41.html#section-9
func (e *Entity) FetchEntityConfiguration(identifier Identifier) (*EntityStatement, error) {
	// TODO(timg): I'd prefer this to be a method on EntityStatement, but sticking it on Entity
	// makes it easier to use the HTTP client
	entityConfigurationURL := identifier.url.JoinPath(EntityConfigurationPath)
	ecBytes, err := e.client.Get(*entityConfigurationURL, EntityStatementContentType)
	if err != nil {
		return nil, err
	}

	entityConfiguration, err := ValidateEntityConfiguration(string(ecBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to validate EC: %w", err)
	}

	return entityConfiguration, nil
}

// AddSubordinate makes this entity add the provided subordinate to its list of federation
// subordinates. If successful, an entity statement for the subordinate will be available from this
// entity's federation fetch and subordinate list endpoints. Callers are responsible for updating
// the Entity Configuration of the subordinate to include this entity's identifier (e.g. by using
// AddSuperior()).
//
// This interface does not conform to any part of the OpenID Federation specification (which says
// nothing about establishing subordination) and is only expected to work within this project.
func (e *Entity) AddSubordinate(subordinate Identifier) error {
	subordinateEC, err := e.FetchEntityConfiguration(subordinate)
	if err != nil {
		return err
	}

	// This is where we might evaluate some policy on the subordinate and decide whether or not we
	// want to emit an ES for them. In this test/prototype setup, we unconditionally trust any
	// subordinate presented to us.

	// Construct the equivalent entity statement
	subordinateEC.Issuer = e.Identifier
	subordinateEC.IssuedAt = time.Now().Unix()
	subordinateEC.Expiration = time.Now().Unix() + 3600 // valid for 1 hour
	// authority_hints is forbidden in an entity statement
	subordinateEC.AuthorityHints = nil

	e.subordinates[subordinate] = *subordinateEC

	return nil
}

// AddSuperior adds the provided identifier to this entity's federation superiors, such that it will
// subsequently be included in the entity configuration. Callers are responsible for getting the
// designated superior to emit an appropriate entity statement for this entity.
func (e *Entity) AddSuperior(superior Identifier) {
	if !slices.Contains(e.superiors, superior) {
		e.superiors = append(e.superiors, superior)
	}
}

func (e *Entity) ServeFederationEndpoints() error {
	// Listen at whatever port is in the identifier, which may not be right
	var err error
	e.listener, err = net.Listen("tcp", net.JoinHostPort("", e.Identifier.url.Port()))
	if err != nil {
		return fmt.Errorf("could not start HTTP server for OIDF EC: %w", err)
	}

	e.done = make(chan struct{})

	go func() {
		mux := http.NewServeMux()

		mux.HandleFunc(EntityConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.entityConfigurationHandler(w, r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})
		mux.HandleFunc(FederationFetchEndpoint, func(w http.ResponseWriter, r *http.Request) {
			panic("not implemented")
		})
		mux.HandleFunc(FederationListEndpoint, func(w http.ResponseWriter, r *http.Request) {
			panic("not implemented")
		})

		httpServer := &http.Server{Handler: mux}

		// Once httpServer is shut down we don't want any lingering connections, so disable KeepAlives.
		httpServer.SetKeepAlivesEnabled(false)

		if err := httpServer.Serve(e.listener); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			log.Println(err)
		}

		e.done <- struct{}{}
	}()

	return nil
}

func (e *Entity) CleanUp() {
	if e.listener == nil {
		return
	}

	e.listener.Close()

	<-e.done
}

// SignChallenge constructs a JWS containing a signature over token using one of the entity's
// acme_requestor keys.
// TODO: should/could move this over to openidfederation01 module
func (e *Entity) SignChallenge(token string) (*jose.JSONWebSignature, error) {
	challengeSigner, err := jose.NewSigner(
		jose.SigningKey{
			// TODO(timg): here we hard code the use of the first acme_requestor key, and assume it
			// is RS256. We could do something like randomly choose a key among that JWKS, but it's
			// annoying to go from jose.JSONWebKey to jose.Algorithm for some reason
			Algorithm: jose.RS256,
			Key:       e.acmeRequestorKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				// kid is REQUIRED by acme-openid-fed, but it doesn't say anything about typ here. I
				// suspect we should set one to avoid token confusion.
				// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5-7
				// TODO(timg): set jose.HeaderType
				"kid": e.acmeRequestorKeys.Keys[0].KeyID,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := challengeSigner.Sign([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("Failed to sign challenge: %w", err)
	}

	return signed, nil
}

func (e *Entity) entityConfigurationHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodGet {
		return fmt.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	entityConfiguration, err := e.SignedEntityConfiguration()
	if err != nil {
		return err, http.StatusInternalServerError
	}

	compact, err := entityConfiguration.CompactSerialize()
	if err != nil {
		return err, http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", EntityStatementContentType)
	// All JWSes MUST use compact serialization
	// https://openid.net/specs/openid-federation-1_0-41.html#name-requirements-notation-and-c
	if _, err := w.Write([]byte(compact)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}

// privateJWKS returns a JSONWebKeySet containing the public and private portions of provided keys
func privateJWKS(keys []interface{}) (jose.JSONWebKeySet, error) {
	privateJWKS := jose.JSONWebKeySet{}
	for _, key := range keys {
		jsonWebKey := jose.JSONWebKey{Key: key}

		thumbprint, err := jsonWebKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to compute thumbprint: %w", err)
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

// publicJWKS returns a JSONWebKeySet containing only the public portion of jwks.
func publicJWKS(jwks *jose.JSONWebKeySet) jose.JSONWebKeySet {
	publicJWKS := jose.JSONWebKeySet{}
	for _, jsonWebKey := range jwks.Keys {
		publicJWKS.Keys = append(publicJWKS.Keys, jsonWebKey.Public())
	}

	return publicJWKS
}
