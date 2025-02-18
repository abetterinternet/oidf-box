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
)

const (
	EntityStatementHeaderType = "entity-statement+jwt"
	SignedChallengeHeaderType = "signed-acme-challenge+jwt"

	// https://openid.net/specs/openid-federation-1_0-41.html#name-obtaining-federation-entity
	EntityConfigurationPath    = "/.well-known/openid-federation"
	EntityStatementContentType = "application/entity-statement+jwt"

	// Federation entity endpoints
	// https://openid.net/specs/openid-federation-1_0-41.html#section-5.1.1
	FederationFetchEndpoint = "/federation-fetch"
	FederationListEndpoint  = "/federation-list"
	// Subordination request endpoint
	FederationSubordinationEndpoint = "/federation-subordination"
	// TODO(timg) Trust mark related endpoints

	// Query parameters for federation endpoints
	QueryParamSub          = "sub"
	QueryParamEntityType   = "entity_type"
	QueryParamTrustMarked  = "trust_marked"
	QueryParamTrustMarkID  = "trust_mark_id"
	QueryParamIntermediate = "intermediate"
)

type EntityTypeIdentifier string

// Identifier identifies an entity in an OpenID Federation.
// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.4
type Identifier struct {
	URL url.URL
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

	return Identifier{URL: *entityURL}, nil
}

func (i *Identifier) Equals(other *Identifier) bool {
	if i == other {
		return true
	}

	if (i == nil) != (other == nil) {
		return false
	}

	return i.URL.String() == other.URL.String()
}

func (i *Identifier) String() string {
	return i.URL.String()
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

// EntityOptions are options for constructing an Entity.
type EntityOptions struct {
	// If true, metadata for the acme_requestor entity type will be constructed and advertised.
	IsACMERequestor bool
	// If set, the entity will advertise acme_issuer metadata using the provided URL.
	ACMEIssuer string
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

	// client is used for OpenID Federation API requests
	// TODO(timg): cache instances of FederationEndpoints
	client HTTPClient
	// listener may be a bound port on which requests for OpenID Federation API (i.e. entity
	// configurations or other federation endpoints) are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

// New constructs a new Entity, generating keys as needed.
func New(identifier string, options EntityOptions) (*Entity, error) {
	parsedIdentifier, err := NewIdentifier(identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identifier '%s': %w", identifier, err)
	}

	var trustAnchors []Identifier
	for _, trustAnchor := range options.TrustAnchors {
		parsedTrustAnchor, err := NewIdentifier(trustAnchor)
		if err != nil {
			return nil, fmt.Errorf("invalid trust anchor identifier %s", trustAnchor)
		}

		trustAnchors = append(trustAnchors, parsedTrustAnchor)
	}

	// Generate the federation entity keys. Hard code a single 2048 bit RSA key for now.
	federationEntityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	federationEntityKeys, err := privateJWKS([]interface{}{federationEntityKey})
	if err != nil {
		return nil, fmt.Errorf("failed to construct JWKS for federation entity: %w", err)
	}

	entity := Entity{
		Identifier:           parsedIdentifier,
		trustAnchors:         trustAnchors,
		federationEntityKeys: federationEntityKeys,
		client:               NewOIDFClient(),
		subordinates:         make(map[Identifier]EntityStatement),
		superiors:            []Identifier{},
	}

	if options.IsACMERequestor {
		// Generate the keys this entity may certify. Hard code one RSA key, one EC key.
		rsaACMERequestorKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key to certify: %w", err)
		}

		ecACMERequestorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate P256 key to certify: %w", err)
		}

		acmeRequestorKeys, err := privateJWKS([]interface{}{rsaACMERequestorKey, ecACMERequestorKey})
		if err != nil {
			return nil, fmt.Errorf("failed to construct JWKS for keys to certify: %w", err)
		}

		entity.acmeRequestorKeys = acmeRequestorKeys
	}

	if options.ACMEIssuer != "" {
		url, err := url.Parse(options.ACMEIssuer)
		if err != nil {
			return nil, fmt.Errorf("invalid ACME issuer URL '%s: %w", options.ACMEIssuer, err)
		}

		entity.acmeDirectory = url
	}

	return &entity, nil
}

// NewAndServe calls New, and then calls ServeFederationEndpoints.
func NewAndServe(identifier string, options EntityOptions) (*Entity, error) {
	entity, err := New(identifier, options)
	if err != nil {
		return nil, err
	}

	if err := entity.ServeFederationEndpoints(); err != nil {
		return nil, err
	}

	return entity, err
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
			FetchEndpoint:         e.Identifier.URL.JoinPath(FederationFetchEndpoint).String(),
			ListEndpoint:          e.Identifier.URL.JoinPath(FederationListEndpoint).String(),
			SubordinationEndpoint: e.Identifier.URL.JoinPath(FederationSubordinationEndpoint).String(),
			// TODO(timg): informational metadata
			// https://openid.net/specs/openid-federation-1_0-41.html#section-5.2.2
		},
	}

	if len(e.acmeRequestorKeys.Keys) > 0 {
		publicACMERequestorKeys := publicJWKS(&e.acmeRequestorKeys)
		metadata[ACMERequestor] = ACMERequestorMetadata{
			CertifiableKeys: &publicACMERequestorKeys,
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

// AddSubordinate makes this entity add the provided subordinate to its list of federation
// subordinates. If successful, an entity statement for the subordinate will be available from this
// entity's federation fetch and subordinate list endpoints. Callers are responsible for updating
// the Entity Configuration of the subordinate to include this entity's identifier (e.g. by using
// AddSuperior()).
//
// This interface does not conform to any part of the OpenID Federation specification (which says
// nothing about establishing subordination) and is only expected to work within this project.
func (e *Entity) AddSubordinate(subordinate Identifier) error {
	entity, err := e.client.NewFederationEndpoints(subordinate)
	if err != nil {
		return err
	}

	// This is where we might evaluate some policy on the subordinate and decide whether or not we
	// want to emit an ES for them. In this test/prototype setup, we unconditionally trust any
	// subordinate presented to us.

	// Construct the equivalent entity statement
	entity.Entity.Issuer = e.Identifier
	entity.Entity.IssuedAt = time.Now().Unix()
	entity.Entity.Expiration = time.Now().Unix() + 3600 // valid for 1 hour
	// authority_hints is forbidden in an entity statement
	entity.Entity.AuthorityHints = nil

	e.subordinates[subordinate] = entity.Entity

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
	e.listener, err = net.Listen("tcp", net.JoinHostPort("", e.Identifier.URL.Port()))
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
			if err, status := e.federationFetchHandler(w, r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})
		mux.HandleFunc(FederationListEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.federationListHandler(w, r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})
		mux.HandleFunc(FederationSubordinationEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.federationSubordinationHandler(r); err != nil {
				http.Error(w, err.Error(), status)
			}
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
				jose.HeaderType: SignedChallengeHeaderType,
				"kid":           e.acmeRequestorKeys.Keys[0].KeyID,
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

// EvaluateTrust checks whether this entity trusts otherEntity. This function assumes all entities
// have a single superior. It walks the tree upwards until it finds a trust anchor and checks
// whether that anchor is trusted. Returns the trust chain of entity statements if otherEntity is
// trusted. The leaf entity is at index 0, the trust anchor is last.
func (e *Entity) EvaluateTrust(otherEntity Identifier) ([]EntityStatement, error) {
	currentEntity, err := e.client.NewFederationEndpoints(otherEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to construct federation endpoints for '%s': %w",
			otherEntity.String(), err)
	}
	trustChain := []EntityStatement{currentEntity.Entity}
	var trustAnchor *EntityStatement

	for {
		// TODO(timg): should check if we're evaluating a ridiculously long chain and bail out, or
		// check for cycles in the chain

		// Have we hit a trust anchor?
		if len(currentEntity.Entity.AuthorityHints) == 0 {
			trustAnchor = &currentEntity.Entity
			break
		}

		if len(currentEntity.Entity.AuthorityHints) > 1 {
			return nil, fmt.Errorf("non-trivial trust chains not supported")
		}

		// Get entity configuration for next superior
		superiorEntity, err := e.client.NewFederationEndpoints(currentEntity.Entity.AuthorityHints[0])
		if err != nil {
			return nil, fmt.Errorf("failed to construct federation endpoints for '%s': %w",
				currentEntity.Entity.AuthorityHints[0].String(), err)
		}

		// Check that the superior subordinates the current entity
		_, err = superiorEntity.SubordinateStatement(currentEntity.Entity.Subject)
		if err != nil {
			return nil, fmt.Errorf("could not get subordinate statement for '%s' from superior '%s': %w",
				currentEntity.Entity.Subject.String(), superiorEntity.Entity.Subject.String(), err)
		}

		trustChain = append(trustChain, superiorEntity.Entity)
		currentEntity = superiorEntity
	}

	// We found a trust anchor. Check if we trust it.
	if !slices.Contains(e.trustAnchors, trustAnchor.Subject) {
		return nil, fmt.Errorf("trust anchor '%s' for constructed chain is not trusted",
			trustAnchor.Subject.String())
	}

	return trustChain, nil
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

func (e *Entity) federationFetchHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodGet {
		return fmt.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	subordinate := r.URL.Query().Get(QueryParamSub)
	if subordinate == "" {
		// TODO(timg): error responses confirming to https://openid.net/specs/openid-federation-1_0-41.html#section-8.9
		return fmt.Errorf("sub query parameter is required"), http.StatusBadRequest
	}

	subordinateIdentifier, err := NewIdentifier(subordinate)
	if err != nil {
		return fmt.Errorf("invalid subordinate '%s': %w", subordinate, err), http.StatusBadRequest
	}

	subordinateStatement, ok := e.subordinates[subordinateIdentifier]
	if !ok {
		return fmt.Errorf("subordinate '%s' not found", subordinate), http.StatusNotFound
	}
	signedSub, err := e.signEntityStatement(subordinateStatement)
	if err != nil {
		return fmt.Errorf("failed to sign subordinate statement: %w", err), http.StatusInternalServerError
	}
	compact, err := signedSub.CompactSerialize()
	if err != nil {
		return err, http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", EntityStatementContentType)
	if _, err := w.Write([]byte(compact)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}

func (e *Entity) federationListHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodGet {
		return fmt.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	// We have no idea whether any subordinate is itself an intermediate so don't support that
	if r.URL.Query().Get(QueryParamIntermediate) != "" ||
		// TODO(timg): if/when we support trust marks, do something with these parameters
		r.URL.Query().Get(QueryParamTrustMarked) != "" ||
		r.URL.Query().Get(QueryParamTrustMarkID) != "" {
		return fmt.Errorf("only entity_type query param is supported"), http.StatusBadRequest
	}

	subordinateIdentifiers := []Identifier{}

	for _, subordinate := range e.subordinates {
		if entityTypes, ok := r.URL.Query()[QueryParamEntityType]; ok {
			for _, entityType := range entityTypes {
				if slices.Contains(subordinate.EntityTypes(), EntityTypeIdentifier(entityType)) {
					subordinateIdentifiers = append(subordinateIdentifiers, subordinate.Subject)
				}
			}
		} else {
			// no entity type parameter provided, so add all identifiers
			subordinateIdentifiers = append(subordinateIdentifiers, subordinate.Subject)
		}
	}

	jsonIdentifiers, err := json.Marshal(subordinateIdentifiers)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(jsonIdentifiers)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}

// federationSubordinationHandler implements an HTTP endpoint for OpenID Federation subordination.
// OIDF deliberately does not define mechanisms for establishing subordination, but we need a way to
// do this so that we can do it across processes.
func (e *Entity) federationSubordinationHandler(r *http.Request) (error, int) {
	if r.Method != http.MethodPost {
		return fmt.Errorf("only POST is allowed"), http.StatusMethodNotAllowed
	}

	subordinates, ok := r.URL.Query()[QueryParamSub]
	if !ok {
		// TODO(timg): error responses confirming to https://openid.net/specs/openid-federation-1_0-41.html#section-8.9
		return fmt.Errorf("sub query parameter is required"), http.StatusBadRequest
	}

	for _, subordinate := range subordinates {
		subordinateIdentifier, err := NewIdentifier(subordinate)
		if err != nil {
			return fmt.Errorf("invalid subordinate '%s': %w", subordinate, err), http.StatusBadRequest
		}

		// Refuse to subordinate yourself
		if subordinateIdentifier == e.Identifier {
			return fmt.Errorf("cannot subordinate self"), http.StatusBadRequest
		}

		// Refuse to subordinate own superiors
		if slices.Contains(e.superiors, subordinateIdentifier) {
			return fmt.Errorf("cannot subordinate own superior '%s'", subordinate), http.StatusBadRequest
		}

		if err := e.AddSubordinate(subordinateIdentifier); err != nil {
			return fmt.Errorf("failed to add subordinate: %w", err), http.StatusInternalServerError
		}
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
