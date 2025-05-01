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
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/errors"
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

	// Non-standard endpoints
	// Subordination request endpoint
	FederationSubordinationEndpoint = "/federation-subordination"
	// Is trusted endpoint
	FederationIsTrustedEndpoint = "/federation-is-trusted"
	// Sign challenge endpoint
	FederationSignChallengeEndpoint = "/sign-challenge"

	// Query parameters for federation endpoints
	QueryParamSub          = "sub"
	QueryParamEntityType   = "entity_type"
	QueryParamTrustAnchor  = "trust_anchor"
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
		return Identifier{}, errors.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: %w",
			identifier, err)
	}

	// TODO(timg): https is required by OpenID Federation, but requiring https identifiers is a
	// hassle in testing here I want to use a bunch of entities like http://localhost:8000
	if entityURL.Scheme != "https" && entityURL.Scheme != "http" {
		return Identifier{}, errors.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: scheme must be https",
			identifier)
	}

	if entityURL.Fragment != "" {
		return Identifier{}, errors.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: has fragment", identifier)
	}

	if len(entityURL.Query()) > 0 {
		return Identifier{}, errors.Errorf(
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
	// ACMEIssuer configures the entity as an acme_issuer. If nil, entity is not an issuer.
	ACMEIssuer *ACMEIssuerOptions
	// ACMERequestor configures the entity as an acme_requestor. If nil, entity is not a requestor.
	ACMERequestor *ACMERequestorOptions
	// TrustAnchors is the identifiers of the trust anchors trusted by this entity.
	TrustAnchors []string
	// FederationEntityKeys used for signing entity statements. The JWKs must contain private keys.
	FederationEntityKeys *jose.JSONWebKeySet
}

// ACMEIssuerOptions configures the entity to be an ACME issuer.
type ACMEIssuerOptions struct {
	// DirectoryURL is where the issuer's ACME directory may be found.
	DirectoryURL string
}

// ACMERequestorOptions configures the entity to be an ACME requestor.
type ACMERequestorOptions struct {
	// Keys are the keys that will be advertised in the entity's metadata and will be used to sign
	// challenges. The JWKs must contain private keys.
	Keys *jose.JSONWebKeySet
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
	superiors map[Identifier]struct{}
	// trustMarks is the trust marks held by this entity.
	// TODO: is a slice of TrustMark right here? We need to hold the JWSes, right?
	trustMarks []TrustMark

	// mutex protects concurrent access to fields
	mutex sync.Mutex

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
			return nil, fmt.Errorf("invalid trust anchor identifier %s: %w", trustAnchor, err)
		}

		trustAnchors = append(trustAnchors, parsedTrustAnchor)
	}

	var federationEntityKeys jose.JSONWebKeySet
	if options.FederationEntityKeys == nil {
		// Generate the federation entity keys. Hard code one P-256 key and one 2048 bit RSA key.
		ecFederationEntityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.Errorf("failed to generate key %w", err)
		}

		rsaFederationEntityKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Errorf("failed to generate key: %w", err)
		}

		federationEntityKeys, err = privateJWKS([]any{ecFederationEntityKey, rsaFederationEntityKey})
		if err != nil {
			return nil, fmt.Errorf("failed to construct JWKS for federation entity: %w", err)
		}
	} else {
		federationEntityKeys = *options.FederationEntityKeys
	}

	entity := Entity{
		Identifier:           parsedIdentifier,
		trustAnchors:         trustAnchors,
		federationEntityKeys: federationEntityKeys,
		client:               NewOIDFClient(),
		subordinates:         make(map[Identifier]EntityStatement),
		superiors:            make(map[Identifier]struct{}),
	}

	if options.ACMERequestor != nil {
		if options.ACMERequestor.Keys == nil {
			// Generate the keys this entity may certify. Hard code one RSA key, one EC key.
			rsaACMERequestorKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, errors.Errorf("failed to generate RSA key to certify: %w", err)
			}

			ecACMERequestorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, errors.Errorf("failed to generate P256 key to certify: %w", err)
			}

			acmeRequestorKeys, err := privateJWKS([]any{rsaACMERequestorKey, ecACMERequestorKey})
			if err != nil {
				return nil, fmt.Errorf("failed to construct JWKS for keys to certify: %w", err)
			}

			entity.acmeRequestorKeys = acmeRequestorKeys
		} else {
			entity.acmeRequestorKeys = *options.ACMERequestor.Keys
		}
	}

	if options.ACMEIssuer != nil {
		url, err := url.Parse(options.ACMEIssuer.DirectoryURL)
		if err != nil {
			return nil, errors.Errorf("invalid ACME issuer URL '%s: %w", options.ACMEIssuer, err)
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
		return nil, errors.Errorf("failed to marshal entity statement to JSON: %w", err)
	}

	if e.federationEntityKeys.Keys[0].KeyID == "" {
		return nil, errors.Errorf("federation entity key KID should be set")
	}

	if e.federationEntityKeys.Keys[0].Algorithm == "" {
		return nil, errors.Errorf("federation entity key alg should be set")
	}

	entityConfigurationSigner, err := jose.NewSigner(
		jose.SigningKey{
			// TODO: probably should validate that the Algorithm field is valid somehow
			Algorithm: jose.SignatureAlgorithm(e.federationEntityKeys.Keys[0].Algorithm),
			Key:       e.federationEntityKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{
				// "typ" required by OIDF
				jose.HeaderType: "entity-statement+jwt",
				// "kid" required by OIDF
				"kid": e.federationEntityKeys.Keys[0].KeyID,
			},
		},
	)
	if err != nil {
		return nil, errors.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := entityConfigurationSigner.Sign(payload)
	if err != nil {
		return nil, errors.Errorf("Failed to sign entity statement: %w", err)
	}

	return signed, nil
}

// entityConfiguration constructs an entity configuration for this entity
func (e *Entity) entityConfiguration() EntityStatement {
	metadata := map[EntityTypeIdentifier]any{
		FederationEntity: FederationEntityMetadata{
			FetchEndpoint: e.Identifier.URL.JoinPath(FederationFetchEndpoint).String(),
			ListEndpoint:  e.Identifier.URL.JoinPath(FederationListEndpoint).String(),
			// TODO(timg): informational metadata
			// https://openid.net/specs/openid-federation-1_0-41.html#section-5.2.2
		},
		ISRGExtensions: ISRGExtensionsEntityMetadata{
			// Non-standard endpoints start here
			SignChallengeEndpoint: e.Identifier.URL.JoinPath(FederationSignChallengeEndpoint).String(),
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

	e.mutex.Lock()
	defer e.mutex.Unlock()
	superiors := []Identifier{}
	for k := range e.superiors {
		superiors = append(superiors, k)
	}

	return EntityStatement{
		Issuer:               e.Identifier,
		Subject:              e.Identifier,
		IssuedAt:             float64(time.Now().Unix()),
		Expiration:           float64(time.Now().Unix() + 3600), // valid for 1 hour
		FederationEntityKeys: publicJWKS(&e.federationEntityKeys),
		Metadata:             metadata,
		AuthorityHints:       superiors,
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
	entity.Entity.IssuedAt = float64(time.Now().Unix())
	entity.Entity.Expiration = float64(time.Now().Unix() + 3600) // valid for 1 hour
	// authority_hints is forbidden in an entity statement
	entity.Entity.AuthorityHints = nil

	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.subordinates[subordinate] = entity.Entity

	return nil
}

// AddSuperior adds the provided identifier to this entity's federation superiors, such that it will
// subsequently be included in the entity configuration. Callers are responsible for getting the
// designated superior to emit an appropriate entity statement for this entity.
func (e *Entity) AddSuperior(superior Identifier) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.superiors[superior] = struct{}{}
}

// GetSubordinate gets a subordinate statement for the named entity, if this entity has emitted one.
func (e *Entity) GetSubordinate(subordinate Identifier) (*EntityStatement, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	subordinateStatement, ok := e.subordinates[subordinate]
	if !ok {
		return nil, errors.Errorf("subordinate '%s' not found", subordinate.String())
	}

	return &subordinateStatement, nil
}

func (e *Entity) ServeFederationEndpoints() error {
	// Listen at whatever port is in the identifier, which may not be right
	var err error
	e.listener, err = net.Listen("tcp", net.JoinHostPort("", e.Identifier.URL.Port()))
	if err != nil {
		return errors.Errorf("could not start HTTP server for OIDF EC: %w", err)
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

		// Non-standard endpoints
		mux.HandleFunc(FederationSubordinationEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.federationSubordinationHandler(r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})
		mux.HandleFunc(FederationIsTrustedEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.federationIsTrustedHandler(w, r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})
		mux.HandleFunc(FederationSignChallengeEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := e.signChallengeHandler(w, r); err != nil {
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
			// TODO: probably should validate that the Algorithm field is valid somehow
			Algorithm: jose.SignatureAlgorithm(e.acmeRequestorKeys.Keys[0].Algorithm),
			Key:       e.acmeRequestorKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{
				// kid is REQUIRED by acme-openid-fed, but it doesn't say anything about typ here. I
				// suspect we should set one to avoid token confusion.
				// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5-7
				jose.HeaderType: SignedChallengeHeaderType,
				"kid":           e.acmeRequestorKeys.Keys[0].KeyID,
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
			return nil, errors.Errorf("non-trivial trust chains not supported")
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
		return nil, errors.Errorf("trust anchor '%s' for constructed chain is not trusted",
			trustAnchor.Subject.String())
	}

	return trustChain, nil
}

// EvaluateTrustChain parses the provided strings as a chain of entity statements and evaluates
// whether this entity trusts the leaf entity.
func (e *Entity) EvaluateTrustChain(entityStatements []string) ([]EntityStatement, error) {
	panic("not implemented")
}

func (e *Entity) entityConfigurationHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodGet {
		return errors.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
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
		return errors.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	subordinate := r.URL.Query().Get(QueryParamSub)
	if subordinate == "" {
		// TODO(timg): error responses confirming to https://openid.net/specs/openid-federation-1_0-41.html#section-8.9
		return errors.Errorf("sub query parameter is required"), http.StatusBadRequest
	}

	subordinateIdentifier, err := NewIdentifier(subordinate)
	if err != nil {
		return errors.Errorf("invalid subordinate '%s': %w", subordinate, err), http.StatusBadRequest
	}

	subordinateStatement, err := e.GetSubordinate(subordinateIdentifier)
	if err != nil {
		return err, http.StatusNotFound
	}
	signedSub, err := e.signEntityStatement(*subordinateStatement)
	if err != nil {
		return errors.Errorf("failed to sign subordinate statement: %w", err), http.StatusInternalServerError
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
		return errors.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	// We have no idea whether any subordinate is itself an intermediate so don't support that
	if r.URL.Query().Get(QueryParamIntermediate) != "" ||
		// TODO(timg): if/when we support trust marks, do something with these parameters
		r.URL.Query().Get(QueryParamTrustMarked) != "" ||
		r.URL.Query().Get(QueryParamTrustMarkID) != "" {
		return errors.Errorf("only entity_type query param is supported"), http.StatusBadRequest
	}

	subordinateIdentifiers := []Identifier{}
	e.mutex.Lock()
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
	e.mutex.Unlock()

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

// FederationIsTrustedHandler is a non-standard endpoint for evaluating trust in entities. It can be
// used in two ways.
//
// If the method is GET, then a `sub` query parameter must be provided, containing an Entity
// Identifier. If this entity trusts the provided `sub`, then it returns HTTP 200 OK.
//
// If the method is POST, then the body must be a JSON document containing a chain of Entity
// Statements. If the chain is valid and is rooted in one of this entity's trust anchors, then it
// returns 200 OK.
//
// This is similar to the standard resolve endpoint, except less flexible.
func (e *Entity) federationIsTrustedHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	// TODO: implement trust chain evaluation as documented.
	if r.Method != http.MethodGet {
		return errors.Errorf("only GET is allowed"), http.StatusMethodNotAllowed
	}

	subs, ok := r.URL.Query()[QueryParamSub]
	if !ok {
		return errors.Errorf("sub query parameter is required"), http.StatusBadRequest
	}

	if len(subs) != 1 {
		return errors.Errorf("only one sub may be provided: %s", subs), http.StatusBadRequest
	}

	entityIdentifier, err := NewIdentifier(subs[0])
	if err != nil {
		return errors.Errorf("entity %s is not a valid identifier: %w", subs[0], err), http.StatusBadRequest
	}
	trustChain, err := e.EvaluateTrust(entityIdentifier)
	if err != nil {
		return errors.Errorf("entity %s not trusted: %w", subs[0], err), http.StatusBadRequest
	}

	jsonTrustChain, err := json.Marshal(trustChain)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(jsonTrustChain)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}

// federationSubordinationHandler implements an HTTP endpoint for OpenID Federation subordination.
// OIDF deliberately does not define mechanisms for establishing subordination, but we need a way to
// do this so that we can do it across processes.
func (e *Entity) federationSubordinationHandler(r *http.Request) (error, int) {
	if r.Method != http.MethodPost {
		return errors.Errorf("only POST is allowed"), http.StatusMethodNotAllowed
	}

	subordinates, ok := r.URL.Query()[QueryParamSub]
	if !ok {
		// TODO(timg): error responses confirming to https://openid.net/specs/openid-federation-1_0-41.html#section-8.9
		return errors.Errorf("sub query parameter is required"), http.StatusBadRequest
	}

	for _, subordinate := range subordinates {
		subordinateIdentifier, err := NewIdentifier(subordinate)
		if err != nil {
			return fmt.Errorf("invalid subordinate '%s': %w", subordinate, err), http.StatusBadRequest
		}

		// Refuse to subordinate yourself
		if subordinateIdentifier == e.Identifier {
			return errors.Errorf("cannot subordinate self"), http.StatusBadRequest
		}

		// Refuse to subordinate own superiors
		e.mutex.Lock()
		if _, ok := e.superiors[subordinateIdentifier]; ok {
			e.mutex.Unlock()
			return errors.Errorf("cannot subordinate own superior '%s'", subordinate), http.StatusBadRequest
		}
		e.mutex.Unlock()

		if err := e.AddSubordinate(subordinateIdentifier); err != nil {
			return fmt.Errorf("failed to add subordinate: %w", err), http.StatusInternalServerError
		}
	}

	return nil, http.StatusOK
}

func (e *Entity) signChallengeHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodPost {
		return errors.Errorf("only POST is allowed"), http.StatusMethodNotAllowed
	}

	challenge, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.Errorf("failed to read challenge from request body: %w", err), http.StatusInternalServerError
	}

	// Sign the token from the challenge and represent that as a compact JWS
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-openid-federation-challenge
	signedToken, err := e.SignChallenge(string(challenge))
	if err != nil {
		return errors.Errorf("failed to sign challenge: %w", err), http.StatusInternalServerError
	}

	compactSignedToken, err := signedToken.CompactSerialize()
	if err != nil {
		return errors.Errorf("failed to compact serialize JWS: %w", err), http.StatusInternalServerError
	}

	if _, err := w.Write([]byte(compactSignedToken)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}

func GenerateCertifiableKeys() (*jose.JSONWebKeySet, error) {
	// Generate the keys this entity may certify. Hard code one RSA key, one EC key.
	rsaACMERequestorKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Errorf("failed to generate RSA key to certify: %w", err)
	}

	ecACMERequestorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Errorf("failed to generate P256 key to certify: %w", err)
	}

	acmeRequestorKeys, err := privateJWKS([]any{rsaACMERequestorKey, ecACMERequestorKey})
	if err != nil {
		return nil, fmt.Errorf("failed to construct JWKS for keys to certify: %w", err)
	}

	return &acmeRequestorKeys, err
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

// publicJWKS returns a JSONWebKeySet containing only the public portion of jwks.
func publicJWKS(jwks *jose.JSONWebKeySet) jose.JSONWebKeySet {
	publicJWKS := jose.JSONWebKeySet{}
	for _, jsonWebKey := range jwks.Keys {
		publicJWKS.Keys = append(publicJWKS.Keys, jsonWebKey.Public())
	}

	return publicJWKS
}

// TestJSONWebKeySet constructs a JWKS suitable for use as a federation entity's keys or as ACME
// requestor keys. This avoids expensive key generation in unit tests. Callers should make sure to
// use a different set of keys for different entities or entity types.
func TestJSONWebKeySet(index int) *jose.JSONWebKeySet {
	var jsonKeys = []string{`{
    "keys": [
        {
            "kty": "EC",
            "kid": "pKIew4-gcTKMBm8L4h-pEvpoLsJ1ZtvHevAV4mWnjxQ=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "G25LB67PwoeUV6ZsKT6zxxYT60lVklzKLCMTBhR_YLY",
            "y": "YZtJ9e_3kjzfRZ9JFyyGlJNn0CKe9HCsPC2QUT4Z52U",
            "d": "dYHV1YPwvTih1k7D5Tbii6f8asd_TtuSaFDPs6v1VGU"
        },
        {
            "kty": "RSA",
            "kid": "9z-eVGazRZk_Aa0MaRUY9Bv1hcgtCYBYkWwkmv3sZsw=",
            "alg": "RS256",
            "n": "vCHAMKZ7rTrnIxS7qgumkV8TO74DfuDPj0suM9VqqZ5u-jbJeQuXStpWI341MMNJYFoZQsSC38yurBck0N7tbgfpvPQDFVzzl5BYJiejZFFlxTrs6R4XluCOZF1k-p1Dqn5NJQKh28NPIP29gk5cOG1zLrPsVwZYINyBoSRXQn9_nLCOIS3itKGayEzGtXMdyUWzD_M78dMdntrPxL1CdPNAe9_8ZTmvd9bNkCwtTtwy0pglhasdLr8k9RvC1kAdy6uEQtTDY-I_wHhPe20U1R5KCCUeYZ3UAhrAmjHCXcfGhEVn221a3bo8td4TLt9vImCvT2LuAumRgg7QDsassQ",
            "e": "AQAB",
            "d": "qU8mi6IIg-oSwbuS-IHrscCCqq1ir_jaUvcx6WwTxfrTnVNZFhqcWb0M8HxQmkXl71SmjzQTJB4sxKs_csptmyx76pUfgUZZ4vkAm7Xokgu_LzTMqS9vw1TsUN7MVc7aasGn47rut7yZpfM1bePfktjNZCaAeAE5prlL4B24ehp90SYAPzWc74brrm_lClNQ2sTwSZfvrx1vE5S1hx_75M2bJnkl0M_ZNnw2UGO4WCFZW0HbnkAtUZGpLI_GCn2zM1vxCvugTAxKywPWIR-5iCvdgHZOPVGnjKpkSxj6FB3BH8HxBRg_fOBzhWDcyG6YLZpTb8U2i84hZisi66FTEQ",
            "p": "wAZm9CmE9fM-wWSwCXGflZ4jedYBDRE1M0My_9UQxbzGbDNDN_HunbG2U0XtafXXBr7ajW1brtYvtcUgpoByAHfEaeUWQjjhoOydD-ulgqaJl83jUFNQ-tLI3N9foT2YthglqL24uWy8UCTFEHLxVXWvcTklqkVHZYM990G2rb8",
            "q": "-s9N9ASWGp7Rwoj6C0MPkpgJXZIthS_nRujTTH2ZnoCKlU_eSiUs2eBI8dLSXryVN3svi2uc-IVklz-042Dq9mpSEUGCzObR7BLDpgtV6La1c2BZhttPGgVq2gkQpOoer8M3Bn6hkJh0oAcoCWDIgmICIHDvQ-jywpubqbQqIY8",
            "dp": "Hi6jbgs8n9_85C7sUH-wgrbZgqP1hFVJFGailH2r5ji2w3kHPrrjM5wkOVCLcZU3mBLVjVc8Cu4Vj6-NYz5bLOGmWLKuXfhM1pt6UG9Mk42ToO22pgCCgPoyoizl_hUNdMm02aIAb_y8WKh-5Qf8EN-vlM9TsUC0aStIyR1mFkc",
            "dq": "2oCWEhuYxbJNXeRFqmAPBhBsQFekTp8QJweZZc8acSrdEP2W1BOVAm9SPVMEsUIr4Tzxi84B38UegGIg7eK2cFzqCFyBXo9MnRUv282OV4ItjEmJVWJkhG_pyfARzwqkF03D92WEzdrz56K0b48gv-4wmiCpYglkzMQSFgN-nOM",
            "qi": "su3T07r2hCEkEAPVp8gOqO_1eZEMmQWSrZjfHbSsX1FgJNj8twjTAgO71jEq09-aVydopeuX1eihAWwT1ln8VN3eBXD0BrP6jYb6KiAMUmuPbEfRW-pQ2deMJQs_nkS1CbLujfns7M6DqPXn3cK39MjbjGUA7Qau4jeqxcFBX74"
        }
    ]
}`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "3F8xmHuj_mI491j5NaCOGH9xKUKu96T0J9KzLn2uZmc=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "J-YFKLKqdNcAt5sy7qtp8Bnbpvy3Hi7Sh5ACOVz1lz8",
            "y": "Br1SrcZtR6CtCBU_qGnhgo4FJ5F99eYG3wzvabYjAQk",
            "d": "U01VEA2k6xKI6PO4f-lm2-7wGNlAsIGOS3KCxJTKXwQ"
        },
        {
            "kty": "RSA",
            "kid": "s1GDQoJwRUi9sG8y0ZkPacairjzmxuZl1AzjacmL2xg=",
            "alg": "RS256",
            "n": "pAgDP5OIbNZPt1YR-3pFhfIbd3kvSbncFL-3Mfmtdng5b9_nmavL0ZU9Li3VaG1OJFkSXLEd2k3o9tq-3s1H-yVrgLJnl6w1AQ-_jNHMHiMZl78vZ9Vl3P4wriCERrS49vANGcKhnGI-j17PUDuNvCUb5ZojzqywUBAG0_9YbgAJ5C-XM8G3hfLyM9vmv31c8J8o19pV6GvBiNHyLgYR8sd1Hk2WciOh8aK6z59-tkFN_y8FryhM5TLoXlX0_wcQPpBPuztk4f4EGJy-ipHFYGdiVlwiID6dtodf_6FmKsovrolDqPmdnsfcmZD5rnVmWO_6rzktUtT87CuhW3csNQ",
            "e": "AQAB",
            "d": "ayIgnQGK9Sr0XdYFYK53ggijD-FClXCi4Zpl2GoudVYIjZ078w5VzMkgcGzXGaFqjCrw50F3MgH4ymIMkBCbltjV4fSj3FhJNixG-357RqO-L3JbUAH8yd3rhY8PVe7rb71RkSWh0DYKjjFqTgjXha7nDYsjH_WCIoiVLRl1dEHehYdmDndbyVGusF9-859r8Fibf-w_lrR6VZ8e-tw59ynOflUX-BW1X52pHlzZ9K_paqQNvrdji4oDf4P9q5qAbgrFspB4l6VhT7kXvdym_QbRos31ypEIuoCAi6SsG7YFKdhjg7dzlTz9NuCWFMRxPGHYT4WDPOzWwy7QptraAQ",
            "p": "zJOoiYt1pPjo8QRxB0P_p12F-e6SKFP4I4CzJyzOwQuZdvlTjzMi7WkENxq8qNx1EQOI0hDirVwZ0afF6pCvI1Eu15MVtZ7pYzr_Ri8jz2Ga_uYX9oRJ1ZVPN3OQ9BvQNvyJlv7ZtdKeLjkhEBsrgO9N1zku-bE4UPdTB675LaE",
            "q": "zUNJYeEO1wzmEn5BLeIhZJ7dfwzVQUA35jgBY1WlJD4RwPLWJ2pdeEmivpS4xt2jY5p3GE44BXpUBE6k6x5FrAt7C2s23cqj8gGCWDwcql1a7f2nU95TWoRx0YnO5eQwfJuGl5BXgbbFsTlukSXZirESqwxorld5YxxbggcjrhU",
            "dp": "Uds3UanirdsG4gFj9INJ1T7_r6y9ALPwkswZYzBznhy1EDzdKWxNqm8dx6rEGFD16pPeeCdXfARhNFmMQLoZyeje9FUfF6f5PMJLiFquWnl0mk-ZAQOXw4VVyBtOwc4rNwU_TJK2rCEVN-uWBirI8nNOUzLHUBOQNB1yNJ3XiGE",
            "dq": "vOnptvDotJoFgg27NVyC-VWRa-ZGu2g8SmFPPbpMZD_QHTIiUWJ-pj-3TgoYycahIwG-DJuoybnda51qAY759q8WTtsdQyHGo-wpp8WjaFTFZHZoszLSqmNtUbmwtzq-OWD2jbXmI9cwubyu-13HivMPyGeCTLrrWIF34wNpHkU",
            "qi": "l7ESaK0DOM_d4B9FsbcpgHVOQd26dmw3TWFswet7Ka-Ofy6r2EKN-fkYsVUPLoMdPtqaQ3B4TL44rBvyN_nBSIn9pnDeRObIDyLXpHTx86--apwsoHdrsBzeRQpdVXEj-s64UlYnDbwt8qjIHCTj18nOSirpVhutLuxT4zWog4M"
        }
    ]
}
`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "9CcbN34jvYy3kYn-x_n5P7oS9GWcK1Qe95G95vW7obI=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "q71BHRpuIuMPNwUtkhdh-vLUhAbOuk0wmc1TnDfK_EI",
            "y": "OlDzW6tuiPXwCxyS4rJCcQnOCgTHSuPJXzeH0GawF6c",
            "d": "Uc2f9TCR6PKhCPiS2pph3eaxNp5Ba_NUboIFAoTfOzM"
        },
        {
            "kty": "RSA",
            "kid": "9BDFaa355XTZlJrCzWfugUWnVcfHp-uo35Xxqvpcfy4=",
            "alg": "RS256",
            "n": "vFKZSILO8WFaweQdn661-sfj1nkz8zaCimr57fOLTp7jQb1QTciSUirurPZptg6DFUe_C1GI7iQGeAjp4hfnJba9oqhWfowyw-MJf2jA4oRfhqQvcVTKq0T7luZIPkecRyIRPiakkTxsRaQsM_Jg8D-FEt6QPhrHO3boP8844KK_UQ1bSSK2l0756rtzjpuD5il-EzvVxR6RHuTUIuKmwzW6LrQecRvIEnG21_kBtd6zHYwE825qyvAdwg_4yn3hQZl0xpg8g2GmitGLPgNZW4DFq-V7rsdgYN8jIB9yepg_vHYS7esH-S3iuDRTgdnzhdocEOVMNczy2BUpjQ_Buw",
            "e": "AQAB",
            "d": "ROvx32DIPf0ESyuiT9uQDFz1nHu1MJDFi8UE_ToBxN9PirKvXhhGvL2rpi90lsWO4c3lNE49z_HtUCbq-e0HknzjwFDdfujud1RzGGcNGJmboFocZtzCY5YWga57yBdLMZldOCLKXcEAWyhvaP-OzL5ihHphzejc-31UGG5NgaBNGv3rYEBZYBewMgk7EMtyXZQbruewr_yQhb0hHA1xR0B11CekSdC37q8KhSYdiAD0_LIDKKcH6kMwYMZzftRdlcOpX1R3UeOoQTTz_3AMdSOXyW6L78F6uLCHxvCdN9ryCD5bdkcu1xeaiUkSe2P2G48qKUj9rMf81r_l9IFVyQ",
            "p": "7v74kkSBUfJT7uG6lm6ZYZkOpIFjQe5iCE0I0QhV2ek3QqtKBY56DpxaP9C7vXo6WmT6AjerEX1SoVI1z6ye5xd5PKgxlzg26o94qwcQxZ41zD0IOrUChnIu2lOpsSDhr7u2psrqV-yipSW1_sC9pFeQ-HsZorn_an6DmZst8Kc",
            "q": "ybisTMzKXIRv3BYKqSq9gLInrSsh6xjHx1oDIauSy4q_TRoCnU3zuvu43W_aQ5obQiEVbCAkz8uiWKZMeBtoLbRoMCVXIWDH2t81xOBE1m9jPFKWSGloWd8y68lDtNCff6Y70sPHac4JPkRmng3LNT0xhZqxZ_OljenahIffFM0",
            "dp": "F202wF-mrXmrcIb_2y8MKdzu6oEkUZokUdv7OUIv6CRMHmTb5J-Kp1P8JLU5MeGBRssPFpiOVDCMoPOGAs1Q5iYO5Ds4YTJJb8SQd3NB2Z0geNyiqd6EWNlobk41G_-1H5yu0rqhLe0sJDQGGuqZrDpJI5IteR3yQ2YTUEM9xZE",
            "dq": "CM_vfv9nS7lhZZz05EUAuFGQGCmNNscDWzscbekf5ZJvHwAm4xZXsnByuAG96DwgOrhVRj71PLqpofPJ3WldGLoL3yaSctvWf0JHCA3AFBoTnLwC4rDwJRTyFYjaU1jVzu7FKETzPjUJBFZaoUb6_J1qv2ptm5vyPIvdxvJklXU",
            "qi": "53T2E3j_iXj6Bs_HI2Q4epyShRrLwNYPZ_WSjKXVwTJdgm0LxeG7BbecJhBWtAi0i5CStNnIhVWxaqZIX9pwE9u4aLW3P7gynRAYbZ1nTFuR3C2Dxyg6kChvcTg8BC_Bhnehr8C3csE8Su4xgHcs_ePtpOEia-i7ofchxiTHzA0"
        }
    ]
}
`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "6wkqtC2mvHTzmS5Fv-TN4z2on8lfl9yE__DHf3eOuwg=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "MF7LAIjt8tjoMDfnVh3fucnRDORGLvUNq6sOr1iiDMg",
            "y": "7NIpVdEm5M353OmLsyTjbz-Y6s3jiVB-0hnzTc9Kz04",
            "d": "Hx2nz4hMJiU9wlbzlHrUMcAxm-w6JI5mlU7OcPyY_zE"
        },
        {
            "kty": "RSA",
            "kid": "VU3zt0xwP0XMp7GQOlY_0Mf1UR3u5sKVB9sEEweLYrU=",
            "alg": "RS256",
            "n": "8YFfParrDe-kiPHyORx7XEKrSA_LrZQpY-eWs_mq9es3bYUyoBV-HbqX1C1rk8X82HSmwLuZ9nofiCv7haero3votaElcxRFCMq7eV20xpVrn1KnoNKHwphW4fMblHHoCQOo75Z6FUUQz18weKblDpUoecLqxv2xfdm_vIQz3NN9qHGFxxrJbjnmbeVcyEgoHSCOGPLHFzdFWJkVqeKqtH_dfOWxaCN_jJuJulpHZpQa3RDrE4KtcBl8GaD4O0eta_t1Ntj7J92Kxt3TYSGgvI2Pl-dJ3ShFhSyDuZahIOd9B9VfrXaSvCXzzbHLq7eZujU-8Pmh6-4gC1GNSlXRiQ",
            "e": "AQAB",
            "d": "yvLvOIGDmmiCmlrINVpMCJI2Ig60GSBjUAN0T7ZGBvct0ymWC5VEMHN31-R7fOlqu_P7lgeRMOIb0XE0o3Lt-CrOuqO7NuQXx3Wm6iznF-LFWFQ7bhi94bfne2WzDaJTXg_nTb_kxC8QG1RhBWMrJoAOTZSRe7wCBkKQsDlg4_ZsseHuv3YQnCaSZryPnc_zyE3tTRM_FAPxudhrIQ8tYv4hk9Wue5bNofADrbElNEaE2E4iOK5IRDUS4e9ZfqJ21DHaSAbkXB8Ub-4T2AA_45mzlgLwUwDbtCBkpQmkJT-lasFtJCQuMd0V2CFPpEssVgwMN9ATnl0h_YjqgkhZCQ",
            "p": "_MhZBiNTGc4hCBLD7ni78TBi2IBb_nxKSvt4D17gjl0yNvgD8gq4xbZkoeSWP8A0CQCBk-k26kd5KwdB63ZzOasqu-PTH-8Yt7YZx1U_sZffp8_hxUmPy7s4Zzi_4y8-QLkd6u8EqmO7OKdIzuovtw3X1WBFyETW7OQj_QHTahs",
            "q": "9JRHdkWJas1BI4j6E6rVNpRg3cCsXpvlp0peKea-QLyCFv-jKVSsEOCSj_lxM9R4EX7DHFeKQkTCwWXOmiuCxl5tKiOO8SNtLtiQyWh8QghFV1nYZmZtZF_QY-m4t8HztRibSbGGnmszCV2nggY6kBYJkLRagz-KsuwTTPFI7Ss",
            "dp": "VXwfdw7tJHXr_8Hw1q2nyUn2s4a9FZPMwAzIrlIEmMB1odc_5lOv5tTmtUULdqW2MzEjoPSmaJYhKOb8aPeWwfLbscy68jq2XjJMB3gR4SoeLa8Eh-Z3pYs76NRtOBQa9mJj9rY8Gq89ekxAOBFEb6BT1EoJb0-wa04_yWkbqO8",
            "dq": "G5zOAJ1TKVqo-wEQ8r17uuC_mumQzFGfeOadgO-LFTXzHfOYkSb9Eh64jUalMCvRrm_4SS_c7SRkNH9w9tjot8qbWoGPNsxAHGTY29RPCwlyAq2jD9SKjyV-GnmdoClmgVCY35YKU8JYjbskGTroy7GhPNQPz_eRiie6-hnXmOc",
            "qi": "tI69QKe3R5a4KzNP0AXyFKKO-3nzee-AN1Rk4dT_1KoEib7t3gyDT1WFf370AlN1BSqlYILaSl0RnA8l4Em_ZcWHTDEXZZR60nbnpWwVlOvNKFrIt4wrdhwGe4wlIbCXYcwtN71qKFCjXUUD1Jpo4SS8srBHD8XstUKNxtToGOE"
        }
    ]
}
`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "5uUmKEKYrNKIcbbVD5z05R41Cgdf6A5ghtK-_8hobF8=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "DnWamXS0GSrkMldIIT32pjcEPARNph7DbBie4S8H6BI",
            "y": "m3VoJDC--oADdoreQGT0LaFuSYFpHkuKM52O9OhsiwQ",
            "d": "5WMJAg4clVI-bHkCynkI-m79jM_DYyy89KTA65y-72Q"
        },
        {
            "kty": "RSA",
            "kid": "g398BL5JCy5eGF-7BxH8U9aHD18dRcT6dWGDO9AKuCE=",
            "alg": "RS256",
            "n": "9CtUevmbqhSiaWRDdOS9rJBgezHMCPmU0yAlW_gH-ObqeJc-cRezWQbyFWC2GKJZaToUbMcuTLbSuKuX_mLwD71FwkB-XRGlWqee_q4F9cRXMerdJBW32OIQHNDuqDbfmepbmXoHhBlt2TyJ951LdO6FdlG6XzvDnk0so_FXclLQOQEtCVPGcipIfohn38jBpttoYJ5wpSGyue_uW-EQZJTN9tX3Ol8M96etgpKdRuxqO6REQO09i-JuCDyFAK0Zv5wkI55076cP8rrpoaeyN1Auq4mV2UEui2lzGteqNd3FrdlhGJAoxXzPNlv2--vQyE4v3iOCYih0yOSuCHQkfw",
            "e": "AQAB",
            "d": "wrywMyhSw5KTefTybA9nS3MW0AqGTX4o-T3BLhmi2hvpU2Zk8bPSYaXNe8lXUkxhfTBKS_uL7Lk_VPPeVJA6IIN3WJcxcS76r1PS1hKbRElktbY4y2fa6kpaSXFFdrnVGh-1ELInvm69kq3a57b3EHqPzS8fsoaq3N12RgbdFJpzE0rrlACPqqXT94lFSestXl44L6ida6X4lMJb_vbTsfX_0HCqp25YmFtklLl8qKaHuz8Q4eufWu-4mTbH5wGK15sQt-IMxND3rrqrZQ-isNREpm8J75u3dip9sIxf17u_t7xoH4kX7kdII_HdWkH48ozWFt7tH-WkQN7niQ718Q",
            "p": "-U8I34w6vrPz8CGsWCa9e0XY5pWDW2Bl8YMSVx93ly_adNmHIW1I-AjFUDZT_uidHolYadC44jqGlbLJL6PAt-oGOn2IJji5rdAsZFQI0_K-sLBkOdvcBuej_TjfiBtX07aPtEOzkkr1q6v2kP1ErLTAvymS78aIlzVRhaRLSUk",
            "q": "-rj7lbYMSvfnvkNqKRFVVQ4HhkP_aRPMVRzannknlzmqlVhBOpEWxG9x8Se3iDweIVtJ944w34FNaKajdUSVlcxyZchCguQObQsymq2iv5sQCF4_kzuw8nDolTfe1F78YA9VyHR83nV6LqhJdxPUQgYEJgfqFrXr7TynY2tDh4c",
            "dp": "NhQ20IcSlxth5sznHZgJshvMmPgFrmSSuHi-GbfxsRHoSUCGV3HlSihc5LFkNv8uVdllHE7yS-B2ITLPAU58F2jkQPvJ9MCJRnLJrlmsMI2PX7RjiUlvyO-mWt9jXZrQylPniCrHYQxxjfOXYIwPwYbT6KOUA_8E0gf2zw58ZkE",
            "dq": "PgOXJtaaf8iFp4fhMDs7UghgUBNtjz34Ymz6ngv1gPAgg0QLDkNo0DmIg0-Bk87a3QFJcFPZPs8qqGHfOFg4b47cFNTNrrZd4xbL83pTMPVXp9o3-2DeSXkn7hCdqwW7gr8IRsaZRCTmjbfORAfBjnsSd52phuiEbG9-L5cOYu0",
            "qi": "R8A_d0ytnce5LdVFEA-Arl_koTiUKEHS-9UOdbndMEGIAldHMtruu2NQ63DRsu5PmcfqCTYNu-DUB8tZDkjgeDbxEwaSBCX9ZmKUgXZ4tcuEA0qkpLIP8VpF-5393QuH1vbD98-gekdPcO5ANhNl7i0RhWjy5I_RMyelewV4DOM"
        }
    ]
}
`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "My3sbzsT3FUiHsL4QuTLD-kOERLmQXPnAPyhBiz-Lfk=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "M0ACS-CI0J52Xy4ireeAVj30aEQdnzDR6nHgduLxqEU",
            "y": "VdtWcWTmsjfwT7dbuK6w7_P8aJal8q_-RmZS7KhGreI",
            "d": "zDu2rT4cJTvpKNSrJwudw6rh1Whh0yG9oj1SOm95ATI"
        },
        {
            "kty": "RSA",
            "kid": "ctP6aYnWuKy3TxIwKQFs77ervz4EO7bkhoF64lwc_XA=",
            "alg": "RS256",
            "n": "yWZe4-HQO5kY6Td9K_D8fRY2wF_mCKSc_xXkyuZg-om4T47DsjdLotE5c4b6mJBMnpELQJJiI9tCHuBp8jvQ_KcZwMWMJmSxBLcIEKw94feGvUAe3xYmMbsZi_VoC_mlaCcmiff6z-Lg6s7E7hLos3pb2Mt3l5E1rY2GDyFBrRQeXOXUSQNTJeVm5z79RAtY43T7noKeaEqOZMH6N6Gq5ZQCfrnUih5NYIbT38bkc-tJPZfH95fHAXSbnv-GUMdtwMKvxyjulHkSVxnFzgsRRqKRiMmQhv2NF36kQP3SYx4IIrMl_6Ls-FeKygra-3MjVQDS8sOlSslFud63-IjkzQ",
            "e": "AQAB",
            "d": "uBR-dLFH_8E-OKPEH-6jCL3OC2VbvtieurRLK30IdNZ-BRGLIxBRbJ7pcQOVdu6laWVPMJTbaMSWGdyqWYJ80QD2k_C72be86H9Wus6DvU7d84pw7Ry0ik3l2rvSfueOXLU0D3T95RcM1vFoo-XalXkoC-5k_770ng2104xlGAikjpmPL0R4nQsxo3N4fXEolq_zCCAJ8At1kB_qR9UjFiG_oXf_CdFLBPpBgCxAW6TRkT3ip8c_lqUP_yv5p9khfwZmxfGOWDT_HGY0jOh4pGp75PQ39Ti_lvkweyL8yvehq8_VoD5KFESAHnozWNSk6Rs2jCfhaCD4DCj7zNtGAQ",
            "p": "1QePjm5isW-ayIVxUJE2ByP1HtHXWgX5ktr9xMztE885OMG_kkI_TBSjWk6cAuYi_R8-yM222JCaJQqIW8oO6HjhoKXWfsMu6s4V2XW4rje3iCjugC6JNnq3F0zqbtu87ZA_KVoBbL67WUU1D8VlZh6FSMszOd_4CmNxK-wAxE0",
            "q": "8gZG6ObA4-WelN2xmuYekQM218tt6LmqSJlujZWvNtVfmwRYksxjn56UXt4ICQFGTYDCye58uD3zWtjG139JEbKI1DyiSjxH3vP1odLdx8yBBXzdgBAbHeFHk5FXoKbYSnHC4Lwpil5T0y04-G98-xfSiF3Wqg-2fYl1009C4oE",
            "dp": "mXG2v9tXD4PaM_Gaq3PNPNtzpl10Bw4itNs0y1roscoj53P3b3x0Z3K-L0BMM_Jc5YJqEO3MdLXDskah7avfjSf1LWgG1ov08YC8UETxX9wWQOdq072xbCJ8WzY17uAsd9ndBQYl3JSOEkE9dTy0SxhU3Rgwr9FZsvHqBL8b1kk",
            "dq": "BxNf51c3tHH2HOwOUTUBF8Q8SjrMT819yPmTXdhOcw_x55pM7J3FG9mLBOsA2SKMZ5-oEjdCtjA5eSJ1Tb-O51GM5oePRxRUFZSUTdLYYQr9iqeH4kKWSF1Ztlq9cRjvod2JkQBvRnhTgw0DaV_5C2463XnA2N_0ud7W7wKWNgE",
            "qi": "ZwGtxQPO7OKExCRHLpf8vMjR6eUi4IiU2MW-uR7Nz8TvGjJxv4QK0uzcm8u7WLtjPVmpNFXF_oZtrhRm-vwRAf9sf9njBZlEqfbsd5FxNGqAk-QulUyoAXJf5b5BDgKFjMq8i81aZ9fnTqYGcb5ltxoONk0pGo5b5hBQP3n77So"
        }
    ]
}
`,
		`{
    "keys": [
        {
            "kty": "EC",
            "kid": "1-BK3hgXYugTHUnAnYmsrGdIcXcGCtsTrdEpC7Pnl7Y=",
            "crv": "P-256",
            "alg": "ES256",
            "x": "9KUb3p_HGrm-Df1BBq5_hHOwv81xAm9Vtizc207oFsk",
            "y": "VHbAQGCJtyPc5-okrJ8S-OLtGqm3XafGx_DOr1j66CQ",
            "d": "Q5jZHniuKLlFnGlTLDxXsAHwFWe7adprhfhhdy0scfc"
        },
        {
            "kty": "RSA",
            "kid": "qU1Hi39er6NquoDz8yHraM4GDNzh2RMVtZDrzAx0YjE=",
            "alg": "RS256",
            "n": "ufLpQgTABlXL5zxdGjUQKovVs_E7JcoHWCvulQR1rMDIIVMRodwTGJhytJwsXuZPbuE0LEVMtnU4lv0xQWg-IZPvQ5lWmhkbAu4sXmePVq-hBlBdvh1UIf081wD6rrPdA8MwUMm9Y8esQvS70Fut0RBJzb0D-Hw_A_ftt9C1vEsBDZzF_Cfd63FZIsR32iD_x4r_8oI0crkCM6vC-ac6LGmjcVScMC9BCpBPL81soJ94GVPm8h13YG7j8ggq2p0qTPDSh7vjK2mmLs5Kzfw7Ya8tshiS48fLHjdk25TDJKdUsjlbWsZeN4rcEwHJ9kbU1wdD8ytICuPYbBvyaryuSQ",
            "e": "AQAB",
            "d": "HBKGEIdzDgHJ5MECNUCpjiLKQn46tbvIXBFV1X103n3EOPO3h74Xy_DH8GhbcoBGobCyFbTonesYfgL_eqZoKt2Qk54EqwL7Rvf6Ds6Hn0iogLGFVXxMBU2b78GgFtvkk_rVwnyScQvl_72-1PfiR9uzqLHOdaccRFcbtlJ1_VT7kMI8wlr1fl3mQJ41TB-pQCxH8Xed6fWjxFzD7tGwFjV-UYw4-6x-_RaNsGdX-jx3m4s0Z8_ZndzL3-UUJV26YGMn_Z0dIv9_v61S7Ison8BHA2WCt7QgSm0UZ6CTS6uH812uEnZCPaxgZxC0ZMLp5Y4biWxJ41gNuSA5iCcLAQ",
            "p": "3yPOTLcn5CI1W_0FUstzREOmFITVjl8fNYR391K2i924GAaykTM4dJ6G7PRnKIvVktwUHxAKS6yXOsd-akKnSEwEzxwiIFx3gd68O9VTsyrME2DHVggLDI2a4aWxbYIKSrSjITqlYHQ741pl1JQOEmMoHrVOlnt-ia-Yi1sKiJk",
            "q": "1VUI28iNTgzVaEDnGMjLFxAKlu34bLLKc0NK-KHg7Qd_l_boxPmdJyXgozQTgpqzzYnDoyrGZAMpiKZzf9g8RHpjSLESAVFV8gjWOLxegGB4OOjS0Ceuqz-W5vagPpnLd59cv7yOXpYQdRZZUgcByR210meGMBhFqV6KD6X1cTE",
            "dp": "GLVlTbdmUmu7TuFYqo9exytag6El6Kr90LZHdnqRPjGiBf8P3OY4FSnMtQZnOeUqFCYMkFf9W93TrS2UAP46edX5Hln2KXEzxoy8eT-pEgjmKisoR42Cc7RmdyAa4o5ox1bzTWWqFGEqlIVZC04NtNmIAsZ-2kj4fRSVprDBHNk",
            "dq": "hLjLsxkZuHZJivveCtBZcba8L9xLkyzEwWMbUIY9zpm8qwmlFW8Kc6GgGUk73iRrOrO78FabaPuCqo6MCvy3ug6-mCn5vrIgm10eEdw3mvzprtZC2dfmVopQUs8bMPcz2-9cn7kqhfQstvu5hEvxs3L1fLqFhISFSnMTx9qDUfE",
            "qi": "Tbt6LDjEbAi-lOtrAUTtv-049tBEF58RLbwfL8jz3K7oVym6aryBr61vSoK6DA9tDbjzCbcZt3VUXySxuZI6ir4ZTbQqy5yoS7NKfkqWOisTBnd25PQ_ujDly5RGX_7s1UQFLI_HDkYKsDVr-mkWx70hpO3emGfk2JE1kXmy5CU"
        }
    ]
}
`}

	var keys jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jsonKeys[index]), &keys); err != nil {
		panic(fmt.Sprintf("failed to unmarshal keys: %s", err))
	}

	return &keys
}
