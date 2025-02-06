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
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// https://openid.net/specs/openid-federation-1_0-41.html#name-obtaining-federation-entity
	EntityConfigurationPath        = "/.well-known/openid-federation"
	EntityConfigurationContentType = "application/entity-statement+jwt"
)

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

	if entityURL.Scheme != "https" {
		return Identifier{}, fmt.Errorf(
			"identifier '%s' is not a valid OIDF entity identifier: scheme must be https",
			identifier)
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

// Entity represents an OpenID Federation Entity.
type Entity struct {
	// identifier for the OpenID Federation Entity.
	identifier Identifier
	// federationEntityKey is this entity's keys
	// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.44
	federationEntityKeys jose.JSONWebKeySet
	// acmeRequestorKeys is the set of keys that this entity MAY request X.509 certificates for
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-requestor-metadata
	acmeRequestorKeys jose.JSONWebKeySet
	// listener may be a bound port on which requests for Entity Configurations are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

// New constructs a new Entity, generating keys as needed.
func New(identifier string) (Entity, error) {
	parsedIdentifier, err := NewIdentifier(identifier)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to parse identifier '%s': %w", identifier, err)
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

	return Entity{
		identifier:           parsedIdentifier,
		federationEntityKeys: federationEntityKeys,
		acmeRequestorKeys:    acmeRequestorKeys,
	}, nil
}

// EntityConfiguration constructs and signs an Entity Configuration for this Entity
func (e *Entity) EntityConfiguration() (*jose.JSONWebSignature, error) {
	ec := map[string]interface{}{
		// iss, sub, iat, exp, jwks are required
		// Identifiers must be coerced into strings before being put into JWT claims, or Go will
		// serialize them as elaborate JSON nightmares
		"iss":  e.identifier.String(),
		"sub":  e.identifier.String(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Unix() + 3600, // valid for 1 hour
		"jwks": publicJWKS(&e.federationEntityKeys),
		// TODO: authority_hints is REQUIRED for non trust anchors
		"metadata": map[string]interface{}{
			"acme_requestor": map[string]interface{}{
				"jwks": publicJWKS(&e.acmeRequestorKeys),
				// OpenID Federation REQUIRES iss and sub
				"iss": e.identifier.String(),
				"sub": e.identifier.String(),
				// TODO: iat and exp are OPTIONAL, consider adding them
			},
		},
	}
	payload, err := json.Marshal(ec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity configuration to JSON: %w", err)
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
		return nil, fmt.Errorf("Failed to sign entity configuration: %w", err)
	}

	return signed, nil
}

func (e *Entity) ServeEntityConfiguration() error {
	// Listen at whatever port is in the identifier, which may not be right
	var err error
	e.listener, err = net.Listen("tcp", net.JoinHostPort("", e.identifier.url.Port()))
	if err != nil {
		return fmt.Errorf("could not start HTTP server for OIDF EC: %w", err)
	}

	e.done = make(chan struct{})

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(EntityConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "only GET is allowed", http.StatusMethodNotAllowed)
				return
			}

			entityConfiguration, err := e.EntityConfiguration()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			compact, err := entityConfiguration.CompactSerialize()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", EntityConfigurationContentType)
			// All JWSes MUST use compact serialization
			// https://openid.net/specs/openid-federation-1_0-41.html#name-requirements-notation-and-c
			if _, err := w.Write([]byte(compact)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
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
