package oidfclient

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	oidf "github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/jwk"

	"github.com/tgeoghegan/oidf-box/errors"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

const (
	// https://openid.net/specs/openid-federation-1_0-41.html#name-obtaining-federation-entity
	EntityConfigurationPath    = ".well-known/openid-federation"
	EntityStatementContentType = "application/entity-statement+jwt"

	// Query parameters for federation endpoints
	QueryParamSub          = "sub"
	QueryParamEntityType   = "entity_type"
	QueryParamTrustAnchor  = "trust_anchor"
	QueryParamTrustMarked  = "trust_marked"
	QueryParamTrustMarkID  = "trust_mark_id"
	QueryParamIntermediate = "intermediate"
)

// HTTPClient is a client used for HTTP requests to OIDF entities. It allows re-use of a single
// client across many instances of FederationEndpoints.
type HTTPClient struct {
	client http.Client
}

func NewOIDFClient() HTTPClient {
	return HTTPClient{client: http.Client{Transport: &http.Transport{
		// TODO(timg): make TLS stuff configurable. For current test purposes, turning off TLS
		// trust verification suffices.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}}
}

func joinURL(base string, path string) (*url.URL, error) {
	var urlString string
	if strings.HasSuffix(base, "/") {
		urlString = base + path
	} else {
		urlString = base + "/" + path
	}

	parsed, err := url.Parse(urlString)
	if err != nil {
		return nil, errors.Errorf("could not parse entity configuration URL: %w", err)
	}

	return parsed, nil
}

func ValidateEntityStatement(esBytes []byte, keys *jwk.JWKS) (*oidf.EntityStatement, error) {
	entityStatement, err := oidf.ParseEntityStatement(esBytes)
	if err != nil {
		return nil, errors.Errorf("failed to parse entity statement: %w", err)
	}

	validated := false
	if entityStatement.Subject == entityStatement.Issuer {
		// This is an entity configuration. It will be signed with its own JWKS.
		if keys != nil {
			return nil, errors.Errorf("entity configuration should be verified with own keys")
		}

		validated = entityStatement.Verify(entityStatement.JWKS)
	} else {
		// This is an entity statement
		if keys == nil {
			return nil, errors.Errorf("keys must be provided to validate entity statement")
		}
		validated = entityStatement.Verify(*keys)
	}

	if validated {
		return entityStatement, nil
	} else {
		return nil, errors.Errorf("failed to validate entity statement (error suppressed by go-oidfed")
	}
}

// NewFederationEndpoints fetches the named entity's entity configuration from the well-known path
// relative to the provided OIDF identifier per
// https://openid.net/specs/openid-federation-1_0-41.html#section-9
func (c *HTTPClient) NewFederationEndpoints(identifier string) (*FederationEndpoints, error) {
	entityConfigurationURL, err := joinURL(identifier, EntityConfigurationPath)
	if err != nil {
		return nil, err
	}
	ecBytes, err := c.get(*entityConfigurationURL, EntityStatementContentType, nil)
	if err != nil {
		return nil, err
	}

	entityConfiguration, err := ValidateEntityStatement(ecBytes, nil)
	if err != nil {
		return nil, errors.Errorf("failed to validate EC: %w", err)
	}

	federationEntityMetadata := entityConfiguration.Metadata.FederationEntity
	var resolve *url.URL
	if federationEntityMetadata.FederationResolveEndpoint != "" {
		resolve, err = url.Parse(federationEntityMetadata.FederationResolveEndpoint)
		if err != nil {
			return nil, errors.Errorf(
				"bad resolve endpoint '%s' in federation entity metadata: %w",
				federationEntityMetadata.FederationResolveEndpoint, err,
			)
		}
	}

	// Non-standard endpoints
	var signChallenge *url.URL
	var acmeChallengeSolverMetadata oidf01.ACMEChallengeSolverEntityMetadata
	if err := entityConfiguration.Metadata.FindEntityMetadata(
		oidf01.ACMEChallengeSolverEntityType,
		&acmeChallengeSolverMetadata,
	); err == nil {
		if acmeChallengeSolverMetadata.SignChallengeEndpoint == "" {
			return nil, errors.Errorf(
				"empty sign challenge endpoint '%s' in ACME challenge solver metadata for %s",
				identifier,
			)
		}

		signChallenge, err = url.Parse(acmeChallengeSolverMetadata.SignChallengeEndpoint)
		if err != nil {
			return nil, errors.Errorf(
				"bad sign challenge endpoint '%s' in ACME challenge solver metadata: %w",
				acmeChallengeSolverMetadata.SignChallengeEndpoint, err)
		}
	}

	return &FederationEndpoints{
		client:                *c,
		Entity:                *entityConfiguration,
		resolveEndpoint:       resolve,
		signChallengeEndpoint: signChallenge,
	}, nil
}

// Get does an HTTP GET of the specified resource and validates that the response has the expected
// Content-Type header and returns the response body.
func (c *HTTPClient) get(resource url.URL, contentType string, queryParams map[string][]string) ([]byte, error) {
	query := resource.Query()
	for k, v := range queryParams {
		for _, v2 := range v {
			query.Add(k, v2)
		}
	}
	resource.RawQuery = query.Encode()

	resp, err := c.client.Get(resource.String())
	if err != nil {
		return nil, errors.Errorf("failed to fetch resource: %w", err)
	}
	defer resp.Body.Close()

	// TODO(timg): probably not all GETs will yield HTTP 200 OK
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Errorf("response has unexpected HTTP status: %d", resp.StatusCode)
		} else {
			return nil, errors.Errorf("response has unexpected HTTP status: %d\nbody: %s", resp.StatusCode, string(body))
		}
	}

	if resp.Header.Get("Content-Type") != contentType {
		return nil, errors.Errorf("response has wrong content type: %s", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// FederationEndpoints provides a client for (some of, WIP) a specific entity's federation endpoints
// defined in https://openid.net/specs/openid-federation-1_0-41.html#name-federation-endpoints
type FederationEndpoints struct {
	client          HTTPClient
	Entity          oidf.EntityStatement
	resolveEndpoint *url.URL
	// Non-standard endpoints
	signChallengeEndpoint *url.URL
	// TODO(timg): other federation endpoints
}

// resolveHTTPResponse is the response to a federation resolve request, on the wire.
type resolveHTTPResponse struct {
	oidf.EntityStatement
	TrustChain []string `json:"trust_chain"`
}

// ResolveResponse is the response to a federation resolve request.
type ResolveResponse struct {
	oidf.ResolveResponse
	EntityConfiguration oidf.EntityStatement
	TrustChain          []oidf.EntityStatement
}

func (fe *FederationEndpoints) Resolve(
	subject string,
	trustAnchors []string,
	entityTypes []string,
) (*ResolveResponse, error) {
	if fe.resolveEndpoint == nil {
		return nil, errors.Errorf("no resolve endpoint in entity metadata")
	}

	resolveResponseBytes, err := fe.client.get(
		*fe.resolveEndpoint,
		"application/resolve-response+jwt",
		map[string][]string{
			QueryParamSub:         {subject},
			QueryParamTrustAnchor: trustAnchors,
			QueryParamEntityType:  entityTypes,
		},
	)
	if err != nil {
		return nil, errors.Errorf("could not get resolve response from server: %w", err)
	}

	resolveResponse, err := oidf.ParseResolveResponse(resolveResponseBytes)
	if err != nil {
		return nil, errors.Errorf("failed to parse resolve response")
	}

	// Validate the trust chain in the response. The 0th element is an entity configuration for the
	// subject.
	subjectEC, err := ValidateEntityStatement(resolveResponse.TrustChain[0].RawJWT, nil)
	if err != nil {
		return nil, errors.Errorf("entity configuration in resolved trust chain not trustworthy: %w", err)
	}
	if subjectEC.Subject != subject {
		return nil, errors.Errorf(
			"entity configuration subject in resolve response '%s' does not match",
			subjectEC.Subject,
		)
	}

	// The remaining elements are a chain of subordinate statements, ending in an EC for the trust
	// anchor. Walk the trust chain backward (starting at the trust anchor), until we hit the end,
	// validating signatures along the way.
	trustChain := resolveResponse.TrustChain[1:]
	slices.Reverse(trustChain)
	var lastKeys *jwk.JWKS
	// Gather validated entity statements in trustChainES
	trustChainES := []oidf.EntityStatement{}
	for i, jws := range trustChain {
		entityStatement, err := ValidateEntityStatement(jws.RawJWT, lastKeys)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			// Beginning of the iterator. Check that the trust anchor from the resolver is among the
			// ones we trust.
			if !slices.Contains(trustAnchors, entityStatement.Subject) {
				return nil, errors.Errorf(
					"trust anchor in resolved trust chain '%s' is not trusted",
					entityStatement.Subject,
				)
			}
		}
		lastKeys = &entityStatement.JWKS

		if i == len(trustChain)-1 {
			// End of the iterator. Check that the subject of the end entity is the subject we are
			// resolving.
			if entityStatement.Subject != subject {
				return nil, errors.Errorf(
					"end entity in resolved trust chain '%s' does not match",
					entityStatement.Subject,
				)
			}
		}

		trustChainES = append(trustChainES, *entityStatement)
	}
	// Reverse the slice of validated entity statements so we can given the caller a trust chain
	// where the 0th element is the end entity, which is what they'd expect given OIDF's
	// specification of a trust chain.
	slices.Reverse(trustChainES)

	return &ResolveResponse{
		ResolveResponse:     *resolveResponse,
		EntityConfiguration: *subjectEC,
		TrustChain:          trustChainES,
	}, nil
}

func (fe *FederationEndpoints) SignChallenge(token string) (string, error) {
	if fe.signChallengeEndpoint == nil {
		return "", errors.Errorf("no sign challenge endpoint in entity metadata")
	}
	resp, err := fe.client.client.Post(fe.signChallengeEndpoint.String(), "text", strings.NewReader(token))
	if err != nil {
		return "", errors.Errorf("failed to POST signature request: %w", err)
	}
	defer resp.Body.Close()

	signedToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("failed to read signed token from response: %w", err)
	}

	return string(signedToken), nil
}
