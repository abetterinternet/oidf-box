package entity

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	_ "github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/errors"
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

// NewFederationEndpoints fetches the named entity's entity configuration from the well-known path
// relative to the provided OIDF identifier per
// https://openid.net/specs/openid-federation-1_0-41.html#section-9
func (c *HTTPClient) NewFederationEndpoints(identifier Identifier) (*FederationEndpoints, error) {
	entityConfigurationURL := identifier.URL.JoinPath(EntityConfigurationPath)
	ecBytes, err := c.get(*entityConfigurationURL, EntityStatementContentType, nil)
	if err != nil {
		return nil, err
	}

	entityConfiguration, err := ValidateEntityStatement(string(ecBytes), nil)
	if err != nil {
		return nil, errors.Errorf("failed to validate EC: %w", err)
	}

	var federationEntityMetadata FederationEntityMetadata
	if err := entityConfiguration.FindMetadata(FederationEntity, &federationEntityMetadata); err != nil {
		return nil, errors.Errorf("EC does not contain federation entity metadata")
	}

	var fetch *url.URL
	if federationEntityMetadata.FetchEndpoint != "" {
		fetch, err = url.Parse(federationEntityMetadata.FetchEndpoint)
		if err != nil {
			return nil, errors.Errorf(
				"bad fetch endpoint '%s' in federation entity metadata: %w",
				federationEntityMetadata.FetchEndpoint, err,
			)
		}
	}
	var list *url.URL
	if federationEntityMetadata.ListEndpoint != "" {
		list, err = url.Parse(federationEntityMetadata.ListEndpoint)
		if err != nil {
			return nil, errors.Errorf(
				"bad list endpoint '%s' in federation entity metadata: %w",
				federationEntityMetadata.ListEndpoint, err,
			)
		}
	}
	var resolve *url.URL
	if federationEntityMetadata.ResolveEndpoint != "" {
		resolve, err = url.Parse(federationEntityMetadata.ResolveEndpoint)
		if err != nil {
			return nil, errors.Errorf(
				"bad resolve endpoint '%s' in federation entity metadata: %w",
				federationEntityMetadata.ResolveEndpoint, err,
			)
		}
	}

	// Non-standard endpoints
	var isrgExtensionMetadata ISRGExtensionsEntityMetadata
	var isTrusted *url.URL
	var signChallenge *url.URL
	if err := entityConfiguration.FindMetadata(ISRGExtensions, &isrgExtensionMetadata); err == nil {
		if isrgExtensionMetadata.SignChallengeEndpoint != "" {
			signChallenge, err = url.Parse(isrgExtensionMetadata.SignChallengeEndpoint)
			if err != nil {
				return nil, errors.Errorf(
					"bad sign challenge endpoint '%s' in ISRG extensions metadata: %w",
					isrgExtensionMetadata.SignChallengeEndpoint, err)
			}
		}
	}

	return &FederationEndpoints{
		client:                *c,
		Entity:                *entityConfiguration,
		fetchEndpoint:         fetch,
		listEndpoint:          list,
		resolveEndpoint:       resolve,
		isTrustedEndpoint:     isTrusted,
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
	Entity          EntityStatement
	fetchEndpoint   *url.URL
	listEndpoint    *url.URL
	resolveEndpoint *url.URL
	// Non-standard endpoints
	subordinationEndpoint *url.URL
	isTrustedEndpoint     *url.URL
	signChallengeEndpoint *url.URL
	// TODO(timg): other federation endpoints
}

// SubordinateStatement fetches a subordinate statement for the provided entity.
// https://openid.net/specs/openid-federation-1_0-41.html#name-fetch-subordinate-statement
func (fe *FederationEndpoints) SubordinateStatement(subordinate Identifier) (*EntityStatement, error) {
	if fe.fetchEndpoint == nil {
		return nil, errors.Errorf("no fetch endpoint in entity metadata")
	}
	esBytes, err := fe.client.get(*fe.fetchEndpoint, EntityStatementContentType, map[string][]string{
		QueryParamSub: {subordinate.String()},
	})
	if err != nil {
		return nil, err
	}

	entityStatement, err := ValidateEntityStatement(string(esBytes), &fe.Entity.FederationEntityKeys)
	if err != nil {
		return nil, errors.Errorf("failed to validate entity statement: %w", err)
	}

	return entityStatement, nil
}

// ListSubordinates lists the subordinates of the entity.
// https://openid.net/specs/openid-federation-1_0-41.html#name-subordinate-listings
// TODO(timg): arguments for trust_marked and trust_mark_id
func (fe *FederationEndpoints) ListSubordinates(
	entityTypes []EntityTypeIdentifier, intermediate bool,
) ([]Identifier, error) {
	if fe.listEndpoint == nil {
		return nil, errors.Errorf("no list endpoint in entity metadata")
	}
	queryParams := make(map[string][]string)
	if len(entityTypes) != 0 {
		entityTypeStrings := []string{}
		for _, entityType := range entityTypes {
			entityTypeStrings = append(entityTypeStrings, string(entityType))
		}
		queryParams[QueryParamEntityType] = entityTypeStrings
	}
	if intermediate {
		queryParams[QueryParamIntermediate] = []string{"true"}
	}

	// TODO(timg): wire up trustMarked and trustMarkID
	identifiersBytes, err := fe.client.get(*fe.listEndpoint, "application/json", queryParams)
	if err != nil {
		return nil, err
	}

	var identifiers []Identifier
	if err := json.Unmarshal(identifiersBytes, &identifiers); err != nil {
		return nil, errors.Errorf("could not unmarshal identifiers: %w", err)
	}

	return identifiers, nil
}

// AddSubordinate adds the provided identifiers as subordinates for the entity.
// OIDF deliberately does not specify how this works, but I needed to invent something to enable
// federation construction across processes.
func (fe *FederationEndpoints) AddSubordinates(subordinates []Identifier) error {
	if fe.subordinationEndpoint == nil {
		return errors.Errorf("no subordination endpoint in entity metadata")
	}
	urlWithSubParam := addSubQueryParam(*fe.subordinationEndpoint, subordinates)

	// Empty body, no content type?
	resp, err := fe.client.client.Post(urlWithSubParam.String(), "", strings.NewReader(""))
	if err != nil {
		return errors.Errorf("failed to POST request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	return nil
}

// IsTrusted returns a validated trust chain if the other entity is trusted by the entity, and an
// error otherwise.
func (fe *FederationEndpoints) IsTrusted(otherEntity Identifier) ([]EntityStatement, error) {
	if fe.isTrustedEndpoint == nil {
		return nil, errors.Errorf("no is trusted endpoint in entity metadata")
	}
	urlWithSubParam := addSubQueryParam(*fe.isTrustedEndpoint, []Identifier{otherEntity})

	trustChainBytes, err := fe.client.get(urlWithSubParam, "application/json", nil)
	if err != nil {
		return nil, errors.Errorf("failed to GET request: %w", err)
	}

	var trustChain []EntityStatement
	if err := json.Unmarshal(trustChainBytes, &trustChain); err != nil {
		return nil, errors.Errorf("could not unmarshal trust chain: %w", err)
	}

	return trustChain, nil
}

type ResolveResponse struct {
	EntityStatement
	TrustChain []string `json:"trust_chain"`
}

func (fe *FederationEndpoints) Resolve(
	subject Identifier,
	trustAnchor Identifier,
	entityTypes []EntityTypeIdentifier,
) (*ResolveResponse, error) {
	if fe.resolveEndpoint == nil {
		return nil, errors.Errorf("no resolve endpoint in entity metadata")
	}

	entityTypeStrings := []string{}
	for _, entityType := range entityTypes {
		entityTypeStrings = append(entityTypeStrings, string(entityType))
	}

	resolveResponseBytes, err := fe.client.get(
		*fe.resolveEndpoint,
		"application/resolve-response+jwt",
		map[string][]string{
			QueryParamSub:         {subject.String()},
			QueryParamTrustAnchor: {trustAnchor.String()},
			QueryParamEntityType:  entityTypeStrings,
		},
	)
	if err != nil {
		return nil, errors.Errorf("could not get resolve response from server: %w", err)
	}

	validatedPayload, err := ValidateEntityStatementReturningPayload(
		string(resolveResponseBytes),
		"resolve-response+jwt",
		&fe.Entity.FederationEntityKeys,
	)
	if err != nil {
		return nil, errors.Errorf("failed to validate entity statement: %w", err)
	}

	var resolveResponse ResolveResponse
	if err := json.Unmarshal(validatedPayload.Payload, &resolveResponse); err != nil {
		return nil, errors.Errorf("could not unmarshal resolve resolve: %w", err)
	}

	if resolveResponse.Subject != subject {
		return nil, errors.Errorf(
			"subject '%s' in resolve response does not match",
			resolveResponse.Subject.String(),
		)
	}

	// Validate the trust chain in the response. The 0th element is an entity configuration for the
	// subject.
	subjectEC, err := ValidateEntityStatement(resolveResponse.TrustChain[0], nil)
	if err != nil {
		return nil, errors.Errorf("entity configuration in resolved trust chain not trustworthy: %w", err)
	}
	if subjectEC.Subject != subject {
		return nil, errors.Errorf(
			"entity configuration subject in resolve response '%s' does not match",
			subjectEC.Subject.String(),
		)
	}

	// The remaining elements are a chain of subordinate statements, ending in an EC for the trust
	// anchor. Walk the trust chain backward (starting at the trust anchor), until we hit the end,
	// validating signatures along the way and checking that the subject of the end entity is right.
	trustChain := resolveResponse.TrustChain[1:]
	slices.Reverse(trustChain)
	var lastKeys *jose.JSONWebKeySet
	for i, jws := range trustChain {
		entityStatement, err := ValidateEntityStatement(jws, lastKeys)
		if err != nil {
			return nil, err
		}
		lastKeys = &entityStatement.FederationEntityKeys

		if i == len(trustChain)-1 {
			// End of the iterator. Check that the subject of the end entity is the subject we are
			// resolving.
			if entityStatement.Subject != subject {
				return nil, errors.Errorf(
					"end entity in resolved trust chain '%s' does not match",
					entityStatement.Subject.String(),
				)
			}
		}
	}

	return &resolveResponse, nil
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

func addSubQueryParam(originalURL url.URL, entities []Identifier) url.URL {
	identifiers := []string{}
	for _, entity := range entities {
		identifiers = append(identifiers, entity.String())
	}

	urlWithQueryParams := originalURL
	urlWithQueryParams.RawQuery = url.Values(map[string][]string{
		QueryParamSub: identifiers,
	}).Encode()

	return urlWithQueryParams
}
