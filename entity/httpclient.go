package entity

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
		return nil, fmt.Errorf("failed to validate EC: %w", err)
	}

	var federationEntityMetadata FederationEntityMetadata
	if err := entityConfiguration.FindMetadata(FederationEntity, &federationEntityMetadata); err != nil {
		return nil, fmt.Errorf("EC does not contain federation entity metadata")
	}

	fetch, err := url.Parse(federationEntityMetadata.FetchEndpoint)
	if err != nil {
		return nil, fmt.Errorf(
			"bad fetch endpoint '%s' in federation entity metadata: %w",
			federationEntityMetadata.FetchEndpoint, err,
		)
	}
	list, err := url.Parse(federationEntityMetadata.ListEndpoint)
	if err != nil {
		return nil, fmt.Errorf(
			"bad list endpoint '%s' in federation entity metadata: %w",
			federationEntityMetadata.ListEndpoint, err,
		)
	}

	return &FederationEndpoints{
		client:        *c,
		Entity:        *entityConfiguration,
		fetchEndpoint: *fetch,
		listEndpoint:  *list,
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
		return nil, fmt.Errorf("failed to fetch EC: %w", err)
	}
	defer resp.Body.Close()

	// TODO(timg): probably not all GETs will yield HTTP 200 OK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response has unexpected HTTP status: %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != contentType {
		return nil, fmt.Errorf("response has wrong content type: %s", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// FederationEndpoints provides a client for (some of, WIP) a specific entity's federation endpoints
// defined in https://openid.net/specs/openid-federation-1_0-41.html#name-federation-endpoints
type FederationEndpoints struct {
	client        HTTPClient
	Entity        EntityStatement
	fetchEndpoint url.URL
	listEndpoint  url.URL
	// TODO(timg): other federation endpoints
}

// SubordinateStatement fetches a subordinate statement for the provided entity.
// https://openid.net/specs/openid-federation-1_0-41.html#name-fetch-subordinate-statement
func (fe *FederationEndpoints) SubordinateStatement(subordinate Identifier) (*EntityStatement, error) {
	esBytes, err := fe.client.get(fe.fetchEndpoint, EntityStatementContentType, map[string][]string{
		QueryParamSub: {subordinate.String()},
	})
	if err != nil {
		return nil, err
	}

	entityStatement, err := ValidateEntityStatement(string(esBytes), &fe.Entity.FederationEntityKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to validate entity statement: %w", err)
	}

	return entityStatement, nil
}

// ListSubordinates lists the subordinates of the entity.
// https://openid.net/specs/openid-federation-1_0-41.html#name-subordinate-listings
// TODO(timg): arguments for trust_marked and trust_mark_id
func (fe *FederationEndpoints) ListSubordinates(
	entityTypes []EntityTypeIdentifier, intermediate bool,
) ([]Identifier, error) {
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
	identifiersBytes, err := fe.client.get(fe.listEndpoint, "application/json", queryParams)
	if err != nil {
		return nil, err
	}

	var identifiers []Identifier
	if err := json.Unmarshal(identifiersBytes, &identifiers); err != nil {
		return nil, fmt.Errorf("could not unmarshal identifiers: %w", err)
	}

	return identifiers, nil
}
