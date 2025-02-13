package entity

import (
	_ "fmt"
	"slices"
	"testing"
)

func TestIdentifier(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "valid",
			input: "https://example.com",
			valid: true,
		},
		{
			name:  "port",
			input: "https://example.com:9999",
			valid: true,
		},
		{
			name:  "path",
			input: "https://example.com/some/path",
			valid: true,
		},
		// {
		// 	name:  "not-https",
		// 	input: "http://example.com",
		// 	valid: false,
		// },
		{
			name:  "query",
			input: "https://example.com?query=param",
			valid: false,
		},
		{
			name:  "fragment",
			input: "https://example.com/path#fragment",
			valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewIdentifier(testCase.input)
			if testCase.valid {
				if err != nil {
					t.Errorf("valid name rejected: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Errorf("invalid name accepted")
				}
			}
		})
	}
}

func TestACMERequestor(t *testing.T) {
	entity, err := New("https://example.com", EntityOptions{
		IsACMERequestor: true,
		TrustAnchors:    []string{"https://example.com/trust-anchor"},
	})
	if err != nil {
		t.Fatalf("failed to construct entity: %s", err.Error())
	}

	entityConfigurationJWS, err := entity.SignedEntityConfiguration()
	if err != nil {
		t.Fatalf("failed to construct EntityConfiguration: %s", err.Error())
	}

	compactSerialized, err := entityConfigurationJWS.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to compact serialize: %s", err.Error())
	}

	entityConfiguration, err := ValidateEntityStatement(compactSerialized, nil)
	if err != nil {
		t.Fatalf("failed to validate JWS: %s", err.Error())
	}

	var requestorMetadata ACMERequestorMetadata
	if err := entityConfiguration.FindMetadata(ACMERequestor, &requestorMetadata); err != nil {
		t.Fatalf("EC does not contain requestor metadata: %s", err.Error())
	}

	// TODO(timg): We should check this more rigorously but there's no
	// convenient .Equals on jose.JSONWebKeySet
	if requestorMetadata.CertifiableKeys == nil {
		t.Errorf("no certifiable keys in requestor metadata")
	}

	if _, ok := entityConfiguration.Metadata[ACMEIssuer]; ok {
		t.Errorf("no issuer metadata should be present")
	}
}

func TestACMEIssuer(t *testing.T) {
	entity, err := New("https://example.com", EntityOptions{
		ACMEIssuer:   "https://example.com/acme",
		TrustAnchors: []string{"https://example.com/trust-anchor"},
	})

	if err != nil {
		t.Fatalf("failed to construct entity: %s", err.Error())
	}

	if err != nil {
		t.Fatalf("Failed to construct EntityConfiguration: %s", err.Error())
	}

	entityConfigurationJWS, err := entity.SignedEntityConfiguration()
	if err != nil {
		t.Fatalf("failed to construct EntityConfiguration: %s", err.Error())
	}

	compactSerialized, err := entityConfigurationJWS.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to compact serialize: %s", err.Error())
	}

	entityConfiguration, err := ValidateEntityStatement(compactSerialized, nil)
	if err != nil {
		t.Fatalf("failed to validate JWS: %s", err.Error())
	}

	var issuerMetadata ACMEIssuerMetadata
	if err := entityConfiguration.FindMetadata(ACMEIssuer, &issuerMetadata); err != nil {
		t.Fatalf("EC does not contain issuer metadata: %s", err.Error())
	}

	if issuerMetadata.Directory != "https://example.com/acme" {
		t.Fatalf("wrong ACME issuer URL")
	}
}

func TestTrustChain(t *testing.T) {
	// Construct entities for trust chain of length 3
	// TODO(timg): this is brittle as these ports may already be bound
	trustAnchor, err := NewAndServe("http://localhost:8001", EntityOptions{})
	if err != nil {
		t.Fatalf("failed to construct trust anchor: %s", err.Error())
	}
	defer trustAnchor.CleanUp()

	intermediate, err := NewAndServe("http://localhost:8002", EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		t.Fatalf("failed to construct intermediate: %s", err.Error())
	}
	defer intermediate.CleanUp()

	leafEntity, err := NewAndServe("http://localhost:8003", EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity: %s", err.Error())
	}
	defer leafEntity.CleanUp()

	oidfClient := NewOIDFClient()

	intermediateClient, err := oidfClient.NewFederationEndpoints(intermediate.Identifier)
	if err != nil {
		t.Fatalf("failed to construct federation endpoints for intermdiate: %s", err.Error())
	}

	trustAnchorClient, err := oidfClient.NewFederationEndpoints(trustAnchor.Identifier)
	if err != nil {
		t.Fatalf("failed to construct federation endpoints for trust anchor: %s", err.Error())
	}

	// Create subordinations
	if err := intermediateClient.AddSubordinates([]Identifier{leafEntity.Identifier}); err != nil {
		t.Fatalf("failed to subordinate leaf entity: %s", err.Error())
	}
	leafEntity.AddSuperior(intermediate.Identifier)

	if err := trustAnchorClient.AddSubordinates([]Identifier{intermediate.Identifier}); err != nil {
		t.Fatalf("failed to subordinate intermediate: %s", err.Error())
	}
	intermediate.AddSuperior(trustAnchor.Identifier)

	// Build a trust chain from leaf entity to trust anchor by re-fetching ECs (hence new
	// FederationEndpoints, examining authority_hints and then getting subordinate statements
	leafEntityClient, err := oidfClient.NewFederationEndpoints(leafEntity.Identifier)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(leafEntityClient.Entity.AuthorityHints) != 1 ||
		!slices.Contains(leafEntityClient.Entity.AuthorityHints, intermediate.Identifier) {
		t.Errorf("leaf entity EC has unexpected authority hints: %+v", leafEntityClient.Entity.AuthorityHints)
	}

	intermediateClient, err = oidfClient.NewFederationEndpoints(leafEntityClient.Entity.AuthorityHints[0])
	if err != nil {
		t.Fatalf("failed to construct federation endpoints for intermdiate: %s", err.Error())
	}

	leafEntityStatement, err := intermediateClient.SubordinateStatement(leafEntity.Identifier)
	if err != nil {
		t.Fatalf("failed to get ES for leaf: %s", err.Error())
	}

	if leafEntityStatement.Subject != leafEntity.Identifier ||
		leafEntityStatement.Issuer != intermediate.Identifier {
		t.Errorf("leaf ES iss/sub wrong: %+v / %+v",
			leafEntityStatement.Issuer, leafEntityStatement.Subject)
	}

	if leafEntityStatement.AuthorityHints != nil {
		t.Errorf("leaf ES contains authority hints")
	}

	if len(intermediateClient.Entity.AuthorityHints) != 1 ||
		!slices.Contains(intermediateClient.Entity.AuthorityHints, trustAnchor.Identifier) {
		t.Errorf("intermediate EC has unexpected authority hints: %+v",
			intermediateClient.Entity.AuthorityHints)
	}

	trustAnchorClient, err = oidfClient.NewFederationEndpoints(intermediateClient.Entity.AuthorityHints[0])
	if err != nil {
		t.Fatalf("failed to construct federation endpoints for trust anchor: %s", err.Error())
	}

	if len(trustAnchorClient.Entity.AuthorityHints) != 0 {
		t.Errorf("trust anchor EC has unexpected authority hints: %+v",
			trustAnchor.entityConfiguration().AuthorityHints)
	}

	intermediateEntityStatement, err := trustAnchorClient.SubordinateStatement(intermediate.Identifier)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if intermediateEntityStatement.Subject != intermediate.Identifier ||
		intermediateEntityStatement.Issuer != trustAnchor.Identifier {
		t.Errorf("intermediate ES iss/sub wrong: %+v / %+v",
			intermediateEntityStatement.Issuer, intermediateEntityStatement.Subject)
	}

	if intermediateEntityStatement.AuthorityHints != nil {
		t.Errorf("intermediate ES contains authority hints")
	}
}

func TestFederationList(t *testing.T) {
	trustAnchor, err := NewAndServe("http://localhost:8001", EntityOptions{})
	if err != nil {
		t.Fatalf("failed to construct trust anchor: %s", err.Error())
	}
	defer trustAnchor.CleanUp()

	intermediate, err := NewAndServe("http://localhost:8002", EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		t.Fatalf("failed to construct intermediate: %s", err.Error())
	}
	defer intermediate.CleanUp()

	leafEntity, err := NewAndServe("http://localhost:8005", EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity")
	}
	defer leafEntity.CleanUp()

	acmeRequestor, err := NewAndServe("http://localhost:8003", EntityOptions{
		TrustAnchors:    []string{"http://localhost:8001"},
		IsACMERequestor: true,
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity: %s", err.Error())
	}
	defer acmeRequestor.CleanUp()

	acmeIssuer, err := NewAndServe("http://localhost:8004", EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
		ACMEIssuer:   "http://example.com",
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity: %s", err.Error())
	}
	defer acmeIssuer.CleanUp()

	// Create subordinations
	if err := trustAnchor.AddSubordinate(intermediate.Identifier); err != nil {
		t.Fatalf("failed to subordinate intermediate: %s", err.Error())
	}
	intermediate.AddSuperior(trustAnchor.Identifier)

	if err := trustAnchor.AddSubordinate(leafEntity.Identifier); err != nil {
		t.Fatalf("failed to subordinate intermediate: %s", err.Error())
	}
	leafEntity.AddSuperior(trustAnchor.Identifier)

	if err := intermediate.AddSubordinate(acmeRequestor.Identifier); err != nil {
		t.Fatalf("failed to subordinate leaf entity: %s", err.Error())
	}
	acmeRequestor.AddSuperior(intermediate.Identifier)

	if err := intermediate.AddSubordinate(acmeIssuer.Identifier); err != nil {
		t.Fatalf("failed to subordinate intermediate: %s", err.Error())
	}
	acmeIssuer.AddSuperior(intermediate.Identifier)

	oidfClient := NewOIDFClient()
	for _, testCase := range []struct {
		name                   string
		entity                 *Entity
		subordinateEntityTypes []EntityTypeIdentifier
		intermediate           bool
		shouldFail             bool
		expectedSubordinates   []*Entity
	}{
		{
			name:                 "all trust anchor subs",
			entity:               trustAnchor,
			expectedSubordinates: []*Entity{leafEntity, intermediate},
		},
		{
			name:         "intermediate trust anchor subs",
			entity:       trustAnchor,
			intermediate: true,
			shouldFail:   true,
		},
		{
			name:                   "ACME issuer trust anchor subs",
			entity:                 trustAnchor,
			subordinateEntityTypes: []EntityTypeIdentifier{ACMEIssuer},
			expectedSubordinates:   []*Entity{},
		},
		{
			name:                   "ACME issuer intermediate subs",
			entity:                 intermediate,
			subordinateEntityTypes: []EntityTypeIdentifier{ACMEIssuer},
			expectedSubordinates:   []*Entity{acmeIssuer},
		},
		{
			name:                   "ACME issuer or requestor intermediate subs",
			entity:                 intermediate,
			subordinateEntityTypes: []EntityTypeIdentifier{ACMEIssuer, ACMERequestor},
			expectedSubordinates:   []*Entity{acmeIssuer, acmeRequestor},
		},
		{
			name:                   "ACME requestor intermediate subs",
			entity:                 intermediate,
			subordinateEntityTypes: []EntityTypeIdentifier{ACMERequestor},
			expectedSubordinates:   []*Entity{acmeRequestor},
		},
		{
			name:         "intermediate intermediate subs",
			entity:       intermediate,
			intermediate: true,
			shouldFail:   true,
		},
		{
			name:   "leaf entity subs",
			entity: leafEntity,
		},
	} {

		t.Run(testCase.name, func(t *testing.T) {
			//Entity{trustAnchor, intermediate, leafEntity, acmeRequestor, acmeIssuer} {
			endpoint, err := oidfClient.NewFederationEndpoints(testCase.entity.Identifier)
			if err != nil {
				t.Fatalf("failed to construct endpoints for %+v: %s",
					testCase.entity.Identifier, err.Error())
			}

			subordinates, err := endpoint.ListSubordinates(testCase.subordinateEntityTypes, testCase.intermediate)
			if testCase.shouldFail {
				if err == nil {
					t.Fatalf("listing subordinates should fail")
				}
			} else {
				if err != nil {
					t.Fatalf("failed to list subordinates for %+v: %s",
						testCase.entity.Identifier, err.Error())
				}

				if len(testCase.expectedSubordinates) != len(subordinates) {
					t.Errorf("unexpected subordinate listing: %+v", subordinates)
				}
				for _, sub := range testCase.expectedSubordinates {
					if !slices.Contains(subordinates, sub.Identifier) {
						t.Errorf("unexpected subordinate listing: %+v", subordinates)
					}
				}
			}
		})
	}
}
