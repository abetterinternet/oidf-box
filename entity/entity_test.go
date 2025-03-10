package entity

import (
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
		{
			name:  "not-https",
			input: "http://example.com",
			valid: true,
		},
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
					t.Errorf("valid name rejected: %s", err)
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
		ACMERequestor:        &ACMERequestorOptions{Keys: TestJSONWebKeySet(0)},
		TrustAnchors:         []string{"https://example.com/trust-anchor"},
		FederationEntityKeys: TestJSONWebKeySet(1),
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
		ACMEIssuer:           &ACMEIssuerOptions{DirectoryURL: "https://example.com/acme"},
		TrustAnchors:         []string{"https://example.com/trust-anchor"},
		FederationEntityKeys: TestJSONWebKeySet(0),
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
	trustAnchor, err := NewAndServe("http://localhost:8001", EntityOptions{
		FederationEntityKeys: TestJSONWebKeySet(0),
	})
	if err != nil {
		t.Fatalf("failed to construct trust anchor: %s", err.Error())
	}
	defer trustAnchor.CleanUp()

	intermediate, err := NewAndServe("http://localhost:8002", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		FederationEntityKeys: TestJSONWebKeySet(1),
	})
	if err != nil {
		t.Fatalf("failed to construct intermediate: %s", err.Error())
	}
	defer intermediate.CleanUp()

	leafEntity, err := NewAndServe("http://localhost:8003", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		FederationEntityKeys: TestJSONWebKeySet(2),
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

	trustChain, err := leafEntity.EvaluateTrust(leafEntity.Identifier)
	if err != nil {
		t.Errorf("failed to evaluate trust: %s", err.Error())
	}

	if !trustChain[0].Subject.Equals(&leafEntity.Identifier) ||
		!trustChain[1].Subject.Equals(&intermediate.Identifier) ||
		!trustChain[2].Subject.Equals(&trustAnchor.Identifier) {
		t.Errorf("unexpected trust chain %v", trustChain)
	}

	// Construct an unrelated entity untrusted by anybody, and it shouldn't be possible to construct
	// a chain for it
	untrustedEntity, err := NewAndServe("http://localhost:8004", EntityOptions{
		FederationEntityKeys: TestJSONWebKeySet(0),
	})
	if err != nil {
		t.Fatalf("failed to construct entity")
	}
	defer untrustedEntity.CleanUp()

	if _, err := leafEntity.EvaluateTrust(untrustedEntity.Identifier); err == nil {
		t.Errorf("untrusted entity should not be trusted")
	}
}

func TestFederationList(t *testing.T) {
	trustAnchor, err := NewAndServe("http://localhost:8001", EntityOptions{
		FederationEntityKeys: TestJSONWebKeySet(1),
	})
	if err != nil {
		t.Fatalf("failed to construct trust anchor: %s", err.Error())
	}
	defer trustAnchor.CleanUp()

	intermediate, err := NewAndServe("http://localhost:8002", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		FederationEntityKeys: TestJSONWebKeySet(2),
	})
	if err != nil {
		t.Fatalf("failed to construct intermediate: %s", err.Error())
	}
	defer intermediate.CleanUp()

	leafEntity, err := NewAndServe("http://localhost:8005", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		FederationEntityKeys: TestJSONWebKeySet(3),
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity")
	}
	defer leafEntity.CleanUp()

	acmeRequestor, err := NewAndServe("http://localhost:8003", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		FederationEntityKeys: TestJSONWebKeySet(4),
		ACMERequestor:        &ACMERequestorOptions{Keys: TestJSONWebKeySet(5)},
	})
	if err != nil {
		t.Fatalf("failed to construct leaf entity: %s", err.Error())
	}
	defer acmeRequestor.CleanUp()

	acmeIssuer, err := NewAndServe("http://localhost:8004", EntityOptions{
		TrustAnchors:         []string{"http://localhost:8001"},
		ACMEIssuer:           &ACMEIssuerOptions{DirectoryURL: "http://example.com"},
		FederationEntityKeys: TestJSONWebKeySet(6),
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

func TestChallengeSigning(t *testing.T) {
	entity, err := NewAndServe("http://localhost:8001", EntityOptions{
		FederationEntityKeys: TestJSONWebKeySet(0),
		ACMERequestor:        &ACMERequestorOptions{Keys: TestJSONWebKeySet(1)},
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer entity.CleanUp()

	signature, err := entity.SignChallenge("token")
	if err != nil {
		t.Fatalf(err.Error())
	}

	compact, err := signature.CompactSerialize()
	if err != nil {
		t.Fatalf(err.Error())
	}

	client := NewOIDFClient()
	endpoints, err := client.NewFederationEndpoints(entity.Identifier)
	if err != nil {
		t.Fatalf(err.Error())
	}

	entityConfiguration := entity.entityConfiguration()
	if err := entityConfiguration.VerifyChallenge(compact, "token"); err != nil {
		t.Fatalf(err.Error())
	}

	if err := endpoints.Entity.VerifyChallenge(compact, "token"); err != nil {
		t.Fatalf(err.Error())
	}
}
