package test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"slices"
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"

	"github.com/tgeoghegan/oidf-box/oidfclient"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

func TestIssuance(t *testing.T) {
	trustAnchor, trustAnchorSubordinateStorage := makeEntity(
		t,
		"trust-anchor", "8001",
		nil, // extraMetadata
		nil, // trust anchor has no authority hints
	)
	intermediate, intermediateSubordinateStorage := makeEntity(
		t,
		"intermediate", "8002",
		nil, // extraMetadata
		[]*fedentities.FedEntity{trustAnchor},
	)
	issuer, _ := makeEntity(t, "issuer", "8003",
		// extraMetadata
		map[string]any{
			oidf01.ACMEIssuerEntityType: oidf01.ACMEIssuerMetadata{
				// Corresponds to pebble/test/config/pebble-config.json
				// TODO(timg) this should be configurable
				Directory: "https://0.0.0.0:14000/dir",
			},
		},
		[]*fedentities.FedEntity{intermediate},
	)

	requestorChallengeSolver, err := oidf01.NewSolver("http://localhost:8004")
	if err != nil {
		log.Fatalf("failed to setup ACME challenge solver: %s", err)
	}
	requestor, _ := makeEntity(t, "requestor", "8004",
		// extraMetadata
		map[string]any{
			oidf01.ACMERequestorEntityType: oidf01.ACMERequestorMetadata{
				ChallengeSigningKeys: requestorChallengeSolver.ChallengeSigningPublicKeys(),
			},
		},
		[]*fedentities.FedEntity{intermediate},
	)

	otherLeafChallengeSolver, err := oidf01.NewSolver("http://localhost:8005")
	if err != nil {
		log.Fatalf("failed to setup ACME challenge solver: %s", err)
	}
	otherLeaf, _ := makeEntity(t, "other-leaf", "8005",
		// extraMetadata
		map[string]any{
			oidf01.ACMERequestorEntityType: oidf01.ACMERequestorMetadata{
				ChallengeSigningKeys: otherLeafChallengeSolver.ChallengeSigningPublicKeys(),
			},
		},
		[]*fedentities.FedEntity{intermediate},
	)

	// Subordinate:
	// - the intermediate to the trust anchor
	// - the issuer, requestor and other leaf entity to the intermediate
	// n.b. this does _not_ use the HTTP enroll endpoint, but instead writes directly to the TA and
	// intermediate's subordinate storage, just like go-oidfed/cli/ta does.
	trustAnchorSubordinateStorage.Write(intermediate.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     intermediate.FederationEntity.JWKS(),
			EntityID: intermediate.FederationEntity.EntityID,
			Metadata: intermediate.FederationEntity.Metadata,
		},
	)
	intermediateSubordinateStorage.Write(issuer.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     issuer.FederationEntity.JWKS(),
			EntityID: issuer.FederationEntity.EntityID,
			Metadata: issuer.FederationEntity.Metadata,
		},
	)
	intermediateSubordinateStorage.Write(requestor.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     requestor.FederationEntity.JWKS(),
			EntityID: requestor.FederationEntity.EntityID,
			Metadata: requestor.FederationEntity.Metadata,
		},
	)
	intermediateSubordinateStorage.Write(otherLeaf.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     otherLeaf.FederationEntity.JWKS(),
			EntityID: otherLeaf.FederationEntity.EntityID,
			Metadata: otherLeaf.FederationEntity.Metadata,
		},
	)

	oidfClient := oidfclient.NewOIDFClient()
	entities := map[string]struct {
		port       string
		identifier string
		entity     *fedentities.FedEntity
		endpoints  *oidfclient.FederationEndpoints
	}{
		"trust anchor": {port: "8001", entity: trustAnchor},
		"intermediate": {port: "8002", entity: intermediate},
		"issuer":       {port: "8003", entity: issuer},
		"requestor":    {port: "8004", entity: requestor},
		"other leaf":   {port: "8005", entity: otherLeaf},
	}
	// Start goroutines to serve each entity's federation endpoints
	for label, val := range entities {
		go func(label string, port string, entity *fedentities.FedEntity) {
			log.Printf("Start serving %s on port %s", label, port)
			if err := http.ListenAndServe(fmt.Sprintf(":%s", port), entity.HttpHandlerFunc()); err != nil {
				log.Fatalf("failed to serve %s Fed endpoints: %s", label, err)
			}
		}(label, val.port, val.entity)
		val.identifier = fmt.Sprintf("http://localhost:%s", val.port)
		client, err := oidfClient.NewFederationEndpoints(val.identifier)
		if err != nil {
			log.Fatalf("failed to create federation endpoints: %s", err)
		}
		val.endpoints = client

		// Write map value back to map -- Go doesn't let you mutate map members while you iterate
		entities[label] = val
	}

	// Setup Pebble and spawn a goroutine to run it
	pebbleFunc, err := setupPebble(t, entities["issuer"].endpoints)
	if err != nil {
		log.Fatalf("failed to setup Pebble: %s", err)
	}

	go pebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  entities["requestor"].endpoints,
		IssuerIdentifier: entities["issuer"].identifier,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			requestorChallengeSolver,
			otherLeafChallengeSolver,
		},
	})

	// It's kinda goofy to have multiple OpenID Federation identifiers in a single ACME order,
	// because what does it mean for a single key in the X.509 realm to be valid for both OIDF
	// entities? But we want to ensure this is possible in the ACME extension.
	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{Type: "openid-federation", Value: requestor.FederationEntity.EntityID},
			{Type: "openid-federation", Value: otherLeaf.FederationEntity.EntityID},
		},
		Bundle: true,
	}
	log.Printf("obtaining cert for 'domains' %+v", request.Identifiers)
	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("PEM certificate:\n%s\n", string(certificates.Certificate))

	block, _ := pem.Decode(certificates.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to parse PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse X.509 certificate: %s", err)
	}

	oidfIdentifiers, err := oidf01.EntityIdentifiersFromCertificate(cert)
	if err != nil {
		log.Fatalf("failed to extract OpenID Federation identifiers from certificate: %s", err)
	}

	if !slices.Contains(oidfIdentifiers, entities["requestor"].identifier) ||
		!slices.Contains(oidfIdentifiers, entities["other leaf"].identifier) ||
		len(oidfIdentifiers) != 2 {
		log.Fatalf("unexpected identifiers in issued cert: %v", oidfIdentifiers)
	}

	fmt.Printf("Identifiers in end entity cert: %s, %s\n", oidfIdentifiers[0], oidfIdentifiers[1])
}
