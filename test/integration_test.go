package test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"

	"github.com/tgeoghegan/oidf-box/oidfclient"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

func TestIssuance(t *testing.T) {
	oidfClient := oidfclient.NewOIDFClient()
	trustAnchor := mustEntity(
		t,
		&oidfClient,
		"trust-anchor",
		nil,   // extraMetadata
		false, // acmeRequestor
		nil,   // trust anchor has no authority hints
	)
	defer trustAnchor.CleanUp()
	intermediate := mustEntity(
		t,
		&oidfClient,
		"intermediate",
		nil,   // extraMetadata
		false, // acmeRequestor
		[]*TestEntity{trustAnchor},
	)
	defer intermediate.CleanUp()
	issuer := mustEntity(
		t,
		&oidfClient,
		"issuer",
		// extraMetadata
		map[string]any{
			oidf01.ACMEIssuerEntityType: oidf01.ACMEIssuerMetadata{
				// Corresponds to pebble/test/config/pebble-config.json
				// TODO(timg) this should be configurable
				Directory: "https://0.0.0.0:14000/dir",
			},
		},
		false, // acmeRequestor
		[]*TestEntity{intermediate},
	)
	defer issuer.CleanUp()
	requestor := mustEntity(
		t,
		&oidfClient,
		"requestor",
		nil,  // extraMetadata
		true, // acmeRequestor
		[]*TestEntity{intermediate},
	)
	defer requestor.CleanUp()
	otherLeaf := mustEntity(
		t,
		&oidfClient,
		"other-leaf",
		nil,  // extraMetadata
		true, // acmeRequestor
		[]*TestEntity{intermediate},
	)
	defer otherLeaf.CleanUp()

	// Setup Pebble and spawn a goroutine to run it
	pebbleFunc, err := setupPebble(t, issuer.Endpoints)
	if err != nil {
		t.Fatalf("failed to setup Pebble: %s", err)
	}

	go pebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  requestor.Endpoints,
		IssuerIdentifier: issuer.FedEntity.FederationEntity.EntityID,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			requestor.ChallengeSolver,
			otherLeaf.ChallengeSolver,
		},
	})

	// It's kinda goofy to have multiple OpenID Federation identifiers in a single ACME order,
	// because what does it mean for a single key in the X.509 realm to be valid for both OIDF
	// entities? But we want to ensure this is possible in the ACME extension.
	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{Type: "openid-federation", Value: requestor.FedEntity.FederationEntity.EntityID},
			{Type: "openid-federation", Value: otherLeaf.FedEntity.FederationEntity.EntityID},
		},
		Bundle: true,
	}
	t.Logf("obtaining cert for 'domains' %+v", request.Identifiers)
	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("PEM certificate:\n%s\n", string(certificates.Certificate))

	block, _ := pem.Decode(certificates.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("failed to parse PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse X.509 certificate: %s", err)
	}

	oidfIdentifiers, err := oidf01.EntityIdentifiersFromCertificate(cert)
	if err != nil {
		t.Fatalf("failed to extract OpenID Federation identifiers from certificate: %s", err)
	}

	if !slices.Contains(oidfIdentifiers, requestor.FedEntity.FederationEntity.EntityID) ||
		!slices.Contains(oidfIdentifiers, otherLeaf.FedEntity.FederationEntity.EntityID) ||
		len(oidfIdentifiers) != 2 {
		t.Fatalf("unexpected identifiers in issued cert: %v", oidfIdentifiers)
	}

	t.Logf("Identifiers in end entity cert: %s, %s\n", oidfIdentifiers[0], oidfIdentifiers[1])
}
