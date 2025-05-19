package test

import (
	"fmt"
	"net"
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

	// Bind any available port for Pebble
	pebbleListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to bind port: %s", err)
	}
	pebbleAddr, err := net.ResolveTCPAddr(pebbleListener.Addr().Network(), pebbleListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to resolve TCP address: %s", err)
	}
	issuer := mustEntity(
		t,
		&oidfClient,
		"issuer",
		// extraMetadata
		map[string]any{
			oidf01.ACMEIssuerEntityType: oidf01.ACMEIssuerMetadata{
				Directory: fmt.Sprintf("https://0.0.0.0:%d/dir", pebbleAddr.Port),
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
	pebbleFunc, err := setupPebble(t, pebbleListener, issuer.Endpoints)
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

	validateIdentifiers(t, certificates.Certificate, []string{
		requestor.FedEntity.FederationEntity.EntityID,
		otherLeaf.FedEntity.FederationEntity.EntityID,
	})
}
