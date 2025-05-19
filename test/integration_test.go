package test

import (
	"fmt"
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"

	"github.com/tgeoghegan/oidf-box/oidfclient"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

func TestIssuanceMultipleNames(t *testing.T) {
	oidfClient := oidfclient.NewOIDFClient()
	trustAnchor := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "trust-anchor",
			// trust anchor has no authority hints
			Superiors: nil,
		},
	)
	defer trustAnchor.CleanUp()
	intermediate := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "intermediate",
			Superiors:  []*TestEntity{trustAnchor},
		},
	)
	defer intermediate.CleanUp()

	// Bind any available port for Pebble
	pebbleListener, pebbleAddr := mustListener(t)
	issuer := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "issuer",
			ExtraMetadata: map[string]any{
				oidf01.ACMEIssuerEntityType: oidf01.ACMEIssuerMetadata{
					Directory: fmt.Sprintf("https://0.0.0.0:%d/dir", pebbleAddr.Port),
				},
			},
			Superiors: []*TestEntity{intermediate},
		},
	)
	defer issuer.CleanUp()
	requestor := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient:    &oidfClient,
			Label:         "requestor",
			ExtraMetadata: map[string]any{},
			ACMERequestor: &ACMERequestorOptions{},
			Superiors:     []*TestEntity{intermediate},
		},
	)
	defer requestor.CleanUp()
	otherLeaf := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient:    &oidfClient,
			Label:         "other-leaf",
			ACMERequestor: &ACMERequestorOptions{},
			Superiors:     []*TestEntity{intermediate},
		},
	)
	defer otherLeaf.CleanUp()

	// Setup Pebble and spawn a goroutine to run it
	pebbleFunc, err := setupPebble(t, pebbleListener, []*TestEntity{trustAnchor}, issuer.Endpoints)
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

func TestIssuancePresentingTrustChain(t *testing.T) {
	oidfClient := oidfclient.NewOIDFClient()
	trustAnchor := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "trust-anchor",
			// trust anchor has no authority hints
			Superiors: nil,
		},
	)
	defer trustAnchor.CleanUp()
	intermediate := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "intermediate",
			Superiors:  []*TestEntity{trustAnchor},
		},
	)
	defer intermediate.CleanUp()

	// Bind any available port for Pebble
	pebbleListener, pebbleAddr := mustListener(t)
	issuer := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient: &oidfClient,
			Label:      "issuer",
			ExtraMetadata: map[string]any{
				oidf01.ACMEIssuerEntityType: oidf01.ACMEIssuerMetadata{
					Directory: fmt.Sprintf("https://0.0.0.0:%d/dir", pebbleAddr.Port),
				},
			},
			Superiors: []*TestEntity{intermediate},
			// Disable the resolve endpoint so that trust can only be established by verifying the
			// trust chain in the ACME challenge response from the requestor.
			DisabledEndpoints: []string{"resolve"},
		},
	)
	defer issuer.CleanUp()
	requestor := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient:    &oidfClient,
			Label:         "requestor",
			ExtraMetadata: map[string]any{},
			ACMERequestor: &ACMERequestorOptions{
				PresentTrustChain: true,
			},
			Superiors: []*TestEntity{intermediate},
		},
	)
	defer requestor.CleanUp()

	// Setup Pebble and spawn a goroutine to run it
	pebbleFunc, err := setupPebble(t, pebbleListener, []*TestEntity{trustAnchor}, issuer.Endpoints)
	if err != nil {
		t.Fatalf("failed to setup Pebble: %s", err)
	}

	go pebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  requestor.Endpoints,
		IssuerIdentifier: issuer.FedEntity.FederationEntity.EntityID,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			requestor.ChallengeSolver,
		},
	})

	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{Type: "openid-federation", Value: requestor.FedEntity.FederationEntity.EntityID},
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
	})
}
