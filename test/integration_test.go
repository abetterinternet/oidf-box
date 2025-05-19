package test

import (
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"

	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

// TestIssuanceMultipleNames tests issuance where:
//
// - two identifiers are in the cert
// - the challenge solver does not include a trust chain in its challenge response
func TestIssuanceMultipleNames(t *testing.T) {
	federation := mustSimpleFederation(t, ACMERequestorOptions{}, nil)
	defer federation.CleanUp()

	otherLeaf := mustEntity(
		t,
		EntityConfiguration{
			OIDFClient:    federation.OIDFClient,
			Label:         "other-leaf",
			ACMERequestor: &ACMERequestorOptions{},
			Superiors:     []*TestEntity{federation.Intermediate},
		},
	)
	defer otherLeaf.CleanUp()

	go federation.PebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  federation.Requestor.Endpoints,
		IssuerIdentifier: federation.Issuer.FedEntity.FederationEntity.EntityID,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			federation.Requestor.ChallengeSolver,
			otherLeaf.ChallengeSolver,
		},
	})

	// It's kinda goofy to have multiple OpenID Federation identifiers in a single ACME order,
	// because what does it mean for a single key in the X.509 realm to be valid for both OIDF
	// entities? But we want to ensure this is possible in the ACME extension.
	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{
				Type:  "openid-federation",
				Value: federation.Requestor.FedEntity.FederationEntity.EntityID,
			},
			{Type: "openid-federation", Value: otherLeaf.FedEntity.FederationEntity.EntityID},
		},
		Bundle: true,
	}

	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		t.Fatal(err)
	}

	validateIdentifiers(t, certificates.Certificate, []string{
		federation.Requestor.FedEntity.FederationEntity.EntityID,
		otherLeaf.FedEntity.FederationEntity.EntityID,
	})
}

// TestIssuancePresentingTrustChain tests issuance where:
//
// - A single identifier is in the cert
// - The solver does provide a trust chain in its response
func TestIssuancePresentingTrustChain(t *testing.T) {
	federation := mustSimpleFederation(t,
		ACMERequestorOptions{
			PresentTrustChain: true,
		},
		// Disable the issuer's resolve endpoint so that trust can only be established by verifying
		// the trust chain in the ACME challenge response from the requestor.
		[]string{"resolve"},
	)
	defer federation.CleanUp()

	go federation.PebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  federation.Requestor.Endpoints,
		IssuerIdentifier: federation.Issuer.FedEntity.FederationEntity.EntityID,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			federation.Requestor.ChallengeSolver,
		},
	})

	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{
				Type:  "openid-federation",
				Value: federation.Requestor.FedEntity.FederationEntity.EntityID,
			},
		},
		Bundle: true,
	}

	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		t.Fatal(err)
	}

	validateIdentifiers(t, certificates.Certificate, []string{
		federation.Requestor.FedEntity.FederationEntity.EntityID,
	})
}

// TestRenew tests renewing an issued certificate
func TestRewew(t *testing.T) {
	// Obtain a new certificate
	federation := mustSimpleFederation(t,
		ACMERequestorOptions{
			PresentTrustChain: true,
		},
		// Disable the issuer's resolve endpoint so that trust can only be established by verifying
		// the trust chain in the ACME challenge response from the requestor.
		[]string{"resolve"},
	)
	defer federation.CleanUp()

	go federation.PebbleFunc()

	legoClient := setupLego(t, LegoConfig{
		RequestorClient:  federation.Requestor.Endpoints,
		IssuerIdentifier: federation.Issuer.FedEntity.FederationEntity.EntityID,
		ChallengeSolvers: []*oidf01.ChallengeSolver{
			federation.Requestor.ChallengeSolver,
		},
	})

	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{
				Type:  "openid-federation",
				Value: federation.Requestor.FedEntity.FederationEntity.EntityID,
			},
		},
		Bundle: true,
	}

	certificateResource, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		t.Fatal(err)
	}

	renewedCertificate, err := legoClient.Certificate.RenewWithOptions(
		*certificateResource,
		&certificate.RenewOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	validateIdentifiers(t, renewedCertificate.Certificate, []string{
		federation.Requestor.FedEntity.FederationEntity.EntityID,
	})
}
