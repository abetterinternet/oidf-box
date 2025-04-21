package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/openidfederation01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/tgeoghegan/oidf-box/entity"
)

// DemoUser implements registration.User
type DemoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *DemoUser) GetEmail() string {
	return u.Email
}
func (u DemoUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *DemoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	trustAnchors := []string{"http://localhost:8001"}
	// Set up a chain of OIDF entities to act as a trust anchor (trusted by all entities) and an
	// intermediate
	// TODO(timg): ports should be configurable
	trustAnchor, err := entity.NewAndServe("http://localhost:8001", entity.EntityOptions{})
	if err != nil {
		log.Fatalf("failed to construct trust anchor: %s", err)
	}
	defer trustAnchor.CleanUp()

	intermediate, err := entity.NewAndServe("http://localhost:8002", entity.EntityOptions{
		TrustAnchors: trustAnchors,
	})
	if err != nil {
		log.Fatalf("failed to construct intermediate: %s", err)
	}
	defer intermediate.CleanUp()

	oidfClient := entity.NewOIDFClient()
	trustAnchorClient, err := oidfClient.NewFederationEndpoints(trustAnchor.Identifier)
	if err != nil {
		log.Fatalf("failed to create API client: %s", err)
	}

	// Subordinate intermediate to the trust anchor
	if err := trustAnchorClient.AddSubordinates([]entity.Identifier{intermediate.Identifier}); err != nil {
		log.Fatalf("failed to subordinate intermediate: %s", err)
	}
	intermediate.AddSuperior(trustAnchor.Identifier)

	intermediateClient, err := oidfClient.NewFederationEndpoints(intermediate.Identifier)
	if err != nil {
		log.Fatalf("failed to create API client for intermediate: %s", err)
	}

	// Create entity for the issuer
	issuer, err := entity.NewAndServe("http://localhost:8004", entity.EntityOptions{
		TrustAnchors: trustAnchors,
		ACMEIssuer: &entity.ACMEIssuerOptions{
			// Corresponds to pebble/test/config/pebble-config.json
			// TODO(timg) this should be configurable
			DirectoryURL: "https://0.0.0.0:14000/dir",
		},
	})
	if err != nil {
		log.Fatalf("failed to construct issuer: %s", err)
	}
	defer issuer.CleanUp()

	// Create entity for the requestor
	requestor, err := entity.NewAndServe("http://localhost:8003", entity.EntityOptions{
		TrustAnchors:  trustAnchors,
		ACMERequestor: &entity.ACMERequestorOptions{},
	})
	if err != nil {
		log.Fatalf("failed to construct reqestor: %s", err)
	}
	defer requestor.CleanUp()
	requestorClient, err := oidfClient.NewFederationEndpoints(requestor.Identifier)
	if err != nil {
		log.Fatalf("failed to create OIDF client: %s", err)
	}

	// Create another entity so that the requestor can put two names in its CSR
	otherLeafEntity, err := entity.NewAndServe("http://localhost:8005", entity.EntityOptions{
		TrustAnchors:  trustAnchors,
		ACMERequestor: &entity.ACMERequestorOptions{},
	})
	if err != nil {
		log.Fatalf("failed to construct other leaf entity")
	}
	defer otherLeafEntity.CleanUp()
	otherLeafClient, err := oidfClient.NewFederationEndpoints(otherLeafEntity.Identifier)
	if err != nil {
		log.Fatalf("failed to create OIDF client: %s", err)
	}

	// Subordinate the issuer, requestor and other leaf entity to the intermediate
	if err := intermediateClient.AddSubordinates([]entity.Identifier{
		issuer.Identifier,
		requestor.Identifier,
		otherLeafEntity.Identifier,
	}); err != nil {
		log.Fatalf("failed to subordinate issuer: %s", err)
	}
	issuer.AddSuperior(intermediate.Identifier)
	requestor.AddSuperior(intermediate.Identifier)
	otherLeafEntity.AddSuperior(intermediate.Identifier)

	log.Printf("serving OpenID Federation endpoints for entities:\n\ttrust anchor: %s\n\tintermediate: %s\n\tissuer: %s\n\trequestor: %s\n\tother leaf: %s\n\t\n",
		trustAnchor.Identifier.String(), intermediate.Identifier.String(), issuer.Identifier.String(), requestor.Identifier.String(), otherLeafEntity.Identifier.String())

	// acme-openid suggests doing discovery to find an entity in the federation with entity type
	// acme_issuer. In this example, we'll just assume we've been provided with the issuer's entity
	// identifier and discover the ACME API through the metadata. We'll eat least verify that we
	// trust the issuer entity, though.
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.2
	trustChain, err := requestorClient.IsTrusted(issuer.Identifier)
	if err != nil {
		log.Fatalf("failed to evaluate trust in ACME issuer: %s", err)
	}
	var issuerMetadata entity.ACMEIssuerMetadata
	if err := trustChain[0].FindMetadata(entity.ACMEIssuer, &issuerMetadata); err != nil {
		log.Fatalf("ACME issuer metadata missing: %s", err)
	}

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	demoUser := DemoUser{
		Email: "you@example.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&demoUser)

	config.CADirURL = issuerMetadata.Directory
	config.Certificate.KeyType = certcrypto.RSA2048

	// Disable TLS verification as Pebble's cert is self-signed
	if defaultTransport, ok := config.HTTPClient.Transport.(*http.Transport); ok {
		// Not sure why we do this clone business instead of just mutating
		// defaultTransport but this is what Lego CLI does
		tr := defaultTransport.Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		config.HTTPClient.Transport = tr
	} else {
		log.Fatal("could not get default HTTP transport")
	}

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Wire up the requestor and the other leaf as challenge solvers
	if err = client.Challenge.SetOpenIDFederation01Solver(openidfederation01.Solver{
		Entities: []*entity.FederationEndpoints{requestorClient, otherLeafClient},
	}); err != nil {
		log.Fatal(err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	demoUser.Registration = reg

	// It's kinda goofy to have multiple OpenID Federation identifiers in a single ACME order,
	// because what does it mean for a single key in the X.509 realm to be valid for both OIDF
	// entities? But we want to ensure this is possible in the ACME extension.
	identifiers := []acme.Identifier{
		{Type: "openid-federation", Value: requestor.Identifier.String()},
		{Type: "openid-federation", Value: otherLeafEntity.Identifier.String()},
	}
	log.Printf("obtaining cert for 'domains' %+v", identifiers)

	request := certificate.ObtainRequest{
		Identifiers: identifiers,
		Bundle:      true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("PEM certificate:\n%s", string(certificates.Certificate))
}
