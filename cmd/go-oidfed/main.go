package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	oidf01challenge "github.com/go-acme/lego/v4/challenge/openidfederation01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	oidf "github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
	yaml "gopkg.in/yaml.v3"

	"github.com/tgeoghegan/oidf-box/entity"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
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

func makeEntity(label, port string, extraMetadata map[string]any, superiors []*fedentities.FedEntity) (*fedentities.FedEntity, storage.SubordinateStorageBackend) {
	authorityHints := []string{}
	for _, superior := range superiors {
		authorityHints = append(authorityHints, superior.FederationEntity.EntityID)
	}

	entityID := fmt.Sprintf("http://localhost:%s", port)

	subordinateStorage, trustMarkStorage := mustEntityStorage(label)

	entity, err := fedentities.NewFedEntity(
		entityID,
		authorityHints,
		&oidf.Metadata{
			// Provide no Federation entity metadata. We'll wire up federation endpoints and
			// handlers later.
			Extra: extraMetadata,
		},
		mustFederationEntitySigningKey(),
		jwa.ES256(),
		0, // Unsure what configuration lifetime does
		fedentities.SubordinateStatementsConfig{
			SubordinateStatementLifetime: 3600, // 1 hour validity
		},
	)
	if err != nil {
		log.Fatalf("failed to instantiate %s: %s", label, err)
	}
	entity.AddFetchEndpoint(fedentities.EndpointConf{Path: "/fetch"}, subordinateStorage)
	entity.AddSubordinateListingEndpoint(
		fedentities.EndpointConf{Path: "/list"}, subordinateStorage, trustMarkStorage)
	entity.AddResolveEndpoint(fedentities.EndpointConf{Path: "/resolve"})

	return entity, subordinateStorage
}

func main() {
	trustAnchor, trustAnchorSubordinateStorage := makeEntity(
		"trust-anchor", "8001",
		nil, // extraMetadata
		nil, // trust anchor has no authority hints
	)
	intermediate, intermediateSubordinateStorage := makeEntity(
		"intermediate", "8002",
		nil, // extraMetadata
		[]*fedentities.FedEntity{trustAnchor},
	)
	issuer, _ := makeEntity("issuer", "8003",
		// extraMetadata
		map[string]any{
			string(entity.ACMEIssuer): entity.ACMEIssuerMetadata{
				// Corresponds to pebble/test/config/pebble-config.json
				// TODO(timg) this should be configurable
				Directory: "https://0.0.0.0:14000/dir",
			},
		},
		[]*fedentities.FedEntity{intermediate},
	)

	certifiableKeys, err := entity.GenerateCertifiableKeys()
	if err != nil {
		log.Fatalf("failed to generate ACME challenge signing keys: %s", err)
	}
	// TODO: bind port 8006 and serve challenge signing there
	requestor, _ := makeEntity("requestor", "8004",
		// extraMetadata
		map[string]any{
			string(entity.ACMERequestor): entity.ACMERequestorMetadata{
				CertifiableKeys: certifiableKeys,
			},
			string(entity.ISRGExtensions): entity.DefaultISRGExtensionsEntityMetadata("http://localhost:8006"),
		},
		[]*fedentities.FedEntity{intermediate},
	)
	otherLeaf, _ := makeEntity("other-leaf", "8005",
		nil, // extraMetadata
		[]*fedentities.FedEntity{intermediate},
	)

	// Subordinate:
	// - the intermediate to the trust anchor
	// - the issuer, requestor and other leaf entity to the intermediate
	// n.b. this does _not_ use the HTTP enroll endpoint, but instead writes directly to the TA and
	// intermediate's subordinate storage.
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

	entities := map[string]struct {
		port       string
		identifier entity.Identifier
		entity     *fedentities.FedEntity
		endpoints  *entity.FederationEndpoints
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
	}

	oidfClient := entity.NewOIDFClient()
	for label, val := range entities {
		identifier, err := entity.NewIdentifier(fmt.Sprintf("http://localhost:%s", val.port))
		if err != nil {
			log.Fatalf("failed to create identifier: %s", err)
		}
		val.identifier = identifier
		client, err := oidfClient.NewFederationEndpoints(identifier)
		if err != nil {
			log.Fatalf("failed to create federation endpoints: %s", err)
		}
		val.endpoints = client

		subordinates, err := client.ListSubordinates([]entity.EntityTypeIdentifier{}, false)
		if err != nil {
			log.Fatalf("failed to list subordinates: %s", err)
		}

		log.Printf("subordinates for %s:\n", label)
		for _, sub := range subordinates {
			log.Printf("%s\n", sub.String())
			subordinateStatement, err := client.SubordinateStatement(sub)
			if err != nil {
				log.Fatalf("failed to get subordinate statement for '%s': %s", sub.String(), err)
			}

			log.Printf("%+v\n", subordinateStatement)
		}

		// Write map value back to map -- Go doesn't let you mutate map members while you iterate
		entities[label] = val
	}

	// Setup Pebble and spawn a goroutine to run it
	pebbleFunc, err := setupPebble(entities["issuer"].endpoints)
	if err != nil {
		log.Fatalf("failed to setup Pebble: %s", err)
	}

	go pebbleFunc()

	// acme-openid suggests doing discovery to find an entity in the federation with entity type
	// acme_issuer. In this example, we'll just assume we've been provided with the issuer's entity
	// identifier and discover the ACME API through the metadata. We'll eat least verify that the
	// requestor trusts the issuer, though.
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.2
	resolveResponse, err := entities["requestor"].endpoints.Resolve(
		entities["issuer"].identifier,
		entities["trust anchor"].identifier,
		[]entity.EntityTypeIdentifier{
			entity.FederationEntity,
			entity.ISRGExtensions,
			entity.ACMEIssuer,
		},
	)
	if err != nil {
		log.Fatalf("failed to evaluate trust in ACME issuer: %s", err)
	}

	var issuerMetadata entity.ACMEIssuerMetadata
	if err := resolveResponse.FindMetadata(entity.ACMEIssuer, &issuerMetadata); err != nil {
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
	if err = client.Challenge.SetOpenIDFederation01Solver(oidf01challenge.Solver{
		Entities: []*entity.FederationEndpoints{
			entities["requestor"].endpoints,
			entities["other leaf"].endpoints,
		},
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
	request := certificate.ObtainRequest{
		Identifiers: []acme.Identifier{
			{Type: "openid-federation", Value: requestor.FederationEntity.EntityID},
			{Type: "openid-federation", Value: otherLeaf.FederationEntity.EntityID},
		},
		Bundle: true,
	}
	log.Printf("obtaining cert for 'domains' %+v", request.Identifiers)
	certificates, err := client.Certificate.Obtain(request)
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
		!slices.Contains(oidfIdentifiers, entities["other-leaf"].identifier) ||
		len(oidfIdentifiers) != 2 {
		log.Fatalf("unexpected identifiers in issued cert: %v", oidfIdentifiers)
	}

	fmt.Printf("Identifiers in end entity cert: %s, %s\n",
		oidfIdentifiers[0].String(), oidfIdentifiers[1].String())
}

func mustFederationEntitySigningKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustEntityStorage(entityLabel string) (storage.SubordinateStorageBackend, storage.TrustMarkedEntitiesStorageBackend) {
	backendStoragePath, err := os.MkdirTemp("", fmt.Sprintf("subordinate-storage-%s-", entityLabel))
	if err != nil {
		log.Fatalf("failed to create temp storage: %s", err)
	}
	storageBackend := storage.NewFileStorage(backendStoragePath)

	return storageBackend.SubordinateStorage(), storageBackend.TrustMarkedEntitiesStorage()
}

// NoopEntityChecker allows any entity to be subordinated.
type NoopEntityChecker struct{}

// UnmarshalYAML implements fedentities.EntityChecker.
func (c NoopEntityChecker) UnmarshalYAML(value *yaml.Node) error {
	panic("unimplemented")
}

func (c NoopEntityChecker) Check(entityConfiguration *oidf.EntityStatement, entityTypes []string) (bool, int, *oidf.Error) {
	return true, 0, nil
}

func setupPebble(issuer *entity.FederationEndpoints) (func(), error) {
	// Log to stdout
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	logger.Printf("Starting Pebble ACME server")

	db := db.NewMemoryStore()
	ca := ca.New(
		logger,
		db,
		"", // OCSP responder URL
		0,  // alternate roots
		1,  // chain length
		map[string]ca.Profile{
			"default": {
				Description:    "The default profile",
				ValidityPeriod: 0, // Will be overridden by the CA's default
			},
		},
	)
	va := va.New(
		logger,
		5002,  // HTTP port
		5001,  // TLS port
		false, //strictMode
		"",    // resolverAddress
		issuer,
		db,
	)
	wfeImpl := wfe.New(
		logger,
		db,
		va,
		ca,
		false, // strictMode
		false, // externalAccountBindingRequired
		3,     // authz retry after
		5,     // order retry after
	)
	muxHandler := wfeImpl.Handler()

	return func() {
		listenAddress := "0.0.0.0:14000"
		logger.Printf("Listening on: %s\n", listenAddress)
		logger.Printf("ACME directory available at https://%s%s",
			listenAddress, wfe.DirectoryPath)
		err := http.ListenAndServeTLS(
			listenAddress,
			"test/certs/localhost/cert.pem",
			"test/certs/localhost/key.pem",
			muxHandler,
		)
		if err != nil {
			log.Fatalf("calling ListenAndServeTLS(): %s", err)
		}
	}, nil
}
