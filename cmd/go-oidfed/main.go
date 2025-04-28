package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/tgeoghegan/oidf-box/entity"
	oidf "github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
	yaml "gopkg.in/yaml.v3"
)

func makeEntity(label, port string, superiors []*fedentities.FedEntity) (*fedentities.FedEntity, storage.SubordinateStorageBackend) {
	authorityHints := []string{}
	for _, superior := range superiors {
		authorityHints = append(authorityHints, superior.FederationEntity.EntityID)
	}
	subordinateStorage, trustMarkStorage := mustEntityStorage(label)
	entity, err := fedentities.NewFedEntity(
		fmt.Sprintf("http://localhost:%s", port),
		authorityHints,
		nil, // Provide no metadata. We'll wire up federation endpoints and handlers later.
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
	entity.AddSubordinateListingEndpoint(fedentities.EndpointConf{Path: "/list"}, subordinateStorage, trustMarkStorage)

	return entity, subordinateStorage
}

func main() {
	trustAnchor, trustAnchorSubordinateStorage := makeEntity(
		"trust-anchor", "8001",
		nil, // trust anchor has no authority hints
	)
	intermediate, intermediateSubordinateStorage := makeEntity("intermediate", "8002", []*fedentities.FedEntity{trustAnchor})
	// TODO: add issuer metadata and challenge satisfaction
	issuer, _ := makeEntity("issuer", "8003", []*fedentities.FedEntity{intermediate})
	// TODO: add requestor metadata and...?
	requestor, _ := makeEntity("requestor", "8004", []*fedentities.FedEntity{intermediate})
	otherLeaf, _ := makeEntity("other-leaf", "8005", []*fedentities.FedEntity{intermediate})

	// Subordinate:
	// - the intermediate to the trust anchor
	// - the issuer, requestor and other leaf entity to the intermediate
	// n.b. this does _not_ use the HTTP enroll endpoint, but instead writes directly to the TA and
	// intermediate's subordinate storage.
	trustAnchorSubordinateStorage.Write(intermediate.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     intermediate.FederationEntity.JWKS(),
			EntityID: intermediate.FederationEntity.EntityID,
		})
	intermediateSubordinateStorage.Write(issuer.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     issuer.FederationEntity.JWKS(),
			EntityID: issuer.FederationEntity.EntityID,
		})
	intermediateSubordinateStorage.Write(requestor.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     requestor.FederationEntity.JWKS(),
			EntityID: requestor.FederationEntity.EntityID,
		})
	intermediateSubordinateStorage.Write(otherLeaf.FederationEntity.EntityID,
		storage.SubordinateInfo{
			JWKS:     otherLeaf.FederationEntity.JWKS(),
			EntityID: otherLeaf.FederationEntity.EntityID,
		})

	serveEntityForever := func(label string, port string, entity *fedentities.FedEntity) {
		log.Printf("Start serving %s on port %s", label, port)
		if err := http.ListenAndServe(fmt.Sprintf(":%s", port), entity.HttpHandlerFunc()); err != nil {
			log.Fatalf("failed to serve %s Fed endpoints: %s", label, err)
		}
	}

	entities := []struct {
		label  string
		port   string
		entity *fedentities.FedEntity
	}{
		{label: "trust anchor", port: "8001", entity: trustAnchor},
		{label: "intermediate", port: "8002", entity: intermediate},
		{label: "issuer", port: "8003", entity: issuer},
		{label: "requestor", port: "8004", entity: requestor},
		{label: "other leaf", port: "8005", entity: otherLeaf},
	}
	for _, val := range entities {
		go serveEntityForever(val.label, val.port, val.entity)
	}

	oidfClient := entity.NewOIDFClient()
	for _, val := range entities {
		identifier, err := entity.NewIdentifier(fmt.Sprintf("http://localhost:%s", val.port))
		if err != nil {
			log.Fatalf("failed to create identifier: %s", err)
		}
		client, err := oidfClient.NewFederationEndpoints(identifier)
		if err != nil {
			log.Fatalf("failed to create federation endpoints: %s", err)
		}

		subordinates, err := client.ListSubordinates([]entity.EntityTypeIdentifier{}, false)
		if err != nil {
			log.Fatalf("failed to list subordinates: %s", err)
		}

		log.Printf("subordinates for %s:\n", val.label)
		for _, sub := range subordinates {
			log.Printf("%s\n", sub.String())
			subordinateStatement, err := client.SubordinateStatement(sub)
			if err != nil {
				log.Fatalf("failed to get subordinate statement for '%s': %s", sub.String(), err)
			}

			log.Printf("%+v\n", subordinateStatement)
		}
	}

	// Loop forever and fed entities be
	for {
	}
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

// authority_hints:
//   - "https://trust-anchor.spid-cie.fedservice.lh/"
// metadata_policy_file: "/data/metadata-policy.json"
// signing_key_file: "/data/signing.key"
// organization_name: "GO oidc-fed Intermediate"
// data_location: "/data"
