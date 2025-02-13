package main

import (
	"log"

	"github.com/tgeoghegan/oidf-box/entity"
)

func main() {
	// Set up a chain of OIDF entities to act as a trust anchor (trusted by all entities) and an
	// intermediate
	// TODO(timg): ports should be configurable
	trustAnchor, err := entity.NewAndServe("http://localhost:8001", entity.EntityOptions{})
	if err != nil {
		log.Fatalf("failed to construct trust anchor: %s", err)
	}
	defer trustAnchor.CleanUp()

	intermediate, err := entity.NewAndServe("http://localhost:8002", entity.EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		log.Fatalf("failed to construct intermediate: %s", err)
	}
	defer intermediate.CleanUp()

	// Subordinate intermediate to the trust anchor
	oidfClient := entity.NewOIDFClient()

	trustAnchorClient, err := oidfClient.NewFederationEndpoints(trustAnchor.Identifier)
	if err != nil {
		log.Fatalf("failed to create API client: %s", err)
	}
	if err := trustAnchorClient.AddSubordinates([]entity.Identifier{intermediate.Identifier}); err != nil {
		log.Fatalf("failed to subordinate intermediate: %s", err)
	}
	intermediate.AddSuperior(trustAnchor.Identifier)

	log.Print("serving OpenID Federation endpoints for entities")
	// Loop forever and serve OpenID Federation endpoints
	for {
	}
}
