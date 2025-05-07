package test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
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

	"github.com/tgeoghegan/oidf-box/oidfclient"
	oidf01 "github.com/tgeoghegan/oidf-box/openidfederation01"
)

// DemoUser implements registration.User
type DemoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func newDemoUser(t *testing.T) DemoUser {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return DemoUser{
		Email: "you@example.com",
		key:   privateKey,
	}
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

type TestEntity struct {
	Label              string
	FedEntity          *fedentities.FedEntity
	SubordinateStorage storage.SubordinateStorageBackend
	Endpoints          *oidfclient.FederationEndpoints
	ChallengeSolver    *oidf01.ChallengeSolver

	// listener may be a bound port on which requests for OpenID Federation API (i.e. entity
	// configurations or other federation endpoints) are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

func mustEntity(
	t *testing.T,
	oidfClient *oidfclient.HTTPClient,
	label string,
	extraMetadata map[string]any,
	acmeRequestor bool,
	superiors []*TestEntity,
) *TestEntity {
	authorityHints := []string{}
	for _, superior := range superiors {
		authorityHints = append(authorityHints, superior.FedEntity.FederationEntity.EntityID)
	}

	// Bind any available port, and then construct an entity ID with that port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to bind port: %s", err)
	}
	addr, err := net.ResolveTCPAddr(listener.Addr().Network(), listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to resolve TCP address: %s", err)
	}

	entityID := fmt.Sprintf("http://localhost:%d", addr.Port)

	subordinateStorage, trustMarkStorage := mustEntityStorage(t, label)

	var challengeSolver *oidf01.ChallengeSolver
	if acmeRequestor {
		challengeSolver, err = oidf01.NewSolver(entityID)
		if err != nil {
			t.Fatalf("failed to setup ACME challenge solver: %s", err)
		}

		if extraMetadata == nil {
			extraMetadata = make(map[string]any)
		}

		extraMetadata[oidf01.ACMERequestorEntityType] = oidf01.ACMERequestorMetadata{
			ChallengeSigningKeys: challengeSolver.ChallengeSigningPublicKeys(),
		}
	}

	entity, err := fedentities.NewFedEntity(
		entityID,
		authorityHints,
		&oidf.Metadata{
			// Provide no Federation entity metadata. We'll wire up federation endpoints and
			// handlers later.
			Extra: extraMetadata,
		},
		mustFederationEntitySigningKey(t),
		jwa.ES256(),
		0, // Unsure what configuration lifetime does
		fedentities.SubordinateStatementsConfig{
			SubordinateStatementLifetime: 3600, // 1 hour validity
		},
	)
	if err != nil {
		t.Fatalf("failed to instantiate %s: %s", label, err)
	}
	entity.AddFetchEndpoint(fedentities.EndpointConf{Path: "/fetch"}, subordinateStorage)
	entity.AddSubordinateListingEndpoint(
		fedentities.EndpointConf{Path: "/list"}, subordinateStorage, trustMarkStorage)
	entity.AddResolveEndpoint(fedentities.EndpointConf{Path: "/resolve"})

	testEntity := TestEntity{
		FedEntity:          entity,
		SubordinateStorage: subordinateStorage,
		ChallengeSolver:    challengeSolver,
		listener:           listener,
		done:               make(chan struct{}),
	}

	for _, superior := range superiors {
		superior.AddSubordinate(&testEntity)
	}

	go func() {
		t.Logf("serve entity '%s' at %s", entityID, listener.Addr().String())
		if err := http.Serve(testEntity.listener, entity.HttpHandlerFunc()); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			t.Log(err)
		}

		testEntity.done <- struct{}{}
	}()

	endpoints, err := oidfClient.NewFederationEndpoints(entityID)
	if err != nil {
		t.Fatalf("failed to create Federation endpoints client: %s", err)
	}

	testEntity.Endpoints = endpoints

	return &testEntity
}

func (e *TestEntity) CleanUp() {
	if e.listener == nil {
		return
	}

	e.listener.Close()

	<-e.done
}

func (e *TestEntity) AddSubordinate(sub *TestEntity) {
	e.SubordinateStorage.Write(sub.FedEntity.FederationEntity.EntityID, storage.SubordinateInfo{
		JWKS:     sub.FedEntity.JWKS(),
		EntityID: sub.FedEntity.FederationEntity.EntityID,
		Metadata: sub.FedEntity.Metadata,
	})
}

func mustFederationEntitySigningKey(t *testing.T) *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func mustEntityStorage(t *testing.T, entityLabel string) (storage.SubordinateStorageBackend, storage.TrustMarkedEntitiesStorageBackend) {
	backendStoragePath, err := os.MkdirTemp("", fmt.Sprintf("subordinate-storage-%s-", entityLabel))
	if err != nil {
		t.Fatalf("failed to create temp storage: %s", err)
	}
	storageBackend := storage.NewFileStorage(backendStoragePath)

	return storageBackend.SubordinateStorage(), storageBackend.TrustMarkedEntitiesStorage()
}

func setupPebble(t *testing.T, issuer *oidfclient.FederationEndpoints) (func(), error) {
	// Log to stdout
	logger := log.New(TestLogWriter{t}, "Pebble ", log.LstdFlags)
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
			"certs/localhost/cert.pem",
			"certs/localhost/key.pem",
			muxHandler,
		)
		if err != nil {
			t.Fatalf("calling ListenAndServeTLS(): %s", err)
		}
	}, nil
}

type LegoConfig struct {
	RequestorClient  *oidfclient.FederationEndpoints
	IssuerIdentifier string
	ChallengeSolvers []*oidf01.ChallengeSolver
}

func setupLego(t *testing.T, config LegoConfig) *lego.Client {
	// acme-openid suggests doing discovery to find an entity in the federation with entity type
	// acme_issuer. In this example, we'll just assume we've been provided with the issuer's entity
	// identifier and discover the ACME API through the metadata. We'll eat least verify that the
	// requestor trusts the issuer, though.
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.2
	resolveResponse, err := config.RequestorClient.Resolve(
		config.IssuerIdentifier,
		config.RequestorClient.Entity.AuthorityHints,
		[]string{oidf01.ACMEIssuerEntityType},
	)
	if err != nil {
		t.Fatalf("failed to evaluate trust in ACME issuer: %s", err)
	}

	var acmeIssuerMetadata oidf01.ACMEIssuerMetadata
	if err := resolveResponse.Metadata.FindEntityMetadata(
		oidf01.ACMEIssuerEntityType,
		&acmeIssuerMetadata,
	); err != nil {
		t.Fatalf("no metadata for entity type '%s' in resolve response: %s", oidf01.ACMEIssuerEntityType, err)
	}

	demoUser := newDemoUser(t)
	legoConfig := lego.NewConfig(&demoUser)

	legoConfig.CADirURL = acmeIssuerMetadata.Directory
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// Disable TLS verification as Pebble's cert is self-signed
	if defaultTransport, ok := legoConfig.HTTPClient.Transport.(*http.Transport); ok {
		// Not sure why we do this clone business instead of just mutating
		// defaultTransport but this is what Lego CLI does
		tr := defaultTransport.Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		legoConfig.HTTPClient.Transport = tr
	} else {
		t.Fatal("could not get default HTTP transport")
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Wire up the requestor and the other leaf as challenge solvers
	if err := client.Challenge.SetOpenIDFederation01Solver(
		oidf01challenge.Solver{Entities: config.ChallengeSolvers},
	); err != nil {
		t.Fatal(err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatal(err)
	}
	demoUser.Registration = reg

	return client
}

// TestLogWriter is an io.Writer that writes to the testing.T's log.
type TestLogWriter struct {
	t *testing.T
}

// Write implements io.Writer.
func (w TestLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))

	return 0, nil
}
