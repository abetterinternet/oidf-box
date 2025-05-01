package openidfederation01

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/tgeoghegan/oidf-box/entity"
	"github.com/tgeoghegan/oidf-box/errors"
)

// ChallengeSolver solves ACME OpenIDFederation challenges over HTTP
type ChallengeSolver struct {
	// challengeSigningKeys is a set of keys that may be used to solve ACME challenges.
	challengeSigningKeys jose.JSONWebKeySet

	// listener may be a bound port on which requests for OpenID Federation API (i.e. entity
	// configurations or other federation endpoints) are listened to
	listener net.Listener
	// done is a channel sent on when the HTTP server is torn down
	done chan struct{}
}

// NewSolver generates keys and creates a ChallengeSolver.
func NewSolver() (*ChallengeSolver, error) {
	challengeSigningKeys, err := entity.GenerateACMEChallengeSigningKeys()
	if err != nil {
		return nil, err
	}

	return &ChallengeSolver{challengeSigningKeys: *challengeSigningKeys}, nil
}

func NewSolverAndServe(port string) (*ChallengeSolver, error) {
	solver, err := NewSolver()
	if err != nil {
		return nil, err
	}

	// Listen at whatever port is in the identifier, which may not be right
	solver.listener, err = net.Listen("tcp", net.JoinHostPort("", port))
	if err != nil {
		return nil, errors.Errorf("could not start HTTP server for OIDF EC: %w", err)
	}

	solver.done = make(chan struct{})

	go func() {
		mux := http.NewServeMux()

		mux.HandleFunc(entity.FederationSignChallengeEndpoint, func(w http.ResponseWriter, r *http.Request) {
			if err, status := solver.signChallengeHandler(w, r); err != nil {
				http.Error(w, err.Error(), status)
			}
		})

		httpServer := &http.Server{Handler: mux}

		// Once httpServer is shut down we don't want any lingering connections, so disable KeepAlives.
		httpServer.SetKeepAlivesEnabled(false)

		if err := httpServer.Serve(solver.listener); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			log.Println(err)
		}

		solver.done <- struct{}{}
	}()

	return solver, nil
}

// ChallengeSigningPublicKeys returns a JSONWebKeySet containing only the public portion of the
// solver's challenge signing keys.
func (s *ChallengeSolver) ChallengeSigningPublicKeys() *jose.JSONWebKeySet {
	publicKeys := entity.PublicJWKS(&s.challengeSigningKeys)
	return &publicKeys
}

// SignChallenge constructs a JWS containing a signature over token using one of the entity's
// acme_requestor keys.
// TODO: should/could move this over to openidfederation01 module
func (s *ChallengeSolver) SignChallenge(token string) (*jose.JSONWebSignature, error) {
	challengeSigner, err := jose.NewSigner(
		jose.SigningKey{
			// TODO: probably should validate that the Algorithm field is valid somehow
			Algorithm: jose.SignatureAlgorithm(s.challengeSigningKeys.Keys[0].Algorithm),
			Key:       s.challengeSigningKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{
				// kid is REQUIRED by acme-openid-fed, but it doesn't say anything about typ here. I
				// suspect we should set one to avoid token confusion.
				// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5-7
				jose.HeaderType: entity.SignedChallengeHeaderType,
				"kid":           s.challengeSigningKeys.Keys[0].KeyID,
			},
		},
	)
	if err != nil {
		return nil, errors.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := challengeSigner.Sign([]byte(token))
	if err != nil {
		return nil, errors.Errorf("Failed to sign challenge: %w", err)
	}

	return signed, nil
}

func (s *ChallengeSolver) signChallengeHandler(w http.ResponseWriter, r *http.Request) (error, int) {
	if r.Method != http.MethodPost {
		return errors.Errorf("only POST is allowed"), http.StatusMethodNotAllowed
	}

	challenge, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.Errorf("failed to read challenge from request body: %w", err),
			http.StatusInternalServerError
	}

	// Sign the token from the challenge and represent that as a compact JWS
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-openid-federation-challenge
	signedToken, err := s.SignChallenge(string(challenge))
	if err != nil {
		return errors.Errorf("failed to sign challenge: %w", err), http.StatusInternalServerError
	}

	compactSignedToken, err := signedToken.CompactSerialize()
	if err != nil {
		return errors.Errorf("failed to compact serialize JWS: %w", err),
			http.StatusInternalServerError
	}

	if _, err := w.Write([]byte(compactSignedToken)); err != nil {
		return err, http.StatusInternalServerError
	}

	return nil, http.StatusOK
}
