package openidfederation01

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/tgeoghegan/oidf-box/entity"
)

func TestCertificateRequest(t *testing.T) {
	identifier, err := entity.NewIdentifier("https://example.com")
	if err != nil {
		t.Fatalf("failed to construct OIDF Identifier: %s", err.Error())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err.Error())
	}

	csr, err := GenerateCSRWithEntityIdentifier(key, identifier)
	if err != nil {
		t.Fatalf("failed to generate CSR: %s", err.Error())
	}

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("CSR invalid: %s", err.Error())
	}

	parsedIdentifier, err := EntityIdentifierFromCSR(parsedCSR)
	if err != nil {
		t.Fatalf("CSR identifier invalid: %s", err)
	}

	if !parsedIdentifier.Equals(&identifier) {
		t.Errorf(
			"identifier mangled during round trip: %s -> %s",
			identifier.String(), parsedIdentifier.String(),
		)
	}
}
