package openidfederation01

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"testing"
)

func TestCertificateRequest(t *testing.T) {
	identifier := "https://example.com"
	identifier2 := "https://example.com:8080"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err.Error())
	}

	csr, err := GenerateCSRWithEntityIdentifiers(key, []string{identifier, identifier2})
	if err != nil {
		t.Fatalf("failed to generate CSR: %s", err.Error())
	}

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("CSR invalid: %s", err.Error())
	}

	parsedIdentifiers, err := EntityIdentifiersFromCSR(parsedCSR)
	if err != nil {
		t.Fatalf("CSR identifier invalid: %s", err)
	}

	if !slices.Contains(parsedIdentifiers, identifier) {
		t.Errorf("first identifier missing from parsed identifiers")
	}

	if !slices.Contains(parsedIdentifiers, identifier2) {
		t.Errorf("second identifier missing from parsed identifiers")
	}

	if len(parsedIdentifiers) != 2 {
		t.Errorf("unexpected identifiers list %+v", parsedIdentifiers)
	}
}
