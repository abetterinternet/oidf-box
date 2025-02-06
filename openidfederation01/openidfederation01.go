package openidfederation01

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/tgeoghegan/oidf-box/entity"
)

// ChallengeResponse is the payload POSTed to an ACME challenge for an openid-federation-01 challenge.
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.6
type ChallengeResponse struct {
	// Sig is the signature over the challenge token.
	// TODO: This could be jose.JSONWebSignature and we would handle the CompactSerialize
	Sig string `json:"sig"`
	// TrustChain (optional) is the chain of OIDF entity statements the issuer can use to validate
	// trust in the requestor.
	// TODO(timg): this isn't used yet, and I think it'll become something more rich than []string
	TrustChain []string `json:"trust_chain,omitempty"`
}

// EntityOID is id-on-OpenIdFederationEntityId, the ASN.1 Object Identifier for OpenID Federation
// Entities.
// The acme-openid draft has chosen the id-on arc, but not a specific value yet, so for now we use
// 99.
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.6.1
var EntityOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 99}

// SubjectAlternativeNameOID is id-ce-subjectAltName, the ASN.1 Object Identifier for a Subject
// Alternative Name extension.
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
var SubjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

// otherName represents an otherName SAN per RFC 5280.
type otherName struct {
	TypeID asn1.ObjectIdentifier
	// This is tagged 0 per RFC 5280's definition of OtherName
	Value string `asn1:"utf8,tag:0,explicit"`
}

type generalNames struct {
	// This is tagged 0 per RFC 5280's definition of GeneralName
	OtherName otherName `asn1:"tag:0"`
}

// GenerateCSRWithEntityIdentifier constructs a CSR with the provided identifier as an otherName SAN
// per the acme-openid draft.
func GenerateCSRWithEntityIdentifier(privateKey crypto.PrivateKey, identifier entity.Identifier) ([]byte, error) {
	// This is a little surprising: the value of a PKIX extension is an OCTET STRING consisting of
	// the ASN.1 encoded extension, so we have to marshal this *and then* stick it in pkix.Extension
	generalName, err := asn1.Marshal(generalNames{
		OtherName: otherName{
			TypeID: EntityOID,
			Value:  identifier.String(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GeneralName to ASN.1: %w", err)
	}

	template := x509.CertificateRequest{
		// No common name per acme-openid draft
		// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5.1
		ExtraExtensions: []pkix.Extension{{
			// OID for SANs https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
			Id:    SubjectAlternativeNameOID,
			Value: generalName,
			// Per RFC 5280, if the Common Name is absent, the SAN extension MUST be critical
			Critical: true,
		}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)

	// Get high on our own supply -- check if we think the CSR we just made is OK
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("CSR invalid: %w", err)
	}

	parsedIdentifier, err := EntityIdentifierFromCSR(parsedCSR)
	if err != nil {
		return nil, fmt.Errorf("CSR identifier invalid: %w", err)
	} else {
		if !parsedIdentifier.Equals(&identifier) {
			return nil, fmt.Errorf("Identifier mangled during round trip: %s -> %s", identifier.String(), parsedIdentifier.String())
		}
	}

	return csr, err
}

// EntityIdentifierFromCSR validates that the CSR conforms to the acme-openid draft and returns the
// OpenID Federation entity identifier therein.
func EntityIdentifierFromCSR(csr *x509.CertificateRequest) (*entity.Identifier, error) {
	if csr.Subject.String() != "" {
		// TODO(timg): there must be a better way to check that a pkix.Name is empty/zero
		return nil, fmt.Errorf("CSR contains subject")
	}

	var identifier *entity.Identifier
	for _, extension := range csr.Extensions {
		// Ignore extensions that aren't SANs
		if !extension.Id.Equal(SubjectAlternativeNameOID) {
			continue
		}

		if identifier != nil {
			return nil, fmt.Errorf("CSR contains multiple SANs")
		}

		if !extension.Critical {
			return nil, fmt.Errorf("SAN extension MUST be critical")
		}

		var names generalNames
		if _, err := asn1.Unmarshal(extension.Value, &names); err != nil {
			return nil, fmt.Errorf("failed to parse general names: %w", err)
		}

		if !names.OtherName.TypeID.Equal(EntityOID) {
			return nil, fmt.Errorf("otherName has wrong object identifier for OpenID Federation entity")
		}

		localIdentifier, err := entity.NewIdentifier(names.OtherName.Value)
		if err != nil {
			return nil, fmt.Errorf("")
		}

		identifier = &localIdentifier
	}

	if identifier == nil {
		return nil, fmt.Errorf("found no acceptable SAN extensions in CSR")
	}

	return identifier, nil
}
