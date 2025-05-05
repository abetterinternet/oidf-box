package openidfederation01

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"

	"github.com/go-jose/go-jose/v4"

	"github.com/tgeoghegan/oidf-box/errors"
)

const (
	// Entity type identifiers for ACME OIDF.
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html
	ACMERequestorEntityType = "acme_requestor"
	ACMEIssuerEntityType    = "acme_issuer"
)

// ACMEIssuerMetadata describes an ACME issuer entity in an OpenID Federation
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.4.1
type ACMEIssuerMetadata struct {
	// The current draft requires that the entire ACME directory appear here, but I argue in the
	// issue below that it makes more sense to put the directory URI. That's also easier to
	// implement.
	// Ideally this would be a url.URL but serializing url.URL sucks!
	// https://github.com/peppelinux/draft-demarco-acme-openid-federation/issues/60
	Directory string `json:"directory"`
}

// ACMERequestorMetadata
// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.4.2
type ACMERequestorMetadata struct {
	ChallengeSigningKeys *jose.JSONWebKeySet `json:"jwks"`
}

// signatureKeyID parses the provided signature and returns the key ID from its JWS header, as well
// as the parsed JWS.
func signatureKeyID(signature string, expectedType string) (*string, *jose.JSONWebSignature, error) {
	// The JWS header indicates what algorithm it's signed with, but jose requires us to provide a
	// list of acceptable signing algorithms.
	// TODO(timg): For now, we'll allow a variety of RSA PKCS1.5 and ECDSA algorithms but this
	// should be configurable somehow.
	jws, err := jose.ParseSigned(signature, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512,
	})
	if err != nil {
		return nil, nil, errors.Errorf("failed to parse JWS signature: %w", err)
	}

	if len(jws.Signatures) > 1 {
		return nil, nil, errors.Errorf("unexpected multi-signature JWS")
	}

	headerType, ok := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType]
	if !ok || headerType != expectedType {
		return nil, nil, errors.Errorf("wrong or no type in JWS header: %+v", jws.Signatures[0])
	}

	if jws.Signatures[0].Header.KeyID == "" {
		return nil, nil, errors.Errorf("JWS header must contain kid")
	}

	return &jws.Signatures[0].Header.KeyID, jws, nil
}

// VerifyChallenge verifies if the signedChallenge is a valid JWS over the provided token, using
// the challenge signing keys in the ACME requestor metadata.
func (m *ACMERequestorMetadata) VerifyChallenge(signedChallenge string, token string) error {
	kid, jws, err := signatureKeyID(signedChallenge, SignedChallengeHeaderType)
	if err != nil {
		return err
	}

	verificationKeys := m.ChallengeSigningKeys.Key(*kid)
	if len(verificationKeys) != 1 {
		return errors.Errorf("found no or multiple keys in JWKS matching header kid %s", *kid)
	}

	challenge, err := jws.Verify(verificationKeys[0])
	if err != nil {
		return errors.Errorf("failed to validate challenge signature: %w", err)
	}

	if string(challenge) != token {
		return errors.Errorf("requestor challenge response signed over wrong token: %s", challenge)
	}

	return nil
}

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

// otherName represents an OtherName SAN per RFC 5280.
type otherName struct {
	TypeID asn1.ObjectIdentifier
	// Value is the value of the other name. This is explicitly tagged 0 per RFC 5280's definition
	// of OtherName
	Value string `asn1:"utf8,tag:0,explicit"`
}

// GenerateCSRWithEntityIdentifiers constructs a CSR with the provided identifiers as otherName SANs
// per the acme-openid draft.
func GenerateCSRWithEntityIdentifiers(privateKey crypto.PrivateKey, identifiers []string) ([]byte, error) {
	// We are constructing a PkixExtension whose value is a SubjectAltName. This is tricky to do
	// because encoding/asn1 does not have amazing support for ASN.1 CHOICE. RFC 5280 defines
	// (https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6):
	//
	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      <snip other possibilities we don't use> }
	//
	// OtherName ::= SEQUENCE {
	//      type-id    OBJECT IDENTIFIER,
	//      value      [0] EXPLICIT ANY DEFINED BY type-id }
	//
	// See https://luca.ntop.org/Teaching/Appunti/asn1.html for detailed discusion of explicit vs.
	// implicit tagging, tag numbers, and contents octets.
	var generalNamesContentOctets [][]byte
	for _, identifier := range identifiers {
		// First we construct an OtherName. The annotations we put on the Value field match RFC
		// 5280's definition of OtherName.value. Straightforward so far.
		otherName := otherName{
			TypeID: EntityOID,
			Value:  identifier,
		}

		// Now, we want to build a GeneralNames value from the list of OtherName. Ideally we'd
		// define a Go structure generalNames that contains []otherName and just asn1.Marshal that.
		//
		// If we naively marshal an otherName or []otherName value, then the tag used to encode each
		// value would be 16 for SEQUENCE. But look again at the ASN.1 definition of GeneralName: it
		// is *implicitly* tagged 0, which means the tag of the underlying value should be
		// *replaced*. Thus, we explicitly marshal each otherName with the desired tag.
		encodedOtherName, err := asn1.MarshalWithParams(otherName, "tag:0")
		if err != nil {
			return nil, errors.Errorf("failed to marshal otherName to ASN.1: %w", err)
		}

		// The content octets of a sequence is the concatenation of the DER encoding of each
		// element, so we simply append each encoded otherName. We'll join them into a single byte
		// slice later.
		generalNamesContentOctets = append(generalNamesContentOctets, encodedOtherName)
	}

	// PKIX extensions are opaque OCTET STRINGs so that implementations can gracefully ignore ones
	// they don't support.
	//
	// To make generalNamesContentOctets into a well-formed DER sequence, we need to prefix it with
	// appropriate tag and length bytes, for which we use asn1.RawValue.
	joined := bytes.Join(generalNamesContentOctets, []byte{})
	marshaledExtension, err := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal, // Sequences are in the universal class
		IsCompound: true,                // Sequences are compound
		Bytes:      joined,
	})
	if err != nil {
		return nil, errors.Errorf("failed to marshal raw values into PKIX extension: %w", err)
	}

	template := x509.CertificateRequest{
		// No common name per acme-openid draft
		// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#section-6.5.1
		ExtraExtensions: []pkix.Extension{{
			// OID for SANs https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
			Id:    SubjectAlternativeNameOID,
			Value: marshaledExtension,
			// Per RFC 5280, if the Common Name is absent, the SAN extension MUST be critical
			Critical: true,
		}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, errors.Errorf("failed to generate CSR: %w", err)
	}

	// Check if we think the CSR we just made is OK
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, errors.Errorf("CSR invalid: %w", err)
	}

	parsedIdentifiers, err := EntityIdentifiersFromCSR(parsedCSR)
	if err != nil {
		return nil, errors.Errorf("CSR identifier invalid: %w", err)
	} else {
		for _, expectedIdentifier := range identifiers {
			if !slices.Contains(parsedIdentifiers, expectedIdentifier) {
				return nil, errors.Errorf(
					"Identifier missing after round trip: %s -> %v",
					expectedIdentifier, parsedIdentifiers,
				)
			}
		}
		if len(parsedIdentifiers) != len(identifiers) {
			return nil, errors.Errorf("unexpected identifier list in CSR: %v", parsedIdentifiers)
		}
	}

	return csr, err
}

// EntityIdentifiersFromCSR validates that the CSR conforms to the acme-openid draft and returns the
// OpenID Federation entity identifiers therein.
func EntityIdentifiersFromCSR(csr *x509.CertificateRequest) ([]string, error) {
	return entityIdentifiersFromExtensions(csr.Subject, csr.Extensions)
}

// EntityIdentifiersFromCertificate validates that the certificate conforms to the acme-openid draft
// and returns the OpenID Federation entity identifiers therein.
func EntityIdentifiersFromCertificate(cert *x509.Certificate) ([]string, error) {
	return entityIdentifiersFromExtensions(cert.Subject, cert.Extensions)
}

func entityIdentifiersFromExtensions(subject pkix.Name, extensions []pkix.Extension) ([]string, error) {
	if subject.String() != "" {
		// TODO(timg): there must be a better way to check that a pkix.Name is empty/zero
		return []string{}, errors.Errorf("Subject is present")
	}

	sawSANExtension := false
	identifiers := []string{}
	for _, extension := range extensions {
		// Ignore extensions that aren't SANs
		if !extension.Id.Equal(SubjectAlternativeNameOID) {
			continue
		}

		if sawSANExtension {
			return nil, errors.Errorf("multiple SAN extensions found")
		}

		sawSANExtension = true

		if !extension.Critical {
			return nil, errors.Errorf("SAN extension MUST be critical")
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(extension.Value, &rawValue); err != nil {
			return nil, errors.Errorf("failed to parse SAN into raw value: %w", err)
		}

		if rawValue.Tag != asn1.TagSequence || rawValue.IsCompound != true || rawValue.Class != asn1.ClassUniversal {
			return nil, errors.Errorf("unexpected raw value in PKIX extension")
		}

		rest := rawValue.Bytes
		for len(rest) > 0 {
			var name otherName
			var err error
			rest, err = asn1.UnmarshalWithParams(rest, &name, "tag:0")
			if err != nil {
				return nil, errors.Errorf("failed to decode otherName from extension: %w", err)
			}
			if !name.TypeID.Equal(EntityOID) {
				return nil, errors.Errorf("otherName has wrong object identifier for OpenID Federation entity")
			}

			identifiers = append(identifiers, name.Value)
		}
	}

	if len(identifiers) == 0 {
		return []string{}, errors.Errorf("found no acceptable SAN extensions")
	}

	return identifiers, nil
}
