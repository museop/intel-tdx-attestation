package tdxattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

const (
	syntheticQuoteVersion    = 4
	syntheticQuoteAttKeyType = 2
	syntheticQuoteTeeType    = 0x00000081
)

// SyntheticQuoteBundle contains a non-Intel, test-only quote and the matching
// trust material needed to verify its local cryptographic chain.
//
// It must never be treated as an Intel-attested quote. The generated PCK chain
// is rooted in a test CA, not the Intel SGX Provisioning Certification Root CA.
type SyntheticQuoteBundle struct {
	Quote       []byte
	RootCertPEM []byte
	PCKChainPEM []byte
}

// SyntheticRootBundle contains a synthetic test root CA certificate and the
// private key that signs synthetic quote PCK intermediates.
type SyntheticRootBundle struct {
	RootKeyPEM  []byte
	RootCertPEM []byte
}

// GenerateSyntheticQuote builds a minimal TDX-shaped quote that exercises the
// same local cryptographic relationships as an Intel DCAP quote:
//
//   - test PCK key signs the QE/TDQE report
//   - QE report_data[0:32] binds SHA256(attestation_key || auth_data)
//   - attestation key signs quote header + TD report body
//   - quote certification data carries the test PCK leaf + intermediate chain
//
// The result is intended for parser/verifier tests and local demonstrations only.
func GenerateSyntheticQuote() (*SyntheticQuoteBundle, error) {
	return generateSyntheticQuote(rand.Reader, time.Now().UTC())
}

// GenerateSyntheticRoot creates the reusable test-only root key material for
// synthetic quote generation.
func GenerateSyntheticRoot() (*SyntheticRootBundle, error) {
	return generateSyntheticRoot(rand.Reader, time.Now().UTC())
}

// GenerateSyntheticQuoteWithRoot builds a synthetic quote signed below the
// caller-provided synthetic test root. The root must be a CA certificate and
// must match rootKey.
func GenerateSyntheticQuoteWithRoot(rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate) (*SyntheticQuoteBundle, error) {
	return generateSyntheticQuoteWithRoot(rand.Reader, time.Now().UTC(), rootKey, rootCert)
}

func generateSyntheticQuote(random io.Reader, now time.Time) (*SyntheticQuoteBundle, error) {
	root, err := generateSyntheticRootMaterial(random, now)
	if err != nil {
		return nil, err
	}
	bundle, err := generateSyntheticQuoteWithRoot(random, now, root.key, root.cert)
	if err != nil {
		return nil, err
	}
	bundle.RootCertPEM = root.certPEM
	return bundle, nil
}

func generateSyntheticQuoteWithRoot(random io.Reader, now time.Time, rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate) (*SyntheticQuoteBundle, error) {
	if rootKey == nil {
		return nil, fmt.Errorf("synthetic root key is required")
	}
	if rootCert == nil {
		return nil, fmt.Errorf("synthetic root certificate is required")
	}
	if !rootCert.IsCA {
		return nil, fmt.Errorf("synthetic root certificate must be a CA")
	}
	if !rootKey.PublicKey.Equal(rootCert.PublicKey) {
		return nil, fmt.Errorf("synthetic root key does not match root certificate")
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate synthetic intermediate key: %w", err)
	}
	pckKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate synthetic PCK key: %w", err)
	}
	attestationKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate synthetic attestation key: %w", err)
	}

	intermediateCert, intermediateDER, err := createSyntheticIntermediateCert(random, intermediateKey, rootKey, rootCert, now)
	if err != nil {
		return nil, err
	}
	_, pckDER, err := createSyntheticPCKCert(random, pckKey, intermediateKey, intermediateCert, now)
	if err != nil {
		return nil, err
	}

	authData := []byte("synthetic-tdx-auth-data")
	attestationPub := marshalP256PublicKeyRaw(&attestationKey.PublicKey)

	qeReport := make([]byte, qeReportSize)
	binding := sha256.Sum256(append(append([]byte(nil), attestationPub...), authData...))
	copy(qeReport[qeReportDataOffset:qeReportDataOffset+32], binding[:])

	qeReportSig, err := signECDSARawSHA256(random, pckKey, qeReport)
	if err != nil {
		return nil, fmt.Errorf("sign synthetic QE report: %w", err)
	}

	headerAndBody := make([]byte, quoteHeaderSize+tdxReportBodySize)
	binary.LittleEndian.PutUint16(headerAndBody[0:2], syntheticQuoteVersion)
	binary.LittleEndian.PutUint16(headerAndBody[2:4], syntheticQuoteAttKeyType)
	binary.LittleEndian.PutUint32(headerAndBody[4:8], syntheticQuoteTeeType)
	if _, err := io.ReadFull(random, headerAndBody[quoteHeaderSize:]); err != nil {
		return nil, fmt.Errorf("fill synthetic TD report body: %w", err)
	}

	quoteSig, err := signECDSARawSHA256(random, attestationKey, headerAndBody)
	if err != nil {
		return nil, fmt.Errorf("sign synthetic quote body: %w", err)
	}

	pckChainPEM := bytes.Join([][]byte{pemEncodeCert(pckDER), pemEncodeCert(intermediateDER)}, nil)
	signatureData := encodeSyntheticSignatureData(quoteSig, attestationPub, qeReport, qeReportSig, authData, pckChainPEM)

	quote := make([]byte, 0, len(headerAndBody)+4+len(signatureData))
	quote = append(quote, headerAndBody...)
	quote = binary.LittleEndian.AppendUint32(quote, uint32(len(signatureData)))
	quote = append(quote, signatureData...)

	return &SyntheticQuoteBundle{
		Quote:       quote,
		RootCertPEM: pemEncodeCert(rootCert.Raw),
		PCKChainPEM: pckChainPEM,
	}, nil
}

type syntheticRootMaterial struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	keyPEM  []byte
	certPEM []byte
}

func generateSyntheticRoot(random io.Reader, now time.Time) (*SyntheticRootBundle, error) {
	root, err := generateSyntheticRootMaterial(random, now)
	if err != nil {
		return nil, err
	}
	return &SyntheticRootBundle{
		RootKeyPEM:  root.keyPEM,
		RootCertPEM: root.certPEM,
	}, nil
}

func generateSyntheticRootMaterial(random io.Reader, now time.Time) (*syntheticRootMaterial, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate synthetic root key: %w", err)
	}
	rootCert, rootDER, err := createSyntheticRootCert(random, rootKey, now)
	if err != nil {
		return nil, err
	}
	rootKeyPEM, err := pemEncodeECPrivateKey(rootKey)
	if err != nil {
		return nil, err
	}
	return &syntheticRootMaterial{
		key:     rootKey,
		cert:    rootCert,
		keyPEM:  rootKeyPEM,
		certPEM: pemEncodeCert(rootDER),
	}, nil
}

func encodeSyntheticSignatureData(quoteSig []byte, attestationPub []byte, qeReport []byte, qeReportSig []byte, authData []byte, pckChainPEM []byte) []byte {
	inner := make([]byte, 0, len(qeReport)+len(qeReportSig)+2+len(authData)+6+len(pckChainPEM))
	inner = append(inner, qeReport...)
	inner = append(inner, qeReportSig...)
	inner = binary.LittleEndian.AppendUint16(inner, uint16(len(authData)))
	inner = append(inner, authData...)
	inner = binary.LittleEndian.AppendUint16(inner, certTypePCKCertChain)
	inner = binary.LittleEndian.AppendUint32(inner, uint32(len(pckChainPEM)))
	inner = append(inner, pckChainPEM...)

	out := make([]byte, 0, len(quoteSig)+len(attestationPub)+6+len(inner))
	out = append(out, quoteSig...)
	out = append(out, attestationPub...)
	out = binary.LittleEndian.AppendUint16(out, certTypeQEReportCertData)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(inner)))
	out = append(out, inner...)
	return out
}

// VerifySyntheticQuoteCrypto verifies only the local cryptographic relationships
// in a synthetic quote. It intentionally skips Intel collateral, freshness, CRL,
// FMSPC, PCEID, and TCB policy checks.
func VerifySyntheticQuoteCrypto(quoteBytes []byte, rootCert *x509.Certificate, verifyTime time.Time) (*ParsedQuote, error) {
	evidence, err := parseAndVerifyQuoteEvidence(VerificationRequest{
		QuoteBytes: quoteBytes,
		RootCert:   rootCert,
		VerifyTime: verifyTime,
	}, false)
	if err != nil {
		return nil, err
	}
	if err := verifyQuoteLocalSignatures(evidence, false); err != nil {
		return nil, err
	}
	return evidence.ParsedQuote, nil
}

func createSyntheticRootCert(random io.Reader, key *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, []byte, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic TDX Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(random, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create synthetic root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse synthetic root cert: %w", err)
	}
	return cert, der, nil
}

func createSyntheticIntermediateCert(random io.Reader, key *ecdsa.PrivateKey, rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate, now time.Time) (*x509.Certificate, []byte, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Synthetic TDX Test PCK Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(random, template, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create synthetic intermediate cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse synthetic intermediate cert: %w", err)
	}
	return cert, der, nil
}

func createSyntheticPCKCert(random io.Reader, key *ecdsa.PrivateKey, issuerKey *ecdsa.PrivateKey, issuer *x509.Certificate, now time.Time) (*x509.Certificate, []byte, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Synthetic TDX Test PCK Leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(random, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create synthetic PCK cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse synthetic PCK cert: %w", err)
	}
	return cert, der, nil
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal synthetic root key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func marshalP256PublicKeyRaw(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 64)
	pub.X.FillBytes(out[:32])
	pub.Y.FillBytes(out[32:])
	return out
}

func signECDSARawSHA256(random io.Reader, priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(random, priv, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}
