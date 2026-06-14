// Package tdxattest exposes the small stable non-CLI surface of this example project.
//
// Cobra and command wiring live under cmd/tdx-attest so importing this package
// does not pull in CLI framework dependencies.
package tdxattest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	core "github.com/museop/intel-tdx-attestation/internal/tdxattest"
)

// SyntheticQuoteBundle contains a non-Intel, test-only quote and the matching
// synthetic trust material needed to verify its local cryptographic chain.
type SyntheticQuoteBundle struct {
	Quote       []byte
	RootCertPEM []byte
	PCKChainPEM []byte
}

// SyntheticRootBundle contains a synthetic test root CA certificate and
// private key for generating non-Intel synthetic quotes.
type SyntheticRootBundle struct {
	RootKeyPEM  []byte
	RootCertPEM []byte
}

// GenerateSyntheticQuote builds a non-Intel synthetic quote for local tests.
func GenerateSyntheticQuote() (*SyntheticQuoteBundle, error) {
	bundle, err := core.GenerateSyntheticQuote()
	if err != nil {
		return nil, err
	}
	return &SyntheticQuoteBundle{
		Quote:       bundle.Quote,
		RootCertPEM: bundle.RootCertPEM,
		PCKChainPEM: bundle.PCKChainPEM,
	}, nil
}

// GenerateSyntheticRoot creates reusable non-Intel synthetic test root
// material for local tests.
func GenerateSyntheticRoot() (*SyntheticRootBundle, error) {
	bundle, err := core.GenerateSyntheticRoot()
	if err != nil {
		return nil, err
	}
	return &SyntheticRootBundle{
		RootKeyPEM:  bundle.RootKeyPEM,
		RootCertPEM: bundle.RootCertPEM,
	}, nil
}

// GenerateSyntheticQuoteWithRoot builds a non-Intel synthetic quote using the
// caller-provided synthetic test root.
func GenerateSyntheticQuoteWithRoot(rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate) (*SyntheticQuoteBundle, error) {
	bundle, err := core.GenerateSyntheticQuoteWithRoot(rootKey, rootCert)
	if err != nil {
		return nil, err
	}
	return &SyntheticQuoteBundle{
		Quote:       bundle.Quote,
		RootCertPEM: bundle.RootCertPEM,
		PCKChainPEM: bundle.PCKChainPEM,
	}, nil
}

// VerifySyntheticQuoteCrypto verifies only the local cryptographic relationships
// in a synthetic quote. Intel collateral and TCB policy checks are not run.
func VerifySyntheticQuoteCrypto(quoteBytes []byte, rootCert *x509.Certificate, verifyTime time.Time) error {
	_, err := core.VerifySyntheticQuoteCrypto(quoteBytes, rootCert, verifyTime)
	return err
}
