package tdxattest

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// loadRevocationList는 PEM 또는 DER 형식의 CRL 파일을 모두 읽을 수 있습니다.
func loadRevocationList(path string) (*x509.RevocationList, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}

	return x509.ParseRevocationList(raw)
}

// verifyPCKCRL은 PCK leaf certificate의 폐기 여부를 확인합니다.
//
// 인증서 체인이 다른 면에서 모두 정상이어도, 폐기된 PCK certificate라면 절대 신뢰하면 안 됩니다.
func verifyPCKCRL(crlPath string, issuerCert *x509.Certificate, pckLeaf *x509.Certificate, verifyTime time.Time, ignoreFreshness bool) error {
	crl, err := loadRevocationList(crlPath)
	if err != nil {
		return fmt.Errorf("load PCK CRL: %w", err)
	}

	if err := crl.CheckSignatureFrom(issuerCert); err != nil {
		return fmt.Errorf("verify PCK CRL signature: %w", err)
	}

	if err := verifyCRLFreshness("PCK CRL", crl.ThisUpdate, crl.NextUpdate, verifyTime, ignoreFreshness); err != nil {
		return err
	}

	if isSerialRevoked(crl, pckLeaf.SerialNumber) {
		return fmt.Errorf("PCK leaf certificate serial is revoked: %s", pckLeaf.SerialNumber.Text(16))
	}

	return nil
}

func verifyCRLFreshness(name string, thisUpdate time.Time, nextUpdate time.Time, verifyTime time.Time, ignoreFreshness bool) error {
	now := verifyTime.UTC()

	if ignoreFreshness {
		fmt.Printf("[warn] %s freshness check is relaxed by -ignore-freshness\n", name)
		return nil
	}

	if now.Before(thisUpdate.UTC()) {
		return fmt.Errorf("%s thisUpdate is in the future: thisUpdate=%s verifyTime=%s", name, thisUpdate.UTC(), now)
	}
	if !nextUpdate.IsZero() && now.After(nextUpdate.UTC()) {
		return fmt.Errorf("%s expired: nextUpdate=%s verifyTime=%s", name, nextUpdate.UTC(), now)
	}
	return nil
}

func isSerialRevoked(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// verifyRootCACRL은 Root CA가 발급한 intermediate 또는 signing certificate가
// Intel SGX Root CA CRL에 의해 폐기되지 않았는지 확인합니다.
func verifyRootCACRL(crlPath string, rootCert *x509.Certificate, certs []*x509.Certificate, verifyTime time.Time, ignoreFreshness bool) error {
	crl, err := loadRevocationList(crlPath)
	if err != nil {
		return fmt.Errorf("load Root CA CRL: %w", err)
	}

	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("verify Root CA CRL signature: %w", err)
	}
	if err := verifyCRLFreshness("Root CA CRL", crl.ThisUpdate, crl.NextUpdate, verifyTime, ignoreFreshness); err != nil {
		return err
	}

	for _, cert := range certs {
		if cert == nil {
			continue
		}
		if isSerialRevoked(crl, cert.SerialNumber) {
			return fmt.Errorf("certificate serial is revoked by Root CA CRL: subject=%s serial=%s", cert.Subject, cert.SerialNumber.Text(16))
		}
	}
	return nil
}
