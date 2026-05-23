package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// parsePEMCerts는 PEM 번들 안에 들어 있는 모든 CERTIFICATE 블록을 추출합니다.
func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM cert: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate blocks found")
	}
	return certs, nil
}

func parseOneCert(data []byte) (*x509.Certificate, error) {
	data = bytes.TrimSpace(data)
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}

func loadCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePEMCerts(raw)
}

// verifyCertChain은 호출자가 제공한 Intel Root CA와 함께 전달된 intermediate를 사용해
// 인증서 체인을 검증합니다.
//
// verifier는 quote나 collateral에 같이 들어 있는 root를 그대로 신뢰하지 않습니다.
// 오직 호출자가 명시적으로 준 root만 trust anchor로 취급합니다.
func verifyCertChain(leaf *x509.Certificate, chain []*x509.Certificate, rootCert *x509.Certificate, verifyTime time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		if sameCert(cert, rootCert) || isSelfSigned(cert) {
			continue
		}
		intermediates.AddCert(cert)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   verifyTime,
	})
	return err
}

func sameCert(a, b *x509.Certificate) bool {
	return bytes.Equal(a.Raw, b.Raw)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func printCert(cert *x509.Certificate) {
	fmt.Println("Subject:     ", cert.Subject.String())
	fmt.Println("Issuer:      ", cert.Issuer.String())
	fmt.Println("Serial:      ", cert.SerialNumber.String())
	fmt.Println("NotBefore:   ", cert.NotBefore.Format(time.RFC3339))
	fmt.Println("NotAfter:    ", cert.NotAfter.Format(time.RFC3339))
	fmt.Println("SHA256 FP:   ", formatFingerprint(sha256.Sum256(cert.Raw)))
	fmt.Println("IsSelfSigned:", isSelfSigned(cert))
}

func formatFingerprint(sum [32]byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		parts = append(parts, encoded[index:index+2])
	}
	return strings.Join(parts, ":")
}
