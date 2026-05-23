package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

func verifyPCKChain(leaf *x509.Certificate, chain []*x509.Certificate, rootCert *x509.Certificate, verifyTime time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		// Quote 안에 포함된 root는 그대로 신뢰하지 않습니다.
		// trust anchor는 오직 -root로 전달된 인증서만 사용합니다.
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

func verifyQEReportSignature(qeReport []byte, rawSig []byte, pckCert *x509.Certificate) error {
	pub, ok := pckCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("PCK cert public key is not ECDSA: %T", pckCert.PublicKey)
	}
	return verifyECDSARawSHA256(pub, qeReport, rawSig)
}

func verifyAKBinding(attestationKey []byte, authData []byte, qeReport []byte) error {
	if len(qeReport) < qeReportDataOffset+qeReportDataSize {
		return fmt.Errorf("QE report too small: %d", len(qeReport))
	}

	h := sha256.New()
	h.Write(attestationKey)
	h.Write(authData)
	expected := h.Sum(nil)

	reportData := qeReport[qeReportDataOffset : qeReportDataOffset+qeReportDataSize]
	actual := reportData[:32]
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("AK binding mismatch: report_data[0:32]=%s expected=%s", hex.EncodeToString(actual), hex.EncodeToString(expected))
	}
	return nil
}

func verifyQuoteSignature(headerAndBody []byte, rawSig []byte, attestationKey []byte) error {
	pub, err := parseECDSAP256PublicKeyRaw(attestationKey)
	if err != nil {
		return err
	}
	return verifyECDSARawSHA256(pub, headerAndBody, rawSig)
}

func parseECDSAP256PublicKeyRaw(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("expected raw P-256 public key x||y length 64, got %d", len(raw))
	}

	x := new(big.Int).SetBytes(raw[:32])
	y := new(big.Int).SetBytes(raw[32:])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("attestation public key is not on P-256")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func verifyECDSARawSHA256(pub *ecdsa.PublicKey, msg []byte, rawSig []byte) error {
	if len(rawSig) != 64 {
		return fmt.Errorf("expected raw ECDSA signature r||s length 64, got %d", len(rawSig))
	}

	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("ECDSA P-256 SHA-256 signature invalid")
	}
	return nil
}
