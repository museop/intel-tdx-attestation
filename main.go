package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	quoteHeaderSize = 48

	// TDX Quote v4 body is TD report body, commonly 584 bytes.
	// SGX Quote v3 body is enclave report body, commonly 384 bytes.
	tdxReportBodySize = 584
	sgxReportBodySize = 384

	ecdsaSigSize    = 64
	ecdsaPubKeySize = 64
	qeReportSize    = 384

	// SGX/TDQE report_data offset inside sgx_report_body_t.
	// sgx_report_body_t.report_data is 64 bytes at offset 320.
	qeReportDataOffset = 320
	qeReportDataSize   = 64

	certTypePCKCertChain     = 5
	certTypeQEReportCertData = 6
)

type ParsedQuote struct {
	HeaderAndBody []byte

	Version    uint16
	AttKeyType uint16
	TeeType    uint32

	SignatureDataLen uint32
	SignatureData    []byte

	QuoteSignature []byte
	AttestationKey []byte

	QEReport          []byte
	QEReportSignature []byte

	AuthData []byte

	CertType uint16
	CertData []byte

	QEReportOrder string
}

func main() {
	var (
		quotePath      = flag.String("quote", "quote.dat", "TDX/SGX DCAP quote file")
		rootPath       = flag.String("root", "Intel_SGX_Provisioning_Certification_RootCA.pem", "Intel SGX Root CA certificate PEM/DER")
		tcbInfoPath    = flag.String("tcbinfo", "tcbinfo.json", "Intel TCB Info JSON")
		qeIdentityPath = flag.String("qeidentity", "qeidentity.json", "Intel QE/TDQE Identity JSON")
		tcbChainPath   = flag.String("tcb-chain", "tcbSigningChain.pem", "Intel TCB signing cert chain PEM")
		qeChainPath    = flag.String("qe-chain", "tcbSigningChain.pem", "Intel QE/TDQE identity signing cert chain PEM")

		// Use this for old sample quote/collateral.
		// Example: -sample-time 2023-02-01T00:00:00Z
		sampleTime = flag.String("sample-time", "", "verification time for sample collateral, e.g. 2023-02-01T00:00:00Z")

		// If true, freshness checks for JSON collateral are relaxed,
		// but certificate verification still needs a CurrentTime.
		ignoreFreshness = flag.Bool("ignore-freshness", false, "ignore TCB/QE Identity issueDate/nextUpdate freshness checks")
	)
	flag.Parse()

	verifyTime := time.Now().UTC()
	if *sampleTime != "" {
		t, err := time.Parse(time.RFC3339, *sampleTime)
		must(err, "parse sample-time")
		verifyTime = t.UTC()
		fmt.Println("[warn] using sample verification time:", verifyTime.Format(time.RFC3339))
	}

	quoteBytes, err := os.ReadFile(*quotePath)
	must(err, "read quote")

	rootBytes, err := os.ReadFile(*rootPath)
	must(err, "read Intel root CA cert")

	rootCert, err := parseOneCert(rootBytes)
	must(err, "parse Intel root CA cert")

	fmt.Println("[Intel Root CA]")
	printCert(rootCert)

	pq, err := parseQuote(quoteBytes)
	must(err, "parse quote")

	fmt.Println("\n[Quote]")
	fmt.Printf("Version:             %d\n", pq.Version)
	fmt.Printf("AttKeyType:          0x%04x\n", pq.AttKeyType)
	fmt.Printf("TEEType:             0x%08x\n", pq.TeeType)
	fmt.Printf("Header+Body bytes:   %d\n", len(pq.HeaderAndBody))
	fmt.Printf("SigDataLen:          %d\n", pq.SignatureDataLen)
	fmt.Printf("AuthDataLen:         %d\n", len(pq.AuthData))
	fmt.Printf("CertType:            %d\n", pq.CertType)
	fmt.Printf("CertDataLen:         %d\n", len(pq.CertData))
	fmt.Printf("QEReportOrder:       %s\n", pq.QEReportOrder)

	if pq.CertType != certTypePCKCertChain {
		must(fmt.Errorf("unsupported certification data type %d; want PCK_CERT_CHAIN=5", pq.CertType), "check cert type")
	}

	pckChain, err := parsePEMCerts(pq.CertData)
	must(err, "parse PCK cert chain from quote certification data")

	if len(pckChain) < 2 {
		must(fmt.Errorf("need at least PCK leaf + intermediate, got %d cert(s)", len(pckChain)), "validate PCK cert count")
	}

	fmt.Printf("\n[PCK certificates from quote] count=%d\n", len(pckChain))
	for i, c := range pckChain {
		fmt.Printf("\n--- pck chain cert[%d] ---\n", i)
		printCert(c)
	}

	pckLeaf := pckChain[0]

	err = verifyPCKChain(pckLeaf, pckChain[1:], rootCert, verifyTime)
	must(err, "verify PCK cert chain")
	fmt.Println("\n[1] PCK certificate chain verification: OK")

	err = verifyQEReportSignature(pq.QEReport, pq.QEReportSignature, pckLeaf)
	must(err, "verify QE/TDQE report signature with PCK cert public key")
	fmt.Println("[2] QE/TDQE report signature verification: OK")

	err = verifyAKBinding(pq.AttestationKey, pq.AuthData, pq.QEReport)
	must(err, "verify AK hash binding in QE/TDQE report_data")
	fmt.Println("[3] AK hash binding verification: OK")

	err = verifyQuoteSignature(pq.HeaderAndBody, pq.QuoteSignature, pq.AttestationKey)
	must(err, "verify quote signature with attestation key")
	fmt.Println("[4] TDX/SGX quote signature verification: OK")

	err = verifyTCBInfoCollateral(
		*tcbInfoPath,
		*tcbChainPath,
		rootCert,
		pckLeaf,
		verifyTime,
		*ignoreFreshness,
	)
	must(err, "verify TCB Info collateral")
	fmt.Println("[5] TCB Info signature / chain / freshness / FMSPC verification: OK")

	err = verifyQEIdentityCollateral(
		*qeIdentityPath,
		*qeChainPath,
		rootCert,
		pq.QEReport,
		verifyTime,
		*ignoreFreshness,
	)
	must(err, "verify QE/TDQE Identity collateral")
	fmt.Println("[6] QE/TDQE Identity signature / chain / freshness verification: OK")

	fmt.Println()
	fmt.Println("RESULT: basic cryptographic quote chain and partial collateral verification are OK")
	fmt.Println()
	fmt.Println("Verified:")
	fmt.Println("  Intel Root CA -> PCK intermediate -> PCK leaf")
	fmt.Println("  PCK leaf public key -> QE/TDQE report signature")
	fmt.Println("  QE/TDQE report_data[0:32] -> SHA256(attestation_key || auth_data)")
	fmt.Println("  Attestation key -> quote signature over quote header + report body")
	fmt.Println("  TCB Info JSON signature")
	fmt.Println("  TCB Info signing certificate chain")
	fmt.Println("  TCB Info issueDate / nextUpdate")
	fmt.Println("  PCK cert FMSPC == TCB Info FMSPC")
	fmt.Println("  QE/TDQE Identity JSON signature")
	fmt.Println("  QE/TDQE Identity signing certificate chain")
	fmt.Println("  QE/TDQE Identity issueDate / nextUpdate")
	fmt.Println("  QE Report MRSIGNER / ISVPRODID / ISVSVN basic policy")
	fmt.Println()
	fmt.Println("Not verified yet:")
	fmt.Println("  PCK CRL")
	fmt.Println("  Root/Intermediate CRL")
	fmt.Println("  Full TCB status evaluation using PCK CPUSVN / PCESVN")
	fmt.Println("  Full QE/TDQE Identity policy, including miscselect / attributes masks")
	fmt.Println("  MRTD/RTMR/REPORTDATA/ATTRIBUTES policy")
	fmt.Println("  REPORTDATA challenge/session binding")
}

func parseQuote(q []byte) (*ParsedQuote, error) {
	if len(q) < quoteHeaderSize+sgxReportBodySize+4 {
		return nil, fmt.Errorf("quote too small: %d bytes", len(q))
	}

	version := binary.LittleEndian.Uint16(q[0:2])
	attKeyType := binary.LittleEndian.Uint16(q[2:4])
	teeType := binary.LittleEndian.Uint32(q[4:8])

	bodySize, err := inferReportBodySize(q)
	if err != nil {
		return nil, err
	}

	signedLen := quoteHeaderSize + bodySize
	if len(q) < signedLen+4 {
		return nil, fmt.Errorf("quote too small for header+body+siglen")
	}

	sigDataLen := binary.LittleEndian.Uint32(q[signedLen : signedLen+4])
	sigStart := signedLen + 4
	sigEnd := sigStart + int(sigDataLen)

	if sigEnd > len(q) {
		return nil, fmt.Errorf("signature data exceeds quote size: sigEnd=%d quoteLen=%d", sigEnd, len(q))
	}

	sigData := q[sigStart:sigEnd]

	p := &ParsedQuote{
		HeaderAndBody:    q[:signedLen],
		Version:          version,
		AttKeyType:       attKeyType,
		TeeType:          teeType,
		SignatureDataLen: sigDataLen,
		SignatureData:    sigData,
	}

	err = parseECDSASignatureData(p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func inferReportBodySize(q []byte) (int, error) {
	if okSignatureDataLength(q, quoteHeaderSize+tdxReportBodySize) {
		return tdxReportBodySize, nil
	}

	if okSignatureDataLength(q, quoteHeaderSize+sgxReportBodySize) {
		return sgxReportBodySize, nil
	}

	return 0, errors.New("cannot infer report body size as TDX(584) or SGX(384)")
}

func okSignatureDataLength(q []byte, signedLen int) bool {
	if len(q) < signedLen+4 {
		return false
	}

	sigLen := binary.LittleEndian.Uint32(q[signedLen : signedLen+4])
	if sigLen == 0 {
		return false
	}

	return signedLen+4+int(sigLen) <= len(q)
}

func parseECDSASignatureData(p *ParsedQuote) error {
	d := p.SignatureData

	// TDX Quote v4 ECDSA 256-bit signature data:
	//
	//   quote_signature          64 bytes
	//   attestation_public_key   64 bytes
	//   certification_data       variable
	if len(d) < ecdsaSigSize+ecdsaPubKeySize+6 {
		return fmt.Errorf("signature data too small: %d", len(d))
	}

	off := 0

	p.QuoteSignature = d[off : off+ecdsaSigSize]
	off += ecdsaSigSize

	p.AttestationKey = d[off : off+ecdsaPubKeySize]
	off += ecdsaPubKeySize

	possibleCertType := binary.LittleEndian.Uint16(d[off : off+2])

	if possibleCertType == certTypeQEReportCertData {
		return parseTDXOuterCertificationData(p, d[off:])
	}

	return parseSGXStyleSignatureDataAfterKey(p, d[off:])
}

func parseTDXOuterCertificationData(p *ParsedQuote, d []byte) error {
	if len(d) < 6 {
		return fmt.Errorf("outer certification data too small: %d", len(d))
	}

	off := 0

	outerCertType := binary.LittleEndian.Uint16(d[off : off+2])
	off += 2

	outerCertDataLen := int(binary.LittleEndian.Uint32(d[off : off+4]))
	off += 4

	if outerCertType != certTypeQEReportCertData {
		return fmt.Errorf(
			"unsupported outer certification data type: got %d, want %d QE_REPORT_CERTIFICATION_DATA",
			outerCertType,
			certTypeQEReportCertData,
		)
	}

	if off+outerCertDataLen > len(d) {
		return fmt.Errorf(
			"outer certification data exceeds signature data: off=%d len=%d total=%d",
			off,
			outerCertDataLen,
			len(d),
		)
	}

	outerCertData := d[off : off+outerCertDataLen]
	return parseQEReportCertificationDataAuto(p, outerCertData)
}

func parseQEReportCertificationDataAuto(p *ParsedQuote, d []byte) error {
	// Intel DCAP ECDSA quote commonly uses:
	//   qe_report            384
	//   qe_report_signature   64
	//   auth_data_len          2
	//   auth_data              variable
	//   inner_cert_data        variable
	//
	// We try report_then_signature first.
	var firstErr error

	if err := parseQEReportCertificationData(p, d, false); err == nil {
		p.QEReportOrder = "report_then_signature"
		return nil
	} else {
		firstErr = err
	}

	if err := parseQEReportCertificationData(p, d, true); err == nil {
		p.QEReportOrder = "signature_then_report"
		return nil
	}

	return fmt.Errorf("failed to parse QE report certification data; first error: %w", firstErr)
}

func parseQEReportCertificationData(p *ParsedQuote, d []byte, signatureThenReport bool) error {
	if len(d) < ecdsaSigSize+qeReportSize+2+6 {
		return fmt.Errorf("QE report certification data too small: %d", len(d))
	}

	off := 0

	var qeReport []byte
	var qeReportSig []byte

	if signatureThenReport {
		qeReportSig = d[off : off+ecdsaSigSize]
		off += ecdsaSigSize

		qeReport = d[off : off+qeReportSize]
		off += qeReportSize
	} else {
		qeReport = d[off : off+qeReportSize]
		off += qeReportSize

		qeReportSig = d[off : off+ecdsaSigSize]
		off += ecdsaSigSize
	}

	authDataLen := int(binary.LittleEndian.Uint16(d[off : off+2]))
	off += 2

	if off+authDataLen > len(d) {
		return fmt.Errorf(
			"QE auth data exceeds QE report certification data: off=%d authLen=%d total=%d",
			off,
			authDataLen,
			len(d),
		)
	}

	authData := d[off : off+authDataLen]
	off += authDataLen

	if off+6 > len(d) {
		return fmt.Errorf("missing inner QE certification data header")
	}

	innerCertType := binary.LittleEndian.Uint16(d[off : off+2])
	off += 2

	innerCertDataLen := int(binary.LittleEndian.Uint32(d[off : off+4]))
	off += 4

	if off+innerCertDataLen > len(d) {
		return fmt.Errorf(
			"inner QE certification data exceeds buffer: off=%d len=%d total=%d",
			off,
			innerCertDataLen,
			len(d),
		)
	}

	if innerCertType != certTypePCKCertChain {
		return fmt.Errorf(
			"unsupported inner QE certification data type: got %d, want %d PCK_CERT_CHAIN",
			innerCertType,
			certTypePCKCertChain,
		)
	}

	p.QEReport = qeReport
	p.QEReportSignature = qeReportSig
	p.AuthData = authData
	p.CertType = innerCertType
	p.CertData = d[off : off+innerCertDataLen]

	return nil
}

func parseSGXStyleSignatureDataAfterKey(p *ParsedQuote, d []byte) error {
	if len(d) < qeReportSize+ecdsaSigSize+2+6 {
		return fmt.Errorf("SGX-style signature tail too small: %d", len(d))
	}

	off := 0

	p.QEReport = d[off : off+qeReportSize]
	off += qeReportSize

	p.QEReportSignature = d[off : off+ecdsaSigSize]
	off += ecdsaSigSize

	authDataLen := int(binary.LittleEndian.Uint16(d[off : off+2]))
	off += 2

	if off+authDataLen > len(d) {
		return fmt.Errorf(
			"auth_data exceeds signature data: off=%d authLen=%d total=%d",
			off,
			authDataLen,
			len(d),
		)
	}

	p.AuthData = d[off : off+authDataLen]
	off += authDataLen

	if off+6 > len(d) {
		return fmt.Errorf("missing certification data header")
	}

	p.CertType = binary.LittleEndian.Uint16(d[off : off+2])
	off += 2

	certDataLen := int(binary.LittleEndian.Uint32(d[off : off+4]))
	off += 4

	if off+certDataLen > len(d) {
		return fmt.Errorf(
			"certification data exceeds signature data: off=%d certLen=%d total=%d",
			off,
			certDataLen,
			len(d),
		)
	}

	p.CertData = d[off : off+certDataLen]
	p.QEReportOrder = "sgx_style_report_then_signature"

	return nil
}

func verifyPCKChain(
	leaf *x509.Certificate,
	chain []*x509.Certificate,
	rootCert *x509.Certificate,
	verifyTime time.Time,
) error {
	intermediates := x509.NewCertPool()

	for _, cert := range chain {
		// Never trust the root embedded in the quote.
		// Only the root supplied by -root is the trust anchor.
		if sameCert(cert, rootCert) {
			continue
		}

		if isSelfSigned(cert) {
			continue
		}

		intermediates.AddCert(cert)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   verifyTime,
	}

	_, err := leaf.Verify(opts)
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
		return fmt.Errorf(
			"AK binding mismatch: report_data[0:32]=%s expected=%s",
			hex.EncodeToString(actual),
			hex.EncodeToString(expected),
		)
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

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
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

func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		rest = remaining

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
	s := strings.ToUpper(hex.EncodeToString(sum[:]))

	var parts []string
	for i := 0; i < len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}

	return strings.Join(parts, ":")
}

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", context, err)
		os.Exit(1)
	}
}
