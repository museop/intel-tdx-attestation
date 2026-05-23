package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	quoteHeaderSize = 48

	// TDX Quote v4의 body는 보통 584바이트 TD report body이고,
	// SGX Quote v3의 body는 보통 384바이트 enclave report body입니다.
	tdxReportBodySize = 584
	sgxReportBodySize = 384

	ecdsaSigSize    = 64
	ecdsaPubKeySize = 64
	qeReportSize    = 384

	// SGX/TDQE report의 report_data는 sgx_report_body_t 내부에 있으며,
	// 오프셋 320에서 시작하는 64바이트입니다.
	qeReportDataOffset = 320
	qeReportDataSize   = 64

	certTypePCKCertChain     = 5
	certTypeQEReportCertData = 6
)

// ParsedQuote는 이후 검증 단계에서 실제로 사용하는 Quote 조각만 담는 구조체입니다.
//
// signed body, attestation key, QE report 관련 데이터, certification data처럼
// 뒤 단계에서 직접 참조하는 값만 보관해 구조를 단순하게 유지합니다.
type ParsedQuote struct {
	HeaderAndBody []byte
	ReportBody    []byte

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

// parseQuote는 raw quote 바이트열을 header/body/signature 영역으로 분리합니다.
//
// 이 함수는 첫 번째 구조 검증 관문입니다. 여기서 quote 레이아웃을 제대로 이해하지 못하면
// 이후 단계의 모든 검증 결과도 신뢰할 수 없습니다.
func parseQuote(quote []byte) (*ParsedQuote, error) {
	if len(quote) < quoteHeaderSize+sgxReportBodySize+4 {
		return nil, fmt.Errorf("quote too small: %d bytes", len(quote))
	}

	version := binary.LittleEndian.Uint16(quote[0:2])
	attKeyType := binary.LittleEndian.Uint16(quote[2:4])
	teeType := binary.LittleEndian.Uint32(quote[4:8])

	bodySize, err := inferReportBodySize(quote)
	if err != nil {
		return nil, err
	}

	signedLen := quoteHeaderSize + bodySize
	if len(quote) < signedLen+4 {
		return nil, fmt.Errorf("quote too small for header+body+siglen")
	}

	signatureDataLen := binary.LittleEndian.Uint32(quote[signedLen : signedLen+4])
	signatureStart := signedLen + 4
	signatureEnd := signatureStart + int(signatureDataLen)

	if signatureEnd > len(quote) {
		return nil, fmt.Errorf("signature data exceeds quote size: sigEnd=%d quoteLen=%d", signatureEnd, len(quote))
	}

	parsed := &ParsedQuote{
		HeaderAndBody:    quote[:signedLen],
		ReportBody:       quote[quoteHeaderSize:signedLen],
		Version:          version,
		AttKeyType:       attKeyType,
		TeeType:          teeType,
		SignatureDataLen: signatureDataLen,
		SignatureData:    quote[signatureStart:signatureEnd],
	}

	if err := parseECDSASignatureData(parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}

func printQuoteSummary(parsed *ParsedQuote) {
	fmt.Println("\n[Quote]")
	fmt.Printf("Version:             %d\n", parsed.Version)
	fmt.Printf("AttKeyType:          0x%04x\n", parsed.AttKeyType)
	fmt.Printf("TEEType:             0x%08x\n", parsed.TeeType)
	fmt.Printf("Header+Body bytes:   %d\n", len(parsed.HeaderAndBody))
	fmt.Printf("SigDataLen:          %d\n", parsed.SignatureDataLen)
	fmt.Printf("AuthDataLen:         %d\n", len(parsed.AuthData))
	fmt.Printf("CertType:            %d\n", parsed.CertType)
	fmt.Printf("CertDataLen:         %d\n", len(parsed.CertData))
	fmt.Printf("QEReportOrder:       %s\n", parsed.QEReportOrder)
}

// inferReportBodySize는 Intel DCAP 계열 도구가 사용하는 길이 일관성 규칙을 이용해
// 현재 quote body가 TDX TD report인지 SGX enclave report인지 구분합니다.
func inferReportBodySize(quote []byte) (int, error) {
	if okSignatureDataLength(quote, quoteHeaderSize+tdxReportBodySize) {
		return tdxReportBodySize, nil
	}
	if okSignatureDataLength(quote, quoteHeaderSize+sgxReportBodySize) {
		return sgxReportBodySize, nil
	}
	return 0, errors.New("cannot infer report body size as TDX(584) or SGX(384)")
}

func okSignatureDataLength(quote []byte, signedLen int) bool {
	if len(quote) < signedLen+4 {
		return false
	}

	signatureLength := binary.LittleEndian.Uint32(quote[signedLen : signedLen+4])
	if signatureLength == 0 {
		return false
	}

	return signedLen+4+int(signatureLength) <= len(quote)
}

func parseECDSASignatureData(parsed *ParsedQuote) error {
	signatureData := parsed.SignatureData

	// TDX Quote v4의 ECDSA-256 signature data는 보통 다음 순서로 배치됩니다.
	//   quote_signature        64바이트
	//   attestation_public_key 64바이트
	//   certification_data     가변 길이
	if len(signatureData) < ecdsaSigSize+ecdsaPubKeySize+6 {
		return fmt.Errorf("signature data too small: %d", len(signatureData))
	}

	offset := 0
	parsed.QuoteSignature = signatureData[offset : offset+ecdsaSigSize]
	offset += ecdsaSigSize

	parsed.AttestationKey = signatureData[offset : offset+ecdsaPubKeySize]
	offset += ecdsaPubKeySize

	possibleCertType := binary.LittleEndian.Uint16(signatureData[offset : offset+2])
	if possibleCertType == certTypeQEReportCertData {
		return parseTDXOuterCertificationData(parsed, signatureData[offset:])
	}

	return parseSGXStyleSignatureDataAfterKey(parsed, signatureData[offset:])
}

func parseTDXOuterCertificationData(parsed *ParsedQuote, data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("outer certification data too small: %d", len(data))
	}

	offset := 0
	outerCertType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	outerCertDataLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if outerCertType != certTypeQEReportCertData {
		return fmt.Errorf("unsupported outer certification data type: got %d, want %d QE_REPORT_CERTIFICATION_DATA", outerCertType, certTypeQEReportCertData)
	}
	if offset+outerCertDataLen > len(data) {
		return fmt.Errorf("outer certification data exceeds signature data: off=%d len=%d total=%d", offset, outerCertDataLen, len(data))
	}

	return parseQEReportCertificationDataAuto(parsed, data[offset:offset+outerCertDataLen])
}

func parseQEReportCertificationDataAuto(parsed *ParsedQuote, data []byte) error {
	firstErr := parseQEReportCertificationData(parsed, data, false)
	if firstErr == nil {
		parsed.QEReportOrder = "report_then_signature"
		return nil
	}
	if err := parseQEReportCertificationData(parsed, data, true); err == nil {
		parsed.QEReportOrder = "signature_then_report"
		return nil
	}
	return fmt.Errorf("failed to parse QE report certification data; first error: %w", firstErr)
}

func parseQEReportCertificationData(parsed *ParsedQuote, data []byte, signatureThenReport bool) error {
	if len(data) < ecdsaSigSize+qeReportSize+2+6 {
		return fmt.Errorf("QE report certification data too small: %d", len(data))
	}

	offset := 0
	var qeReport []byte
	var qeReportSignature []byte

	if signatureThenReport {
		qeReportSignature = data[offset : offset+ecdsaSigSize]
		offset += ecdsaSigSize
		qeReport = data[offset : offset+qeReportSize]
		offset += qeReportSize
	} else {
		qeReport = data[offset : offset+qeReportSize]
		offset += qeReportSize
		qeReportSignature = data[offset : offset+ecdsaSigSize]
		offset += ecdsaSigSize
	}

	authDataLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+authDataLen > len(data) {
		return fmt.Errorf("QE auth data exceeds QE report certification data: off=%d authLen=%d total=%d", offset, authDataLen, len(data))
	}

	authData := data[offset : offset+authDataLen]
	offset += authDataLen
	if offset+6 > len(data) {
		return fmt.Errorf("missing inner QE certification data header")
	}

	innerCertType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	innerCertDataLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if offset+innerCertDataLen > len(data) {
		return fmt.Errorf("inner QE certification data exceeds buffer: off=%d len=%d total=%d", offset, innerCertDataLen, len(data))
	}
	if innerCertType != certTypePCKCertChain {
		return fmt.Errorf("unsupported inner QE certification data type: got %d, want %d PCK_CERT_CHAIN", innerCertType, certTypePCKCertChain)
	}

	parsed.QEReport = qeReport
	parsed.QEReportSignature = qeReportSignature
	parsed.AuthData = authData
	parsed.CertType = innerCertType
	parsed.CertData = data[offset : offset+innerCertDataLen]
	return nil
}

func parseSGXStyleSignatureDataAfterKey(parsed *ParsedQuote, data []byte) error {
	if len(data) < qeReportSize+ecdsaSigSize+2+6 {
		return fmt.Errorf("SGX-style signature tail too small: %d", len(data))
	}

	offset := 0
	parsed.QEReport = data[offset : offset+qeReportSize]
	offset += qeReportSize
	parsed.QEReportSignature = data[offset : offset+ecdsaSigSize]
	offset += ecdsaSigSize

	authDataLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+authDataLen > len(data) {
		return fmt.Errorf("auth_data exceeds signature data: off=%d authLen=%d total=%d", offset, authDataLen, len(data))
	}

	parsed.AuthData = data[offset : offset+authDataLen]
	offset += authDataLen
	if offset+6 > len(data) {
		return fmt.Errorf("missing certification data header")
	}

	parsed.CertType = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	certDataLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if offset+certDataLen > len(data) {
		return fmt.Errorf("certification data exceeds signature data: off=%d certLen=%d total=%d", offset, certDataLen, len(data))
	}

	parsed.CertData = data[offset : offset+certDataLen]
	parsed.QEReportOrder = "sgx_style_report_then_signature"
	return nil
}
