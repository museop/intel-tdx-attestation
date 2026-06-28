package tdxattest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

var (
	oidIntelSGXPCKExtensionRoot = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidIntelSGXExtensionFMSPC   = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

type SignedTCBInfo struct {
	TCBInfo   json.RawMessage `json:"tcbInfo"`
	Signature string          `json:"signature"`
}

// TCBInfoMinimal은 이 verifier가 실제로 사용하는 Intel TCB Info의 부분집합만 담습니다.
//
// 원본 JSON에는 더 많은 필드가 있지만, 현재 코드가 어떤 주장까지 실제로 검증하는지
// 명확히 보이도록 필요한 필드만 구조체에 포함합니다.
type TCBInfoMinimal struct {
	ID         string       `json:"id"`
	Version    int          `json:"version"`
	IssueDate  string       `json:"issueDate"`
	NextUpdate string       `json:"nextUpdate"`
	FMSPC      string       `json:"fmspc"`
	PCEID      string       `json:"pceId"`
	TCBLevels  []TCBLevel   `json:"tcbLevels"`
	TDXModule  TDXModuleRef `json:"tdxModule"`
}

type TCBLevel struct {
	TCB         PlatformTCB `json:"tcb"`
	TCBDate     string      `json:"tcbDate"`
	TCBStatus   string      `json:"tcbStatus"`
	AdvisoryIDs []string    `json:"advisoryIDs"`
}

type PlatformTCB struct {
	SGXTCBComponents []SVNComponent `json:"sgxtcbcomponents"`
	PCESVN           int            `json:"pcesvn"`
	TDXTCBComponents []SVNComponent `json:"tdxtcbcomponents"`
}

type SVNComponent struct {
	SVN int `json:"svn"`
}

type TDXModuleRef struct {
	MRSigner       string `json:"mrsigner"`
	Attributes     string `json:"attributes"`
	AttributesMask string `json:"attributesMask"`
}

type SignedQEIdentityGeneric struct {
	EnclaveIdentity json.RawMessage `json:"enclaveIdentity"`
	TDQEIdentity    json.RawMessage `json:"tdqeIdentity"`
	Signature       string          `json:"signature"`
}

type QEIdentityMinimal struct {
	ID         string     `json:"id"`
	Version    int        `json:"version"`
	IssueDate  string     `json:"issueDate"`
	NextUpdate string     `json:"nextUpdate"`
	MiscSelect string     `json:"miscselect"`
	MiscMask   string     `json:"miscselectMask"`
	Attributes string     `json:"attributes"`
	AttrMask   string     `json:"attributesMask"`
	MRSigner   string     `json:"mrsigner"`
	ISVProdID  int        `json:"isvprodid"`
	TCBLevels  []QETCBLvl `json:"tcbLevels"`
}

type QETCBLvl struct {
	TCB       QETCB  `json:"tcb"`
	TCBDate   string `json:"tcbDate"`
	TCBStatus string `json:"tcbStatus"`
}

type QETCB struct {
	ISVSVN int `json:"isvsvn"`
}

// verifyTCBInfoCollateral은 Intel TCB Info JSON이 진짜인지, 그리고 현재 PCK cert/TDX Quote와
// 실제로 관련 있는 collateral인지 확인합니다.
//
// 실질적으로는 "이 TCB metadata가 이 플랫폼 계열용이 맞는가?", "현재 플랫폼이 적어도 하나의
// 허용 가능한 TCB level을 만족하는가?"를 묻는 단계입니다.
func verifyTCBInfoCollateral(tcbInfoPath string, tcbChainPath string, rootCRLPath string, rootCert *x509.Certificate, pckLeaf *x509.Certificate, tdxMeasurements *TDXMeasurements, verifyTime time.Time, ignoreFreshness bool) error {
	raw, err := os.ReadFile(tcbInfoPath)
	if err != nil {
		return fmt.Errorf("read TCB Info JSON: %w", err)
	}
	chainRaw, err := os.ReadFile(tcbChainPath)
	if err != nil {
		return fmt.Errorf("read TCB signing chain: %w", err)
	}
	rootCRLRaw, err := os.ReadFile(rootCRLPath)
	if err != nil {
		return fmt.Errorf("read Root CA CRL: %w", err)
	}
	return verifyTCBInfoCollateralBytes(raw, chainRaw, rootCRLRaw, rootCert, pckLeaf, tdxMeasurements, verifyTime, ignoreFreshness)
}

func verifyTCBInfoCollateralBytes(raw []byte, chainRaw []byte, rootCRLRaw []byte, rootCert *x509.Certificate, pckLeaf *x509.Certificate, tdxMeasurements *TDXMeasurements, verifyTime time.Time, ignoreFreshness bool) error {
	var signed SignedTCBInfo
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("parse signed TCB Info: %w", err)
	}
	if len(signed.TCBInfo) == 0 {
		return fmt.Errorf("tcbInfo field missing")
	}

	chain, err := parsePEMCerts(chainRaw)
	if err != nil {
		return fmt.Errorf("parse TCB signing chain: %w", err)
	}
	if len(chain) == 0 {
		return fmt.Errorf("empty TCB signing chain")
	}

	signingCert := chain[0]
	if err := verifyCertChain(signingCert, chain[1:], rootCert, verifyTime); err != nil {
		return fmt.Errorf("verify TCB signing cert chain: %w", err)
	}
	if err := verifyRootCACRLBytes(rootCRLRaw, rootCert, []*x509.Certificate{signingCert}, verifyTime, ignoreFreshness); err != nil {
		return fmt.Errorf("verify Root CA CRL for TCB signing cert: %w", err)
	}
	if err := verifyIntelJSONSignature(signingCert, signed.TCBInfo, signed.Signature); err != nil {
		return fmt.Errorf("verify TCB Info JSON signature: %w", err)
	}

	var tcb TCBInfoMinimal
	if err := json.Unmarshal(signed.TCBInfo, &tcb); err != nil {
		return fmt.Errorf("parse TCB Info body: %w", err)
	}
	if err := verifyCollateralFreshness("TCB Info", tcb.IssueDate, tcb.NextUpdate, verifyTime, ignoreFreshness); err != nil {
		return err
	}

	pckFMSPC, err := extractFMSPCFromPCKCert(pckLeaf)
	if err != nil {
		return fmt.Errorf("extract FMSPC from PCK cert: %w", err)
	}
	if !strings.EqualFold(pckFMSPC, tcb.FMSPC) {
		return fmt.Errorf("FMSPC mismatch: pckCert=%s tcbInfo=%s", pckFMSPC, tcb.FMSPC)
	}

	pckPCEID, err := extractPCEIDFromPCKCert(pckLeaf)
	if err != nil {
		return fmt.Errorf("extract PCEID from PCK cert: %w", err)
	}
	if tcb.PCEID != "" && !strings.EqualFold(pckPCEID, tcb.PCEID) {
		return fmt.Errorf("PCEID mismatch: pckCert=%s tcbInfo=%s", pckPCEID, tcb.PCEID)
	}

	fmt.Println()
	fmt.Println("[TCB Info]")
	fmt.Println("ID:        ", tcb.ID)
	fmt.Println("Version:   ", tcb.Version)
	fmt.Println("IssueDate: ", tcb.IssueDate)
	fmt.Println("NextUpdate:", tcb.NextUpdate)
	fmt.Println("FMSPC:     ", tcb.FMSPC)
	fmt.Println("PCEID:     ", tcb.PCEID)
	fmt.Println("PCK FMSPC: ", pckFMSPC)
	fmt.Println("PCK PCEID: ", pckPCEID)

	if tdxMeasurements != nil {
		if err := verifyTDXModuleAgainstTCBInfo(tdxMeasurements, tcb.TDXModule); err != nil {
			return err
		}
	}

	if tdxMeasurements != nil && len(tcb.TCBLevels) > 0 {
		pckTCB, err := extractPlatformTCBFromPCKCert(pckLeaf)
		if err != nil {
			return fmt.Errorf("extract platform TCB from PCK cert: %w", err)
		}
		matchedLevel, err := evaluatePlatformTCB(pckTCB, tdxMeasurements, tcb.TCBLevels)
		if err != nil {
			return err
		}
		fmt.Println("Matched TCB status:", matchedLevel.TCBStatus)
		fmt.Println("Matched TCB date:  ", matchedLevel.TCBDate)
		if len(matchedLevel.AdvisoryIDs) > 0 {
			fmt.Println("Advisories:       ", strings.Join(matchedLevel.AdvisoryIDs, ", "))
		}
	}
	return nil
}

// verifyQEIdentityCollateral은 Intel QE/TDQE identity JSON이 진짜인지 확인하고,
// Quote 안에 들어 있는 QE report가 그 JSON이 설명하는 정책과 맞는지 검사합니다.
func verifyQEIdentityCollateral(qeIdentityPath string, qeChainPath string, rootCRLPath string, rootCert *x509.Certificate, qeReport []byte, verifyTime time.Time, ignoreFreshness bool) error {
	raw, err := os.ReadFile(qeIdentityPath)
	if err != nil {
		return fmt.Errorf("read QE Identity JSON: %w", err)
	}
	chainRaw, err := os.ReadFile(qeChainPath)
	if err != nil {
		return fmt.Errorf("read QE identity signing chain: %w", err)
	}
	rootCRLRaw, err := os.ReadFile(rootCRLPath)
	if err != nil {
		return fmt.Errorf("read Root CA CRL: %w", err)
	}
	return verifyQEIdentityCollateralBytes(raw, chainRaw, rootCRLRaw, rootCert, qeReport, verifyTime, ignoreFreshness)
}

func verifyQEIdentityCollateralBytes(raw []byte, chainRaw []byte, rootCRLRaw []byte, rootCert *x509.Certificate, qeReport []byte, verifyTime time.Time, ignoreFreshness bool) error {
	var signed SignedQEIdentityGeneric
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("parse signed QE Identity: %w", err)
	}

	identityRaw := signed.EnclaveIdentity
	identityKind := "enclaveIdentity"
	if len(identityRaw) == 0 {
		identityRaw = signed.TDQEIdentity
		identityKind = "tdqeIdentity"
	}
	if len(identityRaw) == 0 {
		return fmt.Errorf("neither enclaveIdentity nor tdqeIdentity field found")
	}

	chain, err := parsePEMCerts(chainRaw)
	if err != nil {
		return fmt.Errorf("parse QE identity signing chain: %w", err)
	}
	if len(chain) == 0 {
		return fmt.Errorf("empty QE identity signing chain")
	}

	signingCert := chain[0]
	if err := verifyCertChain(signingCert, chain[1:], rootCert, verifyTime); err != nil {
		return fmt.Errorf("verify QE identity signing cert chain: %w", err)
	}
	if err := verifyRootCACRLBytes(rootCRLRaw, rootCert, []*x509.Certificate{signingCert}, verifyTime, ignoreFreshness); err != nil {
		return fmt.Errorf("verify Root CA CRL for QE identity signing cert: %w", err)
	}
	if err := verifyIntelJSONSignature(signingCert, identityRaw, signed.Signature); err != nil {
		return fmt.Errorf("verify QE Identity JSON signature: %w", err)
	}

	var identity QEIdentityMinimal
	if err := json.Unmarshal(identityRaw, &identity); err != nil {
		return fmt.Errorf("parse QE Identity body: %w", err)
	}
	if err := verifyCollateralFreshness("QE Identity", identity.IssueDate, identity.NextUpdate, verifyTime, ignoreFreshness); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("[QE/TDQE Identity]")
	fmt.Println("Kind:      ", identityKind)
	fmt.Println("ID:        ", identity.ID)
	fmt.Println("Version:   ", identity.Version)
	fmt.Println("IssueDate: ", identity.IssueDate)
	fmt.Println("NextUpdate:", identity.NextUpdate)
	fmt.Println("MRSigner:  ", identity.MRSigner)
	fmt.Println("ISVProdID: ", identity.ISVProdID)

	if len(qeReport) >= qeReportSize {
		if err := compareQEReportWithIdentity(qeReport, identity); err != nil {
			return err
		}
	}

	return nil
}

func verifyIntelJSONSignature(signingCert *x509.Certificate, payload json.RawMessage, signatureHex string) error {
	pub, ok := signingCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("signing cert public key is not ECDSA: %T", signingCert.PublicKey)
	}

	sig, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return fmt.Errorf("decode signature hex: %w", err)
	}

	digest := sha256.Sum256(payload)
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("raw ECDSA signature invalid")
		}
		return nil
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("ASN.1 ECDSA signature invalid")
	}
	return nil
}

func verifyCollateralFreshness(name string, issueDate string, nextUpdate string, verifyTime time.Time, ignoreFreshness bool) error {
	issue, err := parseIntelTime(issueDate)
	if err != nil {
		return fmt.Errorf("%s issueDate parse failed: %w", name, err)
	}
	next, err := parseIntelTime(nextUpdate)
	if err != nil {
		return fmt.Errorf("%s nextUpdate parse failed: %w", name, err)
	}

	now := verifyTime.UTC()
	if ignoreFreshness {
		fmt.Printf("[warn] %s freshness check is relaxed by -ignore-freshness\n", name)
		return nil
	}
	if now.Before(issue) {
		return fmt.Errorf("%s issueDate is in the future: issueDate=%s verifyTime=%s", name, issue, now)
	}
	if now.After(next) {
		return fmt.Errorf("%s expired: nextUpdate=%s verifyTime=%s", name, next, now)
	}
	return nil
}

func parseIntelTime(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000000Z"}

	var lastErr error
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil {
			return parsed.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}

func extractFMSPCFromPCKCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidIntelSGXPCKExtensionRoot) && !ext.Id.Equal(oidIntelSGXExtensionFMSPC) {
			continue
		}
		if ext.Id.Equal(oidIntelSGXExtensionFMSPC) {
			value := unwrapASN1OctetString(ext.Value)
			if len(value) == 6 {
				return strings.ToUpper(hex.EncodeToString(value)), nil
			}
		}

		value, ok := findASN1ValueByOID(ext.Value, oidIntelSGXExtensionFMSPC)
		if !ok {
			continue
		}
		value = unwrapASN1OctetString(value)
		if len(value) != 6 {
			return "", fmt.Errorf("FMSPC found but length is %d, want 6; raw=%s", len(value), strings.ToUpper(hex.EncodeToString(value)))
		}
		return strings.ToUpper(hex.EncodeToString(value)), nil
	}
	return "", fmt.Errorf("FMSPC extension not found in PCK cert")
}

func unwrapASN1OctetString(data []byte) []byte {
	var inner []byte
	if rest, err := asn1.Unmarshal(data, &inner); err == nil && len(rest) == 0 && len(inner) > 0 {
		return inner
	}
	return data
}

func findASN1ValueByOID(data []byte, target asn1.ObjectIdentifier) ([]byte, bool) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	return findASN1ValueByOIDInRaw(raw, target)
}

func findASN1ValueByOIDInRaw(raw asn1.RawValue, target asn1.ObjectIdentifier) ([]byte, bool) {
	if !raw.IsCompound {
		return nil, false
	}

	children, err := parseASN1Children(raw.Bytes)
	if err != nil {
		return nil, false
	}

	for index, child := range children {
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(child.FullBytes, &oid); err == nil && oid.Equal(target) {
			if index+1 < len(children) {
				return children[index+1].FullBytes, true
			}
		}
		if value, ok := findASN1ValueByOIDInRaw(child, target); ok {
			return value, true
		}
	}
	return nil, false
}

func parseASN1Children(data []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	remaining := data
	for len(remaining) > 0 {
		var child asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &child)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		remaining = rest
	}
	return out, nil
}

type PlatformTCBValues struct {
	SGXComponentSVNs []int
	PCESVN           int
}

// evaluatePlatformTCB는 Intel TCB level과의 threshold-style 매칭을 수행합니다.
//
// 이것은 완전한 production TCB 엔진은 아니지만, 적어도 샘플 플랫폼이 주어진 TCB Info JSON의
// 공개된 level 중 하나를 만족하는지는 증명할 수 있습니다.
func evaluatePlatformTCB(pckTCB PlatformTCBValues, tdxMeasurements *TDXMeasurements, levels []TCBLevel) (*TCBLevel, error) {
	tdxSVNs := make([]int, len(tdxMeasurements.TeeTCBSVN))
	for i, value := range tdxMeasurements.TeeTCBSVN {
		tdxSVNs[i] = int(value)
	}

	for _, level := range levels {
		if platformTCBMeetsLevel(pckTCB, tdxSVNs, level.TCB) {
			switch level.TCBStatus {
			case "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded":
				return &level, nil
			default:
				return nil, fmt.Errorf("TCB level matched but status is not acceptable: %s", level.TCBStatus)
			}
		}
	}

	return nil, fmt.Errorf("platform TCB does not satisfy any TCB Info level")
}

func platformTCBMeetsLevel(pckTCB PlatformTCBValues, tdxSVNs []int, level PlatformTCB) bool {
	if len(level.SGXTCBComponents) > len(pckTCB.SGXComponentSVNs) || len(level.TDXTCBComponents) > len(tdxSVNs) {
		return false
	}
	if pckTCB.PCESVN < level.PCESVN {
		return false
	}
	for i, component := range level.SGXTCBComponents {
		if pckTCB.SGXComponentSVNs[i] < component.SVN {
			return false
		}
	}
	for i, component := range level.TDXTCBComponents {
		if tdxSVNs[i] < component.SVN {
			return false
		}
	}
	return true
}

func extractPlatformTCBFromPCKCert(cert *x509.Certificate) (PlatformTCBValues, error) {
	rootValue, err := extractPCKExtensionRoot(cert)
	if err != nil {
		return PlatformTCBValues{}, err
	}

	components := make([]int, 16)
	for i := 0; i < 16; i++ {
		oid := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2, i + 1}
		value, ok := findASN1ValueByOID(rootValue, oid)
		if !ok {
			return PlatformTCBValues{}, fmt.Errorf("missing SGX TCB component OID %s", oid.String())
		}
		component, err := parseASN1Int(value)
		if err != nil {
			return PlatformTCBValues{}, fmt.Errorf("parse SGX TCB component %d: %w", i+1, err)
		}
		components[i] = component
	}

	pcesvnValue, ok := findASN1ValueByOID(rootValue, asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2, 17})
	if !ok {
		return PlatformTCBValues{}, fmt.Errorf("missing PCESVN OID in PCK cert")
	}
	pcesvn, err := parseASN1Int(pcesvnValue)
	if err != nil {
		return PlatformTCBValues{}, fmt.Errorf("parse PCESVN: %w", err)
	}

	return PlatformTCBValues{SGXComponentSVNs: components, PCESVN: pcesvn}, nil
}

func extractPCEIDFromPCKCert(cert *x509.Certificate) (string, error) {
	rootValue, err := extractPCKExtensionRoot(cert)
	if err != nil {
		return "", err
	}
	value, ok := findASN1ValueByOID(rootValue, asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 3})
	if !ok {
		return "", fmt.Errorf("missing PCEID OID in PCK cert")
	}
	value = unwrapASN1OctetString(value)
	if len(value) != 2 {
		return "", fmt.Errorf("unexpected PCEID length: %d", len(value))
	}
	return strings.ToUpper(hex.EncodeToString(value)), nil
}

func verifyTDXModuleAgainstTCBInfo(measurements *TDXMeasurements, module TDXModuleRef) error {
	if module.MRSigner != "" && !strings.EqualFold(bytesToUpperHex(measurements.MRSignerSEAM), module.MRSigner) {
		return fmt.Errorf("TDX module MRSIGNER mismatch: quote=%s tcbInfo=%s", bytesToUpperHex(measurements.MRSignerSEAM), strings.ToUpper(module.MRSigner))
	}
	if err := verifyMaskedHexField("TDX module SEAMATTRIBUTES", measurements.SEAMAttributes, module.Attributes, module.AttributesMask); err != nil {
		return err
	}
	return nil
}

func extractPCKExtensionRoot(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidIntelSGXPCKExtensionRoot) {
			return ext.Value, nil
		}
	}
	return nil, fmt.Errorf("Intel SGX PCK extension root not found")
}

func parseASN1Int(data []byte) (int, error) {
	var out int
	rest, err := asn1.Unmarshal(data, &out)
	if err != nil {
		return 0, err
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("unexpected ASN.1 trailing data")
	}
	return out, nil
}

func compareQEReportWithIdentity(qeReport []byte, identity QEIdentityMinimal) error {
	const (
		qeMiscSelectOffset = 16
		qeAttributesOffset = 48
		qeMREnclaveOffset  = 64
		qeMRSignerOffset   = 128
		qeISVProdIDOffset  = 256
		qeISVSVNOffset     = 258
	)

	miscSelect := qeReport[qeMiscSelectOffset : qeMiscSelectOffset+4]
	attributes := qeReport[qeAttributesOffset : qeAttributesOffset+16]
	mrEnclave := qeReport[qeMREnclaveOffset : qeMREnclaveOffset+32]
	mrSigner := qeReport[qeMRSignerOffset : qeMRSignerOffset+32]
	isvProdID := int(qeReport[qeISVProdIDOffset]) | int(qeReport[qeISVProdIDOffset+1])<<8
	isvSVN := int(qeReport[qeISVSVNOffset]) | int(qeReport[qeISVSVNOffset+1])<<8

	fmt.Println()
	fmt.Println("[QE Report fields]")
	fmt.Println("MISCSELECT:", strings.ToUpper(hex.EncodeToString(miscSelect)))
	fmt.Println("ATTRIBUTES:", strings.ToUpper(hex.EncodeToString(attributes)))
	fmt.Println("MRENCLAVE: ", strings.ToUpper(hex.EncodeToString(mrEnclave)))
	fmt.Println("MRSIGNER:  ", strings.ToUpper(hex.EncodeToString(mrSigner)))
	fmt.Println("ISVPRODID: ", isvProdID)
	fmt.Println("ISVSVN:    ", isvSVN)

	if err := verifyMaskedHexField("QE Identity MISCSELECT", miscSelect, identity.MiscSelect, identity.MiscMask); err != nil {
		return err
	}
	if err := verifyMaskedHexField("QE Identity ATTRIBUTES", attributes, identity.Attributes, identity.AttrMask); err != nil {
		return err
	}
	if identity.MRSigner != "" && !strings.EqualFold(hex.EncodeToString(mrSigner), identity.MRSigner) {
		return fmt.Errorf("QE Identity MRSIGNER mismatch: report=%s identity=%s", strings.ToUpper(hex.EncodeToString(mrSigner)), identity.MRSigner)
	}
	if identity.ISVProdID != 0 && isvProdID != identity.ISVProdID {
		return fmt.Errorf("QE Identity ISVPRODID mismatch: report=%d identity=%d", isvProdID, identity.ISVProdID)
	}
	return checkQETCBLevel(isvSVN, identity.TCBLevels)
}

func verifyMaskedHexField(name string, actual []byte, expectedHex string, maskHex string) error {
	if strings.TrimSpace(expectedHex) == "" || strings.TrimSpace(maskHex) == "" {
		return nil
	}

	expected, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return fmt.Errorf("%s expected hex decode failed: %w", name, err)
	}
	mask, err := hex.DecodeString(strings.TrimSpace(maskHex))
	if err != nil {
		return fmt.Errorf("%s mask hex decode failed: %w", name, err)
	}
	if len(actual) != len(expected) || len(actual) != len(mask) {
		return fmt.Errorf("%s length mismatch: actual=%d expected=%d mask=%d", name, len(actual), len(expected), len(mask))
	}

	maskedActual := make([]byte, len(actual))
	maskedExpected := make([]byte, len(expected))
	for i := range actual {
		maskedActual[i] = actual[i] & mask[i]
		maskedExpected[i] = expected[i] & mask[i]
	}

	if !strings.EqualFold(hex.EncodeToString(maskedActual), hex.EncodeToString(maskedExpected)) {
		return fmt.Errorf("%s mismatch after mask: actual=%s expected=%s mask=%s", name, strings.ToUpper(hex.EncodeToString(maskedActual)), strings.ToUpper(hex.EncodeToString(maskedExpected)), strings.ToUpper(hex.EncodeToString(mask)))
	}
	return nil
}

func checkQETCBLevel(isvSVN int, levels []QETCBLvl) error {
	if len(levels) == 0 {
		fmt.Println("[warn] QE Identity has no tcbLevels")
		return nil
	}

	for _, level := range levels {
		if isvSVN < level.TCB.ISVSVN {
			continue
		}

		fmt.Printf("[QE TCB] matched level: report_isvsvn=%d required_isvsvn=%d status=%s\n", isvSVN, level.TCB.ISVSVN, level.TCBStatus)
		switch level.TCBStatus {
		case "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded":
			return nil
		default:
			return fmt.Errorf("QE TCB status not acceptable: %s", level.TCBStatus)
		}
	}

	return fmt.Errorf("QE ISVSVN %d does not satisfy any QE Identity TCB level", isvSVN)
}
