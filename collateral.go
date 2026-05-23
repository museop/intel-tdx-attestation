package main

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

type TCBInfoMinimal struct {
	ID         string `json:"id"`
	Version    int    `json:"version"`
	IssueDate  string `json:"issueDate"`
	NextUpdate string `json:"nextUpdate"`
	FMSPC      string `json:"fmspc"`
	PCEID      string `json:"pceId"`
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

func verifyTCBInfoCollateral(
	tcbInfoPath string,
	tcbChainPath string,
	rootCert *x509.Certificate,
	pckLeaf *x509.Certificate,
	verifyTime time.Time,
	ignoreFreshness bool,
) error {
	raw, err := os.ReadFile(tcbInfoPath)
	if err != nil {
		return fmt.Errorf("read TCB Info JSON: %w", err)
	}

	var signed SignedTCBInfo
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("parse signed TCB Info: %w", err)
	}

	if len(signed.TCBInfo) == 0 {
		return fmt.Errorf("tcbInfo field missing")
	}

	chain, err := loadCertChain(tcbChainPath)
	if err != nil {
		return fmt.Errorf("load TCB signing chain: %w", err)
	}

	if len(chain) == 0 {
		return fmt.Errorf("empty TCB signing chain")
	}

	signingCert := chain[0]

	if err := verifyCertChain(signingCert, chain[1:], rootCert, verifyTime); err != nil {
		return fmt.Errorf("verify TCB signing cert chain: %w", err)
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

	fmt.Println()
	fmt.Println("[TCB Info]")
	fmt.Println("ID:        ", tcb.ID)
	fmt.Println("Version:   ", tcb.Version)
	fmt.Println("IssueDate: ", tcb.IssueDate)
	fmt.Println("NextUpdate:", tcb.NextUpdate)
	fmt.Println("FMSPC:     ", tcb.FMSPC)
	fmt.Println("PCEID:     ", tcb.PCEID)
	fmt.Println("PCK FMSPC: ", pckFMSPC)

	return nil
}

func verifyQEIdentityCollateral(
	qeIdentityPath string,
	qeChainPath string,
	rootCert *x509.Certificate,
	qeReport []byte,
	verifyTime time.Time,
	ignoreFreshness bool,
) error {
	raw, err := os.ReadFile(qeIdentityPath)
	if err != nil {
		return fmt.Errorf("read QE Identity JSON: %w", err)
	}

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

	chain, err := loadCertChain(qeChainPath)
	if err != nil {
		return fmt.Errorf("load QE identity signing chain: %w", err)
	}

	if len(chain) == 0 {
		return fmt.Errorf("empty QE identity signing chain")
	}

	signingCert := chain[0]

	if err := verifyCertChain(signingCert, chain[1:], rootCert, verifyTime); err != nil {
		return fmt.Errorf("verify QE identity signing cert chain: %w", err)
	}

	if err := verifyIntelJSONSignature(signingCert, identityRaw, signed.Signature); err != nil {
		return fmt.Errorf("verify QE Identity JSON signature: %w", err)
	}

	var id QEIdentityMinimal
	if err := json.Unmarshal(identityRaw, &id); err != nil {
		return fmt.Errorf("parse QE Identity body: %w", err)
	}

	if err := verifyCollateralFreshness("QE Identity", id.IssueDate, id.NextUpdate, verifyTime, ignoreFreshness); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("[QE/TDQE Identity]")
	fmt.Println("Kind:      ", identityKind)
	fmt.Println("ID:        ", id.ID)
	fmt.Println("Version:   ", id.Version)
	fmt.Println("IssueDate: ", id.IssueDate)
	fmt.Println("NextUpdate:", id.NextUpdate)
	fmt.Println("MRSigner:  ", id.MRSigner)
	fmt.Println("ISVProdID: ", id.ISVProdID)

	if len(qeReport) >= qeReportSize {
		if err := compareQEReportWithIdentity(qeReport, id); err != nil {
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

	switch len(sig) {
	case 64:
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])

		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("raw ECDSA signature invalid")
		}

		return nil

	default:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("ASN.1 ECDSA signature invalid")
		}

		return nil
	}
}

func verifyCollateralFreshness(
	name string,
	issueDate string,
	nextUpdate string,
	verifyTime time.Time,
	ignoreFreshness bool,
) error {
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

func parseIntelTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000000Z",
	}

	var lastErr error
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
		lastErr = err
	}

	return time.Time{}, lastErr
}

func loadCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parsePEMCerts(raw)
}

func verifyCertChain(
	leaf *x509.Certificate,
	chain []*x509.Certificate,
	rootCert *x509.Certificate,
	verifyTime time.Time,
) error {
	intermediates := x509.NewCertPool()

	for _, cert := range chain {
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

func extractFMSPCFromPCKCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		// Intel PCK cert usually has one top-level SGX extension:
		//   1.2.840.113741.1.13.1
		//
		// FMSPC is nested inside this extension as:
		//   1.2.840.113741.1.13.1.4
		if !ext.Id.Equal(oidIntelSGXPCKExtensionRoot) &&
			!ext.Id.Equal(oidIntelSGXExtensionFMSPC) {
			continue
		}

		// Rare/simple case: FMSPC directly appears as top-level extension.
		if ext.Id.Equal(oidIntelSGXExtensionFMSPC) {
			value := unwrapASN1OctetString(ext.Value)
			if len(value) == 6 {
				return strings.ToUpper(hex.EncodeToString(value)), nil
			}
		}

		// Common case: parse nested Intel SGX PCK extension.
		value, ok := findASN1ValueByOID(ext.Value, oidIntelSGXExtensionFMSPC)
		if ok {
			value = unwrapASN1OctetString(value)

			if len(value) != 6 {
				return "", fmt.Errorf("FMSPC found but length is %d, want 6; raw=%s",
					len(value),
					strings.ToUpper(hex.EncodeToString(value)),
				)
			}

			return strings.ToUpper(hex.EncodeToString(value)), nil
		}
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
	// If this node is a SEQUENCE/SET, parse its children.
	if raw.IsCompound {
		children, err := parseASN1Children(raw.Bytes)
		if err != nil {
			return nil, false
		}

		for i := 0; i < len(children); i++ {
			child := children[i]

			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(child.FullBytes, &oid); err == nil && oid.Equal(target) {
				// Common Intel layout:
				//   SEQUENCE {
				//     OBJECT IDENTIFIER <target>
				//     OCTET STRING <value>
				//   }
				if i+1 < len(children) {
					return children[i+1].FullBytes, true
				}
			}

			if v, ok := findASN1ValueByOIDInRaw(child, target); ok {
				return v, true
			}
		}
	}

	return nil, false
}

func parseASN1Children(data []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue

	rest := data
	for len(rest) > 0 {
		var child asn1.RawValue

		r, err := asn1.Unmarshal(rest, &child)
		if err != nil {
			return nil, err
		}

		out = append(out, child)
		rest = r
	}

	return out, nil
}
func compareQEReportWithIdentity(qeReport []byte, id QEIdentityMinimal) error {
	// SGX QE Report body offsets for the 384-byte report body layout.
	// These are for the QE/TDQE report embedded inside the quote signature data,
	// not for the TDX TD report body.
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

	if id.MRSigner != "" && !strings.EqualFold(hex.EncodeToString(mrSigner), id.MRSigner) {
		return fmt.Errorf(
			"QE Identity MRSIGNER mismatch: report=%s identity=%s",
			strings.ToUpper(hex.EncodeToString(mrSigner)),
			id.MRSigner,
		)
	}

	if id.ISVProdID != 0 && isvProdID != id.ISVProdID {
		return fmt.Errorf("QE Identity ISVPRODID mismatch: report=%d identity=%d", isvProdID, id.ISVProdID)
	}

	if err := checkQETCBLevel(isvSVN, id.TCBLevels); err != nil {
		return err
	}

	return nil
}

func checkQETCBLevel(isvSVN int, levels []QETCBLvl) error {
	if len(levels) == 0 {
		fmt.Println("[warn] QE Identity has no tcbLevels")
		return nil
	}

	for _, lv := range levels {
		if isvSVN >= lv.TCB.ISVSVN {
			fmt.Printf("[QE TCB] matched level: report_isvsvn=%d required_isvsvn=%d status=%s\n",
				isvSVN,
				lv.TCB.ISVSVN,
				lv.TCBStatus,
			)

			switch lv.TCBStatus {
			case "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded":
				return nil
			default:
				return fmt.Errorf("QE TCB status not acceptable: %s", lv.TCBStatus)
			}
		}
	}

	return fmt.Errorf("QE ISVSVN %d does not satisfy any QE Identity TCB level", isvSVN)
}
