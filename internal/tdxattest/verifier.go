package tdxattest

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

const (
	CheckIntelFull       = "intel-full"
	CheckPCKChain        = "pck-chain"
	CheckQuoteSignatures = "quote-signatures"
	CheckQuoteCrypto     = "quote-crypto"
	CheckPCKCRL          = "pck-crl"
	CheckRootCRL         = "root-crl"
	CheckTCBInfo         = "tcbinfo"
	CheckQEIdentity      = "qeidentity"
	CheckTDXPolicy       = "tdx-policy"
)

type CheckResult struct {
	Name string
}

type VerificationRequest struct {
	QuoteBytes       []byte
	RootCert         *x509.Certificate
	CollateralSource string
	PCSBaseURL       string
	Collateral       *CollateralBundle
	TCBInfoPath      string
	QEIdentityPath   string
	TCBChainPath     string
	QEChainPath      string
	PCKCRLPath       string
	RootCRLPath      string
	TDXPolicyPath    string
	VerifyTime       time.Time
	IgnoreFreshness  bool
	UsedSampleTime   bool
	Checks           []string
}

type VerificationResult struct {
	ParsedQuote     *ParsedQuote
	TDXMeasurements *TDXMeasurements
	Checks          []CheckResult
}

type quoteEvidence struct {
	ParsedQuote     *ParsedQuote
	TDXMeasurements *TDXMeasurements
	PCKChain        []*x509.Certificate
	PCKLeaf         *x509.Certificate
}

type verificationPlan struct {
	pckChain       bool
	quoteSignature bool
	pckCRL         bool
	rootCRL        bool
	tcbInfo        bool
	qeIdentity     bool
	tdxPolicy      bool
}

func (r *VerificationResult) addCheck(name string) {
	r.Checks = append(r.Checks, CheckResult{Name: name})
}

// VerifyQuoteWithCollateral executes the selected local verification checks.
// With no explicit Checks it preserves the default full Intel-style pipeline.
// It returns structured state for tests and future APIs while keeping the
// current educational CLI output stable.
func VerifyQuoteWithCollateral(req VerificationRequest) (*VerificationResult, error) {
	if req.RootCert == nil {
		return nil, fmt.Errorf("root certificate is required")
	}
	collateralSource := strings.ToLower(strings.TrimSpace(req.CollateralSource))
	if collateralSource == "" {
		collateralSource = CollateralSourceLocal
	}
	if collateralSource != CollateralSourceLocal && collateralSource != CollateralSourcePCS {
		return nil, fmt.Errorf("unsupported collateral source %q; supported sources: %s, %s", req.CollateralSource, CollateralSourceLocal, CollateralSourcePCS)
	}

	plan, err := resolveVerificationPlan(req.Checks, req.TDXPolicyPath)
	if err != nil {
		return nil, err
	}

	result := &VerificationResult{}
	if req.UsedSampleTime {
		fmt.Println("[warn] using sample verification time:", req.VerifyTime.Format(time.RFC3339))
	}

	fmt.Println("[Root CA]")
	printCert(req.RootCert)

	evidence, err := parseAndVerifyQuoteEvidence(req, true)
	if err != nil {
		return nil, err
	}
	result.ParsedQuote = evidence.ParsedQuote
	result.TDXMeasurements = evidence.TDXMeasurements
	if plan.pckChain {
		result.addCheck("PCK certificate chain")
	}

	pckChain := evidence.PCKChain
	pckLeaf := evidence.PCKLeaf
	collateral := req.Collateral
	if collateralSource == CollateralSourcePCS && (plan.pckCRL || plan.rootCRL || plan.tcbInfo || plan.qeIdentity) {
		fmt.Println()
		fmt.Println("[PCS]")
		fmt.Println("Fetching Intel collateral from PCS")
		collateral, err = NewPCSClient(req.PCSBaseURL).FetchCollateral(context.Background(), req.RootCert, pckChain, pckLeaf)
		if err != nil {
			return nil, err
		}
		fmt.Println("Collateral source: Intel PCS")
	}

	if plan.pckCRL {
		if err := verifyPCKCRLFromRequest(req, collateral, pckChain[1], pckLeaf); err != nil {
			return nil, fmt.Errorf("verify PCK CRL: %w", err)
		}
		fmt.Println("[2] PCK CRL signature / freshness / revocation verification: OK")
		result.addCheck("PCK CRL")
	}

	if plan.rootCRL {
		if err := verifyRootCACRLFromRequest(req, collateral, []*x509.Certificate{pckChain[1]}); err != nil {
			return nil, fmt.Errorf("verify Root CA CRL for PCK chain: %w", err)
		}
		fmt.Println("[3] Root CA CRL verification for PCK intermediate: OK")
		result.addCheck("Root CA CRL for PCK intermediate")
	}

	if plan.quoteSignature {
		if err := verifyQuoteLocalSignatures(evidence, true); err != nil {
			return nil, err
		}
		result.addCheck("QE/TDQE report signature")
		result.addCheck("AK hash binding")
		result.addCheck("TDX/SGX quote signature")
	}

	if plan.tcbInfo {
		if err := verifyTCBInfoCollateralFromRequest(req, collateral, pckLeaf, result.TDXMeasurements); err != nil {
			return nil, fmt.Errorf("verify TCB Info collateral: %w", err)
		}
		fmt.Println("[7] TCB Info signature / chain / freshness / FMSPC / TCB level verification: OK")
		result.addCheck("TCB Info collateral")
	}

	if plan.qeIdentity {
		if err := verifyQEIdentityCollateralFromRequest(req, collateral, evidence.ParsedQuote.QEReport); err != nil {
			return nil, fmt.Errorf("verify QE/TDQE Identity collateral: %w", err)
		}
		fmt.Println("[8] QE/TDQE Identity signature / chain / freshness verification: OK")
		result.addCheck("QE/TDQE Identity collateral")
	}

	if plan.tdxPolicy {
		policy, err := loadTDXPolicy(req.TDXPolicyPath)
		if err != nil {
			return nil, fmt.Errorf("load TDX policy: %w", err)
		}
		if policy == nil {
			return nil, fmt.Errorf("TDX policy check requires -tdx-policy")
		}
		if result.TDXMeasurements == nil {
			return nil, fmt.Errorf("TDX policy was provided but quote is not a TDX quote")
		}
		if err := verifyTDXPolicy(result.TDXMeasurements, policy); err != nil {
			return nil, fmt.Errorf("verify TDX measurement policy: %w", err)
		}
		fmt.Println("[9] TDX measurement policy verification: OK")
		result.addCheck("TDX measurement policy")
	}

	return result, nil
}

func verifyPCKCRLFromRequest(req VerificationRequest, collateral *CollateralBundle, issuerCert *x509.Certificate, pckLeaf *x509.Certificate) error {
	if collateral != nil {
		if len(collateral.PCKCRL) == 0 {
			return fmt.Errorf("collateral bundle missing PCK CRL")
		}
		return verifyPCKCRLBytes(collateral.PCKCRL, issuerCert, pckLeaf, req.VerifyTime, req.IgnoreFreshness)
	}
	return verifyPCKCRL(req.PCKCRLPath, issuerCert, pckLeaf, req.VerifyTime, req.IgnoreFreshness)
}

func verifyRootCACRLFromRequest(req VerificationRequest, collateral *CollateralBundle, certs []*x509.Certificate) error {
	if collateral != nil {
		if len(collateral.RootCRL) == 0 {
			return fmt.Errorf("collateral bundle missing Root CA CRL")
		}
		return verifyRootCACRLBytes(collateral.RootCRL, req.RootCert, certs, req.VerifyTime, req.IgnoreFreshness)
	}
	return verifyRootCACRL(req.RootCRLPath, req.RootCert, certs, req.VerifyTime, req.IgnoreFreshness)
}

func verifyTCBInfoCollateralFromRequest(req VerificationRequest, collateral *CollateralBundle, pckLeaf *x509.Certificate, tdxMeasurements *TDXMeasurements) error {
	if collateral != nil {
		if len(collateral.TCBInfoJSON) == 0 {
			return fmt.Errorf("collateral bundle missing TCB Info JSON")
		}
		if len(collateral.TCBSigningChainPEM) == 0 {
			return fmt.Errorf("collateral bundle missing TCB signing chain")
		}
		if len(collateral.RootCRL) == 0 {
			return fmt.Errorf("collateral bundle missing Root CA CRL")
		}
		return verifyTCBInfoCollateralBytes(collateral.TCBInfoJSON, collateral.TCBSigningChainPEM, collateral.RootCRL, req.RootCert, pckLeaf, tdxMeasurements, req.VerifyTime, req.IgnoreFreshness)
	}
	return verifyTCBInfoCollateral(req.TCBInfoPath, req.TCBChainPath, req.RootCRLPath, req.RootCert, pckLeaf, tdxMeasurements, req.VerifyTime, req.IgnoreFreshness)
}

func verifyQEIdentityCollateralFromRequest(req VerificationRequest, collateral *CollateralBundle, qeReport []byte) error {
	if collateral != nil {
		if len(collateral.QEIdentityJSON) == 0 {
			return fmt.Errorf("collateral bundle missing QE identity JSON")
		}
		if len(collateral.QEIdentityChainPEM) == 0 {
			return fmt.Errorf("collateral bundle missing QE identity signing chain")
		}
		if len(collateral.RootCRL) == 0 {
			return fmt.Errorf("collateral bundle missing Root CA CRL")
		}
		return verifyQEIdentityCollateralBytes(collateral.QEIdentityJSON, collateral.QEIdentityChainPEM, collateral.RootCRL, req.RootCert, qeReport, req.VerifyTime, req.IgnoreFreshness)
	}
	return verifyQEIdentityCollateral(req.QEIdentityPath, req.QEChainPath, req.RootCRLPath, req.RootCert, qeReport, req.VerifyTime, req.IgnoreFreshness)
}

func resolveVerificationPlan(checks []string, tdxPolicyPath string) (verificationPlan, error) {
	if len(checks) == 0 {
		return verificationPlan{
			pckChain:       true,
			quoteSignature: true,
			pckCRL:         true,
			rootCRL:        true,
			tcbInfo:        true,
			qeIdentity:     true,
			tdxPolicy:      tdxPolicyPath != "",
		}, nil
	}

	plan := verificationPlan{}
	for _, raw := range checks {
		check := strings.ToLower(strings.TrimSpace(raw))
		if check == "" {
			continue
		}
		switch check {
		case "all", CheckIntelFull:
			plan.pckChain = true
			plan.quoteSignature = true
			plan.pckCRL = true
			plan.rootCRL = true
			plan.tcbInfo = true
			plan.qeIdentity = true
			plan.tdxPolicy = tdxPolicyPath != ""
		case CheckPCKChain:
			plan.pckChain = true
		case CheckQuoteSignatures:
			plan.quoteSignature = true
		case CheckQuoteCrypto:
			plan.pckChain = true
			plan.quoteSignature = true
		case CheckPCKCRL:
			plan.pckCRL = true
		case CheckRootCRL:
			plan.rootCRL = true
		case CheckTCBInfo:
			plan.tcbInfo = true
		case CheckQEIdentity:
			plan.qeIdentity = true
		case CheckTDXPolicy:
			plan.tdxPolicy = true
		default:
			return verificationPlan{}, fmt.Errorf("unsupported verification check %q; supported checks: %s", raw, strings.Join(supportedVerificationChecks(), ", "))
		}
	}

	if plan.quoteSignature || plan.pckCRL || plan.rootCRL || plan.tcbInfo || plan.qeIdentity || plan.tdxPolicy {
		plan.pckChain = true
	}
	return plan, nil
}

func supportedVerificationChecks() []string {
	return []string{
		CheckQuoteCrypto,
		CheckPCKChain,
		CheckQuoteSignatures,
		CheckPCKCRL,
		CheckRootCRL,
		CheckTCBInfo,
		CheckQEIdentity,
		CheckTDXPolicy,
		CheckIntelFull,
	}
}

func parseAndVerifyQuoteEvidence(req VerificationRequest, printDetails bool) (*quoteEvidence, error) {
	if req.RootCert == nil {
		return nil, fmt.Errorf("root certificate is required")
	}

	parsedQuote, err := parseQuote(req.QuoteBytes)
	if err != nil {
		return nil, fmt.Errorf("parse quote: %w", err)
	}
	if printDetails {
		printQuoteSummary(parsedQuote)
	}

	var tdxMeasurements *TDXMeasurements
	if len(parsedQuote.ReportBody) == tdxReportBodySize {
		tdxMeasurements, err = parseTDXMeasurements(parsedQuote)
		if err != nil {
			return nil, fmt.Errorf("parse TDX measurements: %w", err)
		}
		if printDetails {
			printTDXMeasurements(tdxMeasurements)
		}
	}

	if parsedQuote.CertType != certTypePCKCertChain {
		return nil, fmt.Errorf("unsupported certification data type %d; want PCK_CERT_CHAIN=5", parsedQuote.CertType)
	}

	pckChain, err := parsePEMCerts(parsedQuote.CertData)
	if err != nil {
		return nil, fmt.Errorf("parse PCK cert chain from quote certification data: %w", err)
	}
	if len(pckChain) < 2 {
		return nil, fmt.Errorf("need at least PCK leaf + intermediate, got %d cert(s)", len(pckChain))
	}

	if printDetails {
		fmt.Printf("\n[PCK certificates from quote] count=%d\n", len(pckChain))
		for index, cert := range pckChain {
			fmt.Printf("\n--- pck chain cert[%d] ---\n", index)
			printCert(cert)
		}
	}

	pckLeaf := pckChain[0]

	if err := verifyPCKChain(pckLeaf, pckChain[1:], req.RootCert, req.VerifyTime); err != nil {
		return nil, fmt.Errorf("verify PCK cert chain: %w", err)
	}
	if printDetails {
		fmt.Println("\n[1] PCK certificate chain verification: OK")
	}

	return &quoteEvidence{
		ParsedQuote:     parsedQuote,
		TDXMeasurements: tdxMeasurements,
		PCKChain:        pckChain,
		PCKLeaf:         pckLeaf,
	}, nil
}

func verifyQuoteLocalSignatures(evidence *quoteEvidence, printDetails bool) error {
	parsedQuote := evidence.ParsedQuote
	pckLeaf := evidence.PCKLeaf

	if err := verifyQEReportSignature(parsedQuote.QEReport, parsedQuote.QEReportSignature, pckLeaf); err != nil {
		return fmt.Errorf("verify QE/TDQE report signature with PCK cert public key: %w", err)
	}
	if printDetails {
		fmt.Println("[4] QE/TDQE report signature verification: OK")
	}

	if err := verifyAKBinding(parsedQuote.AttestationKey, parsedQuote.AuthData, parsedQuote.QEReport); err != nil {
		return fmt.Errorf("verify AK hash binding in QE/TDQE report_data: %w", err)
	}
	if printDetails {
		fmt.Println("[5] AK hash binding verification: OK")
	}

	if err := verifyQuoteSignature(parsedQuote.HeaderAndBody, parsedQuote.QuoteSignature, parsedQuote.AttestationKey); err != nil {
		return fmt.Errorf("verify quote signature with attestation key: %w", err)
	}
	if printDetails {
		fmt.Println("[6] TDX/SGX quote signature verification: OK")
	}
	return nil
}
