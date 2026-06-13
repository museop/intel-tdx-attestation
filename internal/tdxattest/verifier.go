package tdxattest

import (
	"crypto/x509"
	"fmt"
	"time"
)

type CheckResult struct {
	Name string
}

type VerificationRequest struct {
	QuoteBytes      []byte
	RootCert        *x509.Certificate
	TCBInfoPath     string
	QEIdentityPath  string
	TCBChainPath    string
	QEChainPath     string
	PCKCRLPath      string
	RootCRLPath     string
	TDXPolicyPath   string
	VerifyTime      time.Time
	IgnoreFreshness bool
	UsedSampleTime  bool
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

func (r *VerificationResult) addCheck(name string) {
	r.Checks = append(r.Checks, CheckResult{Name: name})
}

// VerifyQuoteWithCollateral executes the full Intel-style local verification
// pipeline. It returns structured state for tests and future APIs while keeping
// the current educational CLI output stable.
func VerifyQuoteWithCollateral(req VerificationRequest) (*VerificationResult, error) {
	if req.RootCert == nil {
		return nil, fmt.Errorf("root certificate is required")
	}

	result := &VerificationResult{}
	if req.UsedSampleTime {
		fmt.Println("[warn] using sample verification time:", req.VerifyTime.Format(time.RFC3339))
	}

	fmt.Println("[Intel Root CA]")
	printCert(req.RootCert)

	evidence, err := parseAndVerifyQuoteEvidence(req, true)
	if err != nil {
		return nil, err
	}
	result.ParsedQuote = evidence.ParsedQuote
	result.TDXMeasurements = evidence.TDXMeasurements
	result.addCheck("PCK certificate chain")

	pckChain := evidence.PCKChain
	pckLeaf := evidence.PCKLeaf

	if err := verifyPCKCRL(req.PCKCRLPath, pckChain[1], pckLeaf, req.VerifyTime, req.IgnoreFreshness); err != nil {
		return nil, fmt.Errorf("verify PCK CRL: %w", err)
	}
	fmt.Println("[2] PCK CRL signature / freshness / revocation verification: OK")
	result.addCheck("PCK CRL")

	if err := verifyRootCACRL(req.RootCRLPath, req.RootCert, []*x509.Certificate{pckChain[1]}, req.VerifyTime, req.IgnoreFreshness); err != nil {
		return nil, fmt.Errorf("verify Root CA CRL for PCK chain: %w", err)
	}
	fmt.Println("[3] Root CA CRL verification for PCK intermediate: OK")
	result.addCheck("Root CA CRL for PCK intermediate")

	if err := verifyQuoteLocalSignatures(evidence, true); err != nil {
		return nil, err
	}
	result.addCheck("QE/TDQE report signature")
	result.addCheck("AK hash binding")
	result.addCheck("TDX/SGX quote signature")

	if err := verifyTCBInfoCollateral(req.TCBInfoPath, req.TCBChainPath, req.RootCRLPath, req.RootCert, pckLeaf, result.TDXMeasurements, req.VerifyTime, req.IgnoreFreshness); err != nil {
		return nil, fmt.Errorf("verify TCB Info collateral: %w", err)
	}
	fmt.Println("[7] TCB Info signature / chain / freshness / FMSPC / TCB level verification: OK")
	result.addCheck("TCB Info collateral")

	if err := verifyQEIdentityCollateral(req.QEIdentityPath, req.QEChainPath, req.RootCRLPath, req.RootCert, evidence.ParsedQuote.QEReport, req.VerifyTime, req.IgnoreFreshness); err != nil {
		return nil, fmt.Errorf("verify QE/TDQE Identity collateral: %w", err)
	}
	fmt.Println("[8] QE/TDQE Identity signature / chain / freshness verification: OK")
	result.addCheck("QE/TDQE Identity collateral")

	policy, err := loadTDXPolicy(req.TDXPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load TDX policy: %w", err)
	}
	if policy != nil {
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
