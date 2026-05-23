package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	defaultQuotePath      = "test_data/quote.dat"
	defaultRootPath       = "test_data/certs/Intel_SGX_Provisioning_Certification_RootCA.pem"
	defaultTCBInfoPath    = "test_data/collateral/tcbinfo.json"
	defaultQEIdentityPath = "test_data/collateral/qeidentity.json"
	defaultTCBChainPath   = "test_data/certs/tcbSigningChain.pem"
	defaultQEChainPath    = "test_data/certs/tcbSigningChain.pem"
	defaultPCKCRLPath     = "test_data/certs/pck_platform_crl.der"
	defaultRootCRLPath    = "test_data/certs/IntelSGXRootCA.crl"
	defaultTDXPolicyPath  = ""
)

// Config는 검증 결과에 영향을 주는 외부 입력을 한곳에 모아 둔 구조체입니다.
//
// verifier는 Quote 같은 증거 데이터와, 인증서/CRL/서명된 JSON 같은 collateral을
// 함께 받아야 합니다. 이 값을 한 구조체로 묶어 두면 run()의 검증 흐름을 읽기 쉬워집니다.
type Config struct {
	QuotePath       string
	RootPath        string
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

func main() {
	cfg, err := parseConfig(os.Args[1:])
	must(err, "parse flags")
	must(run(cfg), "verify quote")
}

// parseConfig는 CLI 플래그를 실제 검증 계획으로 바꿉니다.
//
// 특히 -sample-time, -ignore-freshness 같은 샘플 재현용 옵션은 이후의 여러 검증
// 단계에 공통으로 영향을 주므로 run()와 분리해 두는 편이 이해하기 쉽습니다.
func parseConfig(args []string) (Config, error) {
	fs := flag.NewFlagSet("intel-tdx-attestation", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	quotePath := fs.String("quote", defaultQuotePath, "TDX/SGX DCAP quote file")
	rootPath := fs.String("root", defaultRootPath, "Intel SGX Root CA certificate PEM/DER")
	tcbInfoPath := fs.String("tcbinfo", defaultTCBInfoPath, "Intel TCB Info JSON")
	qeIdentityPath := fs.String("qeidentity", defaultQEIdentityPath, "Intel QE/TDQE Identity JSON")
	tcbChainPath := fs.String("tcb-chain", defaultTCBChainPath, "Intel TCB signing cert chain PEM")
	qeChainPath := fs.String("qe-chain", defaultQEChainPath, "Intel QE/TDQE identity signing cert chain PEM")
	pckCRLPath := fs.String("pck-crl", defaultPCKCRLPath, "Intel PCK CRL file (DER or PEM)")
	rootCRLPath := fs.String("root-crl", defaultRootCRLPath, "Intel SGX Root CA CRL file (DER or PEM)")
	tdxPolicyPath := fs.String("tdx-policy", defaultTDXPolicyPath, "optional TDX measurement policy JSON")
	sampleTime := fs.String("sample-time", "", "verification time for sample collateral, e.g. 2023-02-01T00:00:00Z")
	ignoreFreshness := fs.Bool("ignore-freshness", false, "ignore collateral and CRL freshness checks")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		QuotePath:       *quotePath,
		RootPath:        *rootPath,
		TCBInfoPath:     *tcbInfoPath,
		QEIdentityPath:  *qeIdentityPath,
		TCBChainPath:    *tcbChainPath,
		QEChainPath:     *qeChainPath,
		PCKCRLPath:      *pckCRLPath,
		RootCRLPath:     *rootCRLPath,
		TDXPolicyPath:   *tdxPolicyPath,
		VerifyTime:      time.Now().UTC(),
		IgnoreFreshness: *ignoreFreshness,
	}

	if *sampleTime != "" {
		verifyTime, err := time.Parse(time.RFC3339, *sampleTime)
		if err != nil {
			return Config{}, fmt.Errorf("parse sample-time: %w", err)
		}
		cfg.VerifyTime = verifyTime.UTC()
		cfg.UsedSampleTime = true
	}

	return cfg, nil
}

// run은 검증기를 위에서 아래로 순서대로 실행합니다.
//
// 이 순서는 의도적입니다. 먼저 증거(Quote)를 파싱하고, 그다음 인증서/CRL 상태를
// 확인한 뒤, Quote 서명을 검증하고, Intel collateral을 검증하고, 마지막으로 선택적인
// 애플리케이션별 TDX measurement 정책 비교를 수행합니다.
func run(cfg Config) error {
	if cfg.UsedSampleTime {
		fmt.Println("[warn] using sample verification time:", cfg.VerifyTime.Format(time.RFC3339))
	}

	quoteBytes, err := os.ReadFile(cfg.QuotePath)
	if err != nil {
		return fmt.Errorf("read quote: %w", err)
	}

	rootBytes, err := os.ReadFile(cfg.RootPath)
	if err != nil {
		return fmt.Errorf("read Intel root CA cert: %w", err)
	}

	rootCert, err := parseOneCert(rootBytes)
	if err != nil {
		return fmt.Errorf("parse Intel root CA cert: %w", err)
	}

	fmt.Println("[Intel Root CA]")
	printCert(rootCert)

	parsedQuote, err := parseQuote(quoteBytes)
	if err != nil {
		return fmt.Errorf("parse quote: %w", err)
	}
	printQuoteSummary(parsedQuote)

	var tdxMeasurements *TDXMeasurements
	if len(parsedQuote.ReportBody) == tdxReportBodySize {
		tdxMeasurements, err = parseTDXMeasurements(parsedQuote)
		if err != nil {
			return fmt.Errorf("parse TDX measurements: %w", err)
		}
		printTDXMeasurements(tdxMeasurements)
	}

	if parsedQuote.CertType != certTypePCKCertChain {
		return fmt.Errorf("unsupported certification data type %d; want PCK_CERT_CHAIN=5", parsedQuote.CertType)
	}

	pckChain, err := parsePEMCerts(parsedQuote.CertData)
	if err != nil {
		return fmt.Errorf("parse PCK cert chain from quote certification data: %w", err)
	}
	if len(pckChain) < 2 {
		return fmt.Errorf("need at least PCK leaf + intermediate, got %d cert(s)", len(pckChain))
	}

	fmt.Printf("\n[PCK certificates from quote] count=%d\n", len(pckChain))
	for index, cert := range pckChain {
		fmt.Printf("\n--- pck chain cert[%d] ---\n", index)
		printCert(cert)
	}

	pckLeaf := pckChain[0]

	if err := verifyPCKChain(pckLeaf, pckChain[1:], rootCert, cfg.VerifyTime); err != nil {
		return fmt.Errorf("verify PCK cert chain: %w", err)
	}
	fmt.Println("\n[1] PCK certificate chain verification: OK")

	if err := verifyPCKCRL(cfg.PCKCRLPath, pckChain[1], pckLeaf, cfg.VerifyTime, cfg.IgnoreFreshness); err != nil {
		return fmt.Errorf("verify PCK CRL: %w", err)
	}
	fmt.Println("[2] PCK CRL signature / freshness / revocation verification: OK")

	if err := verifyRootCACRL(cfg.RootCRLPath, rootCert, []*x509.Certificate{pckChain[1]}, cfg.VerifyTime, cfg.IgnoreFreshness); err != nil {
		return fmt.Errorf("verify Root CA CRL for PCK chain: %w", err)
	}
	fmt.Println("[3] Root CA CRL verification for PCK intermediate: OK")

	if err := verifyQEReportSignature(parsedQuote.QEReport, parsedQuote.QEReportSignature, pckLeaf); err != nil {
		return fmt.Errorf("verify QE/TDQE report signature with PCK cert public key: %w", err)
	}
	fmt.Println("[4] QE/TDQE report signature verification: OK")

	if err := verifyAKBinding(parsedQuote.AttestationKey, parsedQuote.AuthData, parsedQuote.QEReport); err != nil {
		return fmt.Errorf("verify AK hash binding in QE/TDQE report_data: %w", err)
	}
	fmt.Println("[5] AK hash binding verification: OK")

	if err := verifyQuoteSignature(parsedQuote.HeaderAndBody, parsedQuote.QuoteSignature, parsedQuote.AttestationKey); err != nil {
		return fmt.Errorf("verify quote signature with attestation key: %w", err)
	}
	fmt.Println("[6] TDX/SGX quote signature verification: OK")

	if err := verifyTCBInfoCollateral(cfg.TCBInfoPath, cfg.TCBChainPath, cfg.RootCRLPath, rootCert, pckLeaf, tdxMeasurements, cfg.VerifyTime, cfg.IgnoreFreshness); err != nil {
		return fmt.Errorf("verify TCB Info collateral: %w", err)
	}
	fmt.Println("[7] TCB Info signature / chain / freshness / FMSPC / TCB level verification: OK")

	if err := verifyQEIdentityCollateral(cfg.QEIdentityPath, cfg.QEChainPath, cfg.RootCRLPath, rootCert, parsedQuote.QEReport, cfg.VerifyTime, cfg.IgnoreFreshness); err != nil {
		return fmt.Errorf("verify QE/TDQE Identity collateral: %w", err)
	}
	fmt.Println("[8] QE/TDQE Identity signature / chain / freshness verification: OK")

	policy, err := loadTDXPolicy(cfg.TDXPolicyPath)
	if err != nil {
		return fmt.Errorf("load TDX policy: %w", err)
	}
	if policy != nil {
		if tdxMeasurements == nil {
			return fmt.Errorf("TDX policy was provided but quote is not a TDX quote")
		}
		if err := verifyTDXPolicy(tdxMeasurements, policy); err != nil {
			return fmt.Errorf("verify TDX measurement policy: %w", err)
		}
		fmt.Println("[9] TDX measurement policy verification: OK")
	}

	printFinalSummary()
	return nil
}

func printFinalSummary() {
	fmt.Println()
	fmt.Println("RESULT: basic cryptographic quote chain and partial collateral verification are OK")
	fmt.Println()
	fmt.Println("Verified:")
	fmt.Println("  Intel Root CA -> PCK intermediate -> PCK leaf")
	fmt.Println("  PCK CRL signature / freshness / non-revoked leaf serial")
	fmt.Println("  Root CA CRL signature / freshness / non-revoked root-issued intermediates/signers")
	fmt.Println("  PCK leaf public key -> QE/TDQE report signature")
	fmt.Println("  QE/TDQE report_data[0:32] -> SHA256(attestation_key || auth_data)")
	fmt.Println("  Attestation key -> quote signature over quote header + report body")
	fmt.Println("  TCB Info JSON signature")
	fmt.Println("  TCB Info signing certificate chain")
	fmt.Println("  TCB Info issueDate / nextUpdate")
	fmt.Println("  PCK cert FMSPC / PCEID == TCB Info")
	fmt.Println("  PCK SGX component SVN / PCESVN + quote TEE_TCB_SVN -> matched TCB Info level")
	fmt.Println("  TCB Info TDX module MRSIGNER / SEAMATTRIBUTES policy")
	fmt.Println("  QE/TDQE Identity JSON signature")
	fmt.Println("  QE/TDQE Identity signing certificate chain")
	fmt.Println("  QE/TDQE Identity issueDate / nextUpdate")
	fmt.Println("  QE Report MISCSELECT / ATTRIBUTES masks")
	fmt.Println("  QE Report MRSIGNER / ISVPRODID / ISVSVN basic policy")
	fmt.Println()
	fmt.Println("Not verified yet:")
	fmt.Println("  Additional TCB evaluation nuance beyond current SGX component SVN / PCESVN / TEE_TCB_SVN threshold matching")
	fmt.Println("  Remaining QE/TDQE Identity policy beyond masked miscselect / attributes and basic signer/product/TCB checks")
	fmt.Println("  TDX measurement policy comparison when no external policy JSON is provided")
	fmt.Println("  MRTD/RTMR/REPORTDATA/ATTRIBUTES policy")
	fmt.Println("  REPORTDATA challenge/session binding")
}

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", context, err)
		os.Exit(1)
	}
}
