package tdxattest

import (
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
	QuotePath        string
	RootPath         string
	CollateralSource string
	PCSBaseURL       string
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

func DefaultConfig() Config {
	return Config{
		QuotePath:        defaultQuotePath,
		RootPath:         defaultRootPath,
		CollateralSource: CollateralSourceLocal,
		PCSBaseURL:       defaultPCSBaseURL,
		TCBInfoPath:      defaultTCBInfoPath,
		QEIdentityPath:   defaultQEIdentityPath,
		TCBChainPath:     defaultTCBChainPath,
		QEChainPath:      defaultQEChainPath,
		PCKCRLPath:       defaultPCKCRLPath,
		RootCRLPath:      defaultRootCRLPath,
		TDXPolicyPath:    defaultTDXPolicyPath,
		VerifyTime:       time.Now().UTC(),
	}
}

// RunVerify는 CLI 파일 입력을 검증 요청으로 바꾼 뒤 구조화된 verifier pipeline을 실행합니다.
func RunVerify(cfg Config) error {
	quoteBytes, err := os.ReadFile(cfg.QuotePath)
	if err != nil {
		return fmt.Errorf("read quote: %w", err)
	}

	rootBytes, err := os.ReadFile(cfg.RootPath)
	if err != nil {
		return fmt.Errorf("read root CA cert: %w", err)
	}

	rootCert, err := parseOneCert(rootBytes)
	if err != nil {
		return fmt.Errorf("parse root CA cert: %w", err)
	}

	result, err := VerifyQuoteWithCollateral(VerificationRequest{
		QuoteBytes:       quoteBytes,
		RootCert:         rootCert,
		CollateralSource: cfg.CollateralSource,
		PCSBaseURL:       cfg.PCSBaseURL,
		TCBInfoPath:      cfg.TCBInfoPath,
		QEIdentityPath:   cfg.QEIdentityPath,
		TCBChainPath:     cfg.TCBChainPath,
		QEChainPath:      cfg.QEChainPath,
		PCKCRLPath:       cfg.PCKCRLPath,
		RootCRLPath:      cfg.RootCRLPath,
		TDXPolicyPath:    cfg.TDXPolicyPath,
		VerifyTime:       cfg.VerifyTime,
		IgnoreFreshness:  cfg.IgnoreFreshness,
		UsedSampleTime:   cfg.UsedSampleTime,
		Checks:           cfg.Checks,
	})
	if err != nil {
		return err
	}

	if len(cfg.Checks) == 0 {
		printFinalSummary()
	} else {
		printSelectedSummary(result.Checks)
	}
	return nil
}

func printSelectedSummary(checks []CheckResult) {
	fmt.Println()
	fmt.Println("RESULT: selected quote verification checks are OK")
	fmt.Println()
	fmt.Println("Verified:")
	for _, check := range checks {
		fmt.Println(" ", check.Name)
	}
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
