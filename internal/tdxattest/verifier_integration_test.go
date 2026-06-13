package tdxattest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("failed to find repo root from %s", file)
		}
		dir = parent
	}
}

func samplePath(root string, parts ...string) string {
	segments := append([]string{root, "test_data"}, parts...)
	return filepath.Join(segments...)
}

func TestVerifyQuoteWithCollateralReturnsStructuredResult(t *testing.T) {
	root := repoRoot(t)
	quoteBytes, err := os.ReadFile(samplePath(root, "quote.dat"))
	if err != nil {
		t.Fatalf("read quote: %v", err)
	}
	rootCert, err := parseOneCert(mustReadFile(t, samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem")))
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	result, err := VerifyQuoteWithCollateral(VerificationRequest{
		QuoteBytes:      quoteBytes,
		RootCert:        rootCert,
		TCBInfoPath:     samplePath(root, "collateral", "tcbinfo.json"),
		QEIdentityPath:  samplePath(root, "collateral", "qeidentity.json"),
		TCBChainPath:    samplePath(root, "certs", "tcbSigningChain.pem"),
		QEChainPath:     samplePath(root, "certs", "tcbSigningChain.pem"),
		PCKCRLPath:      samplePath(root, "certs", "pck_platform_crl.der"),
		RootCRLPath:     samplePath(root, "certs", "IntelSGXRootCA.crl"),
		VerifyTime:      mustParseTime(t, "2023-02-01T00:00:00Z"),
		IgnoreFreshness: true,
		UsedSampleTime:  true,
	})
	if err != nil {
		t.Fatalf("expected structured verification to pass: %v", err)
	}
	if result.ParsedQuote == nil || result.TDXMeasurements == nil {
		t.Fatalf("expected parsed quote and TDX measurements in result")
	}
	if len(result.Checks) != 8 {
		t.Fatalf("expected 8 checks without optional TDX policy, got %d", len(result.Checks))
	}
}

func mustParseTime(t *testing.T, raw string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse time %s: %v", raw, err)
	}
	return parsed
}
