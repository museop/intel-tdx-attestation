package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Dir(file)
}

func samplePath(root string, parts ...string) string {
	segments := append([]string{root, "test_data"}, parts...)
	return filepath.Join(segments...)
}

func TestSampleVerificationPassesWithSampleTimeAndIgnoredFreshness(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", ".",
		"-quote", samplePath(root, "quote.dat"),
		"-root", samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem"),
		"-tcbinfo", samplePath(root, "collateral", "tcbinfo.json"),
		"-qeidentity", samplePath(root, "collateral", "qeidentity.json"),
		"-tcb-chain", samplePath(root, "certs", "tcbSigningChain.pem"),
		"-qe-chain", samplePath(root, "certs", "tcbSigningChain.pem"),
		"-sample-time", "2023-02-01T00:00:00Z",
		"-ignore-freshness",
	)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected sample verification to pass, got error: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	checks := []string{
		"[1] PCK certificate chain verification: OK",
		"[2] PCK CRL signature / freshness / revocation verification: OK",
		"[3] Root CA CRL verification for PCK intermediate: OK",
		"[4] QE/TDQE report signature verification: OK",
		"[5] AK hash binding verification: OK",
		"[6] TDX/SGX quote signature verification: OK",
		"[7] TCB Info signature / chain / freshness / FMSPC / TCB level verification: OK",
		"[8] QE/TDQE Identity signature / chain / freshness verification: OK",
		"Matched TCB status: UpToDate",
		"PCK PCEID:  0000",
		"RESULT: basic cryptographic quote chain and partial collateral verification are OK",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q\nfull output:\n%s", check, output)
		}
	}
}

func TestSampleVerificationFailsWithoutFreshnessOverride(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", ".",
		"-quote", samplePath(root, "quote.dat"),
		"-root", samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem"),
		"-tcbinfo", samplePath(root, "collateral", "tcbinfo.json"),
		"-qeidentity", samplePath(root, "collateral", "qeidentity.json"),
		"-tcb-chain", samplePath(root, "certs", "tcbSigningChain.pem"),
		"-qe-chain", samplePath(root, "certs", "tcbSigningChain.pem"),
		"-sample-time", "2023-02-01T00:00:00Z",
	)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected freshness validation to fail without override\noutput:\n%s", out)
	}

	output := string(out)
	if !strings.Contains(output, "issueDate is in the future") && !strings.Contains(output, "thisUpdate is in the future") {
		t.Fatalf("expected freshness failure in output\nfull output:\n%s", output)
	}
}

func TestSampleTDXPolicyPasses(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", ".",
		"-sample-time", "2023-02-01T00:00:00Z",
		"-ignore-freshness",
		"-tdx-policy", samplePath(root, "tdx_policy_sample.json"),
	)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected TDX policy verification to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "[9] TDX measurement policy verification: OK") {
		t.Fatalf("expected TDX policy verification output\nfull output:\n%s", out)
	}
}

func TestSampleTDXPolicyFailsOnMismatch(t *testing.T) {
	root := repoRoot(t)
	badPolicy := filepath.Join(t.TempDir(), "bad_policy.json")
	if err := os.WriteFile(badPolicy, []byte(`{"mrtd":"00"}`), 0o644); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}

	cmd := exec.Command("go", "run", ".",
		"-sample-time", "2023-02-01T00:00:00Z",
		"-ignore-freshness",
		"-tdx-policy", badPolicy,
	)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected TDX policy mismatch to fail\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "MRTD mismatch") {
		t.Fatalf("expected MRTD mismatch in output\nfull output:\n%s", out)
	}
}
