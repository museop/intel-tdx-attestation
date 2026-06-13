package tdxattest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyntheticCLIEndToEnd(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	quotePath := filepath.Join(tmp, "synthetic_quote.dat")
	rootPath := filepath.Join(tmp, "synthetic_root.pem")
	pckChainPath := filepath.Join(tmp, "synthetic_pck_chain.pem")

	generate := exec.Command("go", "run", "./cmd/tdx-attest", "synthesize",
		"-quote-out", quotePath,
		"-root-out", rootPath,
		"-pck-chain-out", pckChainPath,
	)
	generate.Dir = root
	out, err := generate.CombinedOutput()
	if err != nil {
		t.Fatalf("expected synthesize command to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "synthetic non-Intel quote generated") {
		t.Fatalf("expected synthetic generation result\noutput:\n%s", out)
	}

	verifySyntheticViaVerify := exec.Command("go", "run", "./cmd/tdx-attest", "verify",
		"-mode", "synthetic",
		"-quote", quotePath,
		"-root", rootPath,
	)
	verifySyntheticViaVerify.Dir = root
	out, err = verifySyntheticViaVerify.CombinedOutput()
	if err != nil {
		t.Fatalf("expected verify --mode synthetic command to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "synthetic non-Intel quote cryptographic verification is OK") {
		t.Fatalf("expected synthetic verification result through verify command\noutput:\n%s", out)
	}

	verifyAsIntel := exec.Command("go", "run", "./cmd/tdx-attest", "verify",
		"-quote", quotePath,
		"-root", samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem"),
		"-sample-time", "2023-02-01T00:00:00Z",
		"-ignore-freshness",
	)
	verifyAsIntel.Dir = root
	out, err = verifyAsIntel.CombinedOutput()
	if err == nil {
		t.Fatalf("expected synthetic quote to fail on Intel verification path\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "verify PCK cert chain") {
		t.Fatalf("expected Intel verification path to fail at PCK chain\noutput:\n%s", out)
	}
}
