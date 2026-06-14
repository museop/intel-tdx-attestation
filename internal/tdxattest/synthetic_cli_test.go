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
	rootKeyPath := filepath.Join(tmp, "synthetic_root_key.pem")
	rootPath := filepath.Join(tmp, "synthetic_root.pem")
	pckChainPath := filepath.Join(tmp, "synthetic_pck_chain.pem")

	generateRoot := exec.Command("go", "run", "./cmd/tdx-attest", "synthetic-root",
		"-root-key-out", rootKeyPath,
		"-root-out", rootPath,
	)
	generateRoot.Dir = root
	out, err := generateRoot.CombinedOutput()
	if err != nil {
		t.Fatalf("expected synthetic-root command to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "synthetic test root generated") {
		t.Fatalf("expected synthetic root generation result\noutput:\n%s", out)
	}

	generateQuote := exec.Command("go", "run", "./cmd/tdx-attest", "synthetic-quote",
		"-quote-out", quotePath,
		"-root-key", rootKeyPath,
		"-root", rootPath,
		"-pck-chain-out", pckChainPath,
	)
	generateQuote.Dir = root
	out, err = generateQuote.CombinedOutput()
	if err != nil {
		t.Fatalf("expected synthetic-quote command to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "synthetic non-Intel quote generated") {
		t.Fatalf("expected synthetic generation result\noutput:\n%s", out)
	}

	verifySyntheticViaSelectedCheck := exec.Command("go", "run", "./cmd/tdx-attest", "verify",
		"-check", "quote-crypto",
		"-quote", quotePath,
		"-root", rootPath,
	)
	verifySyntheticViaSelectedCheck.Dir = root
	out, err = verifySyntheticViaSelectedCheck.CombinedOutput()
	if err != nil {
		t.Fatalf("expected verify --check quote-crypto command to pass, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "selected quote verification checks are OK") {
		t.Fatalf("expected selected verification result through verify command\noutput:\n%s", out)
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
