package tdxattest

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSyntheticQuoteVerifiesWithSyntheticRoot(t *testing.T) {
	bundle, err := generateSyntheticQuote(bytes.NewReader(deterministicBytes(8192)), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("generate synthetic quote: %v", err)
	}
	rootCert, err := parseOneCert(bundle.RootCertPEM)
	if err != nil {
		t.Fatalf("parse synthetic root: %v", err)
	}
	parsed, err := VerifySyntheticQuoteCrypto(bundle.Quote, rootCert, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("expected synthetic quote to verify: %v", err)
	}
	if parsed.Version != syntheticQuoteVersion {
		t.Fatalf("unexpected quote version: got %d", parsed.Version)
	}
	if len(parsed.ReportBody) != tdxReportBodySize {
		t.Fatalf("unexpected report body size: got %d", len(parsed.ReportBody))
	}
}

func TestSyntheticQuoteFailsWithIntelRoot(t *testing.T) {
	bundle, err := generateSyntheticQuote(bytes.NewReader(deterministicBytes(8192)), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("generate synthetic quote: %v", err)
	}
	intelRoot, err := parseOneCert(mustReadFile(t, samplePath(repoRoot(t), "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem")))
	if err != nil {
		t.Fatalf("parse Intel root: %v", err)
	}
	_, err = VerifySyntheticQuoteCrypto(bundle.Quote, intelRoot, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err == nil {
		t.Fatalf("expected synthetic quote to fail with Intel root")
	}
	if !strings.Contains(err.Error(), "verify PCK cert chain") {
		t.Fatalf("expected PCK chain failure, got: %v", err)
	}
}

func TestSyntheticQuoteTamperFailures(t *testing.T) {
	bundle, err := generateSyntheticQuote(bytes.NewReader(deterministicBytes(8192)), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("generate synthetic quote: %v", err)
	}
	rootCert, err := parseOneCert(bundle.RootCertPEM)
	if err != nil {
		t.Fatalf("parse synthetic root: %v", err)
	}
	parsed, err := parseQuote(bundle.Quote)
	if err != nil {
		t.Fatalf("parse synthetic quote: %v", err)
	}

	cases := []struct {
		name     string
		mutate   func([]byte)
		wantText string
	}{
		{
			name: "quote signature",
			mutate: func(q []byte) {
				sigStart := len(parsed.HeaderAndBody) + 4
				q[sigStart] ^= 0x01
			},
			wantText: "verify quote signature with attestation key",
		},
		{
			name: "attestation key binding",
			mutate: func(q []byte) {
				akStart := len(parsed.HeaderAndBody) + 4 + ecdsaSigSize
				q[akStart] ^= 0x01
			},
			wantText: "verify AK hash binding in QE/TDQE report_data",
		},
		{
			name: "QE report signature",
			mutate: func(q []byte) {
				outerContentStart := len(parsed.HeaderAndBody) + 4 + ecdsaSigSize + ecdsaPubKeySize + 6
				qeSigStart := outerContentStart + qeReportSize
				q[qeSigStart] ^= 0x01
			},
			wantText: "verify QE/TDQE report signature with PCK cert public key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), bundle.Quote...)
			tc.mutate(tampered)
			_, err := VerifySyntheticQuoteCrypto(tampered, rootCert, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
			if err == nil {
				t.Fatalf("expected tampered quote to fail")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("expected %q in error, got: %v", tc.wantText, err)
			}
		})
	}
}

func deterministicBytes(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((i*37 + 11) % 251)
	}
	return out
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
