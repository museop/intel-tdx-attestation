package tdxattest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestVerifyQuoteWithPCSCollateralSource(t *testing.T) {
	root := repoRoot(t)
	quoteBytes := mustReadFile(t, samplePath(root, "quote.dat"))
	rootCert, err := parseOneCert(mustReadFile(t, samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem")))
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	tcbInfo := mustReadFile(t, samplePath(root, "collateral", "tcbinfo.json"))
	qeIdentity := mustReadFile(t, samplePath(root, "collateral", "qeidentity.json"))
	signingChain := mustReadFile(t, samplePath(root, "certs", "tcbSigningChain.pem"))
	pckCRL := mustReadFile(t, samplePath(root, "certs", "pck_platform_crl.der"))
	rootCRL := mustReadFile(t, samplePath(root, "certs", "IntelSGXRootCA.crl"))

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Ocp-Apim-Subscription-Key") != "" {
			t.Fatalf("PCS request unexpectedly included an API key header")
		}
		requests = append(requests, r.URL.String())
		switch r.URL.Path {
		case "/tdx/certification/v4/tcb":
			if got := r.URL.Query().Get("fmspc"); got != "00806F050000" {
				t.Fatalf("unexpected fmspc query: %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("TCB-Info-Issuer-Chain", url.QueryEscape(string(signingChain)))
			_, _ = w.Write(tcbInfo)
		case "/tdx/certification/v4/qe/identity":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("SGX-Enclave-Identity-Issuer-Chain", url.QueryEscape(string(signingChain)))
			_, _ = w.Write(qeIdentity)
		case "/sgx/certification/v4/pckcrl":
			if got := r.URL.Query().Get("ca"); got != "platform" {
				t.Fatalf("unexpected pckcrl ca query: %q", got)
			}
			if got := r.URL.Query().Get("encoding"); got != "der" {
				t.Fatalf("unexpected pckcrl encoding query: %q", got)
			}
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(pckCRL)
		case "/IntelSGXRootCA.der":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(rootCRL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	rootCert.CRLDistributionPoints = []string{server.URL + "/IntelSGXRootCA.der"}

	result, err := VerifyQuoteWithCollateral(VerificationRequest{
		QuoteBytes:       quoteBytes,
		RootCert:         rootCert,
		CollateralSource: CollateralSourcePCS,
		PCSBaseURL:       server.URL,
		VerifyTime:       mustParseTime(t, "2023-02-01T00:00:00Z"),
		IgnoreFreshness:  true,
		UsedSampleTime:   true,
	})
	if err != nil {
		t.Fatalf("expected PCS-backed verification to pass: %v", err)
	}
	if result == nil || len(result.Checks) != 8 {
		t.Fatalf("expected 8 default checks, got result=%#v", result)
	}

	wantPaths := []string{
		"/tdx/certification/v4/tcb?fmspc=00806F050000",
		"/tdx/certification/v4/qe/identity",
		"/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
		"/IntelSGXRootCA.der",
	}
	for _, want := range wantPaths {
		if !containsRequest(requests, want) {
			t.Fatalf("expected PCS request %s, got %v", want, requests)
		}
	}
}

func TestPCSClientRequiresIssuerChainHeaders(t *testing.T) {
	root := repoRoot(t)
	quoteBytes := mustReadFile(t, samplePath(root, "quote.dat"))
	rootCert, err := parseOneCert(mustReadFile(t, samplePath(root, "certs", "Intel_SGX_Provisioning_Certification_RootCA.pem")))
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	evidence, err := parseAndVerifyQuoteEvidence(VerificationRequest{
		QuoteBytes: quoteBytes,
		RootCert:   rootCert,
		VerifyTime: mustParseTime(t, "2023-02-01T00:00:00Z"),
	}, false)
	if err != nil {
		t.Fatalf("parse sample quote evidence: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tdx/certification/v4/tcb" {
			_, _ = w.Write([]byte(`{"tcbInfo":{},"signature":""}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, err = NewPCSClient(server.URL).FetchCollateral(t.Context(), rootCert, evidence.PCKChain, evidence.PCKLeaf)
	if err == nil || !strings.Contains(err.Error(), "missing TCB-Info-Issuer-Chain") {
		t.Fatalf("expected missing issuer chain error, got %v", err)
	}
}

func containsRequest(requests []string, want string) bool {
	for _, got := range requests {
		if got == want {
			return true
		}
	}
	return false
}

func ExampleCollateralSourcePCS() {
	fmt.Println("go run ./cmd/tdx-attest verify -collateral-source pcs -quote quote.dat")
	// Output: go run ./cmd/tdx-attest verify -collateral-source pcs -quote quote.dat
}
