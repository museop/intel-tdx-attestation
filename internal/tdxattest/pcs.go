package tdxattest

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CollateralSourceLocal = "local"
	CollateralSourcePCS   = "pcs"

	defaultPCSBaseURL     = "https://api.trustedservices.intel.com"
	defaultPCSHTTPTimeout = 20 * time.Second
	defaultRootCRLURL     = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
)

// CollateralBundle contains the network/file collateral needed by the verifier
// after the quote itself has supplied the PCK certificate chain.
type CollateralBundle struct {
	TCBInfoJSON        []byte
	TCBSigningChainPEM []byte
	QEIdentityJSON     []byte
	QEIdentityChainPEM []byte
	PCKCRL             []byte
	RootCRL            []byte
}

type PCSClient struct {
	BaseURL    string
	RootCRLURL string
	HTTPClient *http.Client
}

func NewPCSClient(baseURL string) *PCSClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultPCSBaseURL
	}
	return &PCSClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: defaultPCSHTTPTimeout},
	}
}

func (c *PCSClient) FetchCollateral(ctx context.Context, rootCert *x509.Certificate, pckChain []*x509.Certificate, pckLeaf *x509.Certificate) (*CollateralBundle, error) {
	if rootCert == nil {
		return nil, fmt.Errorf("root certificate is required")
	}
	if pckLeaf == nil {
		return nil, fmt.Errorf("PCK leaf certificate is required")
	}
	if len(pckChain) < 2 {
		return nil, fmt.Errorf("PCK leaf + intermediate chain is required")
	}

	fmspc, err := extractFMSPCFromPCKCert(pckLeaf)
	if err != nil {
		return nil, fmt.Errorf("extract FMSPC from PCK cert: %w", err)
	}
	pckCA, err := pckCRLCAName(pckChain[1])
	if err != nil {
		return nil, err
	}

	tcbBody, tcbHeaders, err := c.get(ctx, c.endpoint("/tdx/certification/v4/tcb", map[string]string{"fmspc": fmspc}))
	if err != nil {
		return nil, fmt.Errorf("fetch TDX TCB Info from PCS: %w", err)
	}
	tcbChain, err := issuerChainFromHeaders(tcbHeaders, "TCB-Info-Issuer-Chain")
	if err != nil {
		return nil, fmt.Errorf("read TCB Info issuer chain header: %w", err)
	}

	qeBody, qeHeaders, err := c.get(ctx, c.endpoint("/tdx/certification/v4/qe/identity", nil))
	if err != nil {
		return nil, fmt.Errorf("fetch TDX QE identity from PCS: %w", err)
	}
	qeChain, err := issuerChainFromHeaders(qeHeaders, "SGX-Enclave-Identity-Issuer-Chain")
	if err != nil {
		return nil, fmt.Errorf("read QE identity issuer chain header: %w", err)
	}

	pckCRL, _, err := c.get(ctx, c.endpoint("/sgx/certification/v4/pckcrl", map[string]string{"ca": pckCA, "encoding": "der"}))
	if err != nil {
		return nil, fmt.Errorf("fetch PCK CRL from PCS: %w", err)
	}

	rootCRLURL := c.RootCRLURL
	if rootCRLURL == "" {
		rootCRLURL = rootCRLDistributionPoint(rootCert)
	}
	rootCRL, _, err := c.get(ctx, rootCRLURL)
	if err != nil {
		return nil, fmt.Errorf("fetch Intel SGX Root CA CRL: %w", err)
	}

	return &CollateralBundle{
		TCBInfoJSON:        tcbBody,
		TCBSigningChainPEM: tcbChain,
		QEIdentityJSON:     qeBody,
		QEIdentityChainPEM: qeChain,
		PCKCRL:             pckCRL,
		RootCRL:            rootCRL,
	}, nil
}

func (c *PCSClient) endpoint(path string, query map[string]string) string {
	values := url.Values{}
	for key, value := range query {
		values.Set(key, value)
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + path
	if encoded := values.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	return endpoint
}

func (c *PCSClient) get(ctx context.Context, rawURL string) ([]byte, http.Header, error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultPCSHTTPTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("GET %s returned %s: %s", rawURL, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, resp.Header, nil
}

func pckCRLCAName(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("PCK intermediate certificate is required")
	}
	name := strings.ToLower(cert.Subject.CommonName)
	switch {
	case strings.Contains(name, "platform"):
		return "platform", nil
	case strings.Contains(name, "processor"):
		return "processor", nil
	default:
		return "", fmt.Errorf("cannot determine PCK CRL CA from intermediate subject %q", cert.Subject.String())
	}
}

func issuerChainFromHeaders(headers http.Header, name string) ([]byte, error) {
	raw := strings.TrimSpace(headers.Get(name))
	if raw == "" {
		return nil, fmt.Errorf("missing %s", name)
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, fmt.Errorf("URL-decode %s: %w", name, err)
	}
	return []byte(decoded), nil
}

func rootCRLDistributionPoint(rootCert *x509.Certificate) string {
	if rootCert != nil && len(rootCert.CRLDistributionPoints) > 0 && strings.TrimSpace(rootCert.CRLDistributionPoints[0]) != "" {
		return rootCert.CRLDistributionPoints[0]
	}
	return defaultRootCRLURL
}
