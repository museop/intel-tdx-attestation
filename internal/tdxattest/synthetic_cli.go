package tdxattest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

type SynthesizeConfig struct {
	QuoteOut    string
	RootOut     string
	PCKChainOut string
}

type GenerateSyntheticRootConfig struct {
	RootKeyOut string
	RootOut    string
}

type GenerateSyntheticQuoteConfig struct {
	QuoteOut    string
	RootKeyPath string
	RootPath    string
	PCKChainOut string
}

type VerifySyntheticConfig struct {
	QuotePath  string
	RootPath   string
	VerifyTime time.Time
}

func RunSynthesize(cfg SynthesizeConfig) error {
	bundle, err := GenerateSyntheticQuote()
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.QuoteOut, bundle.Quote, 0o644); err != nil {
		return fmt.Errorf("write synthetic quote: %w", err)
	}
	if err := os.WriteFile(cfg.RootOut, bundle.RootCertPEM, 0o644); err != nil {
		return fmt.Errorf("write synthetic root: %w", err)
	}
	if cfg.PCKChainOut != "" {
		if err := os.WriteFile(cfg.PCKChainOut, bundle.PCKChainPEM, 0o644); err != nil {
			return fmt.Errorf("write synthetic PCK chain: %w", err)
		}
	}
	fmt.Println("RESULT: synthetic non-Intel quote generated")
	fmt.Println("Quote:              ", cfg.QuoteOut)
	fmt.Println("Synthetic test root:", cfg.RootOut)
	if cfg.PCKChainOut != "" {
		fmt.Println("Synthetic PCK chain:", cfg.PCKChainOut)
	}
	fmt.Println("Note: this quote is for local tests only and is not Intel-attested.")
	return nil
}

func RunGenerateSyntheticRoot(cfg GenerateSyntheticRootConfig) error {
	bundle, err := GenerateSyntheticRoot()
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.RootKeyOut, bundle.RootKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write synthetic root key: %w", err)
	}
	if err := os.WriteFile(cfg.RootOut, bundle.RootCertPEM, 0o644); err != nil {
		return fmt.Errorf("write synthetic root: %w", err)
	}
	fmt.Println("RESULT: synthetic test root generated")
	fmt.Println("Root key:          ", cfg.RootKeyOut)
	fmt.Println("Root certificate:  ", cfg.RootOut)
	fmt.Println("Note: this root is for local synthetic quote tests only and is not an Intel trust anchor.")
	return nil
}

func RunGenerateSyntheticQuote(cfg GenerateSyntheticQuoteConfig) error {
	rootKeyBytes, err := os.ReadFile(cfg.RootKeyPath)
	if err != nil {
		return fmt.Errorf("read synthetic root key: %w", err)
	}
	rootKey, err := parseECPrivateKeyPEM(rootKeyBytes)
	if err != nil {
		return fmt.Errorf("parse synthetic root key: %w", err)
	}

	rootBytes, err := os.ReadFile(cfg.RootPath)
	if err != nil {
		return fmt.Errorf("read synthetic root: %w", err)
	}
	rootCert, err := parseOneCert(rootBytes)
	if err != nil {
		return fmt.Errorf("parse synthetic root: %w", err)
	}

	bundle, err := GenerateSyntheticQuoteWithRoot(rootKey, rootCert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.QuoteOut, bundle.Quote, 0o644); err != nil {
		return fmt.Errorf("write synthetic quote: %w", err)
	}
	if cfg.PCKChainOut != "" {
		if err := os.WriteFile(cfg.PCKChainOut, bundle.PCKChainPEM, 0o644); err != nil {
			return fmt.Errorf("write synthetic PCK chain: %w", err)
		}
	}
	fmt.Println("RESULT: synthetic non-Intel quote generated")
	fmt.Println("Quote:              ", cfg.QuoteOut)
	fmt.Println("Synthetic test root:", cfg.RootPath)
	if cfg.PCKChainOut != "" {
		fmt.Println("Synthetic PCK chain:", cfg.PCKChainOut)
	}
	fmt.Println("Note: this quote is for local tests only and is not Intel-attested.")
	return nil
}

func RunVerifySynthetic(cfg VerifySyntheticConfig) error {
	quoteBytes, err := os.ReadFile(cfg.QuotePath)
	if err != nil {
		return fmt.Errorf("read synthetic quote: %w", err)
	}
	rootBytes, err := os.ReadFile(cfg.RootPath)
	if err != nil {
		return fmt.Errorf("read synthetic root: %w", err)
	}
	rootCert, err := parseOneCert(rootBytes)
	if err != nil {
		return fmt.Errorf("parse synthetic root: %w", err)
	}
	parsed, err := VerifySyntheticQuoteCrypto(quoteBytes, rootCert, cfg.VerifyTime)
	if err != nil {
		return err
	}
	printQuoteSummary(parsed)
	fmt.Println("RESULT: synthetic non-Intel quote cryptographic verification is OK")
	fmt.Println("Note: Intel collateral, CRL, FMSPC, PCEID, and TCB policy were intentionally not checked.")
	return nil
}

func parseECPrivateKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("PEM block not found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not ECDSA: %T", key)
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; want EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}
