package tdxattest

import (
	"fmt"
	"os"
	"time"
)

type SynthesizeConfig struct {
	QuoteOut    string
	RootOut     string
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
