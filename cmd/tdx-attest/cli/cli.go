package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/museop/intel-tdx-attestation/internal/tdxattest"
	"github.com/spf13/cobra"
)

func Execute(args []string) error {
	cmd := newRootCommand()
	cmd.SetArgs(normalizeLegacyLongFlags(args))
	return cmd.Execute()
}

func newRootCommand() *cobra.Command {
	verifyCfg := tdxattest.DefaultConfig()
	rootCmd := &cobra.Command{
		Use:           "tdx-attest",
		Short:         "Verify Intel TDX/SGX DCAP quotes with local collateral",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments: %v", args)
			}
			return tdxattest.RunVerify(verifyCfg)
		},
	}
	addVerifyFlags(rootCmd, &verifyCfg)

	rootCmd.AddCommand(newVerifyCommand())
	rootCmd.AddCommand(newSynthesizeCommand())
	rootCmd.AddCommand(newSyntheticRootCommand())
	rootCmd.AddCommand(newSyntheticQuoteCommand())
	return rootCmd
}

func newVerifyCommand() *cobra.Command {
	cfg := tdxattest.DefaultConfig()
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify selected quote checks with caller-provided data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments: %v", args)
			}
			return tdxattest.RunVerify(cfg)
		},
	}
	addVerifyFlags(cmd, &cfg)
	return cmd
}

func newSynthesizeCommand() *cobra.Command {
	cfg := tdxattest.SynthesizeConfig{}
	cmd := &cobra.Command{
		Use:        "synthesize",
		Short:      "Generate a non-Intel synthetic quote for local tests",
		Deprecated: "use synthetic-root followed by synthetic-quote",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments: %v", args)
			}
			return tdxattest.RunSynthesize(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.QuoteOut, "quote-out", "", "output path for the synthetic quote")
	cmd.Flags().StringVar(&cfg.RootOut, "root-out", "", "output path for the synthetic test root certificate PEM")
	cmd.Flags().StringVar(&cfg.PCKChainOut, "pck-chain-out", "", "optional output path for the synthetic PCK chain PEM embedded in the quote")
	mustMarkFlagRequired(cmd, "quote-out")
	mustMarkFlagRequired(cmd, "root-out")
	return cmd
}

func newSyntheticRootCommand() *cobra.Command {
	cfg := tdxattest.GenerateSyntheticRootConfig{}
	cmd := &cobra.Command{
		Use:     "synthetic-root",
		Aliases: []string{"synthetic_root"},
		Short:   "Generate a reusable non-Intel synthetic test root",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments: %v", args)
			}
			return tdxattest.RunGenerateSyntheticRoot(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.RootKeyOut, "root-key-out", "", "output path for the synthetic test root private key PEM")
	cmd.Flags().StringVar(&cfg.RootOut, "root-out", "", "output path for the synthetic test root certificate PEM")
	mustMarkFlagRequired(cmd, "root-key-out")
	mustMarkFlagRequired(cmd, "root-out")
	return cmd
}

func newSyntheticQuoteCommand() *cobra.Command {
	cfg := tdxattest.GenerateSyntheticQuoteConfig{}
	cmd := &cobra.Command{
		Use:     "synthetic-quote",
		Aliases: []string{"synthetic_quote"},
		Short:   "Generate a non-Intel synthetic quote from an existing synthetic root",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments: %v", args)
			}
			return tdxattest.RunGenerateSyntheticQuote(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.QuoteOut, "quote-out", "", "output path for the synthetic quote")
	cmd.Flags().StringVar(&cfg.RootKeyPath, "root-key", "", "synthetic test root private key PEM")
	cmd.Flags().StringVar(&cfg.RootPath, "root", "", "synthetic test root certificate PEM")
	cmd.Flags().StringVar(&cfg.PCKChainOut, "pck-chain-out", "", "optional output path for the synthetic PCK chain PEM embedded in the quote")
	mustMarkFlagRequired(cmd, "quote-out")
	mustMarkFlagRequired(cmd, "root-key")
	mustMarkFlagRequired(cmd, "root")
	return cmd
}

func addVerifyFlags(cmd *cobra.Command, cfg *tdxattest.Config) {
	var sampleTime string
	cmd.Flags().StringVar(&cfg.QuotePath, "quote", cfg.QuotePath, "TDX/SGX DCAP quote file")
	cmd.Flags().StringVar(&cfg.RootPath, "root", cfg.RootPath, "root CA certificate PEM/DER for selected checks")
	cmd.Flags().StringVar(&cfg.TCBInfoPath, "tcbinfo", cfg.TCBInfoPath, "Intel TCB Info JSON")
	cmd.Flags().StringVar(&cfg.QEIdentityPath, "qeidentity", cfg.QEIdentityPath, "Intel QE/TDQE Identity JSON")
	cmd.Flags().StringVar(&cfg.TCBChainPath, "tcb-chain", cfg.TCBChainPath, "Intel TCB signing cert chain PEM")
	cmd.Flags().StringVar(&cfg.QEChainPath, "qe-chain", cfg.QEChainPath, "Intel QE/TDQE identity signing cert chain PEM")
	cmd.Flags().StringVar(&cfg.PCKCRLPath, "pck-crl", cfg.PCKCRLPath, "Intel PCK CRL file (DER or PEM)")
	cmd.Flags().StringVar(&cfg.RootCRLPath, "root-crl", cfg.RootCRLPath, "Intel SGX Root CA CRL file (DER or PEM)")
	cmd.Flags().StringVar(&cfg.TDXPolicyPath, "tdx-policy", cfg.TDXPolicyPath, "optional TDX measurement policy JSON")
	cmd.Flags().StringSliceVar(&cfg.Checks, "check", cfg.Checks, "optional verification check(s) to run: quote-crypto, pck-chain, quote-signatures, pck-crl, root-crl, tcbinfo, qeidentity, tdx-policy, intel-full")
	cmd.Flags().StringVar(&sampleTime, "sample-time", "", "verification time for sample collateral, e.g. 2023-02-01T00:00:00Z")
	cmd.Flags().BoolVar(&cfg.IgnoreFreshness, "ignore-freshness", false, "ignore collateral and CRL freshness checks")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if sampleTime == "" {
			return nil
		}
		verifyTime, err := time.Parse(time.RFC3339, sampleTime)
		if err != nil {
			return fmt.Errorf("parse sample-time: %w", err)
		}
		cfg.VerifyTime = verifyTime.UTC()
		cfg.UsedSampleTime = true
		return nil
	}
}

func mustMarkFlagRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}

func normalizeLegacyLongFlags(args []string) []string {
	normalized := make([]string, len(args))
	copy(normalized, args)
	for i, arg := range normalized {
		if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") || len(arg) <= 2 {
			continue
		}
		normalized[i] = "-" + arg
	}
	return normalized
}
