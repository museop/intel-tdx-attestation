package main

import (
	"fmt"
	"os"

	"github.com/museop/intel-tdx-attestation/cmd/tdx-attest/cli"
)

func main() {
	if err := cli.Execute(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
