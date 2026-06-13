#!/bin/bash
set -euo pipefail

go run ./cmd/tdx-attest verify \
  -sample-time 2023-02-01T00:00:00Z \
  -ignore-freshness \
  -tdx-policy test_data/tdx_policy_sample.json
