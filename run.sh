#!/bin/bash
go run . \
  -quote quote.dat \
  -root Intel_SGX_Provisioning_Certification_RootCA.pem \
  -tcbinfo tcbinfo.json \
  -qeidentity qeidentity.json \
  -tcb-chain tcbSigningChain.pem \
  -qe-chain tcbSigningChain.pem \
  -sample-time 2023-02-01T00:00:00Z \
  -ignore-freshness