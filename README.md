# intel-tdx-attestation

Intel TDX/SGX DCAP Quote와 Intel collateral을 로컬 파일 또는 Intel PCS API로 검증하는 Go 예제입니다.

이 저장소는 학습/실험용 verifier로, 다음을 이해하기 쉽게 보여주는 데 초점을 둡니다.

- Quote가 어떻게 파싱되는가
- PCK certificate / CRL / TCB Info / QE Identity가 어떻게 연결되는가
- 어떤 검증이 암호학 검증인지, 어떤 검증이 정책 검증인지
- TDX measurement를 어떻게 읽고 비교하는가

> 운영 환경용 완전한 attestation engine은 아니지만, 샘플 데이터와 공식 collateral만으로 재현 가능한 검증은 최대한 포함하고 있습니다.

## 빠른 시작

### 샘플 검증

```bash
go run ./cmd/tdx-attest verify -sample-time 2023-02-01T00:00:00Z -ignore-freshness
```

또는

```bash
bash ./run.sh
```

### 샘플 TDX policy까지 검증

```bash
go run ./cmd/tdx-attest verify \
  -sample-time 2023-02-01T00:00:00Z \
  -ignore-freshness \
  -tdx-policy test_data/tdx_policy_sample.json
```


### Intel PCS에서 collateral을 직접 가져와 검증

`quote.dat`는 여전히 attester/QGS가 만든 quote 파일이어야 하지만, TCB Info, QE Identity, PCK CRL, Root CA CRL, issuer chain은 Intel PCS/인증서 엔드포인트에서 직접 가져올 수 있습니다. 이 조회 경로는 API key를 보내지 않습니다.

```bash
go run ./cmd/tdx-attest verify \
  -quote test_data/quote.dat \
  -collateral-source pcs
```

오래된 샘플 quote를 현재 PCS collateral과 비교하면 TCB 상태나 freshness 때문에 실패할 수 있습니다. 특정 체크만 네트워크 collateral로 확인하려면 `-check`를 함께 사용하세요.

```bash
go run ./cmd/tdx-attest verify \
  -quote test_data/quote.dat \
  -collateral-source pcs \
  -check pck-crl,root-crl
```

### Synthetic self-signed Quote 생성/검증

실험/테스트용으로 Intel이 서명하지 않은 synthetic quote를 만들 수 있습니다.
Synthetic test root 생성과 synthetic quote 생성은 별도 subcommand로 분리되어 있어, 같은 root로
여러 quote를 만들 수 있습니다. 이 quote는 **Intel Root CA 기반 전체 검증을 통과하면 안 되며**,
`verify -check quote-crypto`처럼 필요한 검증 항목을 명시해 로컬 암호학 관계만 확인합니다.

```bash
go run ./cmd/tdx-attest synthetic-root \
  -root-key-out /tmp/synthetic_root_key.pem \
  -root-out /tmp/synthetic_root.pem

go run ./cmd/tdx-attest synthetic-quote \
  -quote-out /tmp/synthetic_quote.dat \
  -root-key /tmp/synthetic_root_key.pem \
  -root /tmp/synthetic_root.pem \
  -pck-chain-out /tmp/synthetic_pck_chain.pem

go run ./cmd/tdx-attest verify \
  -check quote-crypto \
  -quote /tmp/synthetic_quote.dat \
  -root /tmp/synthetic_root.pem
```

`verify`는 `-mode`로 Intel/synthetic을 나누지 않습니다. 기본값은 기존처럼 Intel collateral 기반
전체 검증이며, 필요한 경우 `-check`를 반복하거나 comma-separated 값으로 선택 검증을 추가합니다.
예: `-check quote-crypto`, `-check pck-crl,root-crl`, `-check tdx-policy -tdx-policy policy.json`.

`-check quote-crypto`는 PCK chain, quote signature, QE report signature, AK binding만 검증합니다.
Intel collateral, CRL, FMSPC/PCEID, TCB policy 검증은 해당 check와 데이터 옵션을 명시했을 때만
수행합니다.

## 현재 구현된 검증

- Quote 파싱
- PCK chain 검증
- PCK CRL 검증
- Root CA CRL 검증
- QE/TDQE report signature 검증
- AK binding 검증
- Quote signature 검증
- TCB Info 서명/체인/freshness 검증
- FMSPC / PCEID 비교
- TCB level 매칭
- TCB Info의 `tdxModule` 정책 일부 검증
- QE Identity 서명/체인/freshness 검증
- QE identity 기본 정책 검증
- TDX measurement 추출
- 외부 policy JSON 기반 measurement 비교

## 아직 하지 않는 일

- `REPORTDATA` challenge / session binding
- 앱 정책 없이 measurement를 자동 allow/deny 하는 기능
- QE/TDQE identity의 더 세부적인 정책 엔진 수준 판정
- 현재 threshold matching보다 더 풍부한 TCB nuance 평가

## 문서 안내

상세 설명은 아래 문서로 분리했습니다.

- [검증 개요와 왜 이런 검증이 필요한지](docs/verification-overview.md)
- [용어 정리](docs/glossary.md)
- [샘플 데이터 설명](docs/sample-data.md)
- [Intel PCS API collateral 가이드](docs/intel-pcs-api.md)
- [코드 구조와 파일별 역할](docs/code-structure.md)
- [실행 출력 해설](docs/output-guide.md)
- [샘플 Quote 검증 워크스루](docs/attestation-walkthrough.md)
- [TDX Policy JSON 가이드](docs/policy-json-guide.md)
- [실패 시나리오 가이드](docs/failure-scenarios.md)
- [test_data 디렉터리 안내](test_data/README.md)

## 주요 CLI 옵션

| 옵션 | 기본값 | 설명 |
| --- | --- | --- |
| `-quote` | `test_data/quote.dat` | 검증할 Quote 바이너리 |
| `-root` | `test_data/certs/Intel_SGX_Provisioning_Certification_RootCA.pem` | 선택 검증에 사용할 Root CA 인증서(Intel 또는 synthetic) |
| `-collateral-source` | `local` | collateral 출처. `local`은 파일 옵션 사용, `pcs`는 Intel PCS API에서 조회 |
| `-pcs-base-url` | `https://api.trustedservices.intel.com` | PCS base URL. 테스트 서버/프록시가 필요할 때만 변경 |
| `-tcbinfo` | `test_data/collateral/tcbinfo.json` | Intel TCB Info JSON |
| `-qeidentity` | `test_data/collateral/qeidentity.json` | Intel QE/TDQE Identity JSON |
| `-tcb-chain` | `test_data/certs/tcbSigningChain.pem` | TCB Info signing chain |
| `-qe-chain` | `test_data/certs/tcbSigningChain.pem` | QE/TDQE Identity signing chain |
| `-pck-crl` | `test_data/certs/pck_platform_crl.der` | PCK leaf revocation 확인용 CRL |
| `-root-crl` | `test_data/certs/IntelSGXRootCA.crl` | Root-issued intermediate/signing cert revocation 확인용 CRL |
| `-tdx-policy` | 빈 값 | 선택적 TDX measurement policy JSON |
| `-check` | 빈 값 | 선택 검증 항목. 예: `quote-crypto`, `pck-chain`, `quote-signatures`, `pck-crl`, `root-crl`, `tcbinfo`, `qeidentity`, `tdx-policy`, `intel-full` |
| `-sample-time` | 빈 값 | 샘플 검증 기준 시각 (RFC3339) |
| `-ignore-freshness` | `false` | collateral/CRL freshness 검사를 완화 |

Subcommand:

| 명령 | 설명 |
| --- | --- |
| `verify` | 기본 Intel collateral 검증 경로. subcommand 없이 실행해도 같은 동작입니다. |
| `synthetic-root` | 테스트용 non-Intel synthetic root key/cert를 생성합니다. |
| `synthetic-quote` | 기존 synthetic root로 테스트용 non-Intel synthetic quote를 생성합니다. |

CLI는 Cobra 기반으로 구성되어 있어 command별 help를 확인할 수 있습니다.

```bash
go run ./cmd/tdx-attest --help
go run ./cmd/tdx-attest verify --help
go run ./cmd/tdx-attest synthetic-root --help
go run ./cmd/tdx-attest synthetic-quote --help
```

## 저장소 구조

```text
.
├── cmd/tdx-attest/
│   ├── main.go
│   └── cli/
│       └── cli.go
├── internal/tdxattest/
│   ├── app.go
│   ├── quote.go
│   ├── quote_verify.go
│   ├── verifier.go
│   ├── synthetic_quote.go
│   ├── synthetic_cli.go
│   ├── collateral.go
│   ├── crl.go
│   ├── tdx.go
│   └── certs.go
├── pkg/tdxattest/
│   └── tdxattest.go
├── run.sh
├── docs/
└── test_data/
```

`cmd/tdx-attest`가 실행 진입점이고, Cobra command tree도
`cmd/tdx-attest/cli`에 둡니다. 검증/생성 구현은 `internal/tdxattest`, 외부에서 호출 가능한
최소 non-CLI API는 `pkg/tdxattest`에 둡니다.

## 참고 자료

- Intel TDX Enabling Guide: https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/
- Intel SGX/TDX PCCS API Spec: https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/03/api_specification_for_pccs/
- Intel SGX/TDX PCCS Cache Flows: https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/08/cache_management_flows/
- Intel SGX PCK Certificate & CRL Spec: https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf
- Intel SGX/TDX DCAP Quote Verification Library: https://github.com/intel/confidential-computing.tee.dcap.qvl
