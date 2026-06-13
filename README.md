# intel-tdx-attestation

Intel TDX/SGX DCAP Quote와 Intel collateral을 **로컬 파일만으로 검증하는 Go 예제**입니다.

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

### Synthetic self-signed Quote 생성/검증

실험/테스트용으로 Intel이 서명하지 않은 synthetic quote를 만들 수 있습니다.
이 quote는 **Intel Root CA 기반 검증을 통과하면 안 되며**, 별도 synthetic test root를 명시한
`verify -mode synthetic` 경로에서 로컬 암호학 관계만 확인합니다.

```bash
go run ./cmd/tdx-attest synthesize \
  -quote-out /tmp/synthetic_quote.dat \
  -root-out /tmp/synthetic_root.pem \
  -pck-chain-out /tmp/synthetic_pck_chain.pem

go run ./cmd/tdx-attest verify \
  -mode synthetic \
  -quote /tmp/synthetic_quote.dat \
  -root /tmp/synthetic_root.pem
```

`verify`의 기본 mode는 `intel`입니다. 즉, `-mode synthetic`을 명시하지 않으면 Intel Root CA와
Intel collateral 기반의 real quote 검증 경로로 동작합니다.

`verify -mode synthetic`은 quote signature, QE report signature, AK binding, synthetic PCK chain만
검증합니다. Intel collateral, CRL, FMSPC/PCEID, TCB policy 검증은 의도적으로 수행하지 않습니다.

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
| `-root` | `test_data/certs/Intel_SGX_Provisioning_Certification_RootCA.pem` | Intel Root CA 인증서 |
| `-tcbinfo` | `test_data/collateral/tcbinfo.json` | Intel TCB Info JSON |
| `-qeidentity` | `test_data/collateral/qeidentity.json` | Intel QE/TDQE Identity JSON |
| `-tcb-chain` | `test_data/certs/tcbSigningChain.pem` | TCB Info signing chain |
| `-qe-chain` | `test_data/certs/tcbSigningChain.pem` | QE/TDQE Identity signing chain |
| `-pck-crl` | `test_data/certs/pck_platform_crl.der` | PCK leaf revocation 확인용 CRL |
| `-root-crl` | `test_data/certs/IntelSGXRootCA.crl` | Root-issued intermediate/signing cert revocation 확인용 CRL |
| `-tdx-policy` | 빈 값 | 선택적 TDX measurement policy JSON |
| `-sample-time` | 빈 값 | 샘플 검증 기준 시각 (RFC3339) |
| `-ignore-freshness` | `false` | collateral/CRL freshness 검사를 완화 |

Subcommand:

| 명령 | 설명 |
| --- | --- |
| `verify` | 기본 Intel collateral 검증 경로. subcommand 없이 실행해도 같은 동작입니다. |
| `synthesize` | 테스트용 non-Intel synthetic quote와 synthetic root를 생성합니다. |

CLI는 Cobra 기반으로 구성되어 있어 command별 help를 확인할 수 있습니다.

```bash
go run ./cmd/tdx-attest --help
go run ./cmd/tdx-attest verify --help
go run ./cmd/tdx-attest synthesize --help
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
