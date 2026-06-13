# 샘플 Quote 검증 워크스루

이 문서는 샘플 `quote.dat` 하나를 기준으로, 검증 흐름을 단계별로 따라갑니다.

## 입력 파일들

- `test_data/quote.dat`
- `test_data/certs/Intel_SGX_Provisioning_Certification_RootCA.pem`
- `test_data/certs/pck_platform_crl.der`
- `test_data/certs/IntelSGXRootCA.crl`
- `test_data/certs/tcbSigningChain.pem`
- `test_data/collateral/tcbinfo.json`
- `test_data/collateral/qeidentity.json`
- `test_data/tdx_policy_sample.json` (선택)

## 단계 1. Quote를 파싱한다

코드 위치:
- `internal/tdxattest/quote.go`

여기서 분리되는 것:
- Quote header/body
- Quote signature
- Attestation Key
- QE report
- QE report signature
- 인증서 체인(PCK chain)

왜 필요한가:
- 이후 검증은 모두 이 내부 조각들을 재사용하기 때문입니다.

## 단계 2. Quote 안의 PCK chain을 검증한다

코드 위치:
- `internal/tdxattest/quote_verify.go`
- `internal/tdxattest/certs.go`

무엇을 보나:
- Quote 안 PCK leaf가 Intel Root CA까지 정상 체인인지

왜 필요한가:
- 이 플랫폼 인증서가 Intel이 발급한 체인 안에 있는지 확인해야 하기 때문입니다.

## 단계 3. CRL로 폐기 여부를 확인한다

코드 위치:
- `internal/tdxattest/crl.go`

무엇을 보나:
- `pck_platform_crl.der`로 PCK leaf serial 확인
- `IntelSGXRootCA.crl`로 root-issued intermediate/signing cert serial 확인

왜 필요한가:
- 체인이 맞아도 이미 폐기된 인증서면 신뢰하면 안 됩니다.

## 단계 4. QE report와 Quote signature를 검증한다

코드 위치:
- `internal/tdxattest/quote_verify.go`

무엇을 보나:
- PCK leaf 공개키로 QE report signature 검증
- QE report `report_data`와 AK/auth data binding 검증
- AK로 Quote signature 검증

왜 필요한가:
- 인증서 체인과 Quote 본문이 암호학적으로 연결되어 있는지 확인하기 위해서입니다.

## 단계 5. TCB Info를 검증한다

코드 위치:
- `internal/tdxattest/collateral.go`

무엇을 보나:
- TCB Info JSON 서명
- signing chain
- Root CA CRL
- freshness
- FMSPC / PCEID 일치
- TCB level 매칭
- `tdxModule` 정책 일부 (`MRSIGNERSEAM`, `SEAMATTRIBUTES`)

왜 필요한가:
- 현재 플랫폼 상태가 Intel이 공개한 TCB 정보와 맞는지 확인하기 위해서입니다.

## 단계 6. QE Identity를 검증한다

코드 위치:
- `internal/tdxattest/collateral.go`

무엇을 보나:
- QE Identity JSON 서명
- signing chain
- Root CA CRL
- freshness
- `miscselect`, `attributes`, `MRSIGNER`, `ISVPRODID`, `ISVSVN`

왜 필요한가:
- Quote를 만든 QE/TDQE가 Intel이 허용하는 특성과 일치하는지 확인하기 위해서입니다.

## 단계 7. TDX measurement를 비교한다 (선택)

코드 위치:
- `internal/tdxattest/tdx.go`

무엇을 보나:
- `MRTD`
- `RTMR0~3`
- `REPORTDATA`
- `TDATTRIBUTES`
- `XFAM`

왜 필요한가:
- Intel collateral만으로는 “이 TD가 내 서비스가 기대하는 워크로드인가”를 판단할 수 없기 때문입니다.
- 이 단계는 사용자가 정책 JSON을 제공했을 때만 수행됩니다.

## 샘플 실행 명령

```bash
go run ./cmd/tdx-attest verify \
  -sample-time 2023-02-01T00:00:00Z \
  -ignore-freshness \
  -tdx-policy test_data/tdx_policy_sample.json
```

## 이 워크스루로 이해할 수 있는 것

- Quote 검증이 단일 서명 검증이 아니라 여러 층으로 나뉜다는 점
- Intel collateral이 왜 필요한지
- 앱 정책 검증이 왜 별도 단계인지
