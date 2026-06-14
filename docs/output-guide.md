# 실행 출력 가이드

이 문서는 프로그램을 실행했을 때 보이는 출력이 각각 무엇을 뜻하는지 설명합니다.

## 전체 출력 구조

일반적인 성공 실행은 아래 순서로 진행됩니다.

```text
[Root CA]
[Quote]
[TDX Report measurements]
[PCK certificates from quote]
[1] ... OK
[2] ... OK
...
RESULT: ... OK
Verified:
Not verified yet:
```

## 1. `[Root CA]`

여기서는 verifier가 trust anchor로 사용하는 Root CA 인증서 정보를 출력합니다.

확인 포인트:
- Subject / Issuer
- Validity (`NotBefore`, `NotAfter`)
- SHA256 fingerprint
- Self-signed 여부

의미:
- 이후 모든 certificate/signing chain은 결국 이 root를 기준으로 신뢰됩니다.

## 2. `[Quote]`

Quote 자체의 메타데이터를 보여줍니다.

주요 항목:
- `Version`
- `AttKeyType`
- `TEEType`
- `Header+Body bytes`
- `SigDataLen`
- `AuthDataLen`
- `CertType`
- `CertDataLen`
- `QEReportOrder`

의미:
- Quote가 어떤 형식으로 해석되었는지
- QE report / certification data를 어떤 방식으로 파싱했는지

## 3. `[TDX Report measurements]`

샘플 Quote가 TDX Quote라면 TD report body에서 추출한 measurement를 출력합니다.

예:
- `MRTD`
- `RTMR0~3`
- `REPORTDATA`
- `TDATTRIBUTES`
- `XFAM`

의미:
- Intel collateral이 아닌, **애플리케이션 정책 비교 대상**이 되는 값들입니다.
- `-tdx-policy`가 있으면 이 값들을 기대값과 비교합니다.

## 4. `[PCK certificates from quote]`

Quote 안의 certification data에서 PCK certificate chain을 추출해 인증서별 정보를 보여줍니다.

보통 순서:
1. PCK leaf
2. PCK intermediate (Platform CA 또는 Processor CA)
3. Root CA

의미:
- Quote가 어떤 플랫폼 인증서 체인에 묶여 있는지 보여줍니다.

## 5. 단계별 `OK` 출력

각 줄은 검증 단계를 의미합니다.

### `[1] PCK certificate chain verification: OK`
- PCK leaf가 intermediate/root까지 정상 체인인지 확인했다는 뜻입니다.

### `[2] PCK CRL signature / freshness / revocation verification: OK`
- PCK CRL 자체가 진짜인지
- CRL이 만료되지 않았는지
- PCK leaf serial이 CRL에 올라가 있지 않은지
확인했다는 뜻입니다.

### `[3] Root CA CRL verification for PCK intermediate: OK`
- Root CA가 발급한 intermediate/signing cert가 폐기되지 않았는지 확인했다는 뜻입니다.

### `[4] QE/TDQE report signature verification: OK`
- PCK leaf 공개키로 QE report 서명이 검증되었다는 뜻입니다.

### `[5] AK hash binding verification: OK`
- `SHA256(attestation_key || auth_data)`가 QE report의 `report_data`와 맞는다는 뜻입니다.

### `[6] TDX/SGX quote signature verification: OK`
- Quote 본문 서명이 attestation key로 검증되었다는 뜻입니다.

### `[7] TCB Info signature / chain / freshness / FMSPC / TCB level verification: OK`
- TCB Info JSON의 진위
- signing chain
- freshness
- FMSPC / PCEID 일치
- TCB level 매칭
이 모두 성공했다는 뜻입니다.

### `[8] QE/TDQE Identity signature / chain / freshness verification: OK`
- QE Identity JSON과 QE report 비교가 성공했다는 뜻입니다.

### `[9] TDX measurement policy verification: OK`
- `-tdx-policy`를 준 경우에만 출력됩니다.
- TDX measurement가 기대값과 모두 정확히 일치한다는 뜻입니다.

## 6. `RESULT:`

```text
RESULT: basic cryptographic quote chain and partial collateral verification are OK
```

의미:
- 현재 구현 범위 안에서 모든 검증이 성공했다는 뜻입니다.
- production-grade 전체 attestation 판정과 동일한 의미는 아닙니다.

## 7. `Verified:`

이 블록은 현재 코드가 실제로 보장한 항목 목록입니다.

문서/코드를 읽지 않고도,
- 무엇이 검증되었고
- 무엇이 아직 미구현인지

를 한눈에 알 수 있도록 만든 요약입니다.

## 8. `Not verified yet:`

이 블록은 의도적으로 아직 구현하지 않았거나,
샘플/정적 검증만으로는 일반화하기 어려운 부분입니다.

예:
- challenge/session binding
- 앱 정책 없는 measurement 자동 승인
- 더 깊은 QE/TCB policy engine

## 9. 자주 보는 실패 예시

### Freshness 실패

예:
```text
issueDate is in the future
```
또는
```text
thisUpdate is in the future
```

의미:
- 샘플 collateral/CRL 시각과 현재 verify time이 맞지 않습니다.
- 샘플 재현이라면 `-sample-time`, `-ignore-freshness`가 필요할 수 있습니다.

### Policy mismatch

예:
```text
MRTD mismatch
```

의미:
- Quote에서 추출한 TDX measurement와 `-tdx-policy`의 기대값이 다릅니다.

### Identity mismatch

예:
```text
QE Identity MRSIGNER mismatch
```

의미:
- QE report가 Intel QE Identity JSON 정책과 맞지 않습니다.
