# 실패 시나리오 가이드

이 문서는 어떤 검증이 어떤 이유로 실패할 수 있는지 설명합니다.

## 1. Freshness 실패

### 예시 메시지
- `issueDate is in the future`
- `thisUpdate is in the future`
- `expired`

### 의미
- collateral 또는 CRL의 유효 시각이 현재 verify time과 맞지 않습니다.

### 샘플 환경에서 흔한 이유
- 샘플 데이터가 과거 시점 기준이라 현재 시각으로는 freshness가 맞지 않음

### 대응
- 샘플 재현이라면 `-sample-time`, `-ignore-freshness`
- 운영 환경이라면 최신 collateral/CRL 사용

## 2. 인증서 체인 실패

### 예시 메시지
- `verify PCK cert chain`
- `verify TCB signing cert chain`
- `verify QE identity signing cert chain`

### 의미
- 인증서 체인이 root까지 정상적으로 이어지지 않음

### 의심할 것
- root 경로가 틀렸는지
- 중간 cert가 잘못되었는지
- verify time이 cert validity와 맞는지

## 3. CRL 실패

### 예시 메시지
- `verify PCK CRL signature`
- `certificate serial is revoked`
- `verify Root CA CRL signature`

### 의미
- CRL 자체가 진짜가 아니거나
- CRL이 만료되었거나
- 대상 cert가 이미 폐기되었음

## 4. QE Identity 실패

### 예시 메시지
- `QE Identity MRSIGNER mismatch`
- `QE Identity ISVPRODID mismatch`
- `QE TCB status not acceptable`

### 의미
- Quote 안 QE report가 Intel QE Identity 정책과 맞지 않음

## 5. TCB Info 실패

### 예시 메시지
- `FMSPC mismatch`
- `PCEID mismatch`
- `platform TCB does not satisfy any TCB Info level`

### 의미
- 현재 플랫폼의 PCK/TEE 상태가 TCB Info JSON과 맞지 않음

## 6. TDX policy 실패

### 예시 메시지
- `MRTD mismatch`
- `REPORTDATA mismatch`
- `RTMR0 mismatch`

### 의미
- Quote에서 추출한 measurement가 사용자가 기대한 값과 다름

### 대응
- 정책 파일이 틀렸는지
- 실제 Quote가 다른 workload에서 생성된 것인지
- RTMR/REPORTDATA가 런타임 입력에 의해 달라졌는지 확인
