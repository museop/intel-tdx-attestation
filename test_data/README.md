# test_data 안내

이 디렉터리는 샘플 Quote와 collateral, 그리고 샘플 정책 파일을 모아 둔 곳입니다.

## 목적

- 코드 동작을 빠르게 재현
- 테스트/문서에서 공통 샘플 사용
- Quote / cert / CRL / collateral / policy의 관계를 한곳에서 설명

## 구성

- `quote.dat` : 샘플 TDX Quote
- `certs/` : Root CA, CRL, signing chain, PCK CRL 관련 파일
- `collateral/` : TCB Info, QE Identity JSON
- `tdx_policy_sample.json` : 샘플 Quote에서 파생한 measurement 기대값

## 중요 구분

### 외부 원본에 가까운 파일
- `quote.dat`
- `collateral/*.json`
- `certs/*.pem`
- `certs/*.crl`
- `certs/*.der`

### 이 저장소에서 파생 생성한 파일
- `tdx_policy_sample.json`

이 파일은 샘플 Quote의 실제 measurement를 읽어서 정책 입력 형식으로 만든 예시입니다.

## 샘플 재현 시 권장 명령

```bash
go run . -sample-time 2023-02-01T00:00:00Z -ignore-freshness
```
