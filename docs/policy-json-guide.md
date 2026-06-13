# TDX Policy JSON 가이드

`-tdx-policy` 옵션은 Quote에서 추출한 TDX measurement를 **사용자가 기대하는 값과 exact match 비교**할 때 사용합니다.

## 왜 필요한가

Intel collateral은 보통 다음을 말해줍니다.

- 이 플랫폼이 Intel 체계 안에 있는가
- 이 QE/플랫폼 상태가 허용 가능한가

하지만 Intel collateral만으로는 보통 다음을 말해주지 않습니다.

- 이 TD가 **내 서비스가 기대하는 워크로드**인가
- 이 TD의 `MRTD`, `RTMR`, `REPORTDATA`가 내 기준과 맞는가

그래서 이 저장소는 별도의 정책 파일을 받습니다.

## 지원 필드

현재 비교 가능한 필드:

- `mrseam`
- `mrsignerseam`
- `seamAttributes`
- `tdAttributes`
- `xfam`
- `mrtd`
- `mrconfigid`
- `mrowner`
- `mrownerconfig`
- `rtmr0`
- `rtmr1`
- `rtmr2`
- `rtmr3`
- `reportData`

## 규칙

- 모든 값은 **hex string**입니다.
- 넣지 않은 필드는 비교하지 않습니다.
- 넣은 필드는 **exact match** 합니다.

## 최소 예시

```json
{
  "mrtd": "B65EA009E424E6F761FDD3D7C8962439453B37ECDF62DA04F7BC5D327686BB8BAFC8A5D24A9C31CEE60E4ABA87C2F71B"
}
```

의미:
- `MRTD`만 비교하고 나머지는 무시합니다.

## 샘플 전체 예시

파일:
- `test_data/tdx_policy_sample.json`

이 파일은 샘플 Quote의 실제 measurement를 읽어서 만든 예시입니다.

## 사용 예시

```bash
go run ./cmd/tdx-attest verify \
  -sample-time 2023-02-01T00:00:00Z \
  -ignore-freshness \
  -tdx-policy test_data/tdx_policy_sample.json
```

## 실패 예시

잘못된 policy:

```json
{
  "mrtd": "00"
}
```

예상 결과:
- `MRTD mismatch`

## 정책을 설계할 때 주의할 점

- `REPORTDATA`는 앱 challenge/session/public key binding과 연결될 수 있습니다.
- `RTMR`는 런타임 이벤트에 따라 달라질 수 있습니다.
- `MRTD`는 TD 초기 측정값이라 가장 자주 기준값으로 사용됩니다.

즉, 처음 정책을 만들 때는 보통 다음 순서가 실용적입니다.

1. `MRTD`
2. `TDATTRIBUTES`, `XFAM`
3. 필요 시 `RTMR`
4. 필요 시 `REPORTDATA`
