package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	tdxOffsetTeeTCBSVN    = 0
	tdxOffsetMRSEAM       = tdxOffsetTeeTCBSVN + 16
	tdxOffsetMRSignerSEAM = tdxOffsetMRSEAM + 48
	tdxOffsetSEAMAttrs    = tdxOffsetMRSignerSEAM + 48
	tdxOffsetTDAttrs      = tdxOffsetSEAMAttrs + 8
	tdxOffsetXFAM         = tdxOffsetTDAttrs + 8
	tdxOffsetMRTD         = tdxOffsetXFAM + 8
	tdxOffsetMRConfigID   = tdxOffsetMRTD + 48
	tdxOffsetMROwner      = tdxOffsetMRConfigID + 48
	tdxOffsetMROwnerCfg   = tdxOffsetMROwner + 48
	tdxOffsetRTMR0        = tdxOffsetMROwnerCfg + 48
	tdxOffsetRTMR1        = tdxOffsetRTMR0 + 48
	tdxOffsetRTMR2        = tdxOffsetRTMR1 + 48
	tdxOffsetRTMR3        = tdxOffsetRTMR2 + 48
	tdxOffsetReportData   = tdxOffsetRTMR3 + 48
)

// TDXMeasurements는 애플리케이션 정책 엔진이 주로 관심을 가지는 TD report 필드를 담습니다.
//
// 이 값들 전체가 Intel collateral만으로 자동 판정되는 것은 아닙니다. 많은 필드는
// 서비스가 따로 정한 golden MRTD/RTMR이나 REPORTDATA 바인딩 값과 비교해야 의미가 있습니다.
type TDXMeasurements struct {
	TeeTCBSVN      []byte
	MRSEAM         []byte
	MRSignerSEAM   []byte
	SEAMAttributes []byte
	TDAttributes   []byte
	XFAM           []byte
	MRTD           []byte
	MRConfigID     []byte
	MROwner        []byte
	MROwnerConfig  []byte
	RTMR0          []byte
	RTMR1          []byte
	RTMR2          []byte
	RTMR3          []byte
	ReportData     []byte
}

// TDXPolicy는 샘플/로컬 검증용으로 만든 단순 exact-match 정책 파일입니다.
//
// 이것은 완전한 정책 언어가 아니라, "이 Quote의 TDX measurement가 내가 기대한 값과
// 정확히 같은가?"를 빠르게 확인하기 위한 최소 구조입니다.
type TDXPolicy struct {
	MRSEAM         string `json:"mrseam"`
	MRSignerSEAM   string `json:"mrsignerseam"`
	SEAMAttributes string `json:"seamAttributes"`
	TDAttributes   string `json:"tdAttributes"`
	XFAM           string `json:"xfam"`
	MRTD           string `json:"mrtd"`
	MRConfigID     string `json:"mrconfigid"`
	MROwner        string `json:"mrowner"`
	MROwnerConfig  string `json:"mrownerconfig"`
	RTMR0          string `json:"rtmr0"`
	RTMR1          string `json:"rtmr1"`
	RTMR2          string `json:"rtmr2"`
	RTMR3          string `json:"rtmr3"`
	ReportData     string `json:"reportData"`
}

// parseTDXMeasurements는 Intel QVL 구조체와 맞는 오프셋을 사용해 TDX report body에서
// TD 관련 measurement 필드를 추출합니다.
func parseTDXMeasurements(parsedQuote *ParsedQuote) (*TDXMeasurements, error) {
	if len(parsedQuote.ReportBody) != tdxReportBodySize {
		return nil, fmt.Errorf("quote body is not a TDX TD report: got %d bytes", len(parsedQuote.ReportBody))
	}

	body := parsedQuote.ReportBody
	return &TDXMeasurements{
		TeeTCBSVN:      cloneBytes(body[tdxOffsetTeeTCBSVN:tdxOffsetMRSEAM]),
		MRSEAM:         cloneBytes(body[tdxOffsetMRSEAM:tdxOffsetMRSignerSEAM]),
		MRSignerSEAM:   cloneBytes(body[tdxOffsetMRSignerSEAM:tdxOffsetSEAMAttrs]),
		SEAMAttributes: cloneBytes(body[tdxOffsetSEAMAttrs:tdxOffsetTDAttrs]),
		TDAttributes:   cloneBytes(body[tdxOffsetTDAttrs:tdxOffsetXFAM]),
		XFAM:           cloneBytes(body[tdxOffsetXFAM:tdxOffsetMRTD]),
		MRTD:           cloneBytes(body[tdxOffsetMRTD:tdxOffsetMRConfigID]),
		MRConfigID:     cloneBytes(body[tdxOffsetMRConfigID:tdxOffsetMROwner]),
		MROwner:        cloneBytes(body[tdxOffsetMROwner:tdxOffsetMROwnerCfg]),
		MROwnerConfig:  cloneBytes(body[tdxOffsetMROwnerCfg:tdxOffsetRTMR0]),
		RTMR0:          cloneBytes(body[tdxOffsetRTMR0:tdxOffsetRTMR1]),
		RTMR1:          cloneBytes(body[tdxOffsetRTMR1:tdxOffsetRTMR2]),
		RTMR2:          cloneBytes(body[tdxOffsetRTMR2:tdxOffsetRTMR3]),
		RTMR3:          cloneBytes(body[tdxOffsetRTMR3:tdxOffsetReportData]),
		ReportData:     cloneBytes(body[tdxOffsetReportData:]),
	}, nil
}

func printTDXMeasurements(measurements *TDXMeasurements) {
	fmt.Println()
	fmt.Println("[TDX Report measurements]")
	fmt.Println("TEE_TCB_SVN:    ", bytesToUpperHex(measurements.TeeTCBSVN))
	fmt.Println("MRSEAM:         ", bytesToUpperHex(measurements.MRSEAM))
	fmt.Println("MRSIGNERSEAM:   ", bytesToUpperHex(measurements.MRSignerSEAM))
	fmt.Println("SEAMATTRIBUTES: ", bytesToUpperHex(measurements.SEAMAttributes))
	fmt.Println("TDATTRIBUTES:   ", bytesToUpperHex(measurements.TDAttributes))
	fmt.Println("XFAM:           ", bytesToUpperHex(measurements.XFAM))
	fmt.Println("MRTD:           ", bytesToUpperHex(measurements.MRTD))
	fmt.Println("MRCONFIGID:     ", bytesToUpperHex(measurements.MRConfigID))
	fmt.Println("MROWNER:        ", bytesToUpperHex(measurements.MROwner))
	fmt.Println("MROWNERCONFIG:  ", bytesToUpperHex(measurements.MROwnerConfig))
	fmt.Println("RTMR0:          ", bytesToUpperHex(measurements.RTMR0))
	fmt.Println("RTMR1:          ", bytesToUpperHex(measurements.RTMR1))
	fmt.Println("RTMR2:          ", bytesToUpperHex(measurements.RTMR2))
	fmt.Println("RTMR3:          ", bytesToUpperHex(measurements.RTMR3))
	fmt.Println("REPORTDATA:     ", bytesToUpperHex(measurements.ReportData))
}

func loadTDXPolicy(path string) (*TDXPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var policy TDXPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("parse TDX policy JSON: %w", err)
	}
	return &policy, nil
}

// verifyTDXPolicy는 추출한 measurement를 호출자가 제공한 기대값과 비교합니다.
//
// 이 정책이 선택적인 이유는, Intel collateral만으로는 특정 워크로드가 어떤 MRTD/RTMR이나
// REPORTDATA를 가져야 하는지까지는 결정할 수 없기 때문입니다.
func verifyTDXPolicy(measurements *TDXMeasurements, policy *TDXPolicy) error {
	if policy == nil {
		return nil
	}

	checks := []struct {
		name     string
		actual   []byte
		expected string
	}{
		{"MRSEAM", measurements.MRSEAM, policy.MRSEAM},
		{"MRSIGNERSEAM", measurements.MRSignerSEAM, policy.MRSignerSEAM},
		{"SEAMATTRIBUTES", measurements.SEAMAttributes, policy.SEAMAttributes},
		{"TDATTRIBUTES", measurements.TDAttributes, policy.TDAttributes},
		{"XFAM", measurements.XFAM, policy.XFAM},
		{"MRTD", measurements.MRTD, policy.MRTD},
		{"MRCONFIGID", measurements.MRConfigID, policy.MRConfigID},
		{"MROWNER", measurements.MROwner, policy.MROwner},
		{"MROWNERCONFIG", measurements.MROwnerConfig, policy.MROwnerConfig},
		{"RTMR0", measurements.RTMR0, policy.RTMR0},
		{"RTMR1", measurements.RTMR1, policy.RTMR1},
		{"RTMR2", measurements.RTMR2, policy.RTMR2},
		{"RTMR3", measurements.RTMR3, policy.RTMR3},
		{"REPORTDATA", measurements.ReportData, policy.ReportData},
	}

	for _, check := range checks {
		if err := verifyExactHexValue(check.name, check.actual, check.expected); err != nil {
			return err
		}
	}
	return nil
}

func verifyExactHexValue(name string, actual []byte, expectedHex string) error {
	if strings.TrimSpace(expectedHex) == "" {
		return nil
	}

	expected, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return fmt.Errorf("%s expected hex decode failed: %w", name, err)
	}
	if !strings.EqualFold(hex.EncodeToString(actual), hex.EncodeToString(expected)) {
		return fmt.Errorf("%s mismatch: actual=%s expected=%s", name, bytesToUpperHex(actual), strings.ToUpper(hex.EncodeToString(expected)))
	}
	return nil
}

func bytesToUpperHex(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}

func cloneBytes(data []byte) []byte {
	return append([]byte(nil), data...)
}
