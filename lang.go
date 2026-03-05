package bnbnet

import (
	"bytes"
	"io"
	"log/slog"
	"strings"

	"github.com/zhyonc/bnbnet/enum"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
)

var (
	langEncoder *encoding.Encoder
	langDecoder *encoding.Decoder
)

func SetCharset(region enum.Region) {
	switch region {
	case enum.RegionKR:
		langEncoder = korean.EUCKR.NewEncoder()
		langDecoder = korean.EUCKR.NewDecoder()
	case enum.RegionCN:
		langEncoder = simplifiedchinese.GBK.NewEncoder()
		langDecoder = simplifiedchinese.GBK.NewDecoder()
	case enum.RegionTW:
		langEncoder = traditionalchinese.Big5.NewEncoder()
		langDecoder = traditionalchinese.Big5.NewDecoder()
	case enum.RegionJP:
		langEncoder = japanese.ShiftJIS.NewEncoder()
		langDecoder = japanese.ShiftJIS.NewDecoder()
	default:
		langEncoder = encoding.Nop.NewEncoder()
		langDecoder = encoding.Nop.NewDecoder()
	}
}

func GetLangBuf(s string) []byte {
	reader := strings.NewReader(s)
	transformer := transform.NewReader(reader, langEncoder)
	buf, err := io.ReadAll(transformer)
	if err != nil {
		slog.Error("Failed to get local buf", "str", s)
		return nil
	}
	return buf
}

func GetLangStr(buf []byte) string {
	reader := bytes.NewReader(buf)
	transformer := transform.NewReader(reader, langDecoder)
	decodedBytes, err := io.ReadAll(transformer)
	if err != nil {
		slog.Error("Failed to get local str", "buf", buf)
		return ""
	}
	return string(decodedBytes)
}
