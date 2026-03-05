package crypt

import (
	_ "embed"
	"strconv"
	"strings"
)

var (
	//go:embed gsConvertTableEncode.txt
	gsConvertTableEncodeText string
	//go:embed gsConvertTableDecode.txt
	gsConvertTableDecodeText string
	// Table
	gsConvertTableEncode [16][256]byte
	gsConvertTableDecode [16][256]byte
)

func init() {
	parseTable(gsConvertTableEncodeText, &gsConvertTableEncode)
	parseTable(gsConvertTableDecodeText, &gsConvertTableDecode)
}

func parseTable(text string, table *[16][256]byte) {
	replacer := strings.NewReplacer(
		"0x", "",
		",", " ",
		"\n", " ",
		"\r", " ",
	)
	cleanStr := replacer.Replace(text)
	fields := strings.Fields(cleanStr)

	for i, field := range fields {
		if i >= 16*256 {
			break
		}
		val, _ := strconv.ParseUint(field, 16, 8)
		table[i/256][i%256] = byte(val)
	}
}

type packetHeaderConverter struct{}

func newPacketHeaderConverter() PacketHeaderConverter {

	return &packetHeaderConverter{}
}

// EncodeHeader implements [PacketHeaderConverter].
func (p *packetHeaderConverter) EncodeHeader(headerType uint8, opcode uint8) uint8 {
	return gsConvertTableEncode[headerType%16][opcode]
}

// DecodeHeader implements [PacketHeaderConverter].
func (p *packetHeaderConverter) DecodeHeader(headerType uint8, encryptedOpcode uint8) uint8 {
	return gsConvertTableDecode[headerType%16][encryptedOpcode]
}
