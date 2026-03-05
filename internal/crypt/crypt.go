package crypt

import (
	"github.com/zhyonc/bnbnet/enum"
)

var (
	CPacketHeaderConverter PacketHeaderConverter = newPacketHeaderConverter()
	CBufferManipulator     BufferManipulator     = newBufferManipulator()
	CCRC8                  CRC                   = newCRC8()
	CCRC32                 CRC                   = newCRC32()
)

type PacketHeaderConverter interface {
	EncodeHeader(headerType uint8, opcode uint8) uint8
	DecodeHeader(headerType uint8, encryptedOpcode uint8) uint8
}

type BufferManipulator interface {
	Encode1(buf []byte, n int8) []byte
	Encode2(buf []byte, n int16) []byte
	Encode4(buf []byte, n int32) []byte
	EncodeBuffer(buf []byte, newBuf []byte) []byte
	Encrypt1(buf []byte, n int8) []byte
	Encrypt2(buf []byte, n int16) []byte
	Encrypt4(buf []byte, n int32) []byte
	Decode1(buf []byte) int8
	Decode2(buf []byte) int16
	Decode4(buf []byte) int32
	DecodeBuffer(buf []byte, uSize int) []byte
	Decrypt1(buf []byte) int8
	Decrypt2(buf []byte) int16
	Decrypt4(buf []byte) int32
}

type CRC interface {
	GenCRCTable()
	UpdateCRC(seq uint32, data []byte) int
}

type SendPacketBase interface {
	EncodePacket(degree enum.CipherDegree, data []byte, headerType uint8, seqSnd uint32) []byte
}

type ReceivedPacketBase interface {
	DecodePacket(degree enum.CipherDegree, data []byte, headerType uint8, seqRcv uint32) []byte
}
