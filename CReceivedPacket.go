package bnbnet

import (
	"fmt"
	"strings"

	"github.com/zhyonc/bnbnet/enum"
	"github.com/zhyonc/bnbnet/internal/crypt"
)

type receivePacket struct {
	Base     crypt.ReceivedPacketBase
	Degree   enum.CipherDegree
	RecvBuff []byte
	Length   int
	Offset   int
}

func NewReceivedPacket(buf []byte) CReceivedPacket {
	p := &receivePacket{
		Base:     crypt.NewReceivedPacketBase(),
		RecvBuff: buf,
	}
	p.Degree = gSetting.CipherDegree
	return p
}

// SetRcvPacket implements [CReceivedPacket].
func (p *receivePacket) SetRcvPacket(headerType uint8, seqRcv uint32) bool {
	decryptedData := p.Base.DecodePacket(p.Degree, p.RecvBuff, headerType, seqRcv)
	if decryptedData == nil {
		return false
	}
	p.RecvBuff = decryptedData
	p.Length = len(p.RecvBuff)
	return true
}

// GetType implements [CReceivedPacket].
func (p *receivePacket) GetType() uint8 {
	if p.Length >= 1 {
		if p.Degree == enum.CipherDegree_None {
			return p.RecvBuff[0]
		} else {
			return uint8(crypt.CBufferManipulator.Decrypt1(p.RecvBuff[0:1]))
		}
	}
	return 0
}

// GetRemain implements [CReceivedPacket].
func (p *receivePacket) GetRemain() int {
	return p.Length - p.Offset
}

// GetLength implements [CReceivedPacket].
func (p *receivePacket) GetLength() int {
	return p.Length
}

// DecodeBool implements [CReceivedPacket].
func (p *receivePacket) DecodeBool() bool {
	return p.Decode1() == 1
}

// Decode1 implements [CReceivedPacket].
func (p *receivePacket) Decode1() int8 {
	if p.GetRemain() <= 0 {
		return 0
	}
	var result int8
	if p.Degree == enum.CipherDegree_None {
		result = crypt.CBufferManipulator.Decode1(p.RecvBuff[p.Offset : p.Offset+1])
	} else {
		result = crypt.CBufferManipulator.Decrypt1(p.RecvBuff[p.Offset : p.Offset+1])
	}
	p.Offset += 1
	return result
}

// Decode2 implements [CReceivedPacket].
func (p *receivePacket) Decode2() int16 {
	if p.GetRemain() < 2 {
		return 0
	}
	var result int16
	if p.Degree == enum.CipherDegree_None {
		result = crypt.CBufferManipulator.Decode2(p.RecvBuff[p.Offset : p.Offset+2])
	} else {
		result = crypt.CBufferManipulator.Decrypt2(p.RecvBuff[p.Offset : p.Offset+2])
	}
	p.Offset += 2
	return int16(result)
}

// Decode4 implements [CReceivedPacket].
func (p *receivePacket) Decode4() int32 {
	if p.GetRemain() < 4 {
		return 0
	}
	var result int32
	if p.Degree == enum.CipherDegree_None {
		result = crypt.CBufferManipulator.Decode4(p.RecvBuff[p.Offset : p.Offset+4])
	} else {
		result = crypt.CBufferManipulator.Decrypt4(p.RecvBuff[p.Offset : p.Offset+4])
	}
	p.Offset += 4
	return int32(result)
}

// DecodeBuffer implements [CReceivedPacket].
func (p *receivePacket) DecodeBuffer(uSize int) []byte {
	if p.GetRemain() < uSize || uSize < 0 {
		return nil
	}
	result := crypt.CBufferManipulator.DecodeBuffer(p.RecvBuff[p.Offset:], uSize)
	p.Offset += uSize
	return result
}

// DecryptBuffer implements [CReceivedPacket].
func (p *receivePacket) DecryptBuffer(uSize int) []byte {
	if p.GetRemain() < uSize || uSize < 0 {
		return nil
	}
	result := crypt.CBufferManipulator.DecryptBuffer(p.RecvBuff[p.Offset:], uSize)
	p.Offset += uSize
	return result
}

// DecodeStr implements [CReceivedPacket].
func (p *receivePacket) DecodeStr() string {
	if p.GetRemain() < 2 {
		return ""
	}
	strLen := int(p.Decode2())
	if p.GetRemain() < strLen {
		return ""
	}
	buf := p.DecodeBuffer(strLen)
	return GetLangStr(buf)
}

// DecodeEncryptedStr implements [CReceivedPacket].
func (p *receivePacket) DecryptStr(key uint32) string {
	if p.GetRemain() < 2 {
		return ""
	}
	strLen := int(p.Decode2())
	if p.GetRemain() < strLen {
		return ""
	}
	encryptedBuf := p.DecodeBuffer(strLen)
	buf := crypt.SimpleStreamDecrypt(encryptedBuf, key)
	return GetLangStr(buf)
}

// DumpString implements [CReceivedPacket].
func (p *receivePacket) DumpString(nSize int) string {
	bufLength := len(p.RecvBuff)
	if nSize <= 0 || nSize > bufLength {
		nSize = bufLength
	}
	var builder strings.Builder
	for i := range nSize {
		v := p.RecvBuff[i]
		fmt.Fprintf(&builder, "%02X", v)
		if i < nSize-1 {
			builder.WriteString(" ")
		}
	}
	return builder.String()
}
