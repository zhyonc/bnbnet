package bnbnet

import (
	"fmt"
	"strings"

	"github.com/zhyonc/bnbnet/enum"
	"github.com/zhyonc/bnbnet/internal/crypt"
)

type sendPacket struct {
	Base     crypt.SendPacketBase
	Degree   enum.CipherDegree
	SendBuff []byte
	LogBuff  []byte
	Offset   int
}

func NewSendPacket(nType uint8) CSendPacket {
	p := &sendPacket{
		Base:     crypt.NewSendPacketBase(),
		SendBuff: make([]byte, 0),
		LogBuff:  make([]byte, 0),
	}
	if nType == 0 {
		p.Degree = enum.CipherDegree_None
	} else {
		p.Degree = gSetting.CipherDegree
		p.Encode1(int8(nType))
	}
	return p
}

// GetSendBuffer implements [CSendPacket].
func (p *sendPacket) GetSendBuffer() []byte {
	return p.SendBuff
}

// GetType implements [CSendPacket].
func (p *sendPacket) GetType() uint8 {
	if len(p.SendBuff) >= 1 {
		if p.Degree == enum.CipherDegree_None {
			return p.SendBuff[0]
		} else {
			return uint8(crypt.CBufferManipulator.Decrypt1(p.SendBuff[0:1]))
		}
	}
	return 0
}

// GetLength implements [CSendPacket].
func (p *sendPacket) GetLength() int {
	return len(p.SendBuff)
}

// EncodeBool implements [CSendPacket].
func (p *sendPacket) EncodeBool(b bool) {
	var n int8
	if b {
		n = 1
	}
	p.Encode1(n)
}

// Encode1 implements [CSendPacket].
func (p *sendPacket) Encode1(n int8) {
	if p.Degree == enum.CipherDegree_None {
		p.SendBuff = crypt.CBufferManipulator.Encode1(p.SendBuff, n)
	} else {
		p.SendBuff = crypt.CBufferManipulator.Encrypt1(p.SendBuff, n)
		p.LogBuff = crypt.CBufferManipulator.Encode1(p.LogBuff, n)
	}
	p.Offset++
}

// Encode2 implements [CSendPacket].
func (p *sendPacket) Encode2(n int16) {
	if p.Degree == enum.CipherDegree_None {
		p.SendBuff = crypt.CBufferManipulator.Encode2(p.SendBuff, n)
	} else {
		p.SendBuff = crypt.CBufferManipulator.Encrypt2(p.SendBuff, n)
		p.LogBuff = crypt.CBufferManipulator.Encode2(p.LogBuff, n)
	}
	p.Offset += 2
}

// Encode4 implements [CSendPacket].
func (p *sendPacket) Encode4(n int32) {
	if p.Degree == enum.CipherDegree_None {
		p.SendBuff = crypt.CBufferManipulator.Encode4(p.SendBuff, n)
	} else {
		p.SendBuff = crypt.CBufferManipulator.Encrypt4(p.SendBuff, n)
		p.LogBuff = crypt.CBufferManipulator.Encode4(p.LogBuff, n)
	}
	p.Offset += 4
}

// EncodeBuffer implements [CSendPacket].
func (p *sendPacket) EncodeBuffer(newBuf []byte) {
	p.SendBuff = crypt.CBufferManipulator.EncodeBuffer(p.SendBuff, newBuf)
	if p.Degree != enum.CipherDegree_None {
		p.LogBuff = crypt.CBufferManipulator.EncodeBuffer(p.LogBuff, newBuf)
	}
	p.Offset += len(newBuf)
}

// EncodeStr implements [CSendPacket].
func (p *sendPacket) EncodeStr(s string) {
	buf := GetLangBuf(s)
	bufLength := len(buf)
	p.Encode2(int16(bufLength))
	p.EncodeBuffer(buf)
}

// DumpString implements [CSendPacket].
func (p *sendPacket) DumpString(nSize int) string {
	var buf []byte
	if p.Degree == enum.CipherDegree_None {
		buf = p.SendBuff
	} else {
		buf = p.LogBuff
	}
	bufLength := len(buf)
	if nSize <= 0 || nSize > bufLength {
		nSize = bufLength
	}
	var builder strings.Builder
	for i := range nSize {
		v := buf[i]
		fmt.Fprintf(&builder, "%02X", v)
		if i < nSize-1 {
			builder.WriteString(" ")
		}
	}
	return builder.String()
}

// MakePacketComplete implements [CSendPacket].
func (p *sendPacket) MakePacketComplete(headerType uint8, seqSnd uint32) []byte {
	return p.Base.EncodePacket(p.Degree, p.SendBuff, headerType, seqSnd)
}

// Send implements [CSendPacket].
func (p *sendPacket) Send(cs CClientSocket) {
	cs.PutPacket(p)
	cs.Flush()
}
