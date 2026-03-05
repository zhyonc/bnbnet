package bnbnet

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"

	"github.com/zhyonc/bnbnet/enum"
	"github.com/zhyonc/bnbnet/internal/crypt"
)

const (
	HEADER_LENGTH = 3
)

type clientSocket struct {
	id         int32
	delegate   CClientSocketDelegate
	sock       net.Conn
	rcvBuff    []byte
	sndBuff    []byte
	headerType uint8
	seqRcv     uint32
	seqSnd     uint32
}

func NewClientSocket(delegate CClientSocketDelegate, conn net.Conn) CClientSocket {
	c := &clientSocket{
		delegate:   delegate,
		sock:       conn,
		headerType: uint8(rand.UintN(16)),
		seqRcv:     crypt.HEADER_CODE_SEQ,
		seqSnd:     crypt.HEADER_CODE_SEQ,
	}
	return c
}

// OnConnect implements [CClientSocket].
func (cs *clientSocket) OnConnect() {
	sndPacket := NewSendPacket(0)
	sndPacket.EncodeBool(false)                // true->ErrCannotConnect
	sndPacket.Encode2(int16(gSetting.Version)) // ClientMinimumVersion
	sndPacket.Encode2(int16(gSetting.Version)) // ServerLatestVersion
	sndPacket.Encode4(int32(cs.headerType))    // TableRowIndex
	sndPacket.EncodeStr("")                    // UrlPatch
	sndPacket.Send(cs)
}

// PutPacket implements [CClientSocket].
func (cs *clientSocket) PutPacket(sndPacket CSendPacket) {
	cs.delegate.DebugSndPacketLog(cs.id, sndPacket)
	cs.sndBuff = sndPacket.MakePacketComplete(cs.headerType, cs.seqSnd)
	if cs.sndBuff == nil {
		slog.Error("Failed to MakePacketComplete", "socketID", cs.id, "seqSnd", cs.seqSnd)
		return
	}
	cs.seqSnd += crypt.SEQ_SND_DELTA
}

// Flush implements [CClientSocket].
func (cs *clientSocket) Flush() {
	if cs.sndBuff == nil {
		return
	}
	_, err := cs.sock.Write(cs.sndBuff)
	if err != nil {
		slog.Error("Failed to send packet to client", "err", err)
		return
	}
}

// TryRead implements [CClientSocket].
func (cs *clientSocket) TryRead() {
	defer cs.Close()
	readSize := HEADER_LENGTH
	isHeader := true
	for {
		cs.rcvBuff = make([]byte, readSize)
		_, err := io.ReadFull(cs.sock, cs.rcvBuff)
		if err != nil {
			cs.OnError(err)
			return
		}
		if isHeader {
			// Decrypt Header
			clientHeaderCode := cs.rcvBuff[0]
			serverHeaderCode := crypt.ComputeHeaderCodeRcv(cs.headerType, cs.seqRcv)
			if clientHeaderCode != serverHeaderCode {
				cs.OnError(fmt.Errorf("client header code %d doesn't match server header code %d", clientHeaderCode, serverHeaderCode))
				return
			}
			if gSetting.CipherDegree == enum.CipherDegree_None {
				readSize = int(crypt.CBufferManipulator.Decode2(cs.rcvBuff[1:3]))
			} else {
				readSize = int(crypt.CBufferManipulator.Decrypt2(cs.rcvBuff[1:3]))
			}
			switch gSetting.CipherDegree {
			case enum.CipherDegree_CRC8:
				readSize += 1
			case enum.CipherDegree_CRC32:
				readSize += 4
			}
		} else {
			// Decrypt Data
			rcvPacket := NewReceivedPacket(cs.rcvBuff)
			ok := cs.GetPacket(rcvPacket)
			if !ok {
				cs.OnError(fmt.Errorf("invaild crc value"))
				return
			}
			if gSetting.CipherDegree == enum.CipherDegree_None {
				cs.delegate.DebugRcvPacketLog(cs.id, rcvPacket)
				cs.delegate.DispatchPacket(cs, rcvPacket)
			} else {
				cs.delegate.DispatchPacket(cs, rcvPacket)
				cs.delegate.DebugRcvPacketLog(cs.id, rcvPacket)
			}
			cs.seqRcv += crypt.SEQ_RCV_DELTA
			readSize = HEADER_LENGTH
		}
		isHeader = !isHeader
	}
}

// GetPacket implements [CClientSocket].
func (cs *clientSocket) GetPacket(rcvPacket CReceivedPacket) bool {
	return rcvPacket.SetRcvPacket(cs.headerType, cs.seqRcv)
}

// OnError implements [CClientSocket].
func (cs *clientSocket) OnError(err error) {
	slog.Error("[ClientSocket] OnError", "socketID", cs.id, "err", err)
	cs.Close()
}

// Close implements [CClientSocket].
func (cs *clientSocket) Close() {
	if cs.sock != nil {
		cs.sock.Close()
		cs.sock = nil
	}
}
