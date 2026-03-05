package crypt

import (
	"github.com/zhyonc/bnbnet/enum"
)

type receivedPacketBase struct{}

func NewReceivedPacketBase() ReceivedPacketBase {
	return &receivedPacketBase{}
}

// DecodePacket implements [ReceivedPacketBase].
func (base *receivedPacketBase) DecodePacket(degree enum.CipherDegree, data []byte, headerType uint8, seqRcv uint32) []byte {
	dataLength := int16(len(data))
	var decryptedData []byte
	switch degree {
	case enum.CipherDegree_CRC8:
		decryptedData = SimpleStreamDecrypt(data[:dataLength-1], seqRcv)
		clientCRC := uint8(CBufferManipulator.Decode1(data[dataLength-1 : dataLength]))
		serverCRC := uint8(CCRC8.UpdateCRC(seqRcv, decryptedData))
		if clientCRC != serverCRC {
			return nil
		}
	case enum.CipherDegree_CRC32:
		decryptedData = SimpleStreamDecrypt(data[:dataLength-4], seqRcv)
		clientCRC := uint32(CBufferManipulator.Decode4(data[dataLength-4 : dataLength]))
		serverCRC := uint32(CCRC32.UpdateCRC(seqRcv, decryptedData))
		if clientCRC != serverCRC {
			return nil
		}
	case enum.CipherDegree_None:
		data[0] = CPacketHeaderConverter.DecodeHeader(headerType, data[0])
		decryptedData = data
	}
	return decryptedData
}
