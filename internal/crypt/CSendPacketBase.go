package crypt

import (
	"github.com/zhyonc/bnbnet/enum"
)

type sendPacketBase struct{}

func NewSendPacketBase() SendPacketBase {
	return &sendPacketBase{}
}

// EncodePacket implements [SendPacketBase].
func (base *sendPacketBase) EncodePacket(degree enum.CipherDegree, data []byte, headerType uint8, seqSnd uint32) []byte {
	encryptedData := make([]byte, 0)
	encryptedData = CBufferManipulator.Encode1(encryptedData, int8(ComputeHeaderCodeSnd(headerType, seqSnd)))
	dataLength := int16(len(data))
	switch degree {
	case enum.CipherDegree_None:
		encryptedData = CBufferManipulator.Encode2(encryptedData, dataLength)
		encryptedData = CBufferManipulator.EncodeBuffer(encryptedData, data)
		encryptedData[3] = CPacketHeaderConverter.EncodeHeader(headerType, encryptedData[3])
	case enum.CipherDegree_CRC32:
		encryptedData = CBufferManipulator.Encrypt2(encryptedData, dataLength)
		encryptedData = CBufferManipulator.EncodeBuffer(encryptedData, SimpleStreamEncrypt(data, seqSnd))
		encryptedData = CBufferManipulator.Encode4(encryptedData, int32(CCRC32.UpdateCRC(seqSnd, data)))
	case enum.CipherDegree_CRC8:
		encryptedData = CBufferManipulator.Encrypt2(encryptedData, dataLength)
		encryptedData = CBufferManipulator.EncodeBuffer(encryptedData, SimpleStreamEncrypt(data, seqSnd))
		encryptedData = CBufferManipulator.Encode1(encryptedData, int8(CCRC8.UpdateCRC(seqSnd, data)))
	case enum.CipherDegree_LH_CRC8:
		encryptedData = CBufferManipulator.Encrypt4(encryptedData, int32(dataLength))
		encryptedData = CBufferManipulator.EncodeBuffer(encryptedData, SimpleStreamEncrypt(data, seqSnd))
		encryptedData = CBufferManipulator.Encode1(encryptedData, int8(CCRC8.UpdateCRC(seqSnd, data)))
	default:
		return nil
	}
	return encryptedData
}
