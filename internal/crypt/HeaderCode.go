package crypt

const (
	HEADER_CODE_SEQ      uint32 = 0x28
	HEADER_CODE_MODIFIER uint8  = 0xE7
	HEADER_CODE_SND_BASE uint8  = 0x66
	HEADER_CODE_RCV_BASE uint8  = 0xC0
	SEQ_SND_DELTA        uint32 = 3
	SEQ_RCV_DELTA        uint32 = 3
)

// In CSendPacket::MakePacketComplete
func ComputeHeaderCodeSnd(headerType uint8, seqSnd uint32) uint8 {
	return (headerType + HEADER_CODE_MODIFIER) ^ (HEADER_CODE_SND_BASE + uint8(seqSnd))
}

// In CClientSocket::GetPacket
func ComputeHeaderCodeRcv(headerType uint8, seqRcv uint32) uint8 {
	return (headerType + HEADER_CODE_MODIFIER) ^ (HEADER_CODE_RCV_BASE + uint8(seqRcv))
}
