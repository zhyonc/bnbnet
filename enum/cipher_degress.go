package enum

type CipherDegree uint8

const (
	CipherDegree_None    CipherDegree = 0 // HeaderCode(1) + DataLength(2) + Opcode Obfuscation
	CipherDegree_CRC32   CipherDegree = 1 // HeaderCode(1) + XORDataLength(2) + SimpleStream + CRC32 footer
	CipherDegree_CRC8    CipherDegree = 2 // HeaderCode(1) + XORDataLength(2) + SimpleStream + CRC8 footer
	CipherDegree_LH_CRC8 CipherDegree = 3 // HeaderCode(1) + XORDataLengthRcv(2)/XORDataLengthSnd(4) + SimpleStream + CRC8 footer
)
