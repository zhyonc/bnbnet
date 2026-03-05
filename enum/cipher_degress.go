package enum

type CipherDegree uint8

const (
	CipherDegree_None  CipherDegree = 0 // HeaderCode + Length + Opcode Obfuscation
	CipherDegree_CRC32 CipherDegree = 1 // HeaderCode + XORLength + SimpleStream + CRC32 footer
	CipherDegree_CRC8  CipherDegree = 2 // HeaderCode + XORLength + SimpleStream + CRC8 footer
)
