package crypt

import "encoding/binary"

const (
	XOR_KEY1 int8   = 0x5A
	XOR_KEY2 uint16 = 0xA569
	XOR_KEY4 uint32 = 0x96CA5395
)

type bufferManipulator struct{}

func newBufferManipulator() BufferManipulator {
	bm := &bufferManipulator{}
	return bm
}

// Encode1 implements [BufferManipulator].
func (bm *bufferManipulator) Encode1(buf []byte, n int8) []byte {
	return append(buf, byte(n))
}

// Encode2 implements [BufferManipulator].
func (bm *bufferManipulator) Encode2(buf []byte, n int16) []byte {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(n))
	return append(buf, tmp...)
}

// Encode4 implements [BufferManipulator].
func (bm *bufferManipulator) Encode4(buf []byte, n int32) []byte {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(n))
	return append(buf, tmp...)
}

// EncodeBuffer implements [BufferManipulator].
func (bm *bufferManipulator) EncodeBuffer(buf []byte, newBuf []byte) []byte {
	return append(buf, newBuf...)
}

// Encrypt1 implements [BufferManipulator].
func (bm *bufferManipulator) Encrypt1(buf []byte, n int8) []byte {
	v := n ^ XOR_KEY1
	return bm.Encode1(buf, int8(v))
}

// Encrypt2 implements [BufferManipulator].
func (bm *bufferManipulator) Encrypt2(buf []byte, n int16) []byte {
	v := uint16(n) ^ XOR_KEY2
	return bm.Encode2(buf, int16(v))
}

// Encrypt4 implements [BufferManipulator].
func (bm *bufferManipulator) Encrypt4(buf []byte, n int32) []byte {
	v := uint32(n) ^ XOR_KEY4
	return bm.Encode4(buf, int32(v))
}

// Decode1 implements [BufferManipulator].
func (bm *bufferManipulator) Decode1(buf []byte) int8 {
	return int8(buf[0])
}

// Decode2 implements [BufferManipulator].
func (bm *bufferManipulator) Decode2(buf []byte) int16 {
	return int16(binary.BigEndian.Uint16(buf))
}

// Decode4 implements [BufferManipulator].
func (bm *bufferManipulator) Decode4(buf []byte) int32 {
	return int32(binary.BigEndian.Uint32(buf))
}

// DecodeBuffer implements [BufferManipulator].
func (bm *bufferManipulator) DecodeBuffer(buf []byte, uSize int) []byte {
	result := make([]byte, uSize)
	copy(result, buf[:uSize])
	return result
}

// Decrypt1 implements [BufferManipulator].
func (bm *bufferManipulator) Decrypt1(buf []byte) int8 {
	result := bm.Decode1(buf)
	return result ^ XOR_KEY1
}

// Decrypt2 implements [BufferManipulator].
func (bm *bufferManipulator) Decrypt2(buf []byte) int16 {
	result := bm.Decode2(buf)
	return int16(uint16(result) ^ XOR_KEY2)
}

// Decrypt4 implements [BufferManipulator].
func (bm *bufferManipulator) Decrypt4(buf []byte) int32 {
	result := bm.Decode4(buf)
	return int32(uint32(result) ^ XOR_KEY4)
}
