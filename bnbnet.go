package bnbnet

var (
	gSetting *Setting
)

func New(setting *Setting) {
	SetCharset(setting.Region)
	gSetting = setting
}

type CClientSocket interface {
	OnConnect()
	PutPacket(sndPacket CSendPacket)
	Flush()
	TryRead()
	GetPacket(rcvPacket CReceivedPacket) bool
	OnError(err error)
	Close()
}

type CClientSocketDelegate interface {
	DebugSndPacketLog(id int32, sndPacket CSendPacket)
	DebugRcvPacketLog(id int32, rcvPacket CReceivedPacket)
	DispatchPacket(cs CClientSocket, rcvPacket CReceivedPacket)
	SocketClose(id int32)
}

type CSendPacket interface {
	GetSendBuffer() []byte
	GetType() uint8
	GetLength() int
	EncodeBool(b bool)
	Encode1(n int8)
	Encode2(n int16)
	Encode4(n int32)
	EncodeBuffer(newBuf []byte)
	EncryptBuffer(newBuf []byte)
	EncodeStr(s string)
	DumpString(nSize int) string
	MakePacketComplete(headerType uint8, seqSnd uint32) []byte
	Send(cs CClientSocket)
}

type CReceivedPacket interface {
	SetRcvPacket(headerType uint8, seqRcv uint32) bool
	GetType() uint8
	GetRemain() int
	GetLength() int
	DecodeBool() bool
	Decode1() int8
	Decode2() int16
	Decode4() int32
	DecodeBuffer(uSize int) []byte
	DecryptBuffer(uSize int) []byte
	DecodeStr() string
	DecryptStr(key uint32) string
	DumpString(nSize int) string
}
