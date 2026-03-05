# bnbnet
bnbnet is a pure Golang networking package for Bomb and Bomber

## Installation
 `$ go get github.com/zhyonc/bnbnet@latest`

## Quick Start
```golang
package main

import (
	"log/slog"
	"net"

	"github.com/zhyonc/bnbnet"
	"github.com/zhyonc/bnbnet/enum"
)

type server struct {
	addr string
	lis  net.Listener
}

func NewServer(addr string) *server {
	s := &server{
		addr: addr,
	}
	return s
}

func (s *server) Run() {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		slog.Error("Failed to create tcp listener", "err", err)
		return
	}
	slog.Info("TCPListener is starting on " + s.addr)
	s.lis = lis
	for {
		if s.lis == nil {
			slog.Warn("TCPListener is nil")
			break
		}
		conn, err := s.lis.Accept()
		if err != nil {
			slog.Error("Failed to accept conn", "err", err)
			continue
		}
		slog.Info("New client connected", "addr", conn.RemoteAddr())
		cs := bnbnet.NewClientSocket(s, conn)
		go cs.TryRead()
		cs.OnConnect()
	}
}

func main() {
	bnbnet.New(&bnbnet.Setting{
		Region:       enum.RegionCN,
		CipherDegree: enum.CipherDegree_CRC8,
		Version:      12,
	})
	s := NewServer("127.0.0.1:3838")
	s.Run()
}

```
## Setting
- Region: Determines the Charset
- CipherDegree: Defines packet encryption level (None/CRC8/CRC32)
- Version: Specifies the BnB Client Version number

## Packet
|HeaderCode|DataLength|Data|
|:---:|:---:|:---:|
|1 Byte|2 Bytes|Opcode(1 Byte) + Payload(Any Bytes)|
## CipherDegree: None
Send HeaderType to Client in OnConnect Packet
```golang
sndPacket := NewSendPacket(0)
sndPacket.EncodeBool(false)                // true->ErrCannotConnect
sndPacket.Encode2(int16(gSetting.Version)) // ClientMinimumVersion
sndPacket.Encode2(int16(gSetting.Version)) // ServerLatestVersion
sndPacket.Encode4(int32(headerType))       // TableRowIndex
sndPacket.EncodeStr("")                    // UrlPatch
sndPacket.Send(cs)
```
### Encode
1. Encode1: HeaderCode = (HeaderType + HeaderCodeModifier) ^ (HeaderCodeSndBase + SeqSnd)
	- HeaderType = 1 byte between 0 and 15
	- Fixed HeaderCodeModifier = 0xE7
	- Fixed HeaderCodeSndBase = 0x66
	- SeqSnd = 0x28
2. Encode2: DataLength = len(data)
3. EncodeBuffer: Data = EncryptedOpcode + Payload
	- EncryptedOpcode = gsConvertTableEncode[HeaderType][Opcode]
	- Payload = Original Buffer
4. Progression: SeqSnd += 3
### Decode
1. Decode1 Match HeaderCode = (HeaderType + HeaderCodeModifier) ^ (HeaderCodeRcvBase + SeqRcv)
	- HeaderType = 1 byte between 0 and 15
	- Fixed HeaderCodeModifier = 0xE7
	- Fixed HeaderCodeRcvBase = 0xC0
	- SeqRcv = 0x28
2. Decode2: Get DataLength as read size
3. DecodeBuffer: Data = EncryptedOpcode + Payload
	- Opcode = gsConvertTableDecode[HeaderType][EncryptedOpcode]
	- Payload = Original Buffer
4. Progression: SeqRcv += 3

## CipherDegree: CRC8 & CRC32
```golang
const (
	XOR_KEY1 int8   = 0x5A
	XOR_KEY2 uint16 = 0xA569
	XOR_KEY4 uint32 = 0x96CA5395
)
```
#### Encode
1. Encode1: HeaderCode = (HeaderType + HeaderCodeModifier) ^ (HeaderCodeSndBase + SeqSnd)
	- HeaderType = 1 byte between 0 and 15
	- Fixed HeaderCodeModifier = 0xE7
	- Fixed HeaderCodeSndBase = 0x66
	- SeqSnd = 0x28
2. Encrypt2: EncryptedDataLength = len(data) ^ KEY1
3. EncodeBuffer: EncryptedData = SimpleStreamEncrypt(EncryptedOpcode + EncryptedPayload)
	- EncryptedOpcode = Opcode ^ KEY1
	- EncryptedPayload = Origin Buffer ^ KEY1/KEY2/KEY4
	- SimpleStreamEncrypt refer `SimpleStream.go`
4. Encode CRC
	- CRC8: Encode1 CCRC8.UpdateCRC(SeqSnd, Data)
	- CRC32: Encode4 CCRC32.UpdateCRC(SeqSnd, Data)
4. Progression: SeqSnd += 3
#### Decode
1. Decode1 Match HeaderCode = (HeaderType + HeaderCodeModifier) ^ (HeaderCodeRcvBase + SeqRcv)
	- HeaderType = 1 byte between 0 and 15
	- Fixed HeaderCodeModifier = 0xE7
	- Fixed HeaderCodeRcvBase = 0xC0
	- SeqRcv = 0x28
2. Decrypt2: DataLength = EncryptedDataLength ^ KEY2
3. DecodeBuffer: DecryptedData = SimpleStreamDecrypt(DecryptedOpcode + DecryptedPayload)
	- SimpleStreamDecrypt refer `SimpleStream.go`
	- DecryptedOpcode = EncryptedOpcode ^ KEY1
	- DecryptedPayload = EncryptedPayload ^ KEY1/KEY2/KEY4
4. Decode CRC
	- CRC8: Decode1 Match CCRC8.UpdateCRC(SeqRcv, DecryptedData)
	- CRC32: Decode4 Match CCRC32.UpdateCRC(SeqRcv, DecryptedData)
5. Progression: SeqRcv += 3