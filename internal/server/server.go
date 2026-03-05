package server

import (
	"log/slog"
	"net"

	"github.com/zhyonc/bnbnet"
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
	var idCount int32 = 0
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
		idCount++
	}
}

func (s *server) Shutdown() {
	s.lis.Close()
	s.lis = nil
}

// DebugSndPacketLog implements [bnbnet.CClientSocketDelegate].
func (s *server) DebugSndPacketLog(id int32, sndPacket bnbnet.CSendPacket) {
	op := sndPacket.GetType()
	if op == 0 {
		slog.Info("[CSendPacket]", "socketID", id, "length", sndPacket.GetLength(), "OnConnect", sndPacket.DumpString(-1))
	} else {
		slog.Info("[CSendPacket]", "socketID", id, "length", sndPacket.GetLength(), "opcode", sndPacket.GetType(), "data", sndPacket.DumpString(-1))
	}
}

// DebugRcvPacketLog implements [bnbnet.CClientSocketDelegate].
func (s *server) DebugRcvPacketLog(id int32, rcvPacket bnbnet.CReceivedPacket) {
	slog.Info("[CReceivePacket]", "socketID", id, "length", rcvPacket.GetLength(), "opcode", rcvPacket.GetType(), "data", rcvPacket.DumpString(-1))
}

// DispatchPacket implements [bnbnet.CClientSocketDelegate].
func (s *server) DispatchPacket(cs bnbnet.CClientSocket, rcvPacket bnbnet.CReceivedPacket) {
	op := rcvPacket.Decode1()
	switch op {
	default:
		slog.Info("[DispatchPacket] Unprocessed CReceivePacket", "opcode", op)
	}
}

// SocketClose implements [bnbnet.CClientSocketDelegate].
func (s *server) SocketClose(id int32) {
	slog.Info("Socket closed", "socketID", id)
}
