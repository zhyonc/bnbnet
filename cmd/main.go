package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zhyonc/bnbnet"
	"github.com/zhyonc/bnbnet/enum"
	"github.com/zhyonc/bnbnet/internal/server"
)

const (
	SERVER_ADDR    string     = "127.0.0.1:3838"
	LOG_BACKUP_DIR string     = "./log"
	LOG_LEVEL      slog.Level = slog.LevelDebug
)

func main() {
	// Installation
	bnbnet.New(&bnbnet.Setting{
		Region:       enum.RegionCN,
		CipherDegree: enum.CipherDegree_CRC8,
		Version:      12,
	})
	// Set logger
	done := make(chan bool, 1)
	logFilename := fmt.Sprintf("server-%s.log", time.Now().Format("2006-01-02_15-04-05"))
	bnbnet.SetLogger(LOG_BACKUP_DIR, logFilename, LOG_LEVEL, done)
	// New Server
	s := server.NewServer(SERVER_ADDR)
	// Avoid unexpected exit
	sch := make(chan os.Signal, 1)
	signal.Notify(sch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sch {
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("Server will shutdown after 3s")
				time.Sleep(3 * time.Second)
				s.Shutdown()
				done <- true
				return
			default:
				slog.Info("other signal", "syscall", sig)
			}
		}
	}()
	s.Run()
}
