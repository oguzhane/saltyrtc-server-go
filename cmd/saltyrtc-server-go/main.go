package main

import (
	"os"

	"github.com/OguzhanE/saltyrtc-server-go/core"

	_ "net/http/pprof"
)

var server *core.Server

func main() {
	core.InitLogger()
	addr := ":3838"

	server = core.NewServer()
	server.Start(addr)
	quit := make(chan interface{})
	select {
	case <-quit:
		os.Exit(0)
		return
	}
}
