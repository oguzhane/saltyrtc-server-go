package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/encoding/hexutil"
	salty "github.com/OguzhanE/saltyrtc-server-go/salty"
)

var server *salty.Server

func main() {

	var flags struct {
		Addr      string
		Port      uint
		Verbosity int
		Pk        string
		Sk        string
	}

	flag.StringVar(&flags.Addr, "a", "", "Address")
	flag.UintVar(&flags.Port, "p", 9002, "Port")
	flag.IntVar(&flags.Verbosity, "v", 0, "Logging Verbosity")
	flag.StringVar(&flags.Pk, "pk", "3b9f4eabcb7081fefc870f395048fd7f131c61e2b202bd592bb2f120eb153913", "Public key of server permanent key in hex format")
	flag.StringVar(&flags.Sk, "sk", "bf04cf3abfb416468f82a8f97489720165e61932bb88e7bbfb543ba8d87f0696", "Secret key of server permanent key in hex format")
	flag.Parse()

	if flags.Sk == "" || flags.Pk == "" {
		flag.Usage()
		return
	}

	pkBytes, errPk := hexutil.HexStringToBytes32(flags.Pk)
	skBytes, errSk := hexutil.HexStringToBytes32(flags.Sk)

	if errPk != nil || errSk != nil {
		log.Fatal("Invalid permanent key")
		return
	}

	salty.InitLogger(flags.Verbosity)

	addr := fmt.Sprintf("%s:%d", flags.Addr, flags.Port)

	defaultBox := nacl.NewBoxKeyPair(*pkBytes, *skBytes)
	salty.Sugar.Info("Starting server with the public permanent key: ", flags.Pk)

	server = salty.NewServer(*defaultBox)
	server.Start(addr)
	quit := make(chan interface{})
	select {
	case <-quit:
		os.Exit(0)
		return
	}
}
