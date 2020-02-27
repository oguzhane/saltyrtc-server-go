package salty

import (
	"os"

	"net"
	"syscall"
)

type listener struct {
	ln      net.Listener
	lnaddr  net.Addr
	f       *os.File
	fd      int
	network string
	addr    string
}

func (ln *listener) system() error {
	var err error
	switch netln := ln.ln.(type) {
	case *net.TCPListener:
		ln.f, err = netln.File()
	case *net.UnixListener:
		ln.f, err = netln.File()
	}
	if err != nil {
		ln.close()
		return err
	}
	ln.fd = int(ln.f.Fd())
	return syscall.SetNonblock(ln.fd, true)
}

func (ln *listener) close() {
	if ln.fd != 0 {
		syscall.Close(ln.fd)
	}
	if ln.f != nil {
		ln.f.Close()
	}
	if ln.ln != nil {
		ln.ln.Close()
	}
}
