package core

import (
	"github.com/OguzhanE/saltyrtc-server-go/pkg/evpoll"
)

type loop struct {
	poll    *evpoll.Poll  // epoll or kqueue
	fdconns map[int]*Conn // loop connections fd -> conn
	count   int32         // connection count
}
