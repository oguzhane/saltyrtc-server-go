
# SaltyRTC Signalling Server 
[SaltyRTC signalling server](https://github.com/saltyrtc/saltyrtc-meta/blob/master/Protocol.md) implementation in Go aims to handle high load of websocket connections in such a high performance manner using non-blocking I/O and zero-copy allocation.

The project is currently in an early stage of development. Testing and review is welcome!

## Features
- Non-blocking I/O mechanism
- Low-cost goroutine pool
- Zero-copy allocation

## Install
```
git https://github.com/OguzhanE/saltyrtc-server-go.git
cd saltyrtc-server-go
make build
```

## Usage
```
cd saltyrtc-server-go/cmd/saltyrtc-server-go
./main --help
```
## Credits
- [https://github.com/tidwall/evio](https://github.com/tidwall/evio)
- [https://github.com/gobwas/ws](https://github.com/gobwas/ws)
- [https://github.com/gammazero/workerpool](https://github.com/gammazero/workerpool)
- [https://github.com/eranyanay/1m-go-websockets](https://github.com/eranyanay/1m-go-websockets)
- [https://medium.com/@copyconstruct/the-method-to-epolls-madness-d9d2d6378642](https://medium.com/@copyconstruct/the-method-to-epolls-madness-d9d2d6378642)

## License

This project is licensed under the MIT License - see the  [LICENSE.md](https://github.com/OguzhanE/saltyrtc-server-go/blob/master/LICENSE)  file for details
