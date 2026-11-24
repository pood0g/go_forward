package server

import (
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"go_forward/internal/tunnel"
)

const forwardedTCPChannelType = "forwarded-tcpip"

// data structs as specified in RFC4254, Section 7.1
type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// forwardSet holds the remote forwards opened over one SSH connection. Keeping
// them per connection means a client can only cancel its own listeners, and
// all of them close when that client disconnects.
type forwardSet struct {
	mu        sync.Mutex
	listeners []net.Listener
}

type forwardSetKey struct{}

func forwardsFor(ctx ssh.Context) *forwardSet {
	if f, ok := ctx.Value(forwardSetKey{}).(*forwardSet); ok {
		return f
	}
	f := &forwardSet{}
	ctx.SetValue(forwardSetKey{}, f)
	go func() {
		<-ctx.Done()
		f.closeAll()
	}()
	return f
}

func (f *forwardSet) add(ln net.Listener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listeners = append(f.listeners, ln)
}

func (f *forwardSet) remove(ln net.Listener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, l := range f.listeners {
		if l == ln {
			f.listeners = append(f.listeners[:i], f.listeners[i+1:]...)
			return
		}
	}
}

// cancel closes the listeners bound to port. Listeners are matched by port
// because a client that asked for port 0 only knows the port it was given.
func (f *forwardSet) cancel(port uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.listeners[:0]
	for _, ln := range f.listeners {
		if listenPort(ln) == port {
			ln.Close()
			continue
		}
		kept = append(kept, ln)
	}
	f.listeners = kept
}

func (f *forwardSet) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ln := range f.listeners {
		ln.Close()
	}
	f.listeners = nil
}

func listenPort(ln net.Listener) uint32 {
	return uint32(ln.Addr().(*net.TCPAddr).Port)
}

// handleTCPIPForward serves remote (-R) forwards. A bind port of 0 asks the
// server to pick a free port; the chosen port is returned to the client.
func handleTCPIPForward(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)
	forwards := forwardsFor(ctx)

	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			log.Println("malformed tcpip-forward request:", err)
			return false, nil
		}
		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("remote forward failed to bind", addr, ":", err)
			return false, nil
		}
		port := listenPort(ln)
		forwards.add(ln)
		go acceptRemoteForward(conn, forwards, ln, reqPayload.BindAddr, port)
		return true, gossh.Marshal(&remoteForwardSuccess{port})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			log.Println("malformed cancel-tcpip-forward request:", err)
			return false, nil
		}
		forwards.cancel(reqPayload.BindPort)
		return true, nil

	default:
		return false, nil
	}
}

func acceptRemoteForward(conn *gossh.ServerConn, forwards *forwardSet, ln net.Listener, bindAddr string, bindPort uint32) {
	defer forwards.remove(ln)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go openForwardedChannel(conn, c, bindAddr, bindPort)
	}
}

func openForwardedChannel(conn *gossh.ServerConn, c net.Conn, bindAddr string, bindPort uint32) {
	originHost, originPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	originPort, _ := strconv.Atoi(originPortStr)
	payload := gossh.Marshal(&remoteForwardChannelData{
		DestAddr:   bindAddr,
		DestPort:   bindPort,
		OriginAddr: originHost,
		OriginPort: uint32(originPort),
	})

	ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
	if err != nil {
		log.Println("failed to open forwarded channel:", err)
		c.Close()
		return
	}
	go gossh.DiscardRequests(reqs)
	tunnel.Pipe(ch, c)
}
