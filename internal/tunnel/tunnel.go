// Package tunnel carries SOCKS connections over an SSH connection when the
// proxy runs on the side opposite the one that makes the connection. The
// server opens a dial channel for each request, and the client dials the
// target and copies data both ways.
package tunnel

import (
	"io"
	"log"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// DialChannel is the channel type the server opens to ask the client to dial
// an address.
const DialChannel = "go-forward-dial"

// RegisterRequest is sent by the client after it connects, so the server knows
// which connection to dial through. It is sent without a reply, so servers
// that do not know it ignore it.
const RegisterRequest = "go-forward-register"

type dialRequest struct {
	Address string
}

// OpenDial asks the peer on conn to dial addr and returns the connection to it.
func OpenDial(conn gossh.Conn, addr string) (net.Conn, error) {
	ch, reqs, err := conn.OpenChannel(DialChannel, gossh.Marshal(&dialRequest{Address: addr}))
	if err != nil {
		return nil, err
	}
	go gossh.DiscardRequests(reqs)
	return &channelConn{Channel: ch}, nil
}

// ServeDials handles dial channels from the peer until channels is closed.
func ServeDials(channels <-chan gossh.NewChannel) {
	for newCh := range channels {
		go serveDial(newCh)
	}
}

func serveDial(newCh gossh.NewChannel) {
	var req dialRequest
	if err := gossh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		newCh.Reject(gossh.ConnectionFailed, "malformed dial request")
		return
	}

	target, err := net.Dial("tcp", req.Address)
	if err != nil {
		log.Printf("dial %s failed: %v", req.Address, err)
		newCh.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		target.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer target.Close()
		io.Copy(ch, target)
	}()
	go func() {
		defer ch.Close()
		defer target.Close()
		io.Copy(target, ch)
	}()
}

// channelConn adapts an SSH channel to net.Conn. SSH channels have no
// deadlines or meaningful addresses, so those methods do nothing.
type channelConn struct {
	gossh.Channel
}

func (c *channelConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *channelConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }
