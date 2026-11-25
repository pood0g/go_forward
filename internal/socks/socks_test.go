package socks

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"go_forward/internal/testutil"
)

// TestRemoteResolution checks that a tunnelled proxy hands host names to its
// dialer unresolved, so they are looked up on the side connections leave from.
func TestRemoteResolution(t *testing.T) {
	echo := testutil.EchoServer(t)
	dialed := make(chan string, 1)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed <- addr
		_, port, _ := net.SplitHostPort(addr)
		return net.Dial(network, net.JoinHostPort("127.0.0.1", port))
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go New("", "", dial).Serve(l)

	// The name only exists on the "far side", which the dialer stands in for.
	testutil.CheckEcho(t, "socks", testutil.SocksConnect(t, l.Addr().String(), "only.far-side.invalid", echo))
	if got := <-dialed; got != net.JoinHostPort("only.far-side.invalid", strconv.Itoa(echo)) {
		t.Errorf("dialer got %q, want the unresolved name", got)
	}
}

// TestLogin checks that a proxy with a password refuses a wrong login and
// clients that don't offer one, and accepts the right login.
func TestLogin(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go New("user", "secret", nil).Serve(l)

	// login sends a greeting offering methods, then the login if the proxy
	// asked for one, and returns the proxy's final status byte.
	login := func(methods []byte, user, pass string) byte {
		c := testutil.Dial(t, l.Addr().String())
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write(append([]byte{5, byte(len(methods))}, methods...))
		reply := make([]byte, 2)
		if _, err := io.ReadFull(c, reply); err != nil {
			t.Fatalf("method reply: %v", err)
		}
		if reply[1] != 2 {
			return reply[1]
		}
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		c.Write(msg)
		if _, err := io.ReadFull(c, reply); err != nil {
			t.Fatalf("login reply: %v", err)
		}
		return reply[1]
	}

	if got := login([]byte{0}, "", ""); got != 0xFF {
		t.Errorf("no-auth client: got method %#x, want 0xff", got)
	}
	if got := login([]byte{0, 2}, "user", "wrong"); got == 0 {
		t.Error("wrong password accepted")
	}
	if got := login([]byte{0, 2}, "user", "secret"); got != 0 {
		t.Errorf("right password: got status %d, want 0", got)
	}
}
