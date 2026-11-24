package socks

import (
	"context"
	"net"
	"strconv"
	"testing"

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

func TestParseCredentials(t *testing.T) {
	if u, p, err := ParseCredentials("me:pa:ss"); err != nil || u != "me" || p != "pa:ss" {
		t.Errorf("got %q %q %v", u, p, err)
	}
	for _, bad := range []string{"me", "me:", ":pw"} {
		if _, _, err := ParseCredentials(bad); err == nil {
			t.Errorf("ParseCredentials(%q) succeeded, want error", bad)
		}
	}
}
