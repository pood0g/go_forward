package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestOpenDialRoundTrip checks that the side holding the SSH server connection
// can open a connection to a target that the client side dials.
func TestOpenDialRoundTrip(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &gossh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	// A real socket, not net.Pipe: both SSH sides write their version banner
	// first, which deadlocks on an unbuffered pipe.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c1, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	type serverSide struct {
		conn  *gossh.ServerConn
		chans <-chan gossh.NewChannel
		reqs  <-chan *gossh.Request
		err   error
	}
	type clientSide struct {
		conn  gossh.Conn
		chans <-chan gossh.NewChannel
		reqs  <-chan *gossh.Request
		err   error
	}
	serverCh := make(chan serverSide, 1)
	clientCh := make(chan clientSide, 1)
	go func() {
		conn, chans, reqs, err := gossh.NewServerConn(c1, serverCfg)
		serverCh <- serverSide{conn, chans, reqs, err}
	}()
	go func() {
		conn, chans, reqs, err := gossh.NewClientConn(c2, "test", &gossh.ClientConfig{
			User:            "test",
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		})
		clientCh <- clientSide{conn, chans, reqs, err}
	}()

	cli := <-clientCh
	if cli.err != nil {
		t.Fatal(cli.err)
	}
	client := gossh.NewClient(cli.conn, cli.chans, cli.reqs)
	go ServeDials(client.HandleChannelOpen(DialChannel))

	srv := <-serverCh
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	defer srv.conn.Close()
	go gossh.DiscardRequests(srv.reqs)
	go func() {
		for newCh := range srv.chans {
			newCh.Reject(gossh.Prohibited, "not used in this test")
		}
	}()

	conn, err := OpenDial(srv.conn, echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	want := "hello through the tunnel"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
