// Package testutil holds helpers shared by the end-to-end tests.
package testutil

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// EchoServer starts a TCP echo server on 127.0.0.1 and returns its port.
func EchoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// FreeAddr returns a 127.0.0.1 address with a port that was free a moment ago.
func FreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// CheckEcho sends a message on c and fails the test unless it comes back.
func CheckEcho(t *testing.T, name string, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("hello from " + name)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("%s: write: %v", name, err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("%s: read: %v", name, err)
	}
	if string(got) != string(msg) {
		t.Fatalf("%s: got %q, want %q", name, got, msg)
	}
}

// Dial connects to addr, retrying briefly while a listener starts up.
func Dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		var c net.Conn
		if c, err = net.Dial("tcp", addr); err == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial %s: %v", addr, err)
	return nil
}

// SocksConnect opens a connection to host:port through the SOCKS5 proxy at
// proxy, sending host as a name so the proxy decides where it is resolved.
func SocksConnect(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	c := Dial(t, proxy)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fail := func(step string, err error) {
		c.Close()
		t.Fatalf("socks %s via %s: %s: %v", net.JoinHostPort(host, strconv.Itoa(port)), proxy, step, err)
	}

	// greeting: version 5, one method, no authentication
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		fail("greeting", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		fail("method", err)
	}

	// CONNECT to a domain name
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		fail("request", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		fail("reply", err)
	}
	if head[1] != 0 {
		fail("reply", errReply(head[1]))
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		n := make([]byte, 1)
		io.ReadFull(c, n)
		skip = int(n[0]) + 2
	}
	if _, err := io.ReadFull(c, make([]byte, skip)); err != nil {
		fail("reply address", err)
	}
	c.SetDeadline(time.Time{})
	return c
}

type errReply byte

func (e errReply) Error() string { return "reply code " + strconv.Itoa(int(e)) }
