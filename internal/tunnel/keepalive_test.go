package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// sshPair connects an SSH client and server over loopback TCP. The server's
// global requests are returned unserviced so a test can choose whether the
// server answers keepalives.
func sshPair(t *testing.T) (client gossh.Conn, serverReqs <-chan *gossh.Request) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := gossh.NewSignerFromKey(priv)
	serverCfg := &gossh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	type result struct {
		reqs <-chan *gossh.Request
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		sc, chans, reqs, err := gossh.NewServerConn(c, serverCfg)
		if err == nil {
			go func() {
				for ch := range chans {
					ch.Reject(gossh.Prohibited, "")
				}
			}()
			t.Cleanup(func() { sc.Close() })
		}
		done <- result{reqs, err}
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, _, creqs, err := gossh.NewClientConn(c, "", &gossh.ClientConfig{HostKeyCallback: gossh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	go gossh.DiscardRequests(creqs)
	t.Cleanup(func() { cc.Close() })

	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return cc, r.reqs
}

func waitClosed(conn gossh.Conn, within time.Duration) bool {
	closed := make(chan struct{})
	go func() { conn.Wait(); close(closed) }()
	select {
	case <-closed:
		return true
	case <-time.After(within):
		return false
	}
}

func TestKeepAliveAnswered(t *testing.T) {
	client, serverReqs := sshPair(t)
	go gossh.DiscardRequests(serverReqs) // replies false, as OpenSSH does
	done := make(chan struct{})
	defer close(done)
	go KeepAlive(client, 10*time.Millisecond, 3, done)

	if waitClosed(client, 300*time.Millisecond) {
		t.Fatal("connection closed although the peer answered keepalives")
	}
}

func TestKeepAliveUnanswered(t *testing.T) {
	client, _ := sshPair(t) // server never reads its requests, so never replies
	go KeepAlive(client, 10*time.Millisecond, 3, nil)

	if !waitClosed(client, 2*time.Second) {
		t.Fatal("connection still open although keepalives went unanswered")
	}
}
