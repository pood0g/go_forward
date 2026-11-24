package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"go_forward/internal/socks"
	"go_forward/internal/testutil"
	"go_forward/internal/tunnel"
)

// startServer runs newServer on a loopback port and returns its address.
func startServer(t *testing.T, arguments Arguments) string {
	t.Helper()
	arguments.hostKeyFile = filepath.Join(t.TempDir(), "host_key")
	srv, err := newServer(arguments)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

func dialServer(addr string, auth ...gossh.AuthMethod) (*gossh.Client, error) {
	return gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "user",
		Auth:            auth,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
}

func TestServerAuth(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := gossh.NewSignerFromKey(priv)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := gossh.NewSignerFromKey(otherPriv)

	keys := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(keys, gossh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, Arguments{userName: "user", passWord: "secret", authorizedKeysFile: keys})

	cases := []struct {
		name string
		auth gossh.AuthMethod
		ok   bool
	}{
		{"password", gossh.Password("secret"), true},
		{"wrong password", gossh.Password("nope"), false},
		{"authorized key", gossh.PublicKeys(signer), true},
		{"other key", gossh.PublicKeys(other), false},
	}
	for _, c := range cases {
		client, err := dialServer(addr, c.auth)
		if (err == nil) != c.ok {
			t.Errorf("%s: login ok = %v, want %v (%v)", c.name, err == nil, c.ok, err)
		}
		if client != nil {
			client.Close()
		}
	}
}

// TestServerDropsDeadClient checks that a client which stops answering
// keepalives is disconnected and its remote forward port freed, so a
// reconnecting client can bind it again.
func TestServerDropsDeadClient(t *testing.T) {
	addr := startServer(t, Arguments{userName: "user", passWord: "secret", keepAlive: 1, keepAliveMax: 1})

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := gossh.NewClientConn(tcp, addr, &gossh.ClientConfig{
		User:            "user",
		Auth:            []gossh.AuthMethod{gossh.Password("secret")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		for ch := range chans {
			ch.Reject(gossh.Prohibited, "")
		}
	}()
	_ = reqs // never read, so the server's keepalives get no reply

	ok, reply, err := conn.SendRequest("tcpip-forward", true,
		gossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: %v %v", ok, err)
	}
	var bound remoteForwardSuccess
	if err := gossh.Unmarshal(reply, &bound); err != nil {
		t.Fatal(err)
	}
	fwd := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bound.BindPort)))

	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := net.Listen("tcp", fwd)
		if err == nil {
			l.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward port %s still held by the dead client: %v", fwd, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestServerForwards(t *testing.T) {
	echo := testutil.EchoServer(t)
	echoAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(echo))
	addr := startServer(t, Arguments{userName: "user", passWord: "secret"})

	client, err := dialServer(addr, gossh.Password("secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Local forward: the server connects to the target.
	c, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	testutil.CheckEcho(t, "direct-tcpip", c)

	// Remote forward on port 0: the server picks a port and reports it.
	l, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if l.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("server did not report the port it picked")
	}
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			go tunnel.Pipe(in, testutil.Dial(t, echoAddr))
		}
	}()
	testutil.CheckEcho(t, "tcpip-forward", testutil.Dial(t, l.Addr().String()))

	// Cancelling the forward closes the server's listener.
	l.Close()
	if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
		c.Close()
		t.Error("remote forward still listening after cancel")
	}

	// server -D: the server's proxy dials through the registered client.
	// The reply is requested here only so registration has finished before
	// the proxy is used.
	if ok, _, err := client.SendRequest(tunnel.RegisterRequest, true, nil); err != nil || !ok {
		t.Fatalf("register: %v %v", ok, err)
	}
	go tunnel.ServeDials(client.HandleChannelOpen(tunnel.DialChannel))
	proxyAddr := testutil.FreeAddr(t)
	go socks.Serve(proxyAddr, "", "", dialThroughClient)
	testutil.CheckEcho(t, "server -D", testutil.SocksConnect(t, proxyAddr, "localhost", echo))
}
