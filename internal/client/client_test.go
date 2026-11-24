package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"go_forward/internal/testutil"
	"go_forward/internal/tunnel"
)

// TestForwards runs every kind of forward against a stock gliderlabs server,
// so the client is checked against standard SSH forwarding only.
func TestForwards(t *testing.T) {
	echo := testutil.EchoServer(t)
	echoAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(echo))

	forwarded := &gliderssh.ForwardedTCPHandler{}
	srv := &gliderssh.Server{
		PasswordHandler:               func(ctx gliderssh.Context, pw string) bool { return pw == "secret" },
		LocalPortForwardingCallback:   func(gliderssh.Context, string, uint32) bool { return true },
		ReversePortForwardingCallback: func(gliderssh.Context, string, uint32) bool { return true },
		RequestHandlers: map[string]gliderssh.RequestHandler{
			"tcpip-forward":        forwarded.HandleSSHRequest,
			"cancel-tcpip-forward": forwarded.HandleSSHRequest,
		},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"direct-tcpip": gliderssh.DirectTCPIPHandler,
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	defer srv.Close()

	sshConn, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            "user",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshConn.Close()

	localFwd, remoteFwd := testutil.FreeAddr(t), testutil.FreeAddr(t)
	remoteSocks, localSocks := testutil.FreeAddr(t), testutil.FreeAddr(t)
	args := Arguments{
		local:   []tunnel.Forward{{Listen: localFwd, Target: echoAddr}},
		remote:  []tunnel.Forward{{Listen: remoteFwd, Target: echoAddr}, {Listen: remoteSocks}},
		dynamic: []tunnel.Forward{{Listen: localSocks}},
	}
	if err := startForwards(sshConn, args); err != nil {
		t.Fatal(err)
	}

	testutil.CheckEcho(t, "-L", testutil.Dial(t, localFwd))
	testutil.CheckEcho(t, "-R with target", testutil.Dial(t, remoteFwd))
	testutil.CheckEcho(t, "-R socks", testutil.SocksConnect(t, remoteSocks, "localhost", echo))
	testutil.CheckEcho(t, "-D", testutil.SocksConnect(t, localSocks, "localhost", echo))
}

func TestHostKeyChanged(t *testing.T) {
	newKey := func() ssh.PublicKey {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		key, _ := ssh.NewPublicKey(pub)
		return key
	}
	known, changed := newKey(), newKey()

	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"example.com:2222"}, known) + "\n"
	// A line in the format older versions of the client wrote.
	line += "old.example.com:22 " + string(ssh.MarshalAuthorizedKey(known))
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	check, err := hostKeyCallback(path)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2222}
	if err := check("example.com:2222", addr, known); err != nil {
		t.Errorf("known key rejected: %v", err)
	}
	if err := check("old.example.com:22", addr, known); err != nil {
		t.Errorf("known key in old format rejected: %v", err)
	}
	if err := check("example.com:2222", addr, changed); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Errorf("changed key: got %v, want a CHANGED error", err)
	}
}
