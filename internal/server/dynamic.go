package server

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"go_forward/internal/tunnel"
)

// activeClient is the connection that SOCKS requests on the server are sent
// through. It is the client that registered most recently, and is cleared when
// that client disconnects.
var activeClient struct {
	sync.Mutex
	conn gossh.Conn
}

func setActiveClient(conn gossh.Conn) {
	activeClient.Lock()
	defer activeClient.Unlock()
	activeClient.conn = conn
}

func clearActiveClient(conn gossh.Conn) {
	activeClient.Lock()
	defer activeClient.Unlock()
	if activeClient.conn == conn {
		activeClient.conn = nil
	}
}

// handleRegister records the connection that sent tunnel.RegisterRequest.
func handleRegister(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)
	setActiveClient(conn)
	go func() {
		<-ctx.Done()
		clearActiveClient(conn)
	}()
	return true, nil
}

// dialThroughClient opens the connection for a SOCKS request on the client
// that is currently registered.
func dialThroughClient(ctx context.Context, network, addr string) (net.Conn, error) {
	activeClient.Lock()
	conn := activeClient.conn
	activeClient.Unlock()
	if conn == nil {
		return nil, errors.New("no client is connected to dial through")
	}
	return tunnel.OpenDial(conn, addr)
}
