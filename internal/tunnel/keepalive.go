package tunnel

import (
	"log"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// KeepAliveRequest is the global request OpenSSH uses for keepalives. Peers
// that do not know it still reply (with a failure), which is enough to show
// the connection is alive.
const KeepAliveRequest = "keepalive@openssh.com"

// KeepAlive sends a keepalive request on conn every interval, like OpenSSH's
// ServerAliveInterval and ClientAliveInterval. When max intervals in a row
// pass without a reply, conn is closed so a dead peer is noticed in about
// interval*max instead of waiting for TCP to give up. It returns when conn
// closes or done is closed. An interval or max of 0 disables it.
func KeepAlive(conn gossh.Conn, interval time.Duration, max int, done <-chan struct{}) {
	if interval <= 0 || max <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// At most one request is outstanding. A request whose reply has not
	// arrived by the next tick counts as missed.
	replies := make(chan error, 1)
	pending := false
	missed := 0
	for {
		select {
		case <-done:
			return
		case err := <-replies:
			if err != nil {
				return // connection closed
			}
			pending = false
			missed = 0
		case <-ticker.C:
			if pending {
				missed++
				if missed >= max {
					log.Printf("%s: no keepalive reply for %s, closing connection", conn.RemoteAddr(), time.Duration(missed)*interval)
					conn.Close()
					return
				}
				continue
			}
			pending = true
			go func() {
				_, _, err := conn.SendRequest(KeepAliveRequest, true, nil)
				replies <- err
			}()
		}
	}
}
