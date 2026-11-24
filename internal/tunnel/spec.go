package tunnel

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Forward is a parsed -L, -R or -D value. Listen is the address to listen on
// and Target the address connections go to. An empty Target means a SOCKS
// proxy decides the target per connection.
type Forward struct {
	Listen string
	Target string
}

// ParseForward parses the OpenSSH forms
//
//	port                          SOCKS proxy on 127.0.0.1:port
//	bind:port                     SOCKS proxy on bind:port
//	port:host:hostport            forward 127.0.0.1:port to host:hostport
//	bind:port:host:hostport       forward bind:port to host:hostport
//
// A bind address of "*" or "" listens on all interfaces.
func ParseForward(spec string) (Forward, error) {
	parts := strings.Split(spec, ":")
	bind := "127.0.0.1"
	switch len(parts) {
	case 1, 3:
	case 2, 4:
		bind = parts[0]
		if bind == "" || bind == "*" {
			bind = "0.0.0.0"
		}
		parts = parts[1:]
	default:
		return Forward{}, fmt.Errorf("%q: expected [bind:]port or [bind:]port:host:hostport", spec)
	}

	if err := checkPort(parts[0]); err != nil {
		return Forward{}, fmt.Errorf("%q: %w", spec, err)
	}
	f := Forward{Listen: net.JoinHostPort(bind, parts[0])}
	if len(parts) == 3 {
		if parts[1] == "" {
			return Forward{}, fmt.Errorf("%q: missing target host", spec)
		}
		if err := checkPort(parts[2]); err != nil {
			return Forward{}, fmt.Errorf("%q: %w", spec, err)
		}
		f.Target = net.JoinHostPort(parts[1], parts[2])
	}
	return f, nil
}

func checkPort(port string) error {
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("bad port %q", port)
	}
	return nil
}

// Pipe copies data both ways between a and b. When either direction ends both
// are closed, which ends the other direction. Copy errors are expected at that
// point and are not reported.
func Pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
}
