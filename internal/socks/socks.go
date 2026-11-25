package socks

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"go_forward/internal/tunnel"
)

// Dialer makes the proxy's outgoing connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// handshakeTimeout bounds how long a client may take to authenticate and send
// its request, so idle connections don't pile up.
const handshakeTimeout = 30 * time.Second

var logger = log.New(os.Stdout, "socks5: ", log.LstdFlags)

// Server is a SOCKS5 proxy that supports only the CONNECT command (RFC 1928),
// with optional username and password authentication (RFC 1929).
type Server struct {
	username, password string
	dial               Dialer
}

// Serve runs a tunnelled SOCKS5 proxy (see New) on listenAddr until it fails.
func Serve(listenAddr, username, password string, dial Dialer) error {
	return New(username, password, dial).ListenAndServe("tcp", listenAddr)
}

// New returns a SOCKS5 proxy. dial makes the outgoing connections; nil
// connects directly. A non-empty password enables username and password
// authentication.
//
// Only CONNECT is allowed: BIND and UDP ASSOCIATE would open their sockets on
// the machine running the proxy, not the one connections leave from. Host
// names are passed to dial unresolved, so with a tunnelling dialer they are
// looked up where the connection leaves, which also reaches names only that
// network knows.
func New(username, password string, dial Dialer) *Server {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return &Server{username: username, password: password, dial: dial}
}

// ListenAndServe listens on addr and serves until the listener fails.
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts connections on l until it fails.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// SOCKS5 protocol constants.
const (
	version5         = 5
	authNone         = 0x00
	authPassword     = 0x02
	authNoAcceptable = 0xFF

	cmdConnect = 1

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	repSuccess          = 0
	repFailure          = 1
	repNetUnreachable   = 3
	repHostUnreachable  = 4
	repConnRefused      = 5
	repCmdNotSupported  = 7
	repAddrNotSupported = 8
)

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	if err := s.negotiate(c); err != nil {
		logger.Printf("%s: %v", c.RemoteAddr(), err)
		return
	}
	target, err := s.request(c)
	if err != nil {
		logger.Printf("%s: %v", c.RemoteAddr(), err)
		return
	}

	out, err := s.dial(context.Background(), "tcp", target)
	if err != nil {
		reply(c, replyCode(err), nil)
		logger.Printf("%s: connect %s: %v", c.RemoteAddr(), target, err)
		return
	}
	if err := reply(c, repSuccess, out.LocalAddr()); err != nil {
		out.Close()
		return
	}
	c.SetDeadline(time.Time{})
	tunnel.Pipe(c, out)
}

// negotiate picks an authentication method and, if needed, checks the login.
func (s *Server) negotiate(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if head[0] != version5 {
		return fmt.Errorf("unsupported SOCKS version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	want := byte(authNone)
	if s.password != "" {
		want = authPassword
	}
	if !bytes.Contains(methods, []byte{want}) {
		c.Write([]byte{version5, authNoAcceptable})
		return errors.New("no acceptable authentication method")
	}
	if _, err := c.Write([]byte{version5, want}); err != nil {
		return err
	}
	if want == authPassword {
		return s.checkLogin(c)
	}
	return nil
}

// checkLogin runs the RFC 1929 username and password exchange.
func (s *Server) checkLogin(c net.Conn) error {
	readField := func() ([]byte, error) {
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return nil, err
		}
		b := make([]byte, n[0])
		_, err := io.ReadFull(c, b)
		return b, err
	}
	ver := make([]byte, 1)
	if _, err := io.ReadFull(c, ver); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if ver[0] != 1 {
		return fmt.Errorf("login: unsupported version %d", ver[0])
	}
	user, err := readField()
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	pass, err := readField()
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	userOK := subtle.ConstantTimeCompare(user, []byte(s.username))
	passOK := subtle.ConstantTimeCompare(pass, []byte(s.password))
	if userOK&passOK != 1 {
		c.Write([]byte{1, 1})
		return fmt.Errorf("login failed for user %q", user)
	}
	_, err = c.Write([]byte{1, 0})
	return err
}

// request reads a CONNECT request and returns its target as host:port.
func (s *Server) request(c net.Conn) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	if head[0] != version5 {
		return "", fmt.Errorf("request: unsupported SOCKS version %d", head[0])
	}

	var host string
	switch head[3] {
	case atypIPv4, atypIPv6:
		ip := make([]byte, net.IPv4len)
		if head[3] == atypIPv6 {
			ip = make([]byte, net.IPv6len)
		}
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", fmt.Errorf("request: %w", err)
		}
		host = net.IP(ip).String()
	case atypDomain:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return "", fmt.Errorf("request: %w", err)
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", fmt.Errorf("request: %w", err)
		}
		host = string(name)
	default:
		reply(c, repAddrNotSupported, nil)
		return "", fmt.Errorf("request: unsupported address type %d", head[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return "", fmt.Errorf("request: %w", err)
	}

	if head[1] != cmdConnect {
		reply(c, repCmdNotSupported, nil)
		return "", fmt.Errorf("request: unsupported command %d", head[1])
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

// reply sends a request reply with the given code and bound address.
func reply(c net.Conn, code byte, bound net.Addr) error {
	ip, port := net.IPv4zero.To4(), 0
	if a, ok := bound.(*net.TCPAddr); ok {
		port = a.Port
		if v4 := a.IP.To4(); v4 != nil {
			ip = v4
		} else if len(a.IP) == net.IPv6len {
			ip = a.IP
		}
	}
	atyp := byte(atypIPv4)
	if len(ip) == net.IPv6len {
		atyp = atypIPv6
	}
	msg := append([]byte{version5, code, 0, atyp}, ip...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(port))
	_, err := c.Write(msg)
	return err
}

// replyCode maps a dial error to a SOCKS reply code.
func replyCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return repHostUnreachable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return repHostUnreachable
	}
	return repFailure
}
