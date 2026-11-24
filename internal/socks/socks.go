package socks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/things-go/go-socks5"
)

// ParseCredentials splits a user:password value. An empty value means the proxy
// needs no login, and both returned strings are empty.
func ParseCredentials(spec string) (string, string, error) {
	if spec == "" {
		return "", "", nil
	}
	user, password, ok := strings.Cut(spec, ":")
	if !ok || user == "" || password == "" {
		return "", "", errors.New("expected user:password")
	}
	return user, password, nil
}

// Dialer makes the proxy's outgoing connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Serve runs a SOCKS5 proxy on listenAddr until it fails.
func Serve(listenAddr, username, password string, dial Dialer) error {
	return New(username, password, dial).ListenAndServe("tcp", listenAddr)
}

// New returns a SOCKS5 proxy. dial decides how outgoing connections are made;
// nil connects directly. A non-empty password enables username and password
// authentication.
func New(username, password string, dial Dialer) *socks5.Server {
	opt := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	}
	if dial != nil {
		opt = append(opt, socks5.WithDial(dial))
	}
	if len(password) > 0 {
		creds := socks5.StaticCredentials{username: password}
		auth := socks5.UserPassAuthenticator{Credentials: creds}
		opt = append(opt, socks5.WithAuthMethods([]socks5.Authenticator{auth}))
	}

	return socks5.NewServer(opt...)
}

// Run serves a SOCKS5 proxy. argv is the command line with argv[0] as the
// program name.
func Run(argv []string) {

	parser := argparse.NewParser("go_forward socks", "Creates a SOCKS5 proxy")

	iface := parser.String("i", "interface",
		&argparse.Options{
			Required: false,
			Help:     "The interface to listen on.",
			Default:  "127.0.0.1",
		})

	port := parser.String("p", "port",
		&argparse.Options{
			Required: false,
			Help:     "The port to listen on",
			Default:  "1080",
		})

	username := parser.String("U", "user",
		&argparse.Options{
			Required: false,
			Help:     "Username to use for proxy",
			Default:  "socker",
		})

	password := parser.String("P", "pass",
		&argparse.Options{
			Required: false,
			Help:     "Password to use for proxy",
		})

	argErr := parser.Parse(argv)

	if argErr != nil {
		fmt.Print(parser.Usage(argErr))
		os.Exit(1)
	}

	// set the listener string
	var listnr = fmt.Sprintf("%s:%s", *iface, *port)
	fmt.Printf("Starting SOCKS5 Proxy Listening on %s\n\n", listnr)
	if len(*password) > 0 {
		fmt.Printf("Auth Mode enabled...\n\tUsername: %s\n\n", *username)
	}

	if err := Serve(listnr, *username, *password, nil); err != nil {
		panic(err)
	}
}
