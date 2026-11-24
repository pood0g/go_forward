package socks

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/akamensky/argparse"
	"github.com/things-go/go-socks5"

	"go_forward/internal/secret"
)

// Dialer makes the proxy's outgoing connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Serve runs a tunnelled SOCKS5 proxy (see New) on listenAddr until it fails.
func Serve(listenAddr, username, password string, dial Dialer) error {
	return New(username, password, dial).ListenAndServe("tcp", listenAddr)
}

// New returns a SOCKS5 proxy whose clients and exit are on different machines.
// dial makes the outgoing connections; nil connects directly. A non-empty
// password enables username and password authentication.
//
// Only CONNECT is allowed: BIND and UDP ASSOCIATE would open their sockets on
// the machine running the proxy, not the one connections leave from. When dial
// is set, host names are passed to it unresolved so they are looked up where
// the connection leaves, which also reaches names only that network knows.
func New(username, password string, dial Dialer) *socks5.Server {
	opt := options(username, password)
	opt = append(opt, socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}))
	if dial != nil {
		opt = append(opt, socks5.WithDial(dial), socks5.WithResolver(remoteResolver{}))
	}
	return socks5.NewServer(opt...)
}

func options(username, password string) []socks5.Option {
	opt := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	}
	if len(password) > 0 {
		creds := socks5.StaticCredentials{username: password}
		auth := socks5.UserPassAuthenticator{Credentials: creds}
		opt = append(opt, socks5.WithAuthMethods([]socks5.Authenticator{auth}))
	}
	return opt
}

// remoteResolver leaves host names unresolved, so the dialer receives
// host:port and the far side resolves it.
type remoteResolver struct{}

func (remoteResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
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

	askPassword := parser.Flag("P", "pass",
		&argparse.Options{
			Required: false,
			Help:     "Require a login. Prompts for the password, or reads it from $" + secret.ProxyPasswordEnv,
		})

	argErr := parser.Parse(argv)

	if argErr != nil {
		fmt.Print(parser.Usage(argErr))
		os.Exit(1)
	}

	password := ""
	if *askPassword {
		var err error
		if password, err = secret.Read("SOCKS proxy password for "+*username, secret.ProxyPasswordEnv, true); err != nil {
			log.Fatal(err)
		}
	}

	// set the listener string
	listnr := net.JoinHostPort(*iface, *port)
	fmt.Printf("Starting SOCKS5 Proxy Listening on %s\n\n", listnr)
	if len(password) > 0 {
		fmt.Printf("Auth Mode enabled...\n\tUsername: %s\n\n", *username)
	}

	// A plain proxy: clients and exit are the same machine, so every command
	// works as the library provides it.
	proxy := socks5.NewServer(options(*username, password)...)
	if err := proxy.ListenAndServe("tcp", listnr); err != nil {
		log.Fatal(err)
	}
}
