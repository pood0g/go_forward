package socks

import (
	"fmt"
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/things-go/go-socks5"
)

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

	// create a slice for the options passed to NewServer
	opt := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	}

	// Create a SOCKS5 server
	if len(*password) > 0 {
		fmt.Printf("Auth Mode enabled...\n\tUsername: %s\n\n", *username)
		creds := socks5.StaticCredentials{*username: *password}
		auth := socks5.UserPassAuthenticator{Credentials: creds}
		opt = append(opt, socks5.WithAuthMethods([]socks5.Authenticator{auth}))
	}

	server := socks5.NewServer(opt...)

	// Serve SOCKS5 Proxy
	if err := server.ListenAndServe("tcp", listnr); err != nil {
		panic(err)
	}
}
