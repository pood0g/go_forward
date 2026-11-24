package server

import (
	"errors"
	"log"

	"github.com/akamensky/argparse"

	"go_forward/internal/socks"
	"go_forward/internal/tunnel"
)

// get_args parses argv, where argv[0] is the program name.
func get_args(argv []string) Arguments {
	parser := argparse.NewParser("go_forward server", "A simple SSH server allowing reverse port forwarding.")

	port := parser.String("p", "port",
		&argparse.Options{
			Required: false,
			Help: "The port to run the SSH server on (Optional)",
			Default: "22",
		})

	iface := parser.String("i", "interface",
		&argparse.Options{
			Required: false,
			Help: "The interface to run the SSH server on (Optional)",
			Default: "0.0.0.0",
		})

	userName := parser.String("U", "username",
	&argparse.Options{
		Required: false,
		Help: "The username for authentication to the SSH server (Required unless --stop)",
	})

	passWord := parser.String("P", "password",
	&argparse.Options{
		Required: false,
		Help: "The password for authentication to the SSH server (Optional, one of password or authorized keys is required)",
	})

	authorizedKeys := parser.String("K", "authorized-keys",
	&argparse.Options{
		Required: false,
		Help: "OpenSSH authorized_keys file of public keys allowed to log in as the user (Optional, one of password or authorized keys is required)",
	})

	hostKeyFile := parser.String("H", "host-key",
	&argparse.Options{
		Required: false,
		Help: "File holding the server's host key, created on first run if missing (Optional)",
		Default: "ssh_host_ed25519_key",
	})

	daemon := parser.Flag("d", "daemon",
	&argparse.Options{
		Required: false,
		Help: "Run in the background as a daemon, logging to --log-file (Optional)",
	})

	addKey := parser.String("a", "add-key",
	&argparse.Options{
		Required: false,
		Help: "Add a public key to the --authorized-keys file and exit. Takes an OpenSSH public key line or the path to a .pub file (Optional)",
	})

	dynamic := parser.String("D", "dynamic",
	&argparse.Options{
		Required: false,
		Help: "Start a SOCKS5 proxy on [addr:]port. Its connections leave from the connected client. A bare port listens on 127.0.0.1 (Optional)",
	})

	dynamicAuth := parser.String("", "dynamic-auth",
	&argparse.Options{
		Required: false,
		Help: "user:password the --dynamic proxy requires (Optional, without it the proxy needs no login)",
	})

	stop := parser.Flag("s", "stop",
	&argparse.Options{
		Required: false,
		Help: "Stop the daemon recorded in --pid-file and exit (Optional)",
	})

	pidFile := parser.String("", "pid-file",
	&argparse.Options{
		Required: false,
		Help: "File recording the daemon's pid (Optional)",
		Default: "go_forward_server.pid",
	})

	logFile := parser.String("", "log-file",
	&argparse.Options{
		Required: false,
		Help: "File receiving the daemon's output (Optional)",
		Default: "go_forward_server.log",
	})

	argErr := parser.Parse(argv)

	if argErr != nil {
		log.Fatal(parser.Usage(argErr))
	}

	if *addKey != "" && *authorizedKeys == "" {
		log.Fatal(parser.Usage("--authorized-keys is required with --add-key"))
	}

	dynamicUser, dynamicPass, err := socks.ParseCredentials(*dynamicAuth)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}
	dynamicAddr := ""
	if *dynamic != "" {
		f, err := tunnel.ParseForward(*dynamic)
		if err == nil && f.Target != "" {
			err = errors.New("--dynamic takes [addr:]port")
		}
		if err != nil {
			log.Fatal(parser.Usage(err))
		}
		dynamicAddr = f.Listen
	}

	if !*stop && *addKey == "" {
		if *userName == "" {
			log.Fatal(parser.Usage("--username is required"))
		}
		if *passWord == "" && *authorizedKeys == "" {
			log.Fatal(parser.Usage("one of --password or --authorized-keys is required"))
		}
	}

	return Arguments{
		port: *port,
		iface: *iface,
		userName: *userName,
		passWord: *passWord,
		hostKeyFile: *hostKeyFile,
		authorizedKeysFile: *authorizedKeys,
		daemon: *daemon,
		stop: *stop,
		addKey: *addKey,
		dynamicAddr: dynamicAddr,
		dynamicUser: dynamicUser,
		dynamicPass: dynamicPass,
		pidFile: *pidFile,
		logFile: *logFile,
	}
}
