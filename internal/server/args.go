package server

import (
	"log"

	"github.com/akamensky/argparse"
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
		pidFile: *pidFile,
		logFile: *logFile,
	}
}
