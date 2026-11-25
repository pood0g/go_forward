package main

import (
	b64 "encoding/base64"
	"fmt"
	"os"

	"go_forward/internal/client"
	"go_forward/internal/server"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: go_forward <command> [options]

commands:
  server   run the SSH server (accepts remote and local port forwards)
  client   connect to a server with local, remote and SOCKS forwards

Run 'go_forward <command> -h' for the options of a command.
`)
	os.Exit(2)
}

func main() {

	banner, _ := b64.StdEncoding.DecodeString(BANNER)
	fmt.Printf("%s\n", banner)

	if len(os.Args) < 2 {
		usage()
	}

	// Each command parses its own options. argv keeps the program name first,
	// which argparse expects, and drops the command word.
	argv := append([]string{"go_forward " + os.Args[1]}, os.Args[2:]...)

	switch os.Args[1] {
	case "server":
		server.Run(argv)
	case "client":
		client.Run(argv)
	default:
		usage()
	}
}
