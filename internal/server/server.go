package server

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
)

// Run starts the SSH server. argv is the command line with argv[0] as the
// program name.
func Run(argv []string) {

	arguments := get_args(argv)

	if arguments.stop {
		stopDaemon(arguments.pidFile)
		return
	}

	if arguments.daemon && os.Getenv(daemonEnv) == "" {
		startDaemon(arguments)
		return
	}

	if os.Getenv(daemonEnv) != "" {
		writeDaemonPid(arguments.pidFile)
		watchDaemonSignals(arguments.pidFile)
	}

	hostKey, err := loadOrCreateHostKey(arguments.hostKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("starting SSH server on port %s:%s...", arguments.iface, arguments.port)

	server := ssh.Server{
		Addr: fmt.Sprintf("%s:%s", arguments.iface, arguments.port),
		Handler: ssh.Handler(func(s ssh.Session) {
			io.WriteString(s, "Remote forwarding only...\n")
			<-s.Context().Done()
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Printf("user %s requested remote forward on %s:%d", ctx.User(), host, port)
			return true
		}),
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Printf("user %s requested local forward to %s:%d", ctx.User(), host, port)
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        handleTCPIPForward,
			"cancel-tcpip-forward": handleTCPIPForward,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		Version: "go_forward_server",
	}

	server.AddHostKey(hostKey)

	if arguments.passWord != "" {
		server.PasswordHandler = passwordHandler(arguments.userName, arguments.passWord)
	}

	if arguments.authorizedKeysFile != "" {
		keys, err := loadAuthorizedKeys(arguments.authorizedKeysFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("loaded %d authorized key(s) from %s", len(keys), arguments.authorizedKeysFile)
		server.PublicKeyHandler = publicKeyHandler(arguments.userName, keys)
	}

	log.Fatal(server.ListenAndServe())
}
