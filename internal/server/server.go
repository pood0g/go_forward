package server

import (
	"io"
	"log"
	"net"
	"os"

	"github.com/gliderlabs/ssh"

	"go_forward/internal/socks"
	"go_forward/internal/tunnel"
)

// Run starts the SSH server. argv is the command line with argv[0] as the
// program name.
func Run(argv []string) {

	arguments := get_args(argv)

	if arguments.addKey != "" {
		if err := addAuthorizedKey(arguments.authorizedKeysFile, arguments.addKey); err != nil {
			log.Fatal(err)
		}
		return
	}

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

	server, err := newServer(arguments)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("starting SSH server on %s...", server.Addr)

	if arguments.dynamicAddr != "" {
		log.Printf("starting SOCKS5 proxy on %s, connections leave from the connected client", arguments.dynamicAddr)
		go func() {
			log.Fatal(socks.Serve(arguments.dynamicAddr, arguments.dynamicUser, arguments.dynamicPass, dialThroughClient))
		}()
	}

	log.Fatal(server.ListenAndServe())
}

// newServer builds the SSH server described by arguments.
func newServer(arguments Arguments) (*ssh.Server, error) {
	hostKey, err := loadOrCreateHostKey(arguments.hostKeyFile)
	if err != nil {
		return nil, err
	}

	server := &ssh.Server{
		Addr: net.JoinHostPort(arguments.iface, arguments.port),
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
			tunnel.RegisterRequest: handleRegister,
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
			return nil, err
		}
		log.Printf("loaded %d authorized key(s) from %s", len(keys), arguments.authorizedKeysFile)
		server.PublicKeyHandler = publicKeyHandler(arguments.userName, keys)
	}

	return server, nil
}
