package client

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"go_forward/internal/secret"
	"go_forward/internal/socks"
	"go_forward/internal/tunnel"
)

var knownHostsFile = "./known_hosts"

type Arguments struct {
	remoteHost   string
	sshPort      string
	userName     string
	passWord     string
	identity     string
	generateKey  bool
	local        []tunnel.Forward
	remote       []tunnel.Forward
	dynamic      []tunnel.Forward
	dynamicUser  string
	dynamicPass  string
	keepAlive    int
	keepAliveMax int
}

// getArgs parses argv, where argv[0] is the program name.
func getArgs(argv []string) Arguments {

	parser := argparse.NewParser("go_forward client", "An SSH client for local, remote and dynamic (SOCKS) port forwarding.")

	remoteHost := parser.String("i", "host",
		&argparse.Options{
			Required: false,
			Help:     "The SSH server to connect to (Required unless --generate-key)",
		})
	sshPort := parser.String("p", "port",
		&argparse.Options{
			Required: false,
			Help:     "The port the SSH server listens on (Optional)",
			Default:  "22",
		})
	userName := parser.String("U", "username",
		&argparse.Options{
			Required: false,
			Help:     "The username for authentication to the SSH server (Required unless --generate-key)",
		})
	passWord := parser.Flag("P", "password",
		&argparse.Options{
			Required: false,
			Help:     "Prompt for a password to log in with, or read it from $" + secret.PasswordEnv + " (Optional, one of password or identity is required)",
		})
	identity := parser.String("k", "identity",
		&argparse.Options{
			Required: false,
			Help:     "Private key file for public key authentication, prompts for a passphrase if encrypted (Optional, one of password or identity is required)",
		})
	generateKey := parser.Flag("g", "generate-key",
		&argparse.Options{
			Required: false,
			Help:     "Generate an ed25519 key pair at the --identity path, print the public key and exit (Optional)",
		})
	local := parser.StringList("L", "local",
		&argparse.Options{
			Required: false,
			Help:     "[bind:]port:host:hostport. Listen here and connect to host:hostport from the server. Repeatable (Optional)",
		})
	remote := parser.StringList("R", "remote",
		&argparse.Options{
			Required: false,
			Help:     "[bind:]port:host:hostport listens on the server and connects to host:hostport from here. [bind:]port alone starts a SOCKS5 proxy on the server whose connections leave from here. Repeatable (Optional)",
		})
	dynamic := parser.StringList("D", "dynamic",
		&argparse.Options{
			Required: false,
			Help:     "[bind:]port. Start a SOCKS5 proxy here whose connections leave from the server. Repeatable (Optional)",
		})
	dynamicAuth := parser.String("", "dynamic-auth",
		&argparse.Options{
			Required: false,
			Help:     "Username required by the SOCKS proxies from -D and -R. Prompts for the password, or reads it from $" + secret.ProxyPasswordEnv + " (Optional, without it they need no login)",
		})

	keepAlive := parser.Int("", "keepalive",
		&argparse.Options{
			Required: false,
			Help:     "Seconds between SSH keepalives to the server, 0 disables them (Optional)",
			Default:  15,
		})
	keepAliveMax := parser.Int("", "keepalive-max",
		&argparse.Options{
			Required: false,
			Help:     "Missed keepalives in a row before the connection is closed (Optional)",
			Default:  3,
		})

	argErr := parser.Parse(argv)

	if argErr != nil {
		log.Fatal(parser.Usage(argErr))
	}

	if *generateKey {
		if *identity == "" {
			log.Fatal(parser.Usage("--identity is required with --generate-key"))
		}
		return Arguments{identity: *identity, generateKey: true}
	}

	if *remoteHost == "" || *userName == "" {
		log.Fatal(parser.Usage("--host and --username are required"))
	}
	if !*passWord && *identity == "" {
		log.Fatal(parser.Usage("one of --password or --identity is required"))
	}

	if *keepAlive < 0 || *keepAliveMax < 1 {
		log.Fatal(parser.Usage("--keepalive must be 0 or more and --keepalive-max 1 or more"))
	}

	password := ""
	if *passWord {
		var err error
		password, err = secret.Read(fmt.Sprintf("Password for %s@%s", *userName, *remoteHost), secret.PasswordEnv, false)
		if err != nil {
			log.Fatal(err)
		}
	}
	dynamicPass := ""
	if *dynamicAuth != "" {
		var err error
		dynamicPass, err = secret.Read("SOCKS proxy password for "+*dynamicAuth, secret.ProxyPasswordEnv, true)
		if err != nil {
			log.Fatal(err)
		}
	}

	parse := func(flag string, specs []string, target int) []tunnel.Forward {
		var out []tunnel.Forward
		for _, spec := range specs {
			f, err := tunnel.ParseForward(spec)
			if err == nil && target > 0 && f.Target == "" {
				err = fmt.Errorf("%s %q: expected [bind:]port:host:hostport", flag, spec)
			}
			if err == nil && target < 0 && f.Target != "" {
				err = fmt.Errorf("%s %q: expected [bind:]port", flag, spec)
			}
			if err != nil {
				log.Fatal(parser.Usage(err))
			}
			out = append(out, f)
		}
		return out
	}

	return Arguments{
		remoteHost:   *remoteHost,
		sshPort:      *sshPort,
		userName:     *userName,
		passWord:     password,
		identity:     *identity,
		local:        parse("-L", *local, 1),
		remote:       parse("-R", *remote, 0),
		dynamic:      parse("-D", *dynamic, -1),
		dynamicUser:  *dynamicAuth,
		dynamicPass:  dynamicPass,
		keepAlive:    *keepAlive,
		keepAliveMax: *keepAliveMax,
	}
}

// hostKeyCallback checks server host keys against the OpenSSH known_hosts
// file at path. An unknown host is shown to the user and saved if accepted. A
// host whose key differs from the saved one is refused.
func hostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening known hosts %s: %w", path, err)
	}
	f.Close()

	check, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("reading known hosts %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		var keyErr *knownhosts.KeyError
		if err := check(hostname, remote, key); !errors.As(err, &keyErr) {
			if err == nil {
				log.Println("Host is known, connecting.")
			}
			return err
		}

		fingerprint := ssh.FingerprintSHA256(key)
		if len(keyErr.Want) > 0 {
			want := keyErr.Want[0]
			return fmt.Errorf("host key for %s has CHANGED to %s %s, refusing to connect. "+
				"If the change is expected, remove line %d of %s", hostname, key.Type(), fingerprint, want.Line, want.Filename)
		}

		fmt.Printf("\nHost %s is unknown.\nHost key: %s %s\n", hostname, key.Type(), fingerprint)
		if !askUserBool("Do you want to connect and add it to known hosts (y/n)? ") {
			return errors.New("host key rejected by user")
		}
		kh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("saving host key: %w", err)
		}
		defer kh.Close()
		_, err = fmt.Fprintln(kh, knownhosts.Line([]string{hostname}, key))
		return err
	}, nil
}

func askUserBool(question string) bool {
	var vrfy string
	fmt.Print(question)
	fmt.Scanln(&vrfy)
	fmt.Println()
	return vrfy == "y" || vrfy == "Y"
}

// loadSigner reads a private key file. If the key is encrypted it asks for the
// passphrase on the terminal.
func loadSigner(path string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading identity %s: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("parsing identity %s: %w", path, err)
	}

	fmt.Print("Passphrase for identity: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypting identity %s: %w", path, err)
	}
	return signer, nil
}

func makeSshConfig(user, password, identity string) (*ssh.ClientConfig, error) {

	checkHostKey, err := hostKeyCallback(knownHostsFile)
	if err != nil {
		return nil, err
	}

	var auth []ssh.AuthMethod
	if identity != "" {
		signer, err := loadSigner(identity)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}

	config := ssh.ClientConfig{
		User: user,
		Auth: auth,
		HostKeyAlgorithms: []string{
			// add more key algorithms if needed this is normally used by default in OpenSSHd
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA512,
		},
		HostKeyCallback: checkHostKey,
		Timeout:         15 * time.Second,
	}
	return &config, nil
}

// acceptLoop hands each connection on l to a new connection from dial.
func acceptLoop(l net.Listener, target string, dial func(network, addr string) (net.Conn, error)) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("%s: %s", l.Addr(), err)
			return
		}
		go func() {
			out, err := dial("tcp", target)
			if err != nil {
				log.Printf("connect to %s: %s", target, err)
				conn.Close()
				return
			}
			tunnel.Pipe(conn, out)
		}()
	}
}

// Run connects to the SSH server and sets up the requested forwards. argv is
// the command line with argv[0] as the program name.
func Run(argv []string) {

	args := getArgs(argv)

	if args.generateKey {
		if err := generateKeyPair(args.identity); err != nil {
			log.Fatal(err)
		}
		return
	}

	// get configuration
	cfg, err := makeSshConfig(args.userName, args.passWord, args.identity)
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	// create SSH connection
	sshConn, err := ssh.Dial("tcp", net.JoinHostPort(args.remoteHost, args.sshPort), cfg)
	if err != nil {
		log.Fatalf("%s\n", err)
	}
	defer sshConn.Close()
	log.Printf("Remote: %s\n", sshConn.ServerVersion())

	// Notice a dead server, and keep NAT and firewall state alive on an idle
	// connection.
	go tunnel.KeepAlive(sshConn, time.Duration(args.keepAlive)*time.Second, args.keepAliveMax, nil)

	if err := startForwards(sshConn, args); err != nil {
		log.Fatal(err)
	}

	err = sshConn.Wait()
	log.Printf("connection closed: %v", err)
}

// startForwards sets up the forwards in args over sshConn. They run until the
// connection closes.
func startForwards(sshConn *ssh.Client, args Arguments) error {
	// Let the server's own SOCKS proxy (server -D) send connections through
	// this client. Servers without support ignore the request.
	sshConn.SendRequest(tunnel.RegisterRequest, false, nil)
	go tunnel.ServeDials(sshConn.HandleChannelOpen(tunnel.DialChannel))

	// Remote forwards listen on the server. Port 0 lets the server pick one.
	for _, f := range args.remote {
		l, err := sshConn.Listen("tcp", f.Listen)
		if err != nil {
			return fmt.Errorf("-R %s: %w", f.Listen, err)
		}
		if f.Target == "" {
			log.Printf("SOCKS5 proxy on server %s, connections leave from here", l.Addr())
			proxy := socks.New(args.dynamicUser, args.dynamicPass, nil)
			go func() { log.Printf("-R %s: %s", l.Addr(), proxy.Serve(l)) }()
		} else {
			log.Printf("server %s forwards to %s from here", l.Addr(), f.Target)
			go acceptLoop(l, f.Target, net.Dial)
		}
	}

	// Local forwards listen here and connect from the server.
	for _, f := range args.local {
		l, err := net.Listen("tcp", f.Listen)
		if err != nil {
			return fmt.Errorf("-L %s: %w", f.Listen, err)
		}
		log.Printf("%s forwards to %s from the server", l.Addr(), f.Target)
		go acceptLoop(l, f.Target, sshConn.Dial)
	}

	// Local SOCKS5 proxies whose connections leave from the server.
	for _, f := range args.dynamic {
		l, err := net.Listen("tcp", f.Listen)
		if err != nil {
			return fmt.Errorf("-D %s: %w", f.Listen, err)
		}
		log.Printf("SOCKS5 proxy on %s, connections leave from the server", l.Addr())
		proxy := socks.New(args.dynamicUser, args.dynamicPass, sshConn.DialContext)
		go func() { log.Printf("-D %s: %s", l.Addr(), proxy.Serve(l)) }()
	}
	return nil
}
