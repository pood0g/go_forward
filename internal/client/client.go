package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var knownHostsFile = "./known_hosts"


type Arguments struct {
	remotePort string
	localPort  string
	remoteHost string
	sshPort string
	userName   string
	passWord   string
	identity   string
	generateKey bool
}

// getArgs parses argv, where argv[0] is the program name.
func getArgs(argv []string) Arguments {

	parser := argparse.NewParser("go_forward client", "A simple SSH client allowing reverse port forwarding.")

	localPort := parser.String("l", "local_port",
		&argparse.Options{
			Required: false,
			Help:     "The local port to forward connections to (Optional)",
			Default: "1080",
		})
	remotePort := parser.String("r", "remote_port",
		&argparse.Options{
			Required: false,
			Help:     "The port to open on the SSH server, 0 lets the server pick one (Optional)",
			Default: "1080",
		})
	sshPort := parser.String("R", "ssh_port",
		&argparse.Options{
			Required: false,
			Help:     "The port the SSH server listens on (Required unless --generate-key)",
		})
	remoteHost := parser.String("i", "ssh_host",
		&argparse.Options{
			Required: false,
			Help:     "The remote host to connect to via SSH (Required unless --generate-key)",
		})
	userName := parser.String("U", "username",
		&argparse.Options{
			Required: false,
			Help:     "The username for authentication to the SSH server (Required unless --generate-key)",
		})
	generateKey := parser.Flag("g", "generate-key",
		&argparse.Options{
			Required: false,
			Help:     "Generate an ed25519 key pair at the --identity path, print the public key and exit (Optional)",
		})
	passWord := parser.String("P", "password",
		&argparse.Options{
			Required: false,
			Help:     "The password for authentication to the SSH server (Optional, one of password or identity is required)",
		})
	identity := parser.String("k", "identity",
		&argparse.Options{
			Required: false,
			Help:     "Private key file for public key authentication, prompts for a passphrase if encrypted (Optional, one of password or identity is required)",
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

	if *sshPort == "" || *remoteHost == "" || *userName == "" {
		log.Fatal(parser.Usage("--ssh_port, --ssh_host and --username are required"))
	}
	if *passWord == "" && *identity == "" {
		log.Fatal(parser.Usage("one of --password or --identity is required"))
	}

	return Arguments{
		remotePort: *remotePort,
		localPort:  *localPort,
		remoteHost: *remoteHost,
		sshPort: *sshPort,
		userName:   *userName,
		passWord:   *passWord,
		identity:   *identity,
	}
}

func getKhFile(fileName, hostKey string) error {
	_, err := os.Stat(fileName)
	if err != nil {
		log.Println("Known hosts file doesnt exist, creating...")
		os.Create(knownHostsFile)
		os.Chmod(knownHostsFile, 0600)
		return getKhFile(fileName, hostKey)
	}
	khFile, err := os.OpenFile(fileName, os.O_RDONLY, 0600)
	if err != nil {
		log.Fatalln("It's Dead Jim")
	}
	defer khFile.Close()

	scanner := bufio.NewScanner(khFile)
	for scanner.Scan() {
		if hostKey == scanner.Text()+"\n" {
			log.Println("Host is known, connecting.")
			return nil
		}
	}
	return fmt.Errorf("key not found in %s", knownHostsFile)
}

func writeToFile(fileName, line string) {
	file, _ := os.OpenFile(fileName, os.O_WRONLY, 0600)
	file.Seek(0, 2)
	file.WriteString(line)
}

func askUserBool(question string) bool {
	var vrfy string
	fmt.Print(question)
	fmt.Scanln(&vrfy)
	fmt.Println()
	if vrfy == "y" || vrfy == "Y" {
		return true
	}
	return false
}

func getHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {

	// function for user to manually verify host key.
	var known error

	hostKey := string(ssh.MarshalAuthorizedKey(key))
	log.Printf("Connected to %s", hostname)

	if err := getKhFile(knownHostsFile, fmt.Sprintf("%s %s", hostname, hostKey)); err != nil {
		log.Println(err)
		fmt.Printf("\nHostKey: %s", hostKey)

		if askUserBool("\nHost unknown, do you want to connect and add to known hosts (y/n)? ") {
			writeToFile(knownHostsFile, fmt.Sprintf("%s %s", hostname, ssh.MarshalAuthorizedKey(key)))
			return nil
		} else {
			return fmt.Errorf("host key rejected by user")
		}
	}
	return known
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
		HostKeyCallback: getHostKey,
	}
	return &config, nil
}

func handleConn(remote net.Conn, local net.Conn) {

	// buffered so the second copy can finish after we return
	done := make(chan bool, 2)

	go func() {
		_, err := io.Copy(local, remote)
		if err != nil {
			log.Printf("local > remote: %s", err)
		}
		done <- true
	}()

	go func() {
		_, err := io.Copy(remote, local)
		if err != nil {
			log.Printf("remote > local: %s", err)
		}
		done <- true
	}()

	// one side closed, so close both to end the other copy
	<-done
	remote.Close()
	local.Close()
}

// Run connects to the SSH server and forwards its remote port to a local
// service. argv is the command line with argv[0] as the program name.
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
	sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", args.remoteHost, args.sshPort), cfg)
	if err != nil {
		log.Fatalf("%s\n", err)
	} else {
		log.Printf("Remote: %s\n", sshConn.ServerVersion())
	}

	// Reverse port forward. Port 0 asks the server to pick a free port.
	remotePort, err := sshConn.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", args.remotePort))
	if err != nil {
		log.Fatalf("Could not open remote port: %s", err)
	} else {
		_, boundPort, _ := net.SplitHostPort(remotePort.Addr().String())
		log.Printf("Port forward successful, server listening on port %s.", boundPort)
	}

	// close conn cleanly when main() is completed
	defer sshConn.Close()
	defer remotePort.Close()

	// forever loop
	for {
		// accept connections from remote
		remote, err := remotePort.Accept()
		if err != nil {
			log.Fatalf("Remote: %s", err)
		}

		// try to connect to local service, continue if unsuccessful
		local, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", args.localPort))
		if err != nil {
			log.Printf("Local: %s", err)
			remote.Close()
			continue
		}

		// copy data between the connections, one goroutine per connection
		go handleConn(remote, local)
	}
}
