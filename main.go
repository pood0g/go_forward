package main

import (
	"bufio"
	b64 "encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/ssh"
)

var knownHostsFile = "./known_hosts"

const BANNER = `
ICAgICAgICAgICAgICAgICAgICAgX19fXyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgX18KICAgX19fXyBfX19fXyAgICAgICAvIF9fL19fXyAgX19fX19fICAgICAgX19fX19fIF9f
X19fX19fX18vIC8KICAvIF9fIGAvIF9fIFwgICAgIC8gL18vIF9fIFwvIF9fXy8gfCAvfCAvIC8g
X18gYC8gX19fLyBfXyAgLyAKIC8gL18vIC8gL18vIC8gICAgLyBfXy8gL18vIC8gLyAgIHwgfC8g
fC8gLyAvXy8gLyAvICAvIC9fLyAvICAKIFxfXywgL1xfX19fL19fX18vXy8gIFxfX19fL18vICAg
IHxfXy98X18vXF9fLF8vXy8gICBcX18sXy8gICAKL19fX18vICAgICAvX19fX18vICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAK`

type Arguments struct {
	remotePort string
	localPort  string
	remoteHost string
	sshPort string
	userName   string
	passWord   string
}

func getArgs() Arguments {

	parser := argparse.NewParser("go_forward", "A simple SSH client allowing reverse port forwarding.")

	localPort := parser.String("l", "local_port",
		&argparse.Options{
			Required: true,
			Help:     "The local port to forward on the remote machine",
		})
	remotePort := parser.String("r", "remote_port",
		&argparse.Options{
			Required: true,
			Help:     "The port to forward to on the remote",
		})
	sshPort := parser.String("R", "ssh_port",
		&argparse.Options{
			Required: true,
			Help:     "The port to forward to on the remote",
		})
	remoteHost := parser.String("i", "remote_host",
		&argparse.Options{
			Required: true,
			Help:     "The remote host to connect to via SSH",
		})
	userName := parser.String("U", "username",
		&argparse.Options{
			Required: true,
			Help:     "The username for authentication to the SSH server (Required)",
		})
	passWord := parser.String("P", "password",
		&argparse.Options{
			Required: true,
			Help:     "The password for authentication to the SSH server (Required)",
		})

	argErr := parser.Parse(os.Args)

	if argErr != nil {
		log.Fatal(parser.Usage(argErr))
	}

	return Arguments{
		remotePort: *remotePort,
		localPort:  *localPort,
		remoteHost: *remoteHost,
		sshPort: *sshPort,
		userName:   *userName,
		passWord:   *passWord,
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

func makeSshConfig(user, password string) *ssh.ClientConfig {

	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyAlgorithms: []string{
			// add more key algorithms if needed this is normally used by default in OpenSSHd
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA512,
		},
		HostKeyCallback: getHostKey,
	}
	return &config
}

func handleConn(remote net.Conn, local net.Conn) {

	done := make(chan bool)

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

	<-done
}

func main() {

	banner, _ := b64.StdEncoding.DecodeString(BANNER)
	fmt.Printf("%s\n", banner)

	args := getArgs()

	// get configuration
	cfg := makeSshConfig(args.userName, args.passWord)

	// create SSH connection
	sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", args.remoteHost, args.sshPort), cfg)
	if err != nil {
		log.Fatalf("%s\n", err)
	} else {
		log.Printf("Remote: %s\n", sshConn.ServerVersion())
	}

	// Reverse port forward
	remotePort, err := sshConn.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", args.remotePort))
	if err != nil {
		log.Fatalf("Could not open remote port: %s", err)
	} else {
		log.Printf("Port forward successful.")
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
		local, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", args.remotePort))
		if err != nil {
			log.Printf("Local: %s", err)
			remote.Close()
			continue
		} else {
			// copy data between the connections
			handleConn(remote, local)
		}
	}
}
