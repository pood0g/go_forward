package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	kh "golang.org/x/crypto/ssh/knownhosts"
	// "github.com/akamensky/argparse"
)

func getHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {

	// manually verify host key.
	// TODO implement known_hosts file reading
	var known error

	fmt.Printf("Connected to %s\nHostKey: %s\n", hostname, ssh.MarshalAuthorizedKey(key))

	khFile, err := kh.New("./known_hosts")
	if err != nil {
		log.Printf("KnownHosts: %s", err)
	} else {
		if known := khFile(hostname, remote, key); known != nil {

			var vrfy string
			fmt.Print("Host unknown, do you want to connect anyway (y/n)? ")
			fmt.Scanln(&vrfy)
			fmt.Println()
			if vrfy == "y" || vrfy == "Y" {
				khline := kh.Line([]string{hostname}, key) + "\n"
				os.WriteFile("./known_hosts", []byte(khline), 0640)
				return nil
			} else {
				return fmt.Errorf("host key rejected by user")
			}
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

	fmt.Print("Welcome to go_forward, an ssh port forwarder\n\n")

	// get configuration
	cfg := makeSshConfig("test", "test1234")

	// create SSH connection
	sshConn, err := ssh.Dial("tcp", "127.0.0.1:22", cfg)
	if err != nil {
		log.Fatalf("SSH: %s\n", err)
	} else {
		fmt.Printf("Server: %s\n", sshConn.ServerVersion())
	}

	// Reverse port forward
	remotePort, err := sshConn.Listen("tcp", "127.0.0.1:1085")
	if err != nil {
		log.Fatalf("Could not open remote port: %s", err)
	} else {
		fmt.Printf("Port forward successful.")
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
		local, err := net.Dial("tcp", "127.0.0.1:1080")
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
