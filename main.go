package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"bufio"

	"golang.org/x/crypto/ssh"
	// "github.com/akamensky/argparse"
)

var knownHostsFile = "./known_hosts"

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
		if hostKey == scanner.Text() + "\n" {
			return nil
		}
	}
	return fmt.Errorf("key not found in file")
}

func writeToFile(fileName, line string) {
	file, _ := os.OpenFile(fileName, os.O_WRONLY, 0600)
	file.Seek(0,2)
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
	fmt.Printf("Connected to %s\nHostKey: %s\n", hostname, hostKey)

	if known := getKhFile(knownHostsFile, fmt.Sprintf("%s %s", hostname, hostKey)); known != nil {
		if askUserBool("Host unknown, do you want to connect and add to known hosts (y/n)? ") {
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

	fmt.Print("Welcome to go_forward, an ssh port forwarder\n\n")

	// get configuration
	cfg := makeSshConfig("test", "test1234")

	// create SSH connection
	sshConn, err := ssh.Dial("tcp", "127.0.0.1:22", cfg)
	if err != nil {
		log.Fatalf("%s\n", err)
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
