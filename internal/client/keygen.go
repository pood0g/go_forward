package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// generateKeyPair creates an unencrypted ed25519 key pair. The private key is
// written to path (mode 0600) and the public key to path+".pub". The public key
// is printed so it can be added to a server with `server --add-key`.
func generateKeyPair(path string) error {
	pubPath := path + ".pub"
	for _, p := range []string{path, pubPath} {
		_, err := os.Stat(p)
		if err == nil {
			return fmt.Errorf("%s already exists, refusing to overwrite", p)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	passphrase, err := askNewPassphrase()
	if err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var block *pem.Block
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(priv, "go_forward")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "go_forward", passphrase)
	}
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " go_forward"

	if err := writeNewFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return err
	}
	if err := writeNewFile(pubPath, []byte(pubLine+"\n"), 0644); err != nil {
		os.Remove(path)
		return err
	}

	if len(passphrase) == 0 {
		fmt.Printf("private key written to %s (no passphrase)\n", path)
	} else {
		fmt.Printf("private key written to %s (encrypted)\n", path)
	}
	fmt.Printf("public key written to %s:\n\n%s\n\n", pubPath, pubLine)
	fmt.Printf("add it to a server with:\n  go_forward server --add-key %q -K <authorized_keys>\n", pubLine)
	return nil
}

// askNewPassphrase asks for a passphrase for the new key. Pressing Enter gives
// no passphrase. A non-empty passphrase is asked for twice, and both must match.
func askNewPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Println("stdin is not a terminal, creating the key without a passphrase")
		return nil, nil
	}

	fmt.Print("Passphrase (empty for none): ")
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	if len(first) == 0 {
		return nil, nil
	}

	fmt.Print("Confirm passphrase: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("passphrases do not match, no key was created")
	}
	return first, nil
}

// writeNewFile creates path with the given mode and fails if it already exists.
func writeNewFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return f.Close()
}
