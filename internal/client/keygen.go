package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
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

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "go_forward")
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

	fmt.Printf("private key written to %s\n", path)
	fmt.Printf("public key written to %s:\n\n%s\n\n", pubPath, pubLine)
	fmt.Printf("add it to a server with:\n  go_forward server --add-key %q -K <authorized_keys>\n", pubLine)
	return nil
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
