package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"

	gossh "golang.org/x/crypto/ssh"
)

// loadOrCreateHostKey returns the server's host key stored at path. When the
// file does not exist a new ed25519 key is generated and saved, so clients see
// the same host key fingerprint across restarts.
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err == nil {
		return gossh.ParsePrivateKey(pemBytes)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := gossh.MarshalPrivateKey(priv, "go_forward_server host key")
	if err != nil {
		return nil, err
	}

	// O_EXCL makes sure an existing key is never overwritten.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating host key %s: %w", path, err)
	}
	if err := pem.Encode(f, block); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing host key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("writing host key %s: %w", path, err)
	}

	log.Printf("generated new host key %s", path)
	return gossh.NewSignerFromKey(priv)
}
