package server

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// loadAuthorizedKeys parses an OpenSSH authorized_keys file. Keys with options
// (command=, no-port-forwarding, ...) are rejected rather than silently running
// without those restrictions.
func loadAuthorizedKeys(path string) ([]gossh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading authorized keys %s: %w", path, err)
	}
	return parseAuthorizedKeys(path, data)
}

func parseAuthorizedKeys(path string, data []byte) ([]gossh.PublicKey, error) {
	var keys []gossh.PublicKey
	for len(bytes.TrimSpace(data)) > 0 {
		key, _, options, rest, err := gossh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("parsing authorized keys %s: %w", path, err)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("authorized keys %s: key options are not supported, remove them from %q", path, options)
		}
		keys = append(keys, key)
		data = rest
	}
	return keys, nil
}

// addAuthorizedKey appends one public key to the authorized keys file at path,
// creating the file if needed. input is an OpenSSH public key line, or the path
// to a .pub file containing one. Keys already in the file are not added twice.
func addAuthorizedKey(path string, input string) error {
	line := input
	if data, err := os.ReadFile(input); err == nil {
		line = string(data)
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("expected a single public key line or a .pub file containing one")
	}

	key, _, options, _, err := gossh.ParseAuthorizedKey([]byte(line + "\n"))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if len(options) > 0 {
		return fmt.Errorf("key options are not supported, remove them from the key")
	}

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading authorized keys %s: %w", path, err)
	}
	keys, err := parseAuthorizedKeys(path, existing)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			fmt.Printf("key %s is already in %s\n", gossh.FingerprintSHA256(key), path)
			return nil
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("opening authorized keys %s: %w", path, err)
	}
	defer f.Close()

	// Start on a new line if the existing file does not end with one.
	prefix := ""
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		prefix = "\n"
	}
	if _, err := f.WriteString(prefix + line + "\n"); err != nil {
		return fmt.Errorf("writing authorized keys %s: %w", path, err)
	}

	fmt.Printf("added key %s to %s\n", gossh.FingerprintSHA256(key), path)
	return nil
}

func passwordHandler(userName string, passWord string) ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		// Both comparisons always run so timing does not reveal which one failed.
		userOK := subtle.ConstantTimeCompare([]byte(ctx.User()), []byte(userName)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(password), []byte(passWord)) == 1
		if userOK && passOK {
			log.Printf("user %s connected from %s with password", ctx.User(), ctx.RemoteAddr())
			return true
		}
		return false
	}
}

func publicKeyHandler(userName string, allowed []gossh.PublicKey) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		if ctx.User() != userName {
			return false
		}
		for _, k := range allowed {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				log.Printf("user %s connected from %s with key %s", ctx.User(), ctx.RemoteAddr(), gossh.FingerprintSHA256(key))
				return true
			}
		}
		return false
	}
}
