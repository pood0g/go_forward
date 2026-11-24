package server

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"log"
	"os"

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
