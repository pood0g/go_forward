// Package secret reads passwords without putting them on the command line,
// where any local user can see them in the process list.
package secret

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	// PasswordEnv holds the SSH password for unattended runs.
	PasswordEnv = "GO_FORWARD_PASSWORD"
	// ProxyPasswordEnv holds the SOCKS proxy password for unattended runs.
	ProxyPasswordEnv = "GO_FORWARD_PROXY_PASSWORD"
)

// Read returns the value of the environment variable envName if it is set and
// not empty. Otherwise it asks for the secret on the terminal, without echo.
// With confirm set the secret is asked for twice, for a new password that a
// typo would lock out.
func Read(prompt, envName string, confirm bool) (string, error) {
	if v := os.Getenv(envName); v != "" {
		return v, nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("cannot ask for %s: stdin is not a terminal, set %s instead", lowerFirst(prompt), envName)
	}

	first, err := ask(fd, prompt+": ")
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", errors.New("empty password")
	}
	if confirm {
		second, err := ask(fd, "Confirm "+lowerFirst(prompt)+": ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", errors.New("passwords do not match")
		}
	}
	return first, nil
}

func ask(fd int, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(b), nil
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
