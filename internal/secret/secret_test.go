package secret

import (
	"os"
	"strings"
	"testing"
)

func TestReadFromEnv(t *testing.T) {
	t.Setenv(PasswordEnv, "from-env")
	got, err := Read("Password", PasswordEnv, true)
	if err != nil || got != "from-env" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadWithoutTerminal(t *testing.T) {
	t.Setenv(PasswordEnv, "")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	stdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = stdin }()

	_, err = Read("Password", PasswordEnv, false)
	if err == nil || !strings.Contains(err.Error(), PasswordEnv) {
		t.Fatalf("got %v, want an error naming %s", err, PasswordEnv)
	}
}
