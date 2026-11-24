//go:build !windows

package server

import (
	"os"
	"syscall"
)

// detachAttr starts the child in a new session so it has no controlling
// terminal and survives the parent's shell exiting.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// processRunning reports whether proc exists, using signal 0 which checks
// without delivering anything.
func processRunning(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

func terminateProcess(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
