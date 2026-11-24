//go:build windows

package server

import (
	"os"
	"syscall"
)

const (
	// Not exported by the syscall package.
	detachedProcess = 0x00000008
)

// detachAttr starts the child without a console, in its own process group, so
// it keeps running after the launching console closes.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// processRunning reports whether proc is still alive. On Windows FindProcess
// fails for a process that has exited, so a successful lookup means it runs.
func processRunning(proc *os.Process) bool {
	return proc != nil
}

// terminateProcess kills the daemon: Windows has no SIGTERM for other processes.
func terminateProcess(proc *os.Process) error {
	return proc.Kill()
}
