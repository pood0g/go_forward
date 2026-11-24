package server

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// daemonEnv marks a process as the detached child started by startDaemon.
const daemonEnv = "GO_FORWARD_SERVER_DAEMONIZED"

// startDaemon re-runs this program detached from the terminal, with stdout and
// stderr going to the log file, and returns in the parent process.
func startDaemon(arguments Arguments) {
	if pid, running := readRunningPid(arguments.pidFile); running {
		log.Fatalf("daemon already running with pid %d (see %s)", pid, arguments.pidFile)
	}

	logFile, err := os.OpenFile(arguments.logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("opening log file %s: %v", arguments.logFile, err)
	}
	defer logFile.Close()

	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnv+"=1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		log.Fatalf("starting daemon: %v", err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	// Give the child a moment to fail on startup errors such as a bad port or
	// authorized keys file, so the parent can report them.
	time.Sleep(500 * time.Millisecond)
	if !processAlive(pid) {
		log.Fatalf("daemon exited during startup, see %s", arguments.logFile)
	}

	fmt.Printf("daemon started with pid %d, logging to %s\n", pid, arguments.logFile)
}

// stopDaemon asks the daemon recorded in pidFile to exit.
func stopDaemon(pidFile string) {
	pid, running := readRunningPid(pidFile)
	if !running {
		os.Remove(pidFile)
		fmt.Println("no running daemon found")
		return
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Fatalf("finding daemon pid %d: %v", pid, err)
	}
	if err := terminateProcess(proc); err != nil {
		log.Fatalf("stopping daemon pid %d: %v", pid, err)
	}
	fmt.Printf("sent stop to daemon pid %d\n", pid)
}

// writeDaemonPid records this process's pid so --stop can find it.
func writeDaemonPid(pidFile string) {
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
		log.Fatalf("writing pid file %s: %v", pidFile, err)
	}
}

// watchDaemonSignals removes the pid file and exits when the daemon is told to
// stop.
func watchDaemonSignals(pidFile string) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("daemon stopping")
		os.Remove(pidFile)
		os.Exit(0)
	}()
}

// readRunningPid returns the pid stored in pidFile and whether that process is
// still alive.
func readRunningPid(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return pid, processAlive(pid)
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return processRunning(proc)
}
