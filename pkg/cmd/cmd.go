package cmd

import (
	"context"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// ExitError reports an unsuccessful exit by a command.
type ExitError struct {
	*unix.WaitStatus
}

func (e *ExitError) Error() string {
	// Borrowed from https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/os/exec_posix.go;l=108
	res := ""
	switch {
	case e.WaitStatus.Exited():
		code := e.WaitStatus.ExitStatus()
		res = "exit status " + strconv.Itoa(code)
	case e.WaitStatus.Signaled():
		res = "signal: " + e.WaitStatus.Signal().String()
	case e.WaitStatus.Stopped():
		res = "stop signal: " + e.WaitStatus.StopSignal().String()
		if e.WaitStatus.StopSignal() == unix.SIGTRAP && e.WaitStatus.TrapCause() != 0 {
			res += " (trap " + strconv.Itoa(e.WaitStatus.TrapCause()) + ")"
		}
	case e.WaitStatus.Continued():
		res = "continued"
	}
	if e.WaitStatus.CoreDump() {
		res += " (core dumped)"
	}
	return fmt.Sprintf("ExitError: %s\n", res)
}

// Id uniquely identify a Cmd.
type Id string

// Cmd runs a command and tracks which files the command has interacted with.
type Cmd interface {
	// Run executes the command and traces files it interacted with. On success, it
	// returns a map of such files. On unsuccessful exit, it returns ExitError; it may also return other
	// related errors.
	Run(ctx context.Context) (map[string]bool, error)
	// Id uniquely identify this command.
	Id() Id
}
