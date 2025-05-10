package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// syscallParms maps arch specific registers from syscall.PtraceRegs to common names (see
// syscall(2)).
type syscallParms struct {
	syscall uint64
	arg1    uint64
	arg2    uint64
	arg3    uint64
	arg4    uint64
	arg5    uint64
	arg6    uint64
	arg7    uint64
	retVal  uint64
	retVal2 uint64
	error   uint64
}

// these syscalls don't relate to filesystem, so we can ignore them.
var ignoreSyscallsMap = map[uint64]bool{
	unix.SYS_BRK:               true,
	unix.SYS_CLONE3:            true,
	unix.SYS_CLONE:             true,
	unix.SYS_CLOSE:             true,
	unix.SYS_EXIT_GROUP:        true,
	unix.SYS_FCNTL:             true,
	unix.SYS_FSTAT:             true,
	unix.SYS_GETCWD:            true,
	unix.SYS_GETDENTS64:        true,
	unix.SYS_GETEGID:           true,
	unix.SYS_GETEUID:           true,
	unix.SYS_GETGID:            true,
	unix.SYS_GETPID:            true,
	unix.SYS_GETPPID:           true,
	unix.SYS_GETRANDOM:         true,
	unix.SYS_GETTID:            true,
	unix.SYS_GETUID:            true,
	unix.SYS_IOCTL:             true,
	unix.SYS_MADVISE:           true,
	unix.SYS_MMAP:              true,
	unix.SYS_MPROTECT:          true,
	unix.SYS_MUNMAP:            true,
	unix.SYS_PIPE2:             true,
	unix.SYS_PIPE:              true,
	unix.SYS_PREAD64:           true,
	unix.SYS_PRLIMIT64:         true,
	unix.SYS_READ:              true,
	unix.SYS_RSEQ:              true,
	unix.SYS_RT_SIGACTION:      true,
	unix.SYS_RT_SIGPROCMASK:    true,
	unix.SYS_RT_SIGRETURN:      true,
	unix.SYS_SCHED_GETAFFINITY: true,
	unix.SYS_SET_ROBUST_LIST:   true,
	unix.SYS_SET_TID_ADDRESS:   true,
	unix.SYS_SIGALTSTACK:       true,
	unix.SYS_WAIT4:             true,
	unix.SYS_WRITE:             true,
}

func getSyscallArgPath(pid int, arg uint64) (string, error) {
	var path [syscall.PathMax]byte
	for i := range syscall.PathMax {
		buff := [1]byte{}
		count, err := syscall.PtracePeekText(pid, uintptr(arg+uint64(i)), buff[:])
		if err != nil {
			return "", err
		}
		if count != 1 {
			return "", fmt.Errorf("syscall.PtracePeekText: expected 1 peeked, got %d", count)
		}
		if buff[0] == 0 {
			return string(path[:i]), nil
		}
		path[i] = buff[0]
	}
	return "", errors.New("path exceeds syscall.PathMax")
}

// fileSyscallFnMap maps filesystem related syscalls to functions that extract the file path from
// it.
var fileSyscallFnMap = map[uint64]func(int, *syscallParms) (string, error){
	unix.SYS_CHDIR: func(pid int, scMap *syscallParms) (string, error) {
		pathName, err := getSyscallArgPath(pid, scMap.arg1)
		if err != nil {
			return "", err
		}
		return pathName, nil
	},
	unix.SYS_EXECVE: func(pid int, scMap *syscallParms) (string, error) {
		// TODO understand why execve, first time it is called, comes with all zeroed arguments
		if scMap.arg1 == 0 {
			return "", nil
		}
		pathName, err := getSyscallArgPath(pid, scMap.arg1)
		if err != nil {
			return "", err
		}
		return pathName, nil
	},
	unix.SYS_NEWFSTATAT: func(pid int, scMap *syscallParms) (string, error) {
		path, err := getSyscallArgPath(pid, scMap.arg2)
		if err != nil {
			return "", fmt.Errorf("NEWFSTAT: %w", err)
		}
		if !filepath.IsAbs(path) {
			dirfd := *(*int32)(unsafe.Pointer(&scMap.arg1))
			if dirfd == unix.AT_FDCWD {
				wd, err := os.Getwd()
				if err != nil {
					return "", nil
				}
				path = filepath.Join(wd, path)
			} else {
				dirfdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
				if err != nil {
					return "", err
				}
				path = filepath.Join(dirfdPath, path)
			}
		}
		return filepath.Clean(path), nil
	},
	unix.SYS_OPENAT: func(pid int, scMap *syscallParms) (string, error) {
		path, err := getSyscallArgPath(pid, scMap.arg2)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) {
			dirfd := *(*int32)(unsafe.Pointer(&scMap.arg1))
			if dirfd == unix.AT_FDCWD {
				cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
				if err != nil {
					return "", err
				}
				path = filepath.Join(cwd, path)
			} else {
				dirfdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
				if err != nil {
					return "", err
				}
				path = filepath.Join(dirfdPath, path)
			}
		}
		return filepath.Clean(path), nil
	},
	unix.SYS_STATFS: func(pid int, scMap *syscallParms) (string, error) {
		pathName, err := getSyscallArgPath(pid, scMap.arg1)
		if err != nil {
			return "", err
		}
		return pathName, nil
	},
}

// ExitError reports an unsuccessful exit by a command.
type ExitError struct {
	*syscall.WaitStatus
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
		if e.WaitStatus.StopSignal() == syscall.SIGTRAP && e.WaitStatus.TrapCause() != 0 {
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

// CmdPtraceFile runs a command using ptrace(2) and tracks which files the command has interacted with.
type CmdPtraceFile struct {
	path string
	args []string
	env  []string
	dir  string
}

// NewCmdPtraceFile creates a new command to be executed. The argument semantics are the same of
// [os/exec.Command()] (for name and args) and [os/exec.Cmd] (env and dir).
func NewCmdPtraceFile(
	name string,
	args []string,
	env []string,
	dir string,
) (*CmdPtraceFile, error) {
	// Dir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(wd, dir)
	}
	dir = filepath.Clean(dir)

	// Path
	var path string
	if filepath.Base(name) == name {
		var err error
		path, err = exec.LookPath(name)
		if err != nil {
			return nil, err
		}
	} else {
		path = name
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	path = filepath.Clean(path)

	// Args
	args = append([]string{name}, args...)

	// Env
	if env == nil {
		env = os.Environ()
	}
	pwdFound := false
	for i, e := range env {
		if strings.HasPrefix(e, "PWD=") {
			env[i] = "PWD=" + dir
			pwdFound = true
			break
		}
	}
	if !pwdFound {
		env = append(env, "PWD="+dir)
	}
	sort.Strings(env)

	return &CmdPtraceFile{
		path: path,
		args: args,
		env:  env,
		dir:  dir,
	}, nil
}

// Run executes the command and traces files it interacted with using ptrace(2). On success, it
// returns a map of such files. On unsuccessful exit, it returns ExitError; it may also return other
// related errors.
func (c *CmdPtraceFile) Run(ctx context.Context) (map[string]bool, error) {
	cmd := &exec.Cmd{
		Path: c.path,
		Args: c.args,
		Env:  c.env,
		Dir:  c.dir,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid

	fileMap := map[string]bool{}
	for {
		var waitStatus syscall.WaitStatus
		var rusage syscall.Rusage
		wpid, err := syscall.Wait4(pid, &waitStatus, 0, &rusage)
		if err != nil {
			return nil, err
		}
		if wpid < 0 {
			return nil, fmt.Errorf("syscall.Wait4 returned wpid < 0: %d", wpid)
		}

		if waitStatus.Exited() {
			if waitStatus.ExitStatus() != 0 {
				return nil, &ExitError{WaitStatus: &waitStatus}
			}
			return fileMap, nil
		}

		if waitStatus.Stopped() {
			signal := waitStatus.StopSignal()
			if signal != syscall.SIGTRAP {
				if err = syscall.PtraceCont(pid, int(signal)); err != nil {
					return nil, err
				}
				continue
			}
		} else {
			return nil, &ExitError{WaitStatus: &waitStatus}
		}

		var ptraceRegs syscall.PtraceRegs
		err = syscall.PtraceGetRegs(pid, &ptraceRegs)
		if err != nil {
			return nil, err
		}

		syscallParms := newSyscallParms(&ptraceRegs)

		if _, ok := ignoreSyscallsMap[syscallParms.syscall]; !ok {
			if fn, ok := fileSyscallFnMap[syscallParms.syscall]; ok {
				file, err := fn(pid, syscallParms)
				if err != nil {
					return nil, err
				}
				fileMap[file] = true
			} else {
				syscallName, ok := syscallToNameMap[syscallParms.syscall]
				if !ok {
					syscallName = fmt.Sprintf("(%d)", syscallParms.syscall)
				}
				return nil, fmt.Errorf("Unknown syscall: %s: %#v", syscallName, syscallParms)
			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return nil, err
		}
	}
}

// Id uniquely identify this command.
func (c *CmdPtraceFile) Id() string {
	return fmt.Sprintf(
		"%s%v%v%s%d%d",
		c.path,
		c.args,
		c.env,
		c.dir,
		syscall.Getuid(),
		syscall.Getgid(),
	)
}
