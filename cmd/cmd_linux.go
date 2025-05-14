package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
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
	unix.SYS_DUP2:              true,
	unix.SYS_DUP3:              true,
	unix.SYS_DUP:               true,
	unix.SYS_FUTEX:             true,
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
	var path [unix.PathMax]byte
	for i := range unix.PathMax {
		buff := [1]byte{}
		count, err := unix.PtracePeekText(pid, uintptr(arg+uint64(i)), buff[:])
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

func ptraceSetOptions(pid int) error {
	return unix.PtraceSetOptions(
		pid,
		unix.PTRACE_O_TRACEEXEC|
			// unix.PTRACE_O_TRACESECCOMP|
			unix.PTRACE_O_TRACESYSGOOD|
			unix.PTRACE_O_EXITKILL|
			unix.PTRACE_O_TRACECLONE|
			unix.PTRACE_O_TRACEFORK|
			unix.PTRACE_O_TRACEVFORK,
	)
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
	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	fmt.Printf("pid: %d\n", pid)

	// https://github.com/u-root/u-root/blob/eadd8c6fee2e915e8f331b1c532be4ac98ba2a05/pkg/strace/tracer.go#L185
	var waitStatus unix.WaitStatus
	_, err := unix.Wait4(pid, &waitStatus, 0, nil)
	if err != nil {
		return nil, err
	}

	if err := ptraceSetOptions(pid); err != nil {
		return nil, err
	}

	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return nil, err
	}

	fileMap := map[string]bool{}
	for {
		fmt.Printf("loop\n")
		wpid, err := unix.Wait4(-1, &waitStatus, 0, nil)
		if err != nil {
			return nil, err
		}
		if wpid == pid {
			fmt.Printf("  wpid: %d (parent)\n", wpid)
		} else {
			fmt.Printf("  wpid: %d (child)\n", wpid)
		}
		if wpid < 0 {
			return nil, fmt.Errorf("syscall.Wait4 returned wpid < 0: %d", wpid)
		}

		if waitStatus.Exited() {
			fmt.Printf("  Exitted\n")
			if wpid == pid {
				if waitStatus.ExitStatus() != 0 {
					fmt.Printf("    ExitStatus != 0\n")
					return nil, &ExitError{WaitStatus: &waitStatus}
				}
				fmt.Printf("  DONE!\n")
				return fileMap, nil
			} else {
				continue
			}
		} else if waitStatus.Stopped() {
			// FIXME this logic should properly cater for children
			signal := waitStatus.StopSignal()
			fmt.Printf("  Stopped (signal %s)\n", signal)
			switch signal := waitStatus.StopSignal(); signal {
			case unix.SIGTRAP | 0x80:
				fmt.Printf("    Trace\n")
			case unix.SIGTRAP:
				fmt.Printf("      SIGTRAP\n")
				switch tc := waitStatus.TrapCause(); tc {
				// case unix.PTRACE_EVENT_EXEC:
				// 	fmt.Printf("        PTRACE_EVENT_EXEC\n")
				// 	formerThreadId, err := unix.PtraceGetEventMsg(wpid)
				// 	if err != nil {
				// 		return nil, err
				// 	}
				// 	fmt.Printf("          formerThreadId %d\n", formerThreadId)

				case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
					fmt.Printf("        Child\n")
					childPid, err := unix.PtraceGetEventMsg(wpid)
					if err != nil {
						return nil, err
					}
					fmt.Printf("          PID %d\n", childPid)
					if err := ptraceSetOptions(int(childPid)); err != nil {
						return nil, err
					}
				default:
					fmt.Printf("      PtraceCont %d %s\n", wpid, signal)
					if err = unix.PtraceCont(wpid, int(signal)); err != nil {
						return nil, err
					}
					continue
				}
			case unix.SIGSTOP:
				fmt.Printf("      SIGSTOP\n")

			default:
				fmt.Printf("      PtraceCont %d %s\n", wpid, signal)
				if err = unix.PtraceCont(wpid, int(signal)); err != nil {
					return nil, err
				}
				continue
			}
		} else {
			return nil, &ExitError{WaitStatus: &waitStatus}
		}

		var ptraceRegs unix.PtraceRegs
		err = unix.PtraceGetRegs(wpid, &ptraceRegs)
		if err != nil {
			fmt.Printf("PtraceGetRegs\n")
			return nil, err
		}

		syscallParms := newSyscallParms(&ptraceRegs)

		syscallName, ok := syscallToNameMap[syscallParms.syscall]
		if !ok {
			syscallName = fmt.Sprintf("(%d)", syscallParms.syscall)
		}
		fmt.Printf("  %s\n", syscallName)

		if _, ok := ignoreSyscallsMap[syscallParms.syscall]; !ok {
			if fn, ok := fileSyscallFnMap[syscallParms.syscall]; ok {
				file, err := fn(wpid, syscallParms)
				if err != nil {
					fmt.Printf("fn\n")
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

		err = unix.PtraceSyscall(wpid, 0)
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
		unix.Getuid(),
		unix.Getgid(),
	)
}
