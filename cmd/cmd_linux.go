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
	unix.SYS_ACCEPT:            true,
	unix.SYS_ACCEPT4:           true,
	unix.SYS_ADJTIMEX:          true,
	unix.SYS_ALARM:             true,
	unix.SYS_BIND:              true,
	unix.SYS_BPF:               true,
	unix.SYS_BRK:               true,
	unix.SYS_CAPGET:            true,
	unix.SYS_CAPSET:            true,
	unix.SYS_CLOCK_ADJTIME:     true,
	unix.SYS_CLOCK_GETRES:      true,
	unix.SYS_CLOCK_GETTIME:     true,
	unix.SYS_CLOCK_NANOSLEEP:   true,
	unix.SYS_CLOCK_SETTIME:     true,
	unix.SYS_CLONE3:            true,
	unix.SYS_CLONE:             true,
	unix.SYS_CLOSE:             true,
	unix.SYS_CONNECT:           true,
	unix.SYS_COPY_FILE_RANGE:   true,
	unix.SYS_DUP2:              true,
	unix.SYS_DUP3:              true,
	unix.SYS_DUP:               true,
	unix.SYS_EPOLL_CREATE1:     true,
	unix.SYS_EPOLL_CREATE:      true,
	unix.SYS_EPOLL_CTL:         true,
	unix.SYS_EPOLL_CTL_OLD:     true,
	unix.SYS_EPOLL_PWAIT2:      true,
	unix.SYS_EPOLL_PWAIT:       true,
	unix.SYS_EPOLL_WAIT:        true,
	unix.SYS_EPOLL_WAIT_OLD:    true,
	unix.SYS_EVENTFD2:          true,
	unix.SYS_EVENTFD:           true,
	unix.SYS_EXIT:              true,
	unix.SYS_EXIT_GROUP:        true,
	unix.SYS_FADVISE64:         true,
	unix.SYS_FALLOCATE:         true,
	unix.SYS_FCHDIR:            true,
	unix.SYS_FCHMOD:            true,
	unix.SYS_FCHOWN:            true,
	unix.SYS_FCNTL:             true,
	unix.SYS_FDATASYNC:         true,
	unix.SYS_FLOCK:             true,
	unix.SYS_FORK:              true,
	unix.SYS_FSTAT:             true,
	unix.SYS_FSTATFS:           true,
	unix.SYS_FSYNC:             true,
	unix.SYS_FTRUNCATE:         true,
	unix.SYS_FUTEX:             true,
	unix.SYS_FUTEX_REQUEUE:     true,
	unix.SYS_FUTEX_WAIT:        true,
	unix.SYS_FUTEX_WAITV:       true,
	unix.SYS_FUTEX_WAKE:        true,
	unix.SYS_GETCWD:            true,
	unix.SYS_GETDENTS64:        true,
	unix.SYS_GETDENTS:          true,
	unix.SYS_GETEGID:           true,
	unix.SYS_GETEUID:           true,
	unix.SYS_GETGID:            true,
	unix.SYS_GETGROUPS:         true,
	unix.SYS_GETITIMER:         true,
	unix.SYS_GETPEERNAME:       true,
	unix.SYS_GETPGID:           true,
	unix.SYS_GETPGRP:           true,
	unix.SYS_GETPID:            true,
	unix.SYS_GETPPID:           true,
	unix.SYS_GETRANDOM:         true,
	unix.SYS_GETRESGID:         true,
	unix.SYS_GETRESUID:         true,
	unix.SYS_GETRLIMIT:         true,
	unix.SYS_GETRUSAGE:         true,
	unix.SYS_GETSID:            true,
	unix.SYS_GETSOCKNAME:       true,
	unix.SYS_GETSOCKOPT:        true,
	unix.SYS_GETTID:            true,
	unix.SYS_GETTIMEOFDAY:      true,
	unix.SYS_GETUID:            true,
	unix.SYS_IOCTL:             true,
	unix.SYS_KILL:              true,
	unix.SYS_LISTEN:            true,
	unix.SYS_LSEEK:             true,
	unix.SYS_MADVISE:           true,
	unix.SYS_MINCORE:           true,
	unix.SYS_MMAP:              true,
	unix.SYS_MPROTECT:          true,
	unix.SYS_MREMAP:            true,
	unix.SYS_MSGCTL:            true,
	unix.SYS_MSGGET:            true,
	unix.SYS_MSGRCV:            true,
	unix.SYS_MSGSND:            true,
	unix.SYS_MSYNC:             true,
	unix.SYS_MUNMAP:            true,
	unix.SYS_NANOSLEEP:         true,
	unix.SYS_PAUSE:             true,
	unix.SYS_PIDFD_OPEN:        true,
	unix.SYS_PIDFD_SEND_SIGNAL: true,
	unix.SYS_PIPE2:             true,
	unix.SYS_PIPE:              true,
	unix.SYS_POLL:              true,
	unix.SYS_PREAD64:           true,
	unix.SYS_PRLIMIT64:         true,
	unix.SYS_PTRACE:            true,
	unix.SYS_PWRITE64:          true,
	unix.SYS_READ:              true,
	unix.SYS_READV:             true,
	unix.SYS_RECVFROM:          true,
	unix.SYS_RECVMSG:           true,
	unix.SYS_RESTART_SYSCALL:   true,
	unix.SYS_RSEQ:              true,
	unix.SYS_RT_SIGACTION:      true,
	unix.SYS_RT_SIGPENDING:     true,
	unix.SYS_RT_SIGPROCMASK:    true,
	unix.SYS_RT_SIGQUEUEINFO:   true,
	unix.SYS_RT_SIGRETURN:      true,
	unix.SYS_RT_SIGSUSPEND:     true,
	unix.SYS_RT_SIGTIMEDWAIT:   true,
	unix.SYS_SCHED_GETAFFINITY: true,
	unix.SYS_SCHED_SETAFFINITY: true,
	unix.SYS_SCHED_YIELD:       true,
	unix.SYS_SELECT:            true,
	unix.SYS_SEMCTL:            true,
	unix.SYS_SEMGET:            true,
	unix.SYS_SEMOP:             true,
	unix.SYS_SENDFILE:          true,
	unix.SYS_SENDMSG:           true,
	unix.SYS_SENDTO:            true,
	unix.SYS_SETFSGID:          true,
	unix.SYS_SETFSUID:          true,
	unix.SYS_SETGID:            true,
	unix.SYS_SETGROUPS:         true,
	unix.SYS_SETITIMER:         true,
	unix.SYS_SETPGID:           true,
	unix.SYS_SETREGID:          true,
	unix.SYS_SETRESGID:         true,
	unix.SYS_SETRESUID:         true,
	unix.SYS_SETREUID:          true,
	unix.SYS_SETRLIMIT:         true,
	unix.SYS_SETSID:            true,
	unix.SYS_SETSOCKOPT:        true,
	unix.SYS_SETTIMEOFDAY:      true,
	unix.SYS_SETUID:            true,
	unix.SYS_SET_ROBUST_LIST:   true,
	unix.SYS_SET_TID_ADDRESS:   true,
	unix.SYS_SHMAT:             true,
	unix.SYS_SHMCTL:            true,
	unix.SYS_SHMDT:             true,
	unix.SYS_SHMGET:            true,
	unix.SYS_SHUTDOWN:          true,
	unix.SYS_SIGALTSTACK:       true,
	unix.SYS_SOCKET:            true,
	unix.SYS_SOCKETPAIR:        true,
	unix.SYS_SYSINFO:           true,
	unix.SYS_SYSLOG:            true,
	unix.SYS_TGKILL:            true,
	unix.SYS_TIME:              true,
	unix.SYS_TIMER_CREATE:      true,
	unix.SYS_TIMER_DELETE:      true,
	unix.SYS_TIMER_GETOVERRUN:  true,
	unix.SYS_TIMER_GETTIME:     true,
	unix.SYS_TIMER_SETTIME:     true,
	unix.SYS_TIMES:             true,
	unix.SYS_UNAME:             true,
	unix.SYS_VFORK:             true,
	unix.SYS_WAIT4:             true,
	unix.SYS_WAITID:            true,
	unix.SYS_WRITE:             true,
	unix.SYS_WRITEV:            true,
	unix.SYS_UMASK:             true,
}

func getSyscallArgPath(pid int, arg uint64) (string, error) {
	if arg == 0 {
		return "", nil
	}
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

func getSyscallPath(pid int, scParms *syscallParms) ([]string, error) {
	path, err := getSyscallArgPath(pid, scParms.arg1)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return nil, err
		}
		path = filepath.Join(cwd, path)
	}
	return []string{filepath.Clean(path)}, nil
}

func getSyscallDirfdPath(pid int, scParms *syscallParms) ([]string, error) {
	path, err := getSyscallArgPath(pid, scParms.arg2)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		dirfd := *(*int32)(unsafe.Pointer(&scParms.arg1))
		if dirfd == unix.AT_FDCWD {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if err != nil {
				return nil, err
			}
			path = filepath.Join(cwd, path)
		} else {
			dirfdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
			if err != nil {
				return nil, err
			}
			path = filepath.Join(dirfdPath, path)
		}
	}
	return []string{filepath.Clean(path)}, nil
}

// fileSyscallFnMap maps filesystem related syscalls to functions that extract the file path from
// it.
var fileSyscallFnMap = map[uint64]func(int, *syscallParms) ([]string, error){
	unix.SYS_CHDIR:      getSyscallPath,
	unix.SYS_EXECVE:     getSyscallPath,
	unix.SYS_FACCESSAT2: getSyscallDirfdPath,
	unix.SYS_FCHMODAT:   getSyscallDirfdPath,
	unix.SYS_FCHOWNAT:   getSyscallDirfdPath,
	unix.SYS_FTRUNCATE:  getSyscallPath,
	unix.SYS_MKDIR:      getSyscallPath,
	unix.SYS_MKDIRAT:    getSyscallDirfdPath,
	unix.SYS_MKNODAT:    getSyscallDirfdPath,
	unix.SYS_NEWFSTATAT: getSyscallDirfdPath,
	unix.SYS_OPEN:       getSyscallPath,
	unix.SYS_OPENAT:     getSyscallDirfdPath,
	unix.SYS_READLINK:   getSyscallPath,
	unix.SYS_READLINKAT: getSyscallDirfdPath,
	unix.SYS_RENAME: func(pid int, scParms *syscallParms) ([]string, error) {
		path1, err := getSyscallArgPath(pid, scParms.arg1)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(path1) {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if err != nil {
				return nil, err
			}
			path1 = filepath.Join(cwd, path1)
		}
		path2, err := getSyscallArgPath(pid, scParms.arg1)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(path1) {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if err != nil {
				return nil, err
			}
			path2 = filepath.Join(cwd, path2)
		}
		return []string{
			filepath.Clean(path1),
			filepath.Clean(path2),
		}, nil
	},
	// unix.SYS_RENAMEAT: ,
	unix.SYS_STATFS: getSyscallPath,
	unix.SYS_STAT:   getSyscallPath,
	unix.SYS_STATX:  getSyscallDirfdPath,
	// unix.SYS_SYMLINKAT: ,
	unix.SYS_UNLINK:    getSyscallPath,
	unix.SYS_UNLINKAT:  getSyscallDirfdPath,
	unix.SYS_UTIMENSAT: getSyscallDirfdPath,
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

	// https://github.com/u-root/u-root/blob/eadd8c6fee2e915e8f331b1c532be4ac98ba2a05/pkg/strace/tracer.go#L185
	var waitStatus unix.WaitStatus
	_, err := unix.Wait4(cmd.Process.Pid, &waitStatus, 0, nil)
	if err != nil {
		return nil, err
	}

	if err := unix.PtraceSetOptions(
		cmd.Process.Pid,
		unix.PTRACE_O_TRACEEXEC|
			unix.PTRACE_O_TRACESYSGOOD|
			unix.PTRACE_O_EXITKILL|
			unix.PTRACE_O_TRACECLONE|
			unix.PTRACE_O_TRACEFORK|
			unix.PTRACE_O_TRACEVFORK,
	); err != nil {
		return nil, err
	}

	if err := unix.PtraceSyscall(cmd.Process.Pid, 0); err != nil {
		return nil, err
	}

	fileMap := map[string]bool{}
	for {
		pid, err := unix.Wait4(-1, &waitStatus, 0, nil)
		if err != nil {
			// TODO do we need this?
			// if err == unix.ECHILD {
			// 	return fileMap, nil
			// }
			return nil, err
		}
		// d := "parent"
		// if pid != cmd.Process.Pid {
		// 	d = "child"
		// }
		// fmt.Printf("PID: %d (%s)\n", pid, d)

		var signal unix.Signal
		if waitStatus.Exited() {
			// fmt.Printf("  Exited\n")
			if pid == cmd.Process.Pid {
				// fmt.Printf("  Parent\n")
				if waitStatus.ExitStatus() != 0 {
					return nil, &ExitError{WaitStatus: &waitStatus}
				}
				return fileMap, nil
			}
			// fmt.Printf("  Child\n")
			continue
		} else if waitStatus.Signaled() {
			// fmt.Printf("  Signaled\n")
			continue
		} else if waitStatus.Stopped() {
			// fmt.Printf("  Stopped\n")
			switch stopSignal := waitStatus.StopSignal(); stopSignal {
			case unix.SIGTRAP | 0x80:
				// fmt.Printf("    SIGTRAP | 0x80\n")
				var ptraceRegs unix.PtraceRegs
				err = unix.PtraceGetRegs(pid, &ptraceRegs)
				if err != nil {
					if errno, ok := err.(syscall.Errno); ok {
						if errno == syscall.ESRCH && pid != cmd.Process.Pid {
							continue
						}
					}
					return nil, err
				}

				syscallParms, ok := newSyscallParms(&ptraceRegs)
				if ok {
					// syscallName, ok := syscallToNameMap[syscallParms.syscall]
					// if !ok {
					// 	syscallName = fmt.Sprintf("(%d)", syscallParms.syscall)
					// }
					// fmt.Printf("      %#v\n", syscallName)
					// fmt.Printf("        %#v\n", syscallParms)
					if _, ok := ignoreSyscallsMap[syscallParms.syscall]; !ok {
						if fn, ok := fileSyscallFnMap[syscallParms.syscall]; ok {
							files, err := fn(pid, syscallParms)
							if err != nil {
								return nil, err
							}
							for _, file := range files {
								if len(file) > 0 {
									// fmt.Printf("        file: %s\n", file)
									fileMap[file] = true
								}
							}
						} else {
							syscallName, ok := syscallToNameMap[syscallParms.syscall]
							if !ok {
								syscallName = fmt.Sprintf("(%d)", syscallParms.syscall)
							}
							return nil, fmt.Errorf("Unknown syscall: %s: %#v", syscallName, syscallParms)
						}
					}
				} else {
					// fmt.Printf("      not a syscall\n")
				}
			case unix.SIGSTOP:
				// fmt.Printf("    SIGSTOP\n")
				fallthrough
			case unix.SIGTSTP, unix.SIGTTOU, unix.SIGTTIN:
				// fmt.Printf("    SIGTSTP, SIGTTOU, SIGTTIN\n")
				signal = stopSignal
			case unix.SIGTRAP:
				// fmt.Printf("    SIGTRAP\n")
				switch tc := waitStatus.TrapCause(); tc {
				case unix.PTRACE_EVENT_EXEC, unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
					// fmt.Printf("      PTRACE_EVENT_EXEC, PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK\n")
					// msgPid, err := unix.PtraceGetEventMsg(pid)
					// if err != nil {
					// 	return nil, err
					// }
					// fmt.Printf("       msgPid: %d\n", msgPid)
				default:
					// fmt.Printf("      default\n")
					signal = stopSignal
				}
			default:
				// fmt.Printf("    default\n")
				signal = stopSignal
			}
		}

		// signalName, ok := signalNameMap[signal]
		// if !ok {
		// 	signalName = fmt.Sprintf("%d", signal)
		// }
		// fmt.Printf("  PtraceSyscall(%d, %s)\n", pid, signalName)
		if err := unix.PtraceSyscall(pid, int(signal)); err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.ESRCH && pid != cmd.Process.Pid {
					continue
				}
			}
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
