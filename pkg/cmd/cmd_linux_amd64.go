package cmd

import "golang.org/x/sys/unix"

func init() {
	ignoreSyscallsMap[unix.SYS_ARCH_PRCTL] = true
	ignoreSyscallsMap[unix.SYS_VFORK] = true

	fileSyscallFnMap[unix.SYS_ACCESS] = getSyscallPath
}
