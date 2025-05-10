package cmd

import "golang.org/x/sys/unix"

func init() {
	ignoreSyscallsMap[unix.SYS_ARCH_PRCTL] = true
	ignoreSyscallsMap[unix.SYS_VFORK] = true

	fileSyscallFnMap[unix.SYS_ACCESS] = func(pid int, scMap *syscallParms) (string, error) {
		pathName, err := getSyscallArgPath(pid, scMap.arg1)
		if err != nil {
			return "", err
		}
		return pathName, nil
	}
}
