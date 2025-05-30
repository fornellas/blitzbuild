package cmd

import "golang.org/x/sys/unix"

func newSyscallParms(ptraceRegs *unix.PtraceRegs) (*syscallParms, bool) {
	if ptraceRegs.Orig_rax == ^uint64(0) {
		return nil, false
	}
	return &syscallParms{
		syscall: ptraceRegs.Orig_rax,
		arg1:    ptraceRegs.Rdi,
		arg2:    ptraceRegs.Rsi,
		arg3:    ptraceRegs.Rdx,
		arg4:    ptraceRegs.R10,
		arg5:    ptraceRegs.R8,
		arg6:    ptraceRegs.R9,
		retVal:  ptraceRegs.Rax,
		retVal2: ptraceRegs.Rdx,
	}, true
}
