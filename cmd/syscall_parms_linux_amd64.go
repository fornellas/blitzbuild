package cmd

import "syscall"

func newSyscallParms(ptraceRegs *syscall.PtraceRegs) *syscallParms {
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
	}
}
