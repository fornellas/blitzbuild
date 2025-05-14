package cmd

import "golang.org/x/sys/unix"

func newSyscallParms(ptraceRegs *unix.PtraceRegs) *syscallParms {
	return &syscallParms{
		// TODO validate what Gemini said here, unsure how to map registers from Regs[] to
		// the names from syscall(2)
		syscall: ptraceRegs.Regs[8], // w8
		arg1:    ptraceRegs.Regs[0], // x0
		arg2:    ptraceRegs.Regs[1], // x1
		arg3:    ptraceRegs.Regs[2], // x2
		arg4:    ptraceRegs.Regs[3], // x3
		arg5:    ptraceRegs.Regs[4], // x4
		arg6:    ptraceRegs.Regs[5], // x5
		retVal:  ptraceRegs.Regs[0], // x0
		retVal2: ptraceRegs.Regs[1], // x1
	}
}
