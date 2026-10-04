//go:build linux

package bootstrap

import (
	"syscall"
	"unsafe"
)

// forwardProcAttr keeps the terminal's SIGINT away from the forward (its own
// process group) and, on Linux, has the kernel SIGTERM it when this process
// dies for any reason, SIGKILL included, so a killed openbaoctl cannot orphan
// a tunnel to the server.
func forwardProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

// wantedPdeathsig is the parent-death signal forwardProcAttr asks for.
const wantedPdeathsig = int(syscall.SIGTERM)

// pdeathsig reads the calling process's parent-death signal.
func pdeathsig() int {
	var sig int32

	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 2, uintptr(unsafe.Pointer(&sig)), 0); errno != 0 {
		return -1
	}

	return int(sig)
}
