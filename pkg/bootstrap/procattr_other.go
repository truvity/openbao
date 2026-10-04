//go:build !linux

package bootstrap

import "syscall"

// forwardProcAttr keeps the terminal's SIGINT away from the forward (its own
// process group). Without a parent-death signal on this OS, a SIGKILL of the
// caller leaves the forward running: stop it by hand (kill the kubectl
// port-forward process).
func forwardProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// wantedPdeathsig is -1: there is no parent-death signal here.
const wantedPdeathsig = -1

func pdeathsig() int { return -1 }
