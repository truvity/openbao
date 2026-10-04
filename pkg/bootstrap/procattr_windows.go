//go:build !unix

package bootstrap

import "syscall"

// forwardProcAttr puts the forward in its own process group, so the
// console's Ctrl-C (CTRL_C_EVENT goes to the caller's group) does not reach
// it. There is no parent-death signal here: a kill of the caller leaves the
// forward running, so stop it by hand (end the kubectl port-forward process).
func forwardProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// wantedPdeathsig is -1: there is no parent-death signal here.
const wantedPdeathsig = -1

func pdeathsig() int { return -1 }
