//go:build linux

package sysutil

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func Detach(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
}

func FileOwnerUID(path string) (int, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return int(st.Uid), true
}

func Isatty(fd int) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&t)), 0, 0, 0,
	)
	return errno == 0
}

func SetFullRoot() bool {
	if err := syscall.Setresgid(0, 0, 0); err != nil {
		return false
	}
	return syscall.Setresuid(0, 0, 0) == nil
}

func Setsid() { _, _ = syscall.Setsid() }
