//go:build !linux

package sysutil

import "os/exec"

func Detach(cmd *exec.Cmd) {}

func FileOwnerUID(path string) (int, bool) { return 0, false }

func Isatty(fd int) bool { return false }

func SetFullRoot() bool { return false }

func Setsid() {}
