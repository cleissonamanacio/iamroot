package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/version"
)

func Uname() string {
	out, _ := exec.Command("uname", "-r").Output()
	return strings.TrimSpace(string(out))
}

func CanRunAudit() bool {
	for _, sh := range []string{"bash", "sh"} {
		if _, err := exec.LookPath(sh); err == nil {
			return true
		}
	}
	return false
}

func Run(complete bool) *AuditFindings {
	a := &AuditFindings{KernelVersion: Uname()}

	collectors := []func(a *AuditFindings) []Finding{
		collectKernelEnv,
		collectHardening,
		collectSuid,
		collectSudo,
		collectCapabilities,
		collectSensitiveFiles,
		collectGroups,
		collectLSM,
		collectKsmbd,
	}
	results := make([][]Finding, len(collectors))
	done := make(chan struct{})
	for i, c := range collectors {
		go func(i int, c func(*AuditFindings) []Finding) {
			results[i] = c(a)
			done <- struct{}{}
		}(i, c)
	}
	for range collectors {
		<-done
	}
	for _, r := range results {
		a.Findings = append(a.Findings, r...)
	}
	return a
}

func f(sev Severity, cat, title, detail string, w int) Finding {
	return Finding{Severity: sev, Category: cat, Title: title, Detail: detail, Weight: w}
}

func collectKernelEnv(a *AuditFindings) []Finding {
	var out []Finding
	if _, err := os.Stat("/.dockerenv"); err == nil {
		out = append(out, f(SevWarning, "env", "Inside a Docker container",
			"/.dockerenv present — PrivEsc requires a container escape", 20))
	}
	if pv, err := os.ReadFile("/proc/version"); err == nil {
		kv := version.ParseKernel(a.KernelVersion)
		if kv.Major <= 4 || kv.Major == 3 {
			out = append(out, f(SevWarning, "kernel", "Outdated kernel",
				strings.TrimSpace(string(pv)), 25))
		}
	}
	return out
}

func collectHardening(a *AuditFindings) []Finding {
	var out []Finding

	if cmdline, err := os.ReadFile("/proc/cmdline"); err == nil {
		if strings.Contains(string(cmdline), "nokaslr") {
			out = append(out, f(SevWarning, "hardening", "KASLR disabled",
				"nokaslr on kernel command line — predictable base address", 10))
		}
	}

	cpuinfo, _ := os.ReadFile("/proc/cpuinfo")
	flags := ""
	for _, line := range strings.Split(string(cpuinfo), "\n") {
		if strings.HasPrefix(line, "flags") {
			flags = line
			break
		}
	}
	if !strings.Contains(flags, " smep") {
		out = append(out, f(SevWarning, "hardening", "SMEP absent", "", 8))
	}
	if !strings.Contains(flags, " smap") {
		out = append(out, f(SevWarning, "hardening", "SMAP absent", "", 8))
	}
	if melt, err := os.ReadFile("/sys/devices/system/cpu/vulnerabilities/meltdown"); err == nil {
		m := strings.ToLower(strings.TrimSpace(string(melt)))
		if !strings.Contains(m, "mitigation") && !strings.Contains(m, "not affected") {
			out = append(out, f(SevWarning, "hardening", "PTI not active", string(melt), 8))
		}
	}
	return out
}

func collectSuid(a *AuditFindings) []Finding {
	var out []Finding
	dangerous := map[string]bool{
		"find": true, "bash": true, "cp": true, "vim": true, "nmap": true,
		"python": true, "python3": true, "php": true, "env": true, "chattr": true,
		"perl": true, "ruby": true, "less": true, "more": true, "awk": true,
		"tar": true, "zip": true, "chmod": true, "dd": true, "tee": true,
	}
	for _, dir := range []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSetuid == 0 {
				continue
			}
			name := e.Name()
			if name == "pkexec" {
				a.SuidPkexec = true
				out = append(out, f(SevCritical, "suid", "SUID pkexec present",
					filepath.Join(dir, name)+" — PwnKit (CVE-2021-4034) candidate", 30))
			}
			if dangerous[name] {
				out = append(out, f(SevCritical, "suid", "Dangerous SUID binary",
					filepath.Join(dir, name)+" — instant root via GTFOBins", 30))
			}
		}
	}
	return out
}

func collectSudo(a *AuditFindings) []Finding {
	var out []Finding
	if v, err := exec.Command("sudo", "-V").Output(); err == nil {
		line := strings.SplitN(string(v), "\n", 2)[0]
		a.SudoVersion = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "sudo version "))
		a.SudoVersion = firstToken(a.SudoVersion)
		sv := version.Parse(a.SudoVersion)
		if sv.AtLeast([]int{1, 8, 2}) && sv.Less([]int{1, 9, 6}) {
			out = append(out, f(SevWarning, "sudo", "sudo in Baron Samedit range",
				a.SudoVersion+" (CVE-2021-3156)", 20))
		}
	}

	if out2, err := exec.Command("sudo", "-n", "-l").Output(); err == nil {
		for _, line := range strings.Split(string(out2), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "NOPASSWD:") {
				fields := strings.Fields(line)
				bin := ""
				if len(fields) > 0 {
					bin = fields[len(fields)-1]
				}
				a.NopasswdBinaries = append(a.NopasswdBinaries, bin)
				out = append(out, f(SevCritical, "sudo", "NOPASSWD sudo rule", line, 30))
			}
		}
	}
	return out
}

func collectCapabilities(a *AuditFindings) []Finding {
	var out []Finding
	interesting := []string{"cap_setuid", "cap_dac_override", "cap_chown",
		"cap_setgid", "cap_sys_admin", "cap_fowner"}

	cmd := exec.Command("sh", "-c", "timeout 15 getcap -r / 2>/dev/null || true")
	res, _ := cmd.Output()
	for _, line := range strings.Split(string(res), "\n") {
		lower := strings.ToLower(line)
		for _, cap := range interesting {
			if strings.Contains(lower, cap) {
				a.DangerousCaps = append(a.DangerousCaps, strings.TrimSpace(line))
				out = append(out, f(SevCritical, "caps", "Dangerous capability",
					strings.TrimSpace(line), 25))
				break
			}
		}
	}
	return out
}

func collectSensitiveFiles(a *AuditFindings) []Finding {
	var out []Finding

	if fi, err := os.Stat("/etc/passwd"); err == nil {
		if fi.Mode()&0o002 != 0 {
			a.WritablePasswd = true
			out = append(out, f(SevCritical, "files", "/etc/passwd world-writable",
				"UID-0 injection possible", 35))
		}
	}
	if shadow, err := os.ReadFile("/etc/shadow"); err == nil && len(shadow) > 0 {
		out = append(out, f(SevCritical, "files", "/etc/shadow readable",
			"root hash extractable for offline cracking", 30))
	}
	return out
}

func collectGroups(a *AuditFindings) []Finding {
	var out []Finding
	groups := strings.Fields(execFirst("id -nG 2>/dev/null"))
	for _, g := range groups {
		switch g {
		case "docker":
			a.InDockerGroup = true
			out = append(out, f(SevCritical, "group", "Member of docker group",
				"trivial host root via docker socket", 35))
		case "lxd", "lxc":
			a.InLxdGroup = true
			out = append(out, f(SevCritical, "group", "Member of lxd/lxc group",
				"privileged container escape", 35))
		}
	}
	return out
}

func collectLSM(a *AuditFindings) []Finding {
	var out []Finding
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		a.SelinuxEnforcing = strings.TrimSpace(string(data)) == "1"
	}
	if _, err := os.Stat("/sys/kernel/security/apparmor/profiles"); err == nil {
		a.ApparmorEnforcing = true
	}
	return out
}

func collectKsmbd(a *AuditFindings) []Finding {
	if mods, err := os.ReadFile("/proc/modules"); err == nil &&
		strings.Contains(string(mods), "ksmbd") {
		a.KsmbdLoaded = true
	}
	if _, err := os.Stat("/sys/module/ksmbd"); err == nil {
		a.KsmbdLoaded = true
	}
	return nil
}

func execFirst(script string) string {
	out, _ := exec.Command("sh", "-c", script).Output()
	return strings.TrimSpace(string(out))
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
