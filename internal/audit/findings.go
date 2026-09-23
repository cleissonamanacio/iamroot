package audit

import "fmt"

type Severity int

const (
	SevCritical Severity = iota
	SevWarning
	SevPass
	SevInfo
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevWarning:
		return "WARNING"
	case SevPass:
		return "PASS"
	default:
		return "INFO"
	}
}

func ParseSeverity(s string) Severity {
	switch trimUpper(s) {
	case "CRITICAL":
		return SevCritical
	case "WARNING":
		return SevWarning
	case "PASS":
		return SevPass
	default:
		return SevInfo
	}
}

func trimUpper(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, byte(r-32))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		default:
			out = append(out, byte(r))
		}
	}
	return string(out)
}

type Finding struct {
	Severity    Severity
	Category    string
	Title       string
	Detail      string
	Remediation string
	Weight      int
}

type AuditFindings struct {
	Score    int
	Findings []Finding

	NopasswdBinaries  []string
	WritablePasswd    bool
	SuidPkexec        bool
	DangerousCaps     []string
	InDockerGroup     bool
	InLxdGroup        bool
	WritableCronFiles []string
	WritableSvcFiles  []string
	KernelVersion     string
	SudoVersion       string
	PendingCVEs       []string
	ApparmorEnforcing bool
	SelinuxEnforcing  bool
	KsmbdLoaded       bool
}

func (a *AuditFindings) PipelineSummary() {
	fmt.Printf("\n[*] Audit summary — kernel=%s sudo=%s\n", a.KernelVersion, a.SudoVersion)
	flags := []string{}
	if a.WritablePasswd {
		flags = append(flags, "writable /etc/passwd")
	}
	if a.SuidPkexec {
		flags = append(flags, "SUID pkexec")
	}
	if len(a.DangerousCaps) > 0 {
		flags = append(flags, fmt.Sprintf("%d dangerous caps", len(a.DangerousCaps)))
	}
	if a.InDockerGroup {
		flags = append(flags, "docker group")
	}
	if a.InLxdGroup {
		flags = append(flags, "lxd group")
	}
	if len(a.NopasswdBinaries) > 0 {
		flags = append(flags, fmt.Sprintf("%d NOPASSWD sudo entries", len(a.NopasswdBinaries)))
	}
	if a.ApparmorEnforcing {
		flags = append(flags, "AppArmor enforcing")
	}
	if a.SelinuxEnforcing {
		flags = append(flags, "SELinux enforcing")
	}
	if len(flags) == 0 {
		fmt.Println("[*] No high-signal misconfigurations flagged by audit.")
		return
	}
	for _, f := range flags {
		fmt.Printf("    • %s\n", f)
	}
}
