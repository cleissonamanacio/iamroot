package audit

import (
	"fmt"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/version"
)

type cveEntry struct {
	id, desc string
	lo, hi   string
	poc      string
}

var table = []cveEntry{
	{"CVE-2009-2692", "sock_sendpage NULL deref", "2.6.0", "2.6.31", "Localroot-ALL-CVE"},
	{"CVE-2016-5195", "Dirty COW (COW race)", "2.6.22", "4.8.3", "dirtycow"},
	{"CVE-2017-1000112", "UDP UFO heap overflow", "4.4.0", "4.13", "Localroot-ALL-CVE"},
	{"CVE-2017-16995", "eBPF verifier 32/64 ALU bypass", "4.4.0", "4.14.8", "ebpf_16995"},
	{"CVE-2019-13272", "ptrace_traceme cred misuse", "4.0", "5.1.17", "Localroot-ALL-CVE"},
	{"CVE-2020-8835", "eBPF ALU32 bounds tracking", "5.0", "5.5.19", "Localroot-ALL-CVE"},
	{"CVE-2021-22555", "netfilter IPT_SO_SET_REPLACE OOB", "5.0", "5.12", "Localroot-ALL-CVE"},
	{"CVE-2021-3493", "OverlayFS user-namespace LPE (Ubuntu)", "5.4.0-0", "5.4.0-72", "overlayfs_lpe"},
	{"CVE-2021-4034", "PwnKit — polkit pkexec env hijack", "0", "999", "pwnkit (userspace)"},
	{"CVE-2021-3156", "Baron Samedit — sudo heap overflow", "0", "999", "baron_samedit (userspace)"},
	{"CVE-2022-0847", "Dirty Pipe — pipe page-cache write", "5.8.0", "5.16.11", "dirtypipe"},
	{"CVE-2022-1015", "nf_tables OOB write", "5.0", "5.16.11", "netfilter_oob"},
	{"CVE-2022-2588", "route4 change double free", "5.0", "5.19", "Localroot-ALL-CVE"},
	{"CVE-2023-0386", "OverlayFS SUID copy-up via FUSE", "5.11", "6.2", "overlayfs_cve2023"},
	{"CVE-2023-2640", "Ubuntu OverlayFS trivial LPE", "5.0", "6.2", "gameover_overlay"},
	{"CVE-2023-32233", "nf_tables anonymous set UAF", "6.0", "6.3.1", "nftables_anon"},
	{"CVE-2023-4911", "Looney Tunables — glibc GLIBC_TUNABLES", "0", "999", "looney_tunables (userspace)"},
	{"CVE-2024-1086", "nf_tables UAF (tag/values)", "5.14", "6.6", "nftables_uaf"},
	{"CVE-2025-37899", "ksmbd use-after-free", "5.15", "6.12", "ksmbd_uaf"},
	{"CVE-2026-31431", "CopyFail — AF_ALG authencesn page-cache write", "5.0", "7.1", "copyfail"},
	{"CVE-2026-43284", "DirtyFrag — xfrm-ESP page-cache write (stage 1)", "5.0", "7.1", "dirty_frag"},
	{"CVE-2026-46300", "Fragnesia — xfrm ESP-in-TCP coalesce page-cache", "5.0", "7.1", "fragnesia"},
	{"CVE-2026-46331", "PeditCow — act_pedit OOB page-cache write", "5.0", "7.1", "pedit_cow"},
	{"CVE-2026-43503", "DirtyClone — xfrm ESN clone page-cache write", "5.0", "7.1", "dirty_clone"},
}

func Suggest() {
	kv := version.ParseKernel(Uname())
	fmt.Printf("\n[*] Exploit suggester — kernel %s\n", kv.Raw)
	fmt.Println(strings.Repeat("─", 64))
	any := false
	for _, e := range table {
		if e.lo == "0" {
			fmt.Printf("  %-16s %-44s  %s\n", e.id, e.desc, e.poc)
			any = true
			continue
		}
		lo := version.ParseKernel(e.lo)
		hi := version.ParseKernel(e.hi)
		if kv.GE(lo) && kv.LT(hi) {
			fmt.Printf("  %-16s %-44s  %s\n", e.id, e.desc, e.poc)
			any = true
		}
	}
	if !any {
		fmt.Println("  no kernel CVE matches for this version.")
	}
	fmt.Println(strings.Repeat("─", 64))
	fmt.Printf("[*] Advisory only — see modules for active attempts.\n\n")
}
