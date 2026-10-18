# iamroot — Linux Privilege Escalation Framework (Go + Python)

`iamroot` is a Linux local privilege-escalation auditor and exploit pipeline, splitting the work by language strength:

- **Go** — orchestrator. One statically-linked binary; goroutines drive the
  concurrent audit collectors and the exploit-scan fan-out (no sequential module scanning).
- **Python** — exploit implementations. `ctypes` syscalls (DirtyPipe splice),
  `struct` ELF packing, `re` credential harvesting, `urllib` HTTP (DirtySock
  snapd). The helpers are embedded into the Go binary via `go:embed` and written
  to a tmpfs workdir at runtime.

The result is a single ~6 MB Linux ELF with no target-side dependencies beyond
the target's own `python3` (and optionally `gcc` for compile-dependent CVEs).

---

## Quick Start

### Install on a target (one-liner)

From a GitHub release (works once the repo is published — see *Distribution*):

```bash
bash -c "$(curl -fsSL https://iamroot.victorsec.com/install)"
```

Self-hosters: build from this repo and serve it anywhere — point
`IAMROOT_BASE` at your mirror (see `scripts/install.sh`).

The installer detects the architecture (amd64/arm64), downloads the right
static ELF, verifies it against `SHA256SUMS` when available, and makes it
executable, then runs it. `IAMROOT_BASE` overrides the download source;
`IAMROOT_ARGS` passes flags; `IAMROOT_INSTALL_ONLY=1` installs without running.

### Manual

```bash
# On the build host (macOS or Linux) — cross-compile
make all                      # → dist/iamroot-linux-amd64 + -arm64 + SHA256SUMS

# Upload to target
scp dist/iamroot-linux-amd64 user@target:/dev/shm/iamroot
ssh user@target "chmod +x /dev/shm/iamroot"

# Run on target
/dev/shm/iamroot
```

No target-side build step. The Python helpers ride inside the binary.

---

## Usage

```
iamroot [--complete] [--harvest] [--skip-audit] [--suggest] [--persist] [--list] [--selftest-py]
```

| Flag | Description |
|---|---|
| *(none)* | Concurrent audit + two-pass exploit pipeline (no persistence) |
| `--complete` | Full audit then the pipeline |
| `--harvest` | Credential harvest from web/app configs only |
| `--skip-audit` | Skip Phase 1 audit, go straight to exploits |
| `--suggest` | Exploit suggester: match kernel→CVE (advisory, no execution) |
| `--persist` | Also write a backdoor UID-0 user after a successful exploit |
| `--list` | Dry-run: scan + rank modules, no exploitation |
| `--selftest-py` | Extract embedded Python helpers and run each `--selftest` |

### Auth gate (opt-in)

By default iamroot runs open (research mode). To require a password, set:

```
IAMROOT_PASS_HASH=$(printf %s 'yourpass' | sha256sum | cut -d' ' -f1)
IAMROOT_PASS=yourpass /dev/shm/iamroot
```

---

## How It Works

### Phase 1 — Audit (concurrent)

Each collector runs in its own goroutine and owns a disjoint slice of the
`AuditFindings` struct: kernel/env, hardening (KASLR/SMEP/SMAP/PTI/SELinux/
AppArmor), SUID hunt, sudo version + privileges, capabilities, sensitive-file
perms, group membership (docker/lxd), LSM state, ksmbd. The merged findings feed
every module's `CheckVulnerable` so detection reuses cheap facts.

`--suggest` additionally matches the kernel version against a curated CVE table.

### Phase 1b/1c — Loot + build deps

Passive credential gathering (shell history, `/etc/shadow` unshadow) deposits
passwords into the global cred store, consumed by `SudoPasswdSpray`. If no C
compiler is present, iamroot attempts a silent `apt`/`dnf` install of `gcc` and
`linux-headers-$(uname -r)`.

### Phase 2 — Exploit Pipeline

**Pass 1 — instant misconfigurations** (ordered, first-match wins):
`PasswdInject`, `SuidGtfobins`, `RootGroupAbuse`, `SshKeyInject`, `WwsuidOverwrite`.

**Pass 2 — concurrent scan + confidence-ordered run**: every module's
`CheckVulnerable` is fanned out across goroutines; viable modules are sorted by
confidence DESC (tie-break: base priority ASC) and run sequentially. The first
`Run()` that returns true stops the pipeline.

Every `VULNERABLE` line is annotated with a CVE+NVD URL (parsed from the module
name) or a MITRE ATT&CK TTP for non-CVE techniques.

---

## Module tiers

| Tier | Meaning | Examples |
|---|---|---|
| **A** | Fully working, Go-native (misconfig/config checks) | PasswdInject, SuidGtfobins, SshKeyInject, NopasswdSudo, CapabilityAbuse, DockerEscape, LxdEscape, WritableCron/Service/Timer/Path, NfsNosquash, MysqlUdf, EnlightenmentSuid, … |
| **B** | Fully working, Python via `pylib` | DirtyPipe (ctypes splice), DirtySock (snapd REST), CopyFail (AF_ALG), CredentialHarvest |
| **C** | Kernel CVE exploits — attempted when a payload is available (gcc or an uploaded pre-built binary) | PwnKit, BaronSamedit, DirtyCow, OverlayFS, nf_tables, LooneyTunables, eBPF, and the 2023–2026 page-cache family, … |
| **D** | Advisory only (no execution) | the `--suggest` kernel→CVE scanner |

### Pre-built payloads (Tier C)

Tier-C modules prefer a pre-built payload binary. Upload one to the
work dir and it is detected automatically:

```bash
mkdir -p /dev/shm/nftables_uaf
scp nftables_exploit user@target:/dev/shm/nftables_uaf/exploit
```

Without a payload (and without gcc), a Tier-C module prints the expected upload
path and returns false so the pipeline continues.

