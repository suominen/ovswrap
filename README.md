# OVSwrap — Linux kernel Open vSwitch datapath overflow tracking site

Patch-status tracker for **OVSwrap** (**CVE-2026-64531**), a local
privilege escalation in the Linux kernel Open vSwitch (OVS) datapath.
Parsing of nested netlink action attributes in
`net/openvswitch/flow_netlink.c` lacks a per-attribute size check, so a
`CLONE` action holding hundreds of conntrack actions can expand past
65,535 bytes.  The generated attribute's 16-bit `nla_len` wraps, and
later parsing resumes at attacker-controlled offsets inside the conntrack
data — a heap out-of-bounds the PoC turns into kernel-pointer leaks,
kernel-memory reads, and credential corruption for root.  Reaching it
needs the OVS kernel datapath in use, conntrack/FTP-helper support, and
(for an unprivileged trigger) unprivileged user namespaces enabled.
Found and fixed by Asim Manizada, who
[disclosed it on 2026-07-28](https://www.openwall.com/lists/oss-security/2026/07/28/8)
with a [write-up](https://heyitsas.im/posts/ovswrap).
Public PoC: <https://github.com/manizada/OVSwrap>.

Unlike an ancient bug, this is a **recent regression**: the missing check
was removed by `a1e64addf3ff` (*net: openvswitch: remove misbehaving
actions length check*) in **v6.14** (2025-03-13), and fixed in v7.2-rc4 by
[`3f1f75536668`](https://github.com/torvalds/linux/commit/3f1f755366687d051174739fb99f7d560202f60b)
(*net: openvswitch: reject oversized nested action attrs*).  The cap
removal was backported into stable, so a kernel is exposed only at or
above its series' intro point (5.15.180, 6.1.132, 6.6.84, 6.12.20,
6.13.8; mainline 6.14).  Series below that never received the change and
are **not affected**; distro adoption of the fix is tracked below.

**CVE-2026-64531** is assigned; the kernel CNA backported the fix to
5.15.212, 6.1.178, 6.6.145, 6.12.97, 6.18.40, and 7.1.5, but each
distribution has to pick it up.

The rendered site is published at **<https://kimmo.cloud/ovswrap/>**.
Deployment plan and current setup state live in
[`WEBSITE.md`](WEBSITE.md).

## Source of truth

The tracker is a single Hugo page: [`site/content/_index.md`](site/content/_index.md).
Edit that file; everything else is build infrastructure.

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/ovswrap/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/ovswrap/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/ovswrap/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first.  `make banner` is only needed after
editing `site/assets/ovswrap-tracker.svg`; the rendered PNG is committed.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo, go, git, resvg + RPM tools)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`, `make banner`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css   # PaperMod CSS overrides
    ├── assets/ovswrap-tracker.svg       # social-banner source (→ make banner)
    ├── static/ovswrap-tracker.png       # rendered OpenGraph banner (committed)
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
