---
title: "OVSwrap — Open vSwitch datapath overflow"
description: "Linux kernel Open vSwitch datapath integer/buffer overflow (CVE-2026-64531, OVSwrap) — unprivileged local privilege escalation — distro patch status tracker"
layout: "single"
date: 2026-07-29
lastmod: 2026-08-07
cover:
  image: "ovswrap-tracker.png"
  alt: "OVSwrap — Linux kernel Open vSwitch datapath overflow tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-64531 |
| Alias | `OVSwrap` (the name its [PoC][poc] and [write-up][writeup] use) |
| Component | Kernel: Open vSwitch datapath — nested netlink action-attribute parsing (`net/openvswitch/flow_netlink.c`) |
| Type | Integer overflow → heap out-of-bounds — an oversized nested action stream wraps the 16-bit `nla_len`, so parsing resumes at attacker-controlled offsets |
| Impact | An unprivileged **local** user can escalate to **root** on a host using the OVS kernel datapath with conntrack: the corruption yields kernel-pointer leaks, kernel-memory reads, and credential overwrite. Architecture-independent |
| Upstream fix | [`3f1f75536668`][fix] (*net: openvswitch: reject oversized nested action attrs*); first in **v7.2-rc4** |
| Introduced | [`a1e64addf3ff`][intro] (*net: openvswitch: remove misbehaving actions length check*) in **v6.14** (2025-03-13) |
| Affected window | Mainline **6.14 through 7.1**. The cap removal was backported into stable, so a series is affected only at/above its intro point (5.15.180, 6.1.132, 6.6.84, 6.12.20, 6.13.8); kernels below it — the 5.10 line and older — are **not affected**. Fixed in v7.2-rc4 and the current stable point releases (per-branch *First fixed* below) |
| Discoverer | [Asim Manizada][writeup] (who also authored the upstream fix) |
| Public disclosure | 2026-07-28 ([oss-security][oss]) |
| Public PoC | [manizada/OVSwrap][poc] (ships a BPF mitigation) |
| KEV / EPSS / CVSS | Kernel CNA and NVD: CVSS 3.1 **7.8 HIGH** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, NVD status *Received*); Red Hat revised its rating on 2026-07-31 to **Important**, CVSS 3.1 **7.8 HIGH** (same vector) — up from an initial **Moderate**, CVSS 3.1 **7.0** (`AC:H`) at disclosure; EPSS **0.13%** (percentile ~2.9%, 2026-08-02); not in KEV |
| Reachability | Needs the OVS **kernel datapath** in use, **conntrack/FTP-helper** actions, and — for an unprivileged trigger — **unprivileged user namespaces** enabled |
{.summary}

## How the exploitation chain works

Open vSwitch lets userspace install datapath flows and their **actions**
through a netlink interface. Actions nest: a `CLONE` action wraps a list
of sub-actions, and a conntrack (`ct`) action carries its own nested
attributes. Netlink expresses that nesting with attributes whose length
lives in a **16-bit** `nla_len` field — a hard ceiling of 65,535 bytes per
attribute.

Historically the datapath capped the total generated action stream at
32 KiB, which kept every nested attribute comfortably under the 16-bit
limit. In March 2025 [`a1e64addf3ff`][intro] (*remove misbehaving actions
length check*) deleted that cap because it was rejecting legitimate large
action sets — but nothing replaced the missing per-attribute bound.

An attacker crafts a `CLONE` action holding hundreds of conntrack actions.
When the datapath copies that nested action list, its serialized length
grows past 65,535 bytes and the 16-bit `nla_len` **wraps** to a small
value. Subsequent parsing trusts the wrapped length and **resumes at an
incorrect offset inside the attacker-controlled conntrack data**, reading
and writing structures the length field no longer describes — a heap
out-of-bounds the [PoC][poc] escalates into kernel-pointer leaks,
kernel-memory reads, and credential corruption for root.

> :information_source: Reaching this needs three conditions at once: the
> **OVS kernel datapath** in active use (the `openvswitch` module handling
> flows), **conntrack/FTP-helper** actions in the flow, and — for an
> *unprivileged* trigger — **unprivileged user namespaces** enabled, since
> the OVS netlink API needs `CAP_NET_ADMIN` and a userns grants it inside
> the namespace. Disabling unprivileged userns removes the unprivileged
> path but not a caller that already holds `CAP_NET_ADMIN`. These are
> reachability conditions recorded in prose, **not** verdict columns —
> **only the kernel backport flips a verdict**, and a kernel below its
> series' introducing commit is not affected at all.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`a1e64addf3ff`][intro] | Introduced | *net: openvswitch: remove misbehaving actions length check* (v6.14, 2025-03-13) — removed the 32 KiB cap on generated action streams, leaving no bound to keep a nested action attribute under the 16-bit `nla_len` limit. |
| [`3f1f75536668`][fix] | Fixed | *net: openvswitch: reject oversized nested action attrs* — reinstates a per-attribute size check and rejects action streams that would overflow `nla_len`; first released in **v7.2-rc4**. |

The reachable lifetime runs from **v6.14** through **v7.1**; v7.2-rc4 and
the current stable point releases carry the fix. Because this is a 2025
regression, kernels that never received [`a1e64addf3ff`][intro] are **not
affected** — see *Affected window* above for the per-series boundary.

## Patch status

Two things decide a row: whether its kernel is **in-window** (at or above
its series' intro point — see *Affected window*), and if so whether it
carries the [`3f1f75536668`][fix] backport. The first group is the
upstream kernel; the rest are a focused set of x86-64 distributions, with
per-distribution detail in the sections that follow. *First fixed* and
*Fixed since* stay `—` until a row is fixed.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.2-rc6 | 7.2-rc4 | 2026-07-19 | :white_check_mark: Fixed — carries `3f1f75536668` |
| Linux kernel | 7.1.x | 7.1.7 | 7.1.5 | 2026-07-24 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.43 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.101 | 6.12.97 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.149 | 6.6.145 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.181 | 6.1.178 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.214 | 5.15.212 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.263 | — | — | :heavy_minus_sign: Not affected — predates the introducing commit |
| Debian | sid (unstable) | 7.1.6-1 | 7.1.5-1 | 2026-07-27 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.3-1 | — | — | :x: Vulnerable |
| Debian | 13 (trixie) | 6.12.101-1 | 6.12.100-1 | 2026-07-31 | :white_check_mark: Fixed — DSA-6405-1 |
| Debian | 12 (bookworm) | 6.1.180-1 | 6.1.180-1 | 2026-08-04 | :white_check_mark: Fixed — DLA-4720-1 |
| Debian | 11 (bullseye, LTS) | 5.10.262-1 | — | — | :heavy_minus_sign: Not affected — vulnerable code not present |
| Debian | 11 (6.1 opt-in) | 6.1.180-1~deb11u1 | 6.1.180-1~deb11u1 | 2026-08-06 | :white_check_mark: Fixed |
| Proxmox VE | 9 (default) | 7.0.14-9-pve | 7.0.14-8 | 2026-07-29 | :white_check_mark: Fixed — cherry-pick |
| Proxmox VE | 9 (6.17 old) | 6.17.13-21-pve | 6.17.13-21 | 2026-07-29 | :white_check_mark: Fixed — cherry-pick |
| Proxmox VE | 8 (default) | 6.8.12-39-pve | 6.8.12-39 | 2026-07-29 | :white_check_mark: Fixed — cherry-pick |
| NixOS | Unstable | 6.18.42 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.42 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed |
| Rocky Linux | 10 | 6.12.0-211.43.1.el10_2 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux | 9 | 5.14.0-687.34.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux | 8 | 4.18.0-553.151.1.el8_10 | — | — | :heavy_minus_sign: Not affected — vulnerable code not present |
| Amazon Linux | 2023 (default) | 6.1.177-224.371 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.95-124.187 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.39-79.141 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix was committed to the `net` tree on 2026-07-11 and reached Linus
in **v7.2-rc4** (tagged 2026-07-19); the kernel CNA backported it across
the maintained in-window stable lines on 2026-07-24 (per-branch versions
in the table). Two in-window lines ended upstream without the backport
and have no row: 7.0.y reached end of life at 7.0.14 on 2026-06-27,
before the disclosure (Proxmox's Ubuntu-derived 7.0 kernel lives on
and has its own row), and the short-lived 6.13.y line, in-window from
6.13.8, which no tracked distribution ships.

Because the cap removal was backported into stable only as far down as the
5.15 line, the **5.10.y line and earlier never received it** and are
genuinely *not affected* — the vulnerable code is absent, not merely
unpatched.

### Debian

Debian is affected only in the suites whose kernel carries the 2025 cap
removal. **bullseye** (LTS) ships the 5.10 series, which predates the
regression — the security tracker records *"vulnerable code not present"* —
so its default kernel is **not affected**, while its opt-in 6.1 kernel
(the `linux-6.1` source package, bookworm's kernel rebuilt for bullseye)
*is* in-window — it now carries the fix, having been rebased onto
upstream 6.1.180 (above the 6.1.x branch's 6.1.178 first-fixed release)
with no CVE-specific advisory. **forky** is in-window and below its
series' fixed release, so it remains vulnerable pending a security
upload; **bookworm**, **trixie**, **sid**, and bullseye's opt-in
`linux-6.1` already carry the fix.
Debian has shipped unprivileged user namespaces **enabled** by
default since bullseye (`kernel.unprivileged_userns_clone=1`) and does not
apply Ubuntu's AppArmor userns restriction, so on a stock Debian host the
unprivileged local vector is open unless an admin disables it.

### Proxmox VE

Proxmox ships its own kernels (`proxmox-kernel-*`), so Debian's status
does not carry over. On 2026-07-28 Proxmox cherry-picked the fix into
three series — PVE 9's 7.0 default (7.0.14-8), its superseded 6.17
series (6.17.13-21), and PVE 8's 6.8 default (6.8.12-39) — each naming
CVE-2026-64531 in the packaging changelog, with the fixed builds
published in `pve-no-subscription`. The 6.8 fix is notable: although
the upstream 6.8 base predates the regression, Proxmox's Ubuntu-derived
6.8 kernel received the cherry-pick — Ubuntu's heavy backporting
carried the vulnerable code in, so a pre-6.14 Proxmox series cannot be
assumed safe by version alone.

An *opt-in* series is Proxmox's preview of a likely next default; an
*old* series is a superseded default or an opt-in overtaken by a newer
one. Proxmox stops updating superseded series after a short transition
tail — 6.17 caught the fix inside that tail — and every such series is
end-of-life upstream, so a fix there could only arrive as a late
Proxmox cherry-pick.

The 6.14 series has no row: its updates had already ended before the
disclosure. PVE 9 launched with 6.14 as its default and superseded it
with 6.17 on 2025-11-11; the last 6.14 builds — PVE 9's 6.14.11-9 and
PVE 8's opt-in rebuild 6.14.11-9~bpo12+1 — date to 2026-05-15, with no
OVSwrap cherry-pick then or since. A host still booted into any 6.14
kernel is in-window and permanently vulnerable; move to the release's
current default kernel.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks with heavily backported feature
sets, so the base version alone cannot decide whether the 2025 OVS cap
removal is present — Red Hat's assessment is authoritative, and it
arrived on 2026-07-27: **EL8 (4.18) is not affected** (*vulnerable code
not present*), while **EL9 (5.14) and EL10 (6.12.0) are affected** with
no fix available yet. EL9 carries the cap removal as a backport despite
its base predating the regression — the same pattern as Proxmox's
Ubuntu-derived 6.8 kernel. Rocky rebuilds RHEL's kernels unchanged, so
these verdicts carry over; the affected rows flip when Rocky rebuilds
the fixing RHSA (AlmaLinux, typically the fastest rebuild, is the
leading indicator). Oracle Linux and CloudLinux OS track the RHEL
determination. The niche `kernel-rt` real-time variant carries the same
per-release verdicts and has no separate row.

### Amazon Linux

No ALAS has been issued for this CVE yet, so every AL2023 kernel stream
remains vulnerable pending an Amazon cherry-pick. The *default* row is
the plain `kernel` package (a 6.1-series stream); the 6.12 and 6.18
opt-in rows are the `kernel6.12` and `kernel6.18` packages.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Compare the running kernel against the *Patch status* table — a kernel
below its series' introducing point (anything on 5.10.y or older) is not
affected:

```bash
uname -r
```

**Is the OVS kernel datapath in use?**  The bug is only reachable when the
`openvswitch` module is loaded and handling flows:

```bash
lsmod | grep openvswitch
```

**Are conntrack actions in play?**  OVS conntrack pulls in `nf_conntrack`;
its absence means the `ct()` action path that drives the overflow is not
active:

```bash
lsmod | grep nf_conntrack
```

**Can unprivileged users create user namespaces?**  A non-zero value means
a local unprivileged user can obtain `CAP_NET_ADMIN` in a namespace and
reach the OVS netlink API:

```bash
sysctl kernel.unprivileged_userns_clone
```

Where that Debian/Ubuntu knob is absent, check the generic limit instead
(0 disables unprivileged user namespaces):

```bash
cat /proc/sys/user/max_user_namespaces
```

## Public PoC

The upstream PoC is in [manizada/OVSwrap][poc]; the researcher's
[write-up][writeup] describes the primitive, and the repository also ships
a BPF-based mitigation. Do **not** run the exploit on a system you are not
authorised to test.

## Mitigation

The real fix is a patched kernel (the [`3f1f75536668`][fix] backport).
Until one is installed, three interim measures narrow the exposure, in the
order the [write-up][writeup] recommends — none is a fix.

### Disable the `openvswitch` module (if you don't use OVS)

If the host does not use the OVS kernel datapath, the surest interim
measure is to stop the `openvswitch` module from loading at all — the
vulnerable code is then unreachable, and unlike the userns knob below this
also blocks privileged and container callers. Unload it if it is present
but idle:

```bash
sudo modprobe -r openvswitch
```

Then keep it from being (re)loaded, including on-demand autoload;
`install openvswitch /bin/false` is surer than a plain `blacklist
openvswitch`, which only suppresses alias-based autoloading:

```bash
echo 'install openvswitch /bin/false' | sudo tee /etc/modprobe.d/ovswrap.conf
```

Only do this where OVS is genuinely unused — a host that runs Open vSwitch
(many virtualization, OVN, and Kubernetes nodes) needs the module and must
fall back to the measures below.

### Disable unprivileged user namespaces (removes the unprivileged trigger)

On Debian/Ubuntu kernels, turn off unprivileged userns so a non-root local
user cannot obtain `CAP_NET_ADMIN` to reach the OVS netlink API:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

Persist it:

```bash
echo 'kernel.unprivileged_userns_clone=0' | sudo tee /etc/sysctl.d/99-ovswrap.conf
```

Where that knob is absent, cap the generic limit with
`user.max_user_namespaces=0` instead. This closes the *unprivileged* path
only; a caller that already holds `CAP_NET_ADMIN` (root, or a container
granted it) is unaffected, and containerized workloads that rely on
unprivileged userns will break.

### Apply the PoC's BPF mitigation (last resort)

The [PoC repository][poc] ships a BPF program that rejects oversized OVS
action sets before they reach the vulnerable path. Treat it as a last
resort for hosts that must keep the OVS datapath and unprivileged userns
enabled; auditing and loading third-party BPF carries its own risk, so
prefer the kernel patch wherever it is available.

## Risk notes

- **OVS datapath hosts with conntrack:** the exposed surface is any host
  running the OVS kernel datapath with conntrack `ct()` actions —
  virtualization hosts, OVN/Kubernetes networking nodes, and SDN
  gateways are the headline population.
- **Unprivileged local escalation:** with unprivileged user namespaces
  enabled (common on desktops and many container hosts), an ordinary
  local user reaches the bug without any prior privilege — shared and
  multi-user hosts are directly in scope.
- **Recent regression, not universal:** kernels below their series'
  introducing point (notably the entire 5.10 line and older EL kernels)
  are genuinely not affected — check the window before assuming exposure.
- **Backports available:** the fix has landed in v7.2-rc4 and the
  maintained stable lines (see the table), but distro kernels that have
  not yet adopted a fixed release or an independent cherry-pick remain
  vulnerable — check the distribution row for your kernel.

## Verification log

Every verdict in the table above is backed by a checkable source. This
log records the provenance — the advisory, repository index, or git
reference that established each fact — so any row can be audited or
reproduced. Most readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `3f1f75536668` (*net: openvswitch: reject oversized nested
  action attrs*), authored by Asim Manizada and first released in
  **v7.2-rc4** (tag date 2026-07-19, confirmed via `~/src/linux/stable`
  `git log`/`describe`). It reinstates a per-attribute size bound.
- The bug was introduced by `a1e64addf3ff` (*net: openvswitch: remove
  misbehaving actions length check*), Ilya Maximets, first in **v6.14**
  (`describe --contains` → `v6.14-rc7~…`), which removed the 32 KiB cap.
- **CVE-2026-64531** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`; record keys on `3f1f755366687d…`). The `.dyad`'s
  **introduced** side (backports at 5.15.180 / 6.1.132 / 6.6.84 / 6.12.20 /
  6.13.8; none below 5.15.180) establishes the not-affected boundary; its
  fixed side matches the stable backports below.
- **Stable backports** (fix cherry-picks confirmed by subject grep against
  `~/src/linux/stable`, each a new SHA): 5.15.212 (`ab8556412413`),
  6.1.178 (`c66bd2626c27`), 6.6.145 (`d573250d2284`), 6.12.97
  (`f1efff885840`), 6.18.40 (`dbd14f736be0`), 7.1.5 (`1b41cbe05b18`) — all
  tagged 2026-07-24 (`finger_banner` current point releases match).
- **Not-affected lines** confirmed by the *absence* of the introducing
  subject on `origin/linux-5.10.y` (and by the `.dyad` listing no intro
  pair below 5.15.180): 5.10.y and earlier lack the cap removal.
- The kernel CNA now publishes a CVSS score in the `vulns.git` record
  (`.cvss` present); NVD mirrors the same vector. See *Scoring* below.

#### Distributions

- **Debian** (via the Debian security tracker data for CVE-2026-64531):
  - unstable/sid — `7.1.5-1` carries the fix — fixed. *First fixed*
    `7.1.5-1`; *Fixed since* 2026-07-27, the version's `first_seen` in
    snapshot.debian.org.
  - testing/forky — `7.1.3-1`, in-window and below 7.1.5 — vulnerable.
  - stable/trixie — `6.12.100-1` (trixie-security) carries the fix,
    shipped as **DSA-6405-1** — fixed. *First fixed* `6.12.100-1`;
    *Fixed since* 2026-07-31, the version's `first_seen` in
    snapshot.debian.org.
  - oldstable/bookworm — `6.1.180-1` (bookworm-security) carries the
    fix, shipped as **DLA-4720-1** — fixed. *First fixed* `6.1.180-1`;
    *Fixed since* 2026-08-04, the version's `first_seen` in
    snapshot.debian.org.
  - LTS/bullseye default — `5.10.262-1`; the tracker notes *"Vulnerable
    code not present"* (5.10 predates `a1e64addf3ff`) — not affected.
  - LTS/bullseye opt-in `linux-6.1` — `6.1.180-1~deb11u1`, rebased onto
    upstream 6.1.180 (≥ 6.1.178, the 6.1.x branch's first-fixed release)
    — fixed (window-derived; the tracker carries no `linux-6.1` record
    for this CVE). *First fixed* `6.1.180-1~deb11u1`; *Fixed since*
    2026-08-06, the version's `first_seen` in snapshot.debian.org.
- **Proxmox VE** (via the `pve-no-subscription` `Packages.gz` indexes
  and the `pve-kernel` packaging changelogs, `~/src/proxmox/pve-kernel`):
  - PVE 9 default 7.0 — `proxmox-kernel-7.0` 7.0.14-8 published; its
    changelog entry (2026-07-28) names *fix CVE-2026-64531 "OVSWrap"
    LPE* — fixed.
  - PVE 9 6.17 (old) — 6.17.13-21 published; changelog entry
    (2026-07-28) names the CVE — fixed.
  - PVE 8 default 6.8 — 6.8.12-39 published; changelog entry
    (2026-07-28) names the CVE — fixed. Proxmox thereby treats the
    Ubuntu-derived 6.8 kernel as affected although the upstream 6.8
    base predates the regression.
  - 6.14 series (no rows) — the `trixie-6.14` and `bookworm-6.14`
    branches last built 6.14.11-9 / 6.14.11-9~bpo12+1 on 2026-05-15,
    before the disclosure, and carry no OVSwrap cherry-pick; the
    series was superseded as PVE 9's default on 2025-11-11
    (`proxmox-kernel-meta` 2.0.1 in that repo's changelog).
- **NixOS** (via `kernels-org.json` and the `linux_default` alias at
  each channel's `git-revision` pin, `~/src/nixos/nixpkgs`) — default
  `linuxPackages` (`linux_6_18`) is `6.18.42` on both nixos-unstable and
  nixos-26.05, a fixed release — fixed.
- **Rocky / RHEL family** (via the Red Hat CSAF/VEX record and the
  Rocky BaseOS repodata; the hydra securitydata API still returns 404
  for this CVE):
  - Red Hat's assessment, released 2026-07-27: RHEL 9 and 10 `kernel`
    (and `kernel-rt`) *known_affected* with no remediation available;
    RHEL 8 (and 7) *known_not_affected*, justification
    *vulnerable_code_not_present*.
  - Rocky 10 — BaseOS kernel `6.12.0-211.43.1.el10_2`; RHEL 10
    affected, no RHSA — vulnerable.
  - Rocky 9 — `5.14.0-687.34.1.el9_8`; RHEL 9 affected (the 5.14 fork
    carries the cap removal by backport), no RHSA — vulnerable.
  - Rocky 8 — `4.18.0-553.151.1.el8_10`; RHEL 8 not affected — not
    affected.
- **Amazon Linux** (via the AL2023 core repodata — `primary.xml.gz` for
  versions, `updateinfo.xml.gz` for advisories):
  - `updateinfo.xml.gz` has no entry for CVE-2026-64531 — no ALAS; all
    three streams stay vulnerable.
  - Streams (default `kernel` 6.1.177-224.371; `kernel6.12`
    6.12.95-124.187; `kernel6.18` 6.18.39-79.141) are in-window and
    below their series' fixed releases.

#### Scoring

- **Kernel CNA** (`vulns.git` `.cvss`/`.json`, `origin/master`): CVSS 3.1
  **7.8 HIGH** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`).
- **NVD**: same CVSS 3.1 7.8 HIGH vector; `vulnStatus` *Received*.
- **Red Hat** (CSAF/VEX record, revised 2026-07-31): severity
  **Important**, CVSS 3.1 **7.8 HIGH**
  (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) — matches the kernel
  CNA/NVD vector; the initial 2026-07-27 assessment rated it Moderate/7.0
  (`AC:H`).
- **EPSS**: 0.13% (percentile ~2.9%), as of 2026-08-02 (FIRST.org). Not
  in KEV.
{{< /details >}}

## References

| Source | URL |
|---|---|
| Public PoC (manizada) | <https://github.com/manizada/OVSwrap> |
| Researcher write-up | <https://heyitsas.im/posts/ovswrap> |
| oss-security disclosure | <https://www.openwall.com/lists/oss-security/2026/07/28/8> |
| Kernel fix | <https://github.com/torvalds/linux/commit/3f1f755366687d051174739fb99f7d560202f60b> |
| Introducing commit | <https://github.com/torvalds/linux/commit/a1e64addf3ff9257b45b78bc7d743781c3f41340> |
| CVE-2026-64531 | <https://www.cve.org/CVERecord?id=CVE-2026-64531> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-64531> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-64531> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
{.references}

[poc]: https://github.com/manizada/OVSwrap
[writeup]: https://heyitsas.im/posts/ovswrap
[oss]: https://www.openwall.com/lists/oss-security/2026/07/28/8
[fix]: https://github.com/torvalds/linux/commit/3f1f755366687d051174739fb99f7d560202f60b
[intro]: https://github.com/torvalds/linux/commit/a1e64addf3ff9257b45b78bc7d743781c3f41340
