---
title: "OVSwrap — Open vSwitch datapath overflow"
description: "Linux kernel Open vSwitch datapath integer/buffer overflow (CVE-2026-64531, OVSwrap) — unprivileged local privilege escalation — distro patch status tracker"
layout: "single"
date: 2026-07-29
lastmod: 2026-07-29
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
| KEV / EPSS / CVSS | No CVSS in the kernel CNA record or NVD yet (NVD status *Received*); not in KEV. Pending |
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
| Linux kernel | mainline | 7.2-rc5 | 7.2-rc4 | 2026-07-19 | :white_check_mark: Fixed — carries `3f1f75536668` |
| Linux kernel | 7.1.x | 7.1.5 | 7.1.5 | 2026-07-24 | :white_check_mark: Fixed |
| Linux kernel | 7.0.x | 7.0.14 | — | — | :x: Vulnerable — EOL without the fix |
| Linux kernel | 6.18.x | 6.18.40 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.98 | 6.12.97 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.145 | 6.6.145 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.178 | 6.1.178 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.212 | 5.15.212 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.261 | — | — | :heavy_minus_sign: Not affected — predates the introducing commit |
| Debian | sid (unstable) | 7.1.5-1 | 7.1.5-1 | 2026-07-24 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.3-1 | — | — | :x: Vulnerable |
| Debian | 13 (trixie) | 6.12.96-1 | — | — | :x: Vulnerable |
| Debian | 12 (bookworm) | 6.1.177-1 | — | — | :x: Vulnerable |
| Debian | 11 (bullseye, LTS) | 5.10.259-1 | — | — | :heavy_minus_sign: Not affected — vulnerable code not present |
| Debian | 11 (linux-6.1 opt-in) | 6.1.177-1~deb11u1 | — | — | :x: Vulnerable |
| Proxmox VE | 9 (7.0 default) | 7.0.14-6-pve | — | — | :grey_question: Unverified — pending Proxmox advisory |
| Proxmox VE | 9 (6.17 old) | 6.17.13-19-pve | — | — | :grey_question: Unverified — pending Proxmox advisory |
| Proxmox VE | 9 (6.14 old) | 6.14.11-9-pve | — | — | :grey_question: Unverified — pending Proxmox advisory |
| Proxmox VE | 8 (6.8 default) | 6.8.12-38-pve | — | — | :grey_question: Unverified — predates the regression; likely not affected |
| Proxmox VE | 8 (6.14 opt-in) | 6.14.11-9-bpo12-pve | — | — | :grey_question: Unverified — pending Proxmox advisory |
| NixOS | Unstable | 6.18.40 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.40 | 6.18.40 | 2026-07-24 | :white_check_mark: Fixed |
| Rocky Linux | 10 | 6.12.0-211.39.1.el10_2 | — | — | :grey_question: Unverified — EL10 6.12.0 fork; pending Red Hat assessment |
| Rocky Linux | 9 | 5.14.0-687.30.1.el9_8 | — | — | :grey_question: Unverified — 5.14 predates the upstream regression; pending Red Hat assessment |
| Rocky Linux | 8 | 4.18.0-553.147.1.el8_10 | — | — | :grey_question: Unverified — 4.18 predates the upstream regression; pending Red Hat assessment |
| Amazon Linux | 2023 (kernel 6.1) | 6.1.176-223.369 | — | — | :x: Vulnerable — default stream, no ALAS yet |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.192 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (kernel6.18) | 6.18.38-76.139 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix was committed to the `net` tree on 2026-07-11 and reached Linus
in **v7.2-rc4** (tagged 2026-07-19); the kernel CNA backported it across
the maintained in-window stable lines on 2026-07-24 (per-branch versions
in the table). 7.0.y reached end of life at 7.0.14 while in-window and
never received the backport; the short-lived 6.13.y line was in-window
from 6.13.8 and is likewise permanently unpatched, but no tracked
distribution ships it, so it has no row.

Because the cap removal was backported into stable only as far down as the
5.15 line, the **5.10.y line and earlier never received it** and are
genuinely *not affected* — the vulnerable code is absent, not merely
unpatched.

### Debian

Debian is affected only in the suites whose kernel carries the 2025 cap
removal. **bullseye** (LTS) ships the 5.10 series, which predates the
regression — the security tracker records *"vulnerable code not present"* —
so its default kernel is **not affected**, while its opt-in `linux-6.1`
kernel *is* in-window and still needs the fix. **bookworm**, **trixie**,
and **forky** are all in-window and below their series' fixed release, so
they are vulnerable pending a security upload; **sid** already carries the
fix. Debian has shipped unprivileged user namespaces **enabled** by
default since bullseye (`kernel.unprivileged_userns_clone=1`) and does not
apply Ubuntu's AppArmor userns restriction, so on a stock Debian host the
unprivileged local vector is open unless an admin disables it.

### Proxmox VE

Proxmox ships its own kernels (`proxmox-kernel-*`), so Debian's status
does not carry over, and no Proxmox advisory has appeared yet. Its
6.14-and-newer series (PVE 9's 7.0, 6.17, and 6.14; PVE 8's 6.14 opt-in)
are in-window and would need a Proxmox cherry-pick, while PVE 8's 6.8
default predates the regression and is expected *not affected*.

An *opt-in* series is Proxmox's preview of a likely next default; an *old*
series is a superseded default or an opt-in overtaken by a newer one.
Proxmox stops updating superseded series after a short transition tail,
and every such series is end-of-life upstream, so a fix for an in-window
*old* row could only ever arrive as a Proxmox cherry-pick.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks with heavily backported feature
sets, so the base version alone cannot decide whether the 2025 OVS cap
removal is present — Red Hat's assessment is authoritative, and none had
been published at seed. EL8 (4.18) and EL9 (5.14) predate v6.14 by years
and are expected not affected; EL10 (6.12.0 base) is closer to the window
and needs explicit confirmation. Oracle Linux and CloudLinux OS track the
RHEL determination.

### Amazon Linux

No ALAS has been issued for this CVE yet, so every AL2023 kernel stream
remains vulnerable pending an Amazon cherry-pick.

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

*Last verified 2026-07-29.*

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
- No CVSS was present in the `vulns.git` record (`.cvss` absent) and NVD
  reported status *Received* with an empty `metrics` block — scores
  pending.

#### Distributions

- **Debian** (via the Debian security tracker page for CVE-2026-64531,
  fetched 2026-07-29):
  - unstable/sid — `7.1.5-1` carries the fix — fixed. *First fixed*
    `7.1.5-1`; *Fixed since* shown as the upstream 7.1.5 tag date
    (2026-07-24) pending the exact sid-upload date from
    snapshot.debian.org.
  - testing/forky — `7.1.3-1`, in-window and below 7.1.5 — vulnerable.
  - stable/trixie — `6.12.96-1`, below the 6.12.97 fix — vulnerable.
  - oldstable/bookworm — `6.1.177-1`, below the 6.1.178 fix — vulnerable.
  - LTS/bullseye default — `5.10.259-1`; the tracker notes *"Vulnerable
    code not present"* (5.10 predates `a1e64addf3ff`) — not affected.
  - LTS/bullseye opt-in `linux-6.1` — `6.1.177-1~deb11u1`, in-window and
    below 6.1.178 — vulnerable.
- **Proxmox VE** — seeded `:grey_question:`; no Proxmox advisory found at
  seed. Current-kernel versions are carried over from the sibling
  trackers' 2026-07-28 refresh (provisional until first verification).
  Window expectation: PVE 9 (7.0 / 6.17 / 6.14) and the PVE 8 6.14 opt-in
  are in-window; the PVE 8 6.8 default predates the regression.
- **NixOS** — default `linuxPackages` on nixos-unstable and nixos-26.05 at
  `6.18.40`, a fixed release — fixed (provisional until reconfirmed
  against the channel pin).
- **Rocky / RHEL family** — seeded `:grey_question:`; the Red Hat
  security-data API returned no record for CVE-2026-64531 at seed
  (HTTP 404). EL8 (4.18) and EL9 (5.14) predate v6.14 (expected not
  affected); EL10 (6.12.0 base) needs explicit confirmation. NVRs carried
  over from the 2026-07-28 sibling refresh.
- **Amazon Linux** — AL2023's three streams (kernel 6.1, kernel6.12,
  kernel6.18) are in-window and below their series' fixed release, with no
  ALAS issued at seed — vulnerable. Versions carried over from the
  2026-07-28 refresh.
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
