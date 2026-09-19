# Running it on the UniFi gateway itself

Short version: **it works, and it is the wrong place to put it.** Both halves
of that sentence are true and neither cancels the other. If a gateway is the
only hardware you have, this page is how to do it properly and what you are
giving up.

---

## What you are giving up

This product exists to notice when your UniFi equipment stops reporting.
Hosted on the gateway, it **shares fate with the thing it is watching.**

When that box reboots, wedges, loses power or takes a firmware update, the
daemon whose job is to raise the alarm goes down with it. The most important
alarm it has — *the site went quiet* — is the one it structurally cannot send,
because sending it requires the box that just died.

Nothing in the software fixes that. It is a property of where the software is.

The daemon says so at **every start**, not just at install:

```
WARNING: this daemon is running ON this UniFi Cloud Gateway Fiber, so it
         shares fate with the equipment it watches: if this device reboots,
         wedges or loses power, the alarm about that will not be sent by
         anything.
```

That line is deliberate and it is not going away. It is the same reasoning as
the warning about a peer being the only source of door events: a structural
limitation whose only symptom is silence has to be stated, because nothing on
any screen will ever reveal it.

### Cover it, and the deployment is fine

Two ways, either is enough:

- **Pair a peer at another site** over Xtremission Link. Each installation then
  sees the other's silence, and the capability claim already handles the
  hand-back.
- **Point an off-site heartbeat at this installation** — anything that alarms
  on *absence* rather than on a message. It needs no inbound access and works
  behind CGNAT.

With one of those in place, on-box is a reasonable deployment. Without either,
you have monitoring that cannot report its own death.

---

## Install

Nothing special to run. SSH into the gateway (UniFi gateways log in as root),
put the `linux-arm64` binary somewhere under `/data`, and install as usual:

```bash
/data/notifymatrix/notifymatrix install
```

The installer detects the platform and adjusts itself. You do not pass a flag,
because the differences are corrections rather than preferences — an operator
who had to know to ask for them would get a unit that does not start.

### What it does differently here

| | Ordinary Linux | UniFi gateway |
|---|---|---|
| Data directory | `/var/lib/notifymatrix` | **`/data/notifymatrix`** |
| Write access | `StateDirectory=` | `ReadWritePaths=` |
| Runs as | `notifymatrix` | **`root`** |
| TPM group | `SupplementaryGroups=tss` | omitted |
| Memory | unbounded | `MemoryHigh=256M` `MemoryMax=512M` |
| Install refuses if | — | under 256 MB available |

**`/data`, and it is not configurable.** On UniFi OS the root filesystem is an
overlay whose writable upper layer *is* the persistent `/data` partition, so a
file written anywhere on the root filesystem physically lands on persistent
storage — which is why a unit in `/etc/systemd/system` survives a firmware
upgrade, and how the community's `udm-boot` survives one too. The state
directory is still pinned to `/data` rather than left at `/var/lib`, because
relying on the overlay to carry your incident history means relying on an
implementation detail of somebody else's firmware. A factory reset clears
`/data`, like everything else.

**Root, and this is a real departure.** ARCHITECTURE.md §9a says least
privilege and this breaks it. A gateway has no `useradd` on every image,
administers itself as root, and keeps `/etc` on an overlay shared with the
firmware — so creating a system account there is a change to somebody else's
base image that has to survive their upgrades, for a boundary that buys little
on a box where your own shell is root already. Pass `--user` if you have made
an account and know your image keeps it.

**No `tss` group.** There is no TPM on these devices, and systemd *fails* a
unit whose `SupplementaryGroups` names a group that does not exist — so the
line that protects the secret store everywhere else would stop the daemon from
starting at all here.

**A memory fence, because this box also routes.** Not a tuning knob: a backstop
so a fault in this process cannot take capacity from the routing and inspection
paths on the same hardware. Steady state is far below the soft limit. The hard
limit sits well clear of it because the failure modes are not symmetric —
being throttled is survivable and self-correcting, being killed stops the
alerting.

**The install refuses below 256 MB available.** What is being protected is not
this product; it is the network. An alerting daemon that degrades the network
it watches has made the site worse.

---

## Consequences worth knowing

**Your secrets get weaker.** The Linux secret chain is systemd-creds → TPM2 →
key file → plaintext. A gateway has no TPM and the daemon cannot write a
host-key credential, so you land on the **key file** tier — which is explicitly
*not machine-bound*. Copy the config and the key file together and the secrets
travel with them, and on this box they both live under `/data`. Better than
plaintext, not equivalent to a TPM. The settings page reports the mechanism in
use; believe it rather than this table.

**Ports.** Pick ones UniFi OS is not already using. The defaults (8322 and the
peer link port) are normally clear, but check on your own box rather than
assuming.

**The probe's local-network restriction means something different here.** It
refuses to reach anything outside private address space. Running *on the
router*, "local" now covers every VLAN it routes — a materially wider reach
than the same check on an ordinary LAN host. Nothing is bypassed; the blast
radius is just larger than it is elsewhere.

**Upgrades.** Re-run `install` after replacing the binary. The unit, the
config and the store are all on persistent storage and carry across a firmware
upgrade untouched.

---

## What has and has not been verified

Verified: the `linux-arm64` build is a **statically linked** ELF with no glibc
dependency (so the gateway's glibc version is irrelevant), the unit renders
correctly for the platform, platform detection requires both signals, and the
memory fence and headroom floor are consistent with each other.

Not verified on real hardware: whether every hardening directive in the unit
(`ProtectSystem=strict`, the syscall filters) behaves on a UniFi OS kernel, and
whether `/var/lib` would in fact persist — the `/data` pin makes that question
moot rather than answering it. If you run this on a real gateway and something
in the unit misbehaves, that is the interesting bug report.
