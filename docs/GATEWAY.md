# Running it on the UniFi gateway itself

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="images/whats-this-button-do-dark.gif">
    <img alt="A stick figure standing in front of a server rack, contemplating the large red button on it" src="images/whats-this-button-do-light.gif" width="70%">
  </picture>
</p>

**This exists because it could, not because it should.**

Somebody was always going to press the button. Better that it works properly,
refuses to install where it would do harm, and tells you at every start
exactly what you gave up — than that it half-works on a router somewhere and
nothing ever mentions it.

So: **this is not the recommended way to run this product.** It is the
supported way to do an unrecommended thing, which is a different promise and a
smaller one. Everything below is the difference.

---

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

SSH into the gateway — UniFi gateways log in as root, so there is no `sudo`
here — and paste this:

```bash
case "$(uname -m)" in aarch64|arm64) A=arm64 ;; x86_64|amd64) A=amd64 ;; *) echo "unsupported: $(uname -m)"; exit 1 ;; esac
cd "$(mktemp -d)"
wget -qO notifymatrix "https://github.com/suburbazine/Unifi-Notification-Matrix/releases/latest/download/notifymatrix-linux-$A"
wget -qO SHA256SUMS "https://github.com/suburbazine/Unifi-Notification-Matrix/releases/latest/download/SHA256SUMS"
grep " notifymatrix-linux-$A$" SHA256SUMS | sed "s|notifymatrix-linux-$A|notifymatrix|" | sha256sum -c - || { echo "CHECKSUM FAILED - not installing"; rm -f notifymatrix; exit 1; }
chmod +x notifymatrix && ./notifymatrix install
```

If `wget` is missing, `curl -fsSL -o <file> <url>` does the same job and is
present on every current UniFi OS image.

**The checksum step is not decoration and it fails closed.** It renames the
published checksum line to match the downloaded filename, and if the two
disagree the file is deleted rather than installed. A downloaded binary you
did not check is a binary somebody else may have chosen for you — and this one
is about to run as root on the device that routes your network.

**It downloads to a temporary directory on purpose.** `install` copies the
program to `/usr/local/bin/notifymatrix` and points the service unit at that
copy, so the download is finished with the moment the install succeeds. An
earlier version of this page had you download into `/data/notifymatrix` — which
left a stray binary and a checksum file sitting in what is meant to be the
state directory, next to the config and the incident store.

So there are two paths that matter and they are not the same one:

| | Where |
|---|---|
| The program | `/usr/local/bin/notifymatrix` — put there by `install` |
| Config, store, audit, keys | `/data/notifymatrix` |

For the stronger check — which proves *which workflow in which repository*
built the file, rather than only that it matches a checksum published beside
it — every release also ships a cosign bundle. See §1 of `RELEASING.md`.

The installer detects the platform and adjusts itself. There is no flag to
pass: the differences below are corrections rather than preferences, and an
operator who had to know to ask for them would get a unit that does not start.

### Straight after installing

**Copy the setup token.** `install` prints a one-time token and waits for you
to type `copied` before it lets go. Run it in an interactive SSH session, not
from a script, or you will have to fetch it afterwards with
`./notifymatrix setup-token`.

**Set a listen address you can actually reach.** The default is
`127.0.0.1:8322`, which on a gateway means the interface is reachable only
from a shell on the gateway itself. Edit `/data/notifymatrix/config.yaml`:

```yaml
web:
  listen: 0.0.0.0:8322
```

and restart with `systemctl restart notifymatrix`. Do **not** forward that port
— it carries the settings sign-in. Only `ack_listen` is meant to be forwarded.

### Updating

Re-run the same block. `install` replaces `/usr/local/bin/notifymatrix` and
restarts the unit onto it; the config, the incident store and the unit itself
are untouched.

Confirm it took by checking that `notifymatrix version` and the version shown
in the interface agree. They come from different places — the first runs the
file, the second asks the running service — so a disagreement is exactly the
half-finished upgrade worth catching.

### Uninstalling

```bash
/data/notifymatrix/notifymatrix uninstall
```

The state directory is left behind on purpose — it holds the incident history,
and an uninstall that silently deleted the record of every alarm the site has
had is not a thing to do without being asked. Remove `/data/notifymatrix` by
hand when you are sure.

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

**Running as root costs a hole in the syscall filter.** SQLite's unix layer
checks for euid 0 and chowns the database and its journal so a root-created
file inherits the directory's ownership. `@chown` lives inside `@privileged`,
which the hardened unit denies — so on the first run the store opened, the
process was killed with `SIGSYS`, the database stayed at zero bytes with a
journal beside it, and systemd restarted it into the same wall fifty-six times
before anybody looked.

The appliance unit therefore re-permits `@chown`, and only `@chown`:
`@setuid`, `@mount`, `@module`, `@raw-io`, `@reboot` and `@swap` all stay
denied. The ordinary unit does not need the grant and does not get it, because
an unprivileged service never makes SQLite take that branch.

This is the first thing the root decision actually cost, and it is here rather
than in a commit message because it is the kind of thing that comes back.

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

**The whole path works on real hardware**, confirmed on a UniFi gateway running
UniFi OS 6: install, the service staying up, the setup token, and the web
interface reachable from the LAN. `ProtectSystem=strict`, `ReadWritePaths`,
`MemoryHigh`/`MemoryMax` and the absence of the `tss` group all behave as
written.

From the build: the `linux-arm64` binary is a **statically linked** ELF with no
glibc dependency, so the gateway's glibc version is irrelevant.

### What it costs on the box

Around **15–20 MB** resident, against a 256 MB soft fence — so the fence is
better than ten times the working set, which is what a backstop against a fault
should look like rather than a ceiling the daemon lives against.

Read that as an order of magnitude, not a specification. It was measured on an
**idle** installation: no console configured, nothing ingesting, no incidents
open. A working site carries an entity record and live incidents and will sit
higher. Both are bounded by construction — 500 entities, 200 link receipts —
so not dramatically higher, but this is not a number to tune a limit against.

### Found by running it, not by reading it

Four things broke on first contact with real hardware, and none was reachable
from any test written for them. They are listed because they share a shape:
each was something a change depended on **without declaring that it did**.

- **The syscall filter killed the daemon.** Running as root makes SQLite reach
  for `chown`, which `@privileged` denies. See the `@chown` note above.
- **The key file did not follow `--data-dir`.** It was resolved from
  `$STATE_DIRECTORY`, which only exists for a unit with `StateDirectory=` —
  the directive this platform cannot use. Removing it silently moved the key.
- **The gateway data directory never applied.** The path was resolved for every
  subcommand before the installer ran, so the installer's own default could
  never fire, and everything agreed on the wrong directory.
- **The install instructions downloaded into the state directory**, because
  `install` relocates the program to `/usr/local/bin` and nothing said so.

### Still not verified

Whether `/var/lib` would persist across a firmware upgrade. The `/data` pin
sidesteps that question rather than answering it, and it stays pinned for
exactly that reason.

Nothing here has been through a firmware upgrade yet. The overlay argument says
the unit, the binary and the state all survive one; that is reasoning from how
UniFi OS is built, not a report from the other side of an upgrade. If you take
one and something does not come back, that is the bug report worth having.
