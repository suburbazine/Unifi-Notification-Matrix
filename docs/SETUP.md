# Setting it up

This walks through a first installation from nothing. It assumes no UniFi
experience beyond being able to log into your own console.

**If you only read one thing:** run this at any point and it will tell you what
is left to do, checked against your actual configuration.

```bash
notifymatrix setup
```

---

## 0. Before you start

You need:

- a **UniFi OS console** (a Dream Machine, a UNVR, a Cloud Key) on your network,
- a computer on the **same network** that stays on — this is where notifymatrix
  runs. A small always-on PC, a NAS, a Raspberry Pi. It does not need to be
  powerful.
- a phone, if you want to be notified on one.

Nothing needs to be exposed to the internet. The console connects **outward** to
this machine; nothing connects inward from outside.

---

## 1. Get an API key from your console

Open your console in a browser — the box itself on your network, not
`unifi.ui.com`.

1. **Settings → Control Plane → Integrations**
2. Create an API key.
3. **Copy it now.** The console shows it once and never again.

> **Each application issues its own key.** Protect, Access and Network are
> separate, and a Protect key will not work for Access. Create one for each
> application you want watched. A key for the wrong application looks exactly
> like a wrong key when it fails.

---

## 2. Run it once

```bash
notifymatrix setup
```

That creates the configuration file and prints the checklist. The file has
instructions in it — every section is commented.

It will tell you where the file is. On Windows that is usually
`C:\ProgramData\notifymatrix\config.yaml`; on Linux, under
`/var/lib/notifymatrix/`.

---

## 3. Add your console

Open the configuration file and add:

```yaml
consoles:
  - name: home
    host: 192.168.1.1
    api_key: <paste the key here>
    insecure_skip_verify: true
    sources: [protect, access, network]
```

`insecure_skip_verify: true` is normal — UniFi consoles use self-signed
certificates. You can pin the certificate later; the checklist will remind you.

**`sources` is the setting people most often leave empty.** A console with no
sources listed is polled for nothing, and everything still looks correct.

| source | what it watches |
|---|---|
| `protect` | cameras, sensors, doorbells, alarm hubs — pushed live |
| `access` | doors: forced open, held open, refused credentials |
| `network` | switches and access points going offline |

The key is encrypted the next time the configuration is saved, and is bound to
this machine. Copying the file to another computer will not carry the
credentials with it.

---

## 4. Choose how you want to be told

The quickest is **ntfy**:

1. Install the ntfy app on your phone.
2. Pick a topic name nobody could guess — treat it like a password. Anyone who
   guesses a topic name on the public server can read everything sent to it.
3. Subscribe to it in the app.
4. Put it in the configuration:

```yaml
channels:
  ntfy:
    enabled: true
    server_url: https://ntfy.sh
    topic: <something nobody could guess>
```

Email works too, and needs an SMTP server, a username and a password.

**Pushover** is the other good phone option, and it needs **two** credentials
that are easy to mix up:

```yaml
channels:
  pushover:
    enabled: true
    token: <application token>   # created at pushover.net/apps/build
    user: <user or group key>    # shown on your own dashboard
```

Swap them and Pushover reports an invalid *application token*, which reads as a
bad token rather than as the pair being the wrong way round.

> Pushover has an "emergency" priority that re-alerts until you acknowledge it
> **in Pushover**. This product deliberately never uses it. That would be a
> second escalation with a second acknowledgement it cannot see — you would
> silence your phone while the incident kept escalating everywhere else.

**A webhook** sends one JSON document per alert to anything you run — Home
Assistant, Node-RED, a script of your own:

```yaml
channels:
  webhook:
    enabled: true
    url: http://homeassistant.local:8123/api/webhook/notifymatrix
    secret: <any long random string>
```

With `secret` set, each request carries `X-NotifyMatrix-Signature` and
`X-NotifyMatrix-Timestamp`. Your receiver should compute
`HMAC-SHA256(secret, timestamp + "." + body)` and compare. Without it, anyone
who learns the URL can feed you false alarms.

The payload carries a `version` field and will not change shape under you.

**Enable at least one.** With no channel, incidents are tracked and nobody is
ever told — which is the one failure this product exists to prevent.

Two is better than one. A phone that is asleep and a mailbox that is not fail
in different ways.

### Check it before you rely on it

Open the interface, go to **Settings**, and press **Send a test** on each
channel you enabled. It reports what happened to that attempt — including the
service's own error, which usually says exactly what is wrong.

It tests the **saved** settings, so save first if you have just typed something.

---

## 5. Make the acknowledgement links work

Alerts carry a link that stops the escalation. This is the setting most often
got wrong, and the failure only shows up at 3am:

```yaml
web:
  listen: 0.0.0.0:8322
  ack_base_url: http://192.168.1.50:8322
```

`ack_base_url` must be an address **the phone can actually reach** — this
machine's address on your network, not `127.0.0.1`. If it points at loopback,
the link in a notification opens nothing on the phone holding it, and the only
way to stop the alert is to walk to a computer.

`listen: 0.0.0.0:8322` lets other devices on your network reach the interface.
Leave it at `127.0.0.1:8322` if you only ever use it from this machine.

---

## 5a. If somebody may be away from the site

Everything above assumes the phone is on the same network. If nobody is at the
site when an alarm fires, the acknowledgement link has to be reachable from
outside — otherwise the alert repeats and **nobody can stop it**.

There are two ways to do that, and they are not equally good.

### The easy way: a VPN (recommended)

**Tailscale** or **WireGuard** on the phone. Nothing is forwarded, nothing is
exposed to the internet, and the traffic is encrypted end to end.

With Tailscale, this machine gets an address like `100.x.y.z` that works from
anywhere:

```yaml
web:
  ack_base_url: http://100.101.102.103:8322
```

No firewall change at all. If you are not sure which option to pick, pick this
one.

### The harder way: forward a port

If you are going to forward a port, **scope it**, and understand why.

> **A NAT port forward cannot restrict by path.** Forwarding the port the
> interface runs on publishes *everything on it* — the status page, which names
> your cameras, doors and currently-open alarms, and the settings sign-in page —
> to the entire internet. The status page is deliberately readable without a
> password so it works as a wall display. That is a reasonable trade on your own
> network. It is not one on the open internet.

So give the forward something safe to point at:

```yaml
web:
  listen: 0.0.0.0:8322
  ack_listen: auto
  ack_base_url: https://alarms.example.com
```

`ack_listen` starts a **second listener that serves only `/ack/`**. Everything
else on that port — the status page, the settings API, the webhook receiver —
returns 404.

`auto` picks a random port in the 49152–65535 range on first start, writes it
back into the configuration, and **never changes it again**. The daemon prints
it:

```
note: picked port 49898 for acknowledgements and wrote it to .../config.yaml.
      It will not change again. Forward THAT port, and set
      web.ack_base_url to the address it is reachable on.
```

A random port is **not** a security measure — a port scan finds an open port
whatever its number. What it buys is that the forwarded port is not one of the
handful that automated scanners probe constantly, and that it will not collide
with something else you run. The acknowledgement token is what actually
protects an acknowledgement.

You can also set it by hand: `ack_listen: 0.0.0.0:49898`.

#### Scoping the forward

In your router or firewall:

| | |
|---|---|
| Protocol | **TCP only** |
| External port | the port above (for example 49898) |
| Internal address | this machine's LAN address |
| Internal port | the same port |
| Source | restrict it if your firewall can. Most home routers cannot. |

- **Forward only that one port.** Do not forward `web.listen`.
- **Do not use "DMZ" or "expose host".** That forwards everything on the
  machine, which is the opposite of scoping.
- **Do not forward UDP.** Nothing here uses it.
- If your firewall supports **geo-blocking** or a source-address allowlist,
  use it. If you know which country your phone will be in, that alone removes
  most of the background traffic.

#### TLS is not optional here

The acknowledgement token travels **in the URL**. Over plain `http` on the open
internet, anyone on the path can read it and silence your alarm.

Put a reverse proxy with a certificate in front of the ack listener —
[Caddy](https://caddyserver.com) does this in two lines and obtains the
certificate itself:

```
alarms.example.com {
    reverse_proxy 127.0.0.1:49898
}
```

With a proxy in front, set `listen` and `ack_listen` to `127.0.0.1` and forward
443 to the proxy instead. notifymatrix will stop warning about exposure once
the main listener is on loopback, because then nothing can be forwarded to it.

If running a reverse proxy is more than you want to take on, **use the VPN
option**. It is genuinely less work and it is safer.

#### Check it the way it will actually be used

From a phone, **on mobile data with Wi-Fi turned off**, open the acknowledgement
link from a real alert. That is the only test that matches the situation this
exists for. Testing it from inside the building proves nothing about it.

---

## 6. Restart, and check

```bash
notifymatrix stop && notifymatrix start
notifymatrix setup
```

The checklist reads your real configuration **and** the running daemon, so it
can tell "configured" from "working".

---

## 7. The alarms that need a rule made by hand

Some alarms are **not readable by any API**. They exist only as UniFi **Alarm
Manager** rules that push to a URL, and no API can create those rules — so if
nobody makes them by hand, those alarms never reach this product at all.

That covers:

- **WAN outages**, threat detections and PoE faults (Network)
- **NVR disk failure, storage and power loss** (Protect) — absent from the
  public API entirely
- anything else you want that is not in the table in step 3

### Doing it

Add a hook for each rule you plan to create:

```yaml
hooks:
  - name: wan-offline
    product: network
    condition: wan-down
    severity: critical
    entity: Head office WAN
```

Restart, then run `notifymatrix setup`. It prints **two** things for each hook:

```
  wan-offline (network)
    URL:    http://192.168.1.50:8322/hook/A63JH-b4lF06a48LbzCjEhUWoIxnW4sxYrA
    Header: Authorization: Bearer xK2n-Qp7ZmR4vT8cLd0aYhJ3wEuNfGsB1iOkX5tPqM
    nothing has ever arrived here
```

**You need both.** The URL says which hook an alarm belongs to; the header says
the caller is really your console.

> **Why not just the URL?** Because a URL is not a password. It travels through
> the Alarm Manager form, the console's own configuration backup, your browser
> history, any proxy log on the path, and whatever screenshot you take while
> setting it up. A header goes through none of those. So this product requires
> both, and there is no setting to turn that off — an "allow unauthenticated"
> option is one that ends up in a forum post.
>
> Both are credentials. Do not paste either into a chat or a ticket.

Then, in the UniFi console:

1. Open the application (Network, Protect or Access).
2. **Settings → Alarm Manager.** In Network it may be under
   **Settings → System → Alarms**.
3. Create an alarm and pick the trigger — for example **WAN Offline**.
4. For the action choose **Webhook**, method **POST**.
5. Paste the URL into the **Delivery URL** field.
6. Add a **custom header**: name `Authorization`, value `Bearer <the rest>`.
7. Save, then press **Test**.

Run `notifymatrix setup` again. It will say whether the alarm arrived.

> **A test alarm raises a real incident here, on purpose.** That is what proves
> the whole chain works — the rule, the network path, the escalation, and the
> notification on your phone. Acknowledge it and you are done.
>
> Until an alarm has actually arrived, the checklist reports the hook as
> **unverified** rather than done. A hook that looks right is not evidence that
> anybody made the rule.

### If the test does nothing

Run `notifymatrix setup` and read the line under the hook:

| It says | What that means |
|---|---|
| `nothing has ever arrived here` | The console is not reaching us at all. Check the rule exists, is enabled, and that the URL points at an address the console can reach. |
| `REFUSED n times -- no Authorization header` | **The rule works.** The console is reaching us and being turned away. You pasted the URL and not the header. |
| `REFUSED n times -- the Authorization header did not match` | The header is there but wrong. Copy the whole value including the word `Bearer`. |

A refused request gets a bare `404` and no explanation, deliberately — somebody
who found your URL learns nothing from probing it. The explanation is on this
side, where it costs nothing to say.

---

## 8. Install it as a service

Run from a terminal, it stops when you close the window, when you log out, and
when the machine reboots.

```bash
notifymatrix install
```

It asks for administrator rights, installs itself to start at boot, and
configures itself to restart after a crash.

```bash
notifymatrix status
```

If that ever says it will **not** restart after a crash, reinstall — that
configuration looks completely healthy and will not come back from a failure at
2am.

---

## 9. Set a password for the settings page

Anyone on your network can read the status page. That is deliberate: it makes a
wall display useful. Changing settings, acknowledging alarms and reading the
audit record must not be open to everyone.

1. Open `http://<this machine>:8322/`.
2. The daemon prints a one-time setup token each time it starts. Enter it.
3. Choose a password. The token then stops working.

---

## What to expect afterwards

- **Nothing happens for days.** That is correct. This product is quiet until
  something is wrong.
- **It notices its own failures.** If a source stops reporting for longer than
  it promised, that becomes an incident too — a dead source and a quiet site
  look identical from outside, and only one of them is fine.
- **Access doors need a position sensor.** Door forced and door held both
  depend on one, and most doors do not have one fitted. The status page reports
  how many of yours do.
- **`notifymatrix probe`** asks your console what it actually exposes, which is
  how firmware nobody here has seen gets described. It only talks to local
  networks and it publishes nothing on its own.

## When something is wrong

```bash
notifymatrix setup        # what is not finished
notifymatrix status       # is the service running, will it restart
notifymatrix incidents    # what is open right now
notifymatrix selfcheck    # what this machine can do
```

The audit record is plain text, one JSON object per line, in the data
directory. It records the events a rule **silenced** as deliberately as the
ones it delivered — because "why was I not paged" is the hard question.
