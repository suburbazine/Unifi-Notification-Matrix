package config

import "strings"

// fileHeader is the comment block written at the top of every saved config.
//
// REWRITTEN ON EVERY SAVE, not just on creation. The interface rewrites this
// file, and a header that survived only the first write would vanish the first
// time somebody changed a setting -- taking the instructions away from exactly
// the person who has just proved they are editing things.
//
// It is long, and that is the point. This file is the surface an operator
// meets before anything else works, and a bare `channels: {}` tells somebody
// who has never seen it nothing at all about what to put there.
const fileHeader = `# notifymatrix configuration
#
# This file is read when the service starts. Change it and restart:
#     notifymatrix stop && notifymatrix start
#
# Not sure what is missing? Run:
#     notifymatrix setup
# It checks this file and tells you what is left to do, step by step.
#
# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------
# API keys and passwords in this file are encrypted, and are bound to THIS
# machine -- DPAPI on Windows, a machine-bound key on Linux. Copying this file
# to another computer will not carry the credentials with it; they have to be
# entered again there.
#
# To set one, paste the plain value and restart. It is encrypted on the next
# save, and the daemon will warn you that it was readable on disk until then.
#
# ---------------------------------------------------------------------------
# consoles: the UniFi hardware to watch
# ---------------------------------------------------------------------------
# consoles:
#   - name: home                 # any name you like; appears in alerts
#     host: 192.168.1.1          # the console's address on your network
#     api_key: <paste it here>   # Settings > Control Plane > Integrations
#     insecure_skip_verify: true # normal: consoles use self-signed certificates
#     fingerprint: ""            # optional; pin the certificate once you know it
#     sources: [protect, access, network]
#
# Protect, Access and Network each issue their OWN API key. One key does not
# cover the others, and a key for the wrong application looks exactly like a
# wrong key.
#
# What each source does:
#   protect  cameras, sensors, doorbells, alarm hubs. Pushed live.
#   access   doors: forced open, held open, refused credentials.
#   network  switches and access points going offline. WAN outages, threats
#            and PoE faults need a webhook as well -- see hooks, below.
#
# ---------------------------------------------------------------------------
# hooks: alarms UniFi pushes to you
# ---------------------------------------------------------------------------
# Some alarms exist ONLY as UniFi "Alarm Manager" rules, which no API can
# create. You have to make the rule in the UniFi interface by hand and point it
# at a URL here. Add a hook with a name, restart, then run "notifymatrix setup"
# -- it prints the URL to paste and then tells you when an alarm has actually
# arrived, so you can tell a working rule from one you only think you made.
#
# hooks:
#   - name: wan-offline          # match the Alarm Manager rule's name
#     product: network
#     condition: wan-down        # what an alarm at this URL means
#     severity: critical
#
# Each hook gets TWO generated credentials: a token in its URL, and a bearer
# token the console must send as an Authorization header. You paste both into
# the Alarm Manager rule. Both are required and there is no way to turn the
# header off -- a URL is not a password, because it travels through the console
# backup, your browser history and every proxy log on the path, and a header
# does not.
#
# Treat both as passwords. "notifymatrix setup" prints them.
#
# ---------------------------------------------------------------------------
# channels: how you get told
# ---------------------------------------------------------------------------
# channels:
#   ntfy:
#     enabled: true
#     server_url: https://ntfy.sh    # optional; this is the default
#     topic: <something nobody could guess>
#   email:
#     enabled: true
#     host: smtp.example.com
#     port: 587
#     username: you@example.com
#     password: <paste it here>
#     from: you@example.com
#     recipients: [you@example.com]
#     tls: auto                     # optional; auto, starttls or implicit
#
#   pushover:
#     enabled: true
#     token: <application token>    # pushover.net/apps/build -- create one
#     user: <user or group key>     # your Pushover dashboard
#   webhook:
#     enabled: true
#     url: http://homeassistant.local:8123/api/webhook/notifymatrix
#     secret: <any long random string>
#
# An ntfy topic on the public server is readable by anyone who guesses the
# name. Treat the topic name as a password, or run your own ntfy server.
#
# Pushover needs TWO different credentials and they are easy to swap: "token"
# is the APPLICATION token you create once, "user" is your own account key.
# Swapped, the console says the application token is invalid, which reads as a
# bad token rather than as the pair being the wrong way round.
#
# The webhook channel POSTs one JSON document per alert to anything you run --
# Home Assistant, Node-RED, a script of your own. Set "secret" and each request
# is signed, so your receiver can prove it came from here and reject a replay.
# Without it, anyone who learns the URL can feed you false alarms.
#
# ---------------------------------------------------------------------------
# web: the local interface and the acknowledgement links
# ---------------------------------------------------------------------------
# web:
#   listen: 127.0.0.1:8322      # use 0.0.0.0:8322 to reach it from a phone
#   ack_base_url: http://192.168.1.50:8322
#
# ack_base_url is the setting people most often get wrong. Alerts carry a link
# that stops the escalation, and if this points at 127.0.0.1 that link opens
# nothing on the phone holding it. It must be an address the phone can reach.
#
# For a phone on the same network, that is this machine LAN address.
#
# IF SOMEBODY MAY BE AWAY FROM THE SITE, the link has to be reachable from
# outside or nobody can stop a repeating alarm. Two ways, and they are not
# equally good:
#
#   BEST -- a VPN. Tailscale or WireGuard on the phone. Nothing forwarded,
#   nothing exposed, and ack_base_url is just the VPN address of this machine.
#
#   IF YOU FORWARD A PORT -- scope it. A NAT forward CANNOT restrict by path,
#   so forwarding web.listen publishes the status page (your cameras, doors and
#   open alarms) and the settings sign-in to the whole internet. Instead set:
#
#     ack_listen: auto
#
#   That starts a SECOND listener serving only /ack/ -- everything else on it
#   is a 404. "auto" picks a random port in 49152-65535 on first start, writes
#   it back here, and never changes it. Forward THAT port, TCP only, and put
#   TLS in front of it: the acknowledgement token travels in the URL.
#
# Full walkthrough, including the firewall rule: docs/SETUP.md section 5a.
#
# Nothing else needs to be exposed. The consoles connect OUTWARD to this
# machine; nothing connects inward from outside.
#
# ---------------------------------------------------------------------------
# quiet_hours, rules and policies
# ---------------------------------------------------------------------------
# quiet_hours holds non-critical alerts until morning; critical alarms are
# never held. rules adjust severity or silence noisy devices. policies decide
# how often an unacknowledged incident is repeated, and through which channels.
# All three have sensible defaults and can be left out entirely.
#
# ===========================================================================
# Everything below this line is written by notifymatrix. Comments you add to
# it will be lost the next time settings are saved from the interface.
# ===========================================================================
`

// withHeader prepends the instructions to a marshalled config.
func withHeader(body []byte) []byte {
	var b strings.Builder
	b.Grow(len(fileHeader) + len(body) + 1)
	b.WriteString(fileHeader)
	b.WriteByte('\n')
	b.Write(body)
	return []byte(b.String())
}
