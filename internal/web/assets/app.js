// The operator interface. Plain DOM, no framework, no build step.
//
// Everything user-supplied goes in through textContent rather than innerHTML:
// incident titles come from UniFi, which means they come from whoever named a
// camera, and this page is the one place that data is rendered.
"use strict";

var REFRESH_MS = 5000;
var state = { authed: false, setupRequired: false, minPassword: 12, tab: "incidents" };

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function byId(id) { return document.getElementById(id); }

function api(method, path, body) {
  var opts = {
    method: method,
    headers: { "Accept": "application/json" },
    credentials: "same-origin"
  };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (r) {
    return r.text().then(function (t) {
      var data = {};
      if (t) { try { data = JSON.parse(t); } catch (e) { data = { error: "unreadable response" }; } }
      return { status: r.status, ok: r.ok, data: data };
    });
  });
}

// ---------- formatting ----------

function age(seconds) {
  if (seconds === null || seconds === undefined) return "";
  var s = Math.max(0, Math.round(seconds));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}
function stamp(iso) {
  if (!iso) return "never";
  var d = new Date(iso);
  if (isNaN(d.getTime())) return "never";
  return d.toLocaleString();
}
function badge(text, cls) { return el("span", "badge " + (cls || ""), text); }

// ---------- incidents ----------

function incidentCard(inc, showActions) {
  var cls = "card";
  // An acknowledged-but-unresolved incident is an OPEN OBLIGATION, not a
  // finished thing, so it must not look like a closed one.
  if (inc.state === "acknowledged") cls += " acked";
  else if (inc.severity === "critical" && !inc.acknowledged) cls += " crit";
  if (inc.state === "closed") cls += " done";

  var card = el("div", cls);
  var head = el("div", "row");
  head.appendChild(badge(inc.severity, "sev-" + inc.severity));
  head.appendChild(badge(inc.state, "st-" + inc.state));
  head.appendChild(el("div", "title grow", inc.title || inc.dedup_key));
  head.appendChild(el("span", "muted small", age(inc.age_seconds) + " old"));
  card.appendChild(head);

  var meta = [];
  meta.push(inc.source || "unknown source");
  meta.push(inc.alert_count === 1 ? "1 alert" : inc.alert_count + " alerts");
  if (inc.last_alert_at) meta.push("last alert " + stamp(inc.last_alert_at));
  if (inc.acknowledged) {
    meta.push("acknowledged " + stamp(inc.acked_at) + (inc.ack_via ? " via " + inc.ack_via : ""));
  }
  if (inc.resolved) meta.push("condition cleared " + stamp(inc.resolved_at));
  if (inc.predecessor_id) meta.push("recurrence of " + inc.predecessor_id);
  card.appendChild(el("div", "muted small", meta.join("  ·  ")));

  if (inc.acknowledged && !inc.resolved && inc.state !== "closed") {
    card.appendChild(el("div", "warn small",
      "Acknowledged, but the condition has not cleared. Still open."));
  }
  if (inc.detail) card.appendChild(el("div", "detail", inc.detail));

  // The last delivery error is why nothing is arriving. It gets the loudest
  // treatment on the page.
  if (inc.last_delivery_error) {
    card.appendChild(el("div", "delivery-error", "Delivery failed: " + inc.last_delivery_error));
  }

  if (showActions && state.authed && inc.state !== "closed") {
    var bar = el("div", "formbar");
    if (!inc.acknowledged) {
      var ackBtn = el("button", "act primary", "Acknowledge");
      ackBtn.addEventListener("click", function () {
        act(ackBtn, "POST", "api/incidents/" + encodeURIComponent(inc.id) + "/ack", {});
      });
      bar.appendChild(ackBtn);
    }
    var closeBtn = el("button", "act", "Close");
    closeBtn.addEventListener("click", function () {
      act(closeBtn, "POST", "api/incidents/" + encodeURIComponent(inc.id) + "/close",
        { reason: "closed from the web UI" });
    });
    bar.appendChild(closeBtn);
    card.appendChild(bar);
  }
  return card;
}

function act(button, method, path, body) {
  button.disabled = true;
  api(method, path, body).then(function (res) {
    button.disabled = false;
    if (!res.ok) {
      button.parentNode.appendChild(el("div", "msg err", res.data.error || "that did not work"));
      return;
    }
    refreshIncidents();
  });
}

function refreshIncidents() {
  api("GET", "api/incidents?limit=100").then(function (res) {
    if (!res.ok) return;
    var open = byId("open-incidents"), recent = byId("recent-incidents");
    clear(open); clear(recent);
    var list = res.data.incidents || [];
    var nOpen = 0, nDone = 0;
    list.forEach(function (inc) {
      if (inc.state === "closed") { recent.appendChild(incidentCard(inc, false)); nDone++; }
      else { open.appendChild(incidentCard(inc, true)); nOpen++; }
    });
    if (!nOpen) {
      open.appendChild(el("div", "empty",
        "Nothing open. Check Health to confirm the sources are actually reporting."));
    }
    if (!nDone) recent.appendChild(el("div", "empty", "Nothing closed recently."));
  });
}

// ---------- health ----------

function renderHealth(h) {
  var srcs = byId("health-sources"); clear(srcs);
  if (!h || !h.sources || !h.sources.length) {
    srcs.appendChild(el("div", "empty", "No sources are configured, so nothing is being watched."));
  } else {
    var t = table(["Source", "Last seen", "Expected within", "State"]);
    h.sources.forEach(function (s) {
      var row = t.tBodies[0].insertRow();
      row.insertCell().textContent = s.name;
      row.insertCell().textContent = s.last_seen
        ? stamp(s.last_seen) + " (" + age(s.age_seconds) + " ago)" : "never";
      row.insertCell().textContent = s.expected_within_seconds
        ? age(s.expected_within_seconds) : "—";
      var c = row.insertCell();
      c.appendChild(badge(s.silent ? "silent" : "reporting", s.silent ? "off" : "on"));
      if (s.detail) c.appendChild(el("div", "muted small", s.detail));
    });
    srcs.appendChild(wrap(t));
  }

  var chs = byId("health-channels"); clear(chs);
  if (!h || !h.channels || !h.channels.length) {
    chs.appendChild(el("div", "empty", "No channels are configured, so an alarm has nowhere to go."));
  } else {
    var ct = table(["Channel", "Enabled", "Queued", "Dropped", "Sending", "Last error"]);
    h.channels.forEach(function (c) {
      var row = ct.tBodies[0].insertRow();
      row.insertCell().textContent = c.name;
      row.insertCell().appendChild(badge(c.enabled ? "on" : "off", c.enabled ? "on" : "off"));
      row.insertCell().textContent = c.pending + " / " + c.depth;
      var d = row.insertCell();
      d.textContent = c.dropped;
      if (c.dropped > 0) d.className = "err";
      row.insertCell().textContent = c.in_flight ? "yes" : "no";
      var e = row.insertCell();
      e.textContent = c.last_error || "—";
      if (c.last_error) e.className = "err";
    });
    chs.appendChild(wrap(ct));
  }

  var svc = byId("health-service"); clear(svc);
  var card = el("div", "card");
  var s = (h && h.service) || {};
  var r1 = el("div", "row");
  r1.appendChild(badge(s.state || "unknown", s.state === "running" ? "on" : "off"));
  r1.appendChild(badge(
    s.restarts_after_crash ? "restarts after a crash" : "will NOT restart after a crash",
    s.restarts_after_crash ? "on" : "off"));
  if (s.start_type) r1.appendChild(el("span", "muted small", "start: " + s.start_type));
  if (s.pid) r1.appendChild(el("span", "muted small", "pid " + s.pid));
  card.appendChild(r1);
  var lines = [];
  if (h && h.started_at) {
    lines.push("running since " + stamp(h.started_at) + " (" + age(h.uptime_seconds) + ")");
  }
  if (s.detail) lines.push(s.detail);
  if (lines.length) card.appendChild(el("div", "muted small", lines.join("  ·  ")));
  if (s.unclean_previous_exit) {
    card.appendChild(el("div", "delivery-error",
      "The last exit was unclean — a crash, or a power cut."));
  }

  // Channels, policies and rules are all built once, at start. Until this
  // button existed, applying a saved change meant opening a terminal -- told
  // to somebody whose reason for being on this page is that they would rather
  // not. Worse, nothing said so, so a channel could read as enabled
  // everywhere a human looks and still not be told anything at 3am.
  if (state.authed && s.state && s.state !== "not installed") {
    var bar = el("div", "formbar");
    var msg = el("div", "msg");
    ["restart", "stop", "start"].forEach(function (action) {
      if (action === "start" && s.state === "running") return;
      if (action === "stop" && s.state !== "running") return;
      var b = el("button", action === "restart" ? "act primary" : "act",
        action.charAt(0).toUpperCase() + action.slice(1) + " the service");
      b.addEventListener("click", function () {
        msg.className = "msg";
        msg.textContent = "asking the service manager to " + action + "…";
        api("POST", "api/service", { action: action }).then(function (res) {
          if (!res.ok) {
            msg.className = "msg err";
            msg.textContent = (res.data && res.data.error) || (action + " failed");
            return;
          }
          // A restart or a stop takes THIS page's server down with it, so
          // there is no success response worth waiting for -- saying
          // "reconnecting" is the honest description of what happens next.
          msg.textContent = action === "start"
            ? "started."
            : "asked. This page will go quiet for a few seconds while it restarts.";
          setTimeout(refreshAll, 6000);
        });
      });
      bar.appendChild(b);
    });
    card.appendChild(bar);
    card.appendChild(msg);
  }
  svc.appendChild(card);
  if (state.authed) renderUpdate(svc);
}

// ---------- updates ----------

function renderUpdate(into) {
  var card = el("div", "card");
  card.appendChild(el("div", "title", "Version"));
  var body = el("div");
  card.appendChild(body);
  into.appendChild(card);

  var draw = function (u, note, noteClass) {
    clear(body);
    var r = el("div", "row");
    r.appendChild(badge("running " + (u.current || "unknown"), "on"));
    if (u.available) r.appendChild(badge(u.available + " available", ""));
    body.appendChild(r);

    if (u.error) {
      // A check that failed is NOT "up to date". Reported as its own line,
      // because the two look identical from the outside and one of them is a
      // machine sitting on a build with a known problem.
      body.appendChild(el("div", "delivery-error",
        "The last check for updates failed: " + u.error));
    }
    if (!u.can_apply && u.why) {
      body.appendChild(el("div", "note", u.why));
    }

    var bar = el("div", "formbar");
    var check = el("button", "act", "Check for updates");
    check.addEventListener("click", function () {
      draw(u, "checking…", "msg");
      api("POST", "api/update/check").then(function (res) {
        if (!res.ok) {
          draw(u, (res.data && res.data.error) || "the check failed", "msg err");
          return;
        }
        draw(res.data, res.data.available ? "" : "This is the newest release.", "msg");
      });
    });
    bar.appendChild(check);

    if (u.available && u.can_apply) {
      var go = el("button", "act primary", "Install " + u.available + " and restart");
      go.addEventListener("click", function () {
        draw(u, "downloading and checking the signature…", "msg");
        api("POST", "api/update/apply", { version: u.available }).then(function (res) {
          if (!res.ok) {
            // Shown verbatim. "signed by a different publisher" is not a
            // transient error to retry past -- it is the thing the check
            // exists to catch, and summarising it away would throw out the
            // only sentence that matters.
            draw(u, (res.data && res.data.error) || "the update failed", "msg err");
            return;
          }
          draw(u, "installed. Restarting — this page will go quiet briefly.", "msg");
          setTimeout(refreshAll, 8000);
        });
      });
      bar.appendChild(go);
    }
    if (u.available && u.release_url) {
      var link = document.createElement("a");
      link.href = u.release_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.className = "act";
      link.textContent = "Release notes";
      bar.appendChild(link);
    }
    body.appendChild(bar);
    if (note) {
      var m = el("div", noteClass || "msg", note);
      body.appendChild(m);
    }
  };

  api("GET", "api/update").then(function (res) {
    if (!res.ok) { clear(body); body.appendChild(el("div", "note",
      "This build cannot check for updates.")); return; }
    draw(res.data, "", "msg");
  });
}

function table(cols) {
  var t = document.createElement("table");
  var head = t.createTHead().insertRow();
  cols.forEach(function (c) {
    var th = document.createElement("th");
    th.textContent = c;
    head.appendChild(th);
  });
  t.createTBody();
  return t;
}
function wrap(t) { var d = el("div", "card"); d.appendChild(t); return d; }

// ---------- status ----------

function refreshStatus() {
  api("GET", "api/status").then(function (res) {
    var h = byId("headline");
    if (!res.ok) {
      h.textContent = "unreachable";
      h.className = "badge off";
      return;
    }
    var d = res.data;
    var wasAuthed = state.authed;
    state.authed = !!d.authenticated;
    state.setupRequired = !!d.setup_required;
    state.minPassword = d.min_password_length || 12;

    var c = d.incidents || {};
    if (c.alerting > 0) { h.textContent = c.alerting + " alerting"; h.className = "badge off"; }
    else if (c.open > 0) { h.textContent = c.open + " open"; h.className = "badge"; }
    else { h.textContent = "all clear"; h.className = "badge on"; }

    var sess = byId("session"); clear(sess);
    if (state.authed) {
      var out = el("button", "act", "Sign out");
      out.addEventListener("click", function () {
        api("POST", "api/signout", {}).then(function () { state.authed = false; refreshAll(); });
      });
      sess.appendChild(out);
    } else {
      sess.appendChild(el("span", "muted small",
        state.setupRequired ? "setup required" : "signed out"));
    }
    renderHealth(d.health);
    if (wasAuthed !== state.authed) refreshTab();
  });
}

// ---------- sign in / setup ----------

function labelled(text, input) {
  var d = document.createElement("div");
  d.appendChild(el("label", null, text));
  d.appendChild(input);
  return d;
}

function renderSignIn(container) {
  clear(container);
  var card = el("div", "card signin");
  if (state.setupRequired) {
    card.appendChild(el("div", "title", "Set the first password"));
    card.appendChild(el("div", "note",
      "The daemon printed a one-time setup token to its console when it started. " +
      "It is the only way to set the first password, and it works once."));
    var tok = el("input"); tok.type = "text"; tok.autocomplete = "off";
    card.appendChild(labelled("Setup token", tok));
    var pw = el("input"); pw.type = "password"; pw.autocomplete = "new-password";
    card.appendChild(labelled("New password (at least " + state.minPassword + " characters)", pw));
    var msg = el("div", "msg err");
    var go = el("button", "act primary", "Set password");
    go.addEventListener("click", function () {
      msg.textContent = "";
      api("POST", "api/setup", { token: tok.value, password: pw.value }).then(function (res) {
        if (!res.ok) { msg.textContent = res.data.error || "that did not work"; return; }
        refreshAll();
      });
    });
    var bar = el("div", "formbar"); bar.appendChild(go);
    card.appendChild(bar); card.appendChild(msg);
  } else {
    card.appendChild(el("div", "title", "Sign in"));
    card.appendChild(el("div", "note",
      "Status is public so a wall display needs no login. Changing anything does."));
    var p = el("input"); p.type = "password"; p.autocomplete = "current-password";
    card.appendChild(labelled("Password", p));
    var msg2 = el("div", "msg err");
    var submit = function () {
      msg2.textContent = "";
      api("POST", "api/session", { password: p.value }).then(function (res) {
        if (!res.ok) { msg2.textContent = res.data.error || "sign-in failed"; return; }
        p.value = ""; refreshAll();
      });
    };
    var btn = el("button", "act primary", "Sign in");
    btn.addEventListener("click", submit);
    p.addEventListener("keydown", function (e) { if (e.key === "Enter") submit(); });
    var bar2 = el("div", "formbar"); bar2.appendChild(btn);
    card.appendChild(bar2); card.appendChild(msg2);
  }
  container.appendChild(card);
}

// ---------- settings ----------

function refreshSettings() {
  var body = byId("settings-body");
  api("GET", "api/settings").then(function (res) {
    if (res.status === 401) { renderSignIn(body); return; }
    if (!res.ok) {
      clear(body);
      body.appendChild(el("div", "card err", res.data.error || "could not load settings"));
      return;
    }
    renderSettings(body, res.data);
  });
}

function bind(obj, key, numeric) {
  var i = el("input");
  i.type = numeric ? "number" : "text";
  i.value = (obj[key] === undefined || obj[key] === null) ? "" : obj[key];
  i.addEventListener("input", function () {
    obj[key] = numeric ? (i.value === "" ? 0 : Number(i.value)) : i.value;
  });
  return i;
}
function bindList(obj, key) {
  var i = el("input");
  i.type = "text";
  i.value = (obj[key] || []).join(", ");
  i.addEventListener("input", function () {
    obj[key] = i.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  });
  return i;
}
// inList is a checkbox over membership of a string array, for settings that
// are a set rather than a value -- a console's sources, above all.
function inList(obj, key, value) {
  var i = el("input");
  i.type = "checkbox";
  i.style.width = "auto";
  var has = function () { return (obj[key] || []).indexOf(value) >= 0; };
  i.checked = has();
  i.addEventListener("change", function () {
    var cur = obj[key] || (obj[key] = []);
    var at = cur.indexOf(value);
    if (i.checked && at < 0) cur.push(value);
    if (!i.checked && at >= 0) cur.splice(at, 1);
  });
  return i;
}
function check(obj, key) {
  var i = el("input");
  i.type = "checkbox";
  i.checked = !!obj[key];
  i.style.width = "auto";
  i.addEventListener("change", function () { obj[key] = i.checked; });
  return i;
}
function secretRow(card, isSet, label, obj, key) {
  var r = el("div", "row");
  r.appendChild(badge(isSet ? label + " set" : label + " not set", isSet ? "on" : "off"));
  card.appendChild(r);
  var i = el("input");
  i.type = "password"; i.autocomplete = "off";
  i.placeholder = "leave blank to keep what is stored";
  i.addEventListener("input", function () { obj[key] = i.value; });
  card.appendChild(labelled("Replace " + label, i));
}

function renderSettings(body, s) {
  clear(body);
  // A working copy: the inputs edit this, and this is what gets posted back.
  var draft = JSON.parse(JSON.stringify(s));

  body.appendChild(el("h3", null, "Consoles"));
  var consoles = draft.consoles || (draft.consoles = []);
  consoles.forEach(function (c, idx) {
    var card = el("div", "card");
    var f = el("div", "fields");
    f.appendChild(labelled("Name", bind(c, "name")));
    f.appendChild(labelled("Host or IP address", bind(c, "host")));
    f.appendChild(labelled("Certificate fingerprint (SHA-256, optional)", bind(c, "fingerprint")));
    card.appendChild(f);

    // Sources were displayed as a comma-joined string and could only be
    // changed by editing YAML -- on the setting that decides whether anything
    // is watched at all. A console with no source is polled for nothing and
    // looks entirely healthy doing it.
    card.appendChild(el("div", "label", "Watch these applications"));
    var sr = el("div", "row");
    ["protect", "access", "network"].forEach(function (name) {
      sr.appendChild(labelled(name, inList(c, "sources", name)));
    });
    card.appendChild(sr);

    var ir = el("div", "row");
    ir.appendChild(labelled("Skip certificate check", check(c, "insecure_skip_verify")));
    card.appendChild(ir);
    card.appendChild(el("div", "note",
      "Leave the certificate check on. A UniFi console's certificate is " +
      "self-signed, so the usual answer is to paste its SHA-256 fingerprint " +
      "above -- that pins this one console. Skipping the check instead accepts " +
      "ANY certificate, which is the state an attacker on your network needs."));

    if (c.api_key_credential) {
      var cr = el("div", "row");
      cr.appendChild(el("span", "muted small",
        "service credential " + c.api_key_credential + " overrides the key in the file"));
      card.appendChild(cr);
    }
    secretRow(card, c.api_key_set, "API key", c, "api_key_new");
    card.appendChild(el("div", "note",
      "The stored key is never sent to this page, only whether one exists. " +
      "Protect, Access and Network each issue their OWN key -- one key does " +
      "not cover the others."));

    var rm = el("button", "act", "Remove this console");
    rm.addEventListener("click", function () {
      consoles.splice(idx, 1);
      renderSettings(body, draft);
    });
    var rb = el("div", "formbar"); rb.appendChild(rm);
    card.appendChild(rb);
    body.appendChild(card);
  });
  if (!consoles.length) {
    body.appendChild(el("div", "empty",
      "No consoles configured. Nothing is being watched."));
  }
  var addCon = el("button", "act primary", "Add a console");
  addCon.addEventListener("click", function () {
    consoles.push({ name: "", host: "", sources: ["protect"], api_key_set: false });
    renderSettings(body, draft);
  });
  var addBar = el("div", "formbar"); addBar.appendChild(addCon);
  body.appendChild(addBar);

  body.appendChild(el("h3", null, "Channels"));
  var ch = draft.channels || (draft.channels = {});
  // Every channel card is rendered whether or not the config already has one,
  // so a channel can be ADDED here rather than only edited. Before this, a
  // channel absent from the file was invisible in the interface and the only
  // way to add one was to hand-edit YAML -- which is exactly the person this
  // interface exists for.
  ch.ntfy = ch.ntfy || { enabled: false };
  ch.email = ch.email || { enabled: false, recipients: [] };
  ch.pushover = ch.pushover || { enabled: false };
  ch.webhook = ch.webhook || { enabled: false };

  if (ch.ntfy) {
    var nc = el("div", "card");
    nc.appendChild(el("div", "title", "ntfy"));
    var nf = el("div", "fields");
    nf.appendChild(labelled("Enabled", check(ch.ntfy, "enabled")));
    nf.appendChild(labelled("Server URL", bind(ch.ntfy, "server_url")));
    nf.appendChild(labelled("Topic", bind(ch.ntfy, "topic")));
    nc.appendChild(nf);
    secretRow(nc, ch.ntfy.token_set, "token", ch.ntfy, "token_new");
    testRow(nc, "ntfy");
    body.appendChild(nc);
  }
  if (ch.email) {
    var ec = el("div", "card");
    ec.appendChild(el("div", "title", "Email"));
    var ef = el("div", "fields");
    ef.appendChild(labelled("Enabled", check(ch.email, "enabled")));
    ef.appendChild(labelled("Host", bind(ch.email, "host")));
    ef.appendChild(labelled("Port", bind(ch.email, "port", true)));
    ef.appendChild(labelled("TLS (auto, starttls, implicit, none)", bind(ch.email, "tls")));
    ef.appendChild(labelled("Username", bind(ch.email, "username")));
    ef.appendChild(labelled("From", bind(ch.email, "from")));
    ef.appendChild(labelled("Recipients (comma separated)", bindList(ch.email, "recipients")));
    ec.appendChild(ef);
    secretRow(ec, ch.email.password_set, "password", ch.email, "password_new");
    testRow(ec, "email");
    body.appendChild(ec);
  }
  if (ch.pushover) {
    var pc = el("div", "card");
    pc.appendChild(el("div", "title", "Pushover"));
    var pf = el("div", "fields");
    pf.appendChild(labelled("Enabled", check(ch.pushover, "enabled")));
    pf.appendChild(labelled("Device (blank = all)", bind(ch.pushover, "device")));
    pf.appendChild(labelled("Sound (blank = account default)", bind(ch.pushover, "sound")));
    pc.appendChild(pf);
    secretRow(pc, ch.pushover.token_set, "application token", ch.pushover, "token_new");
    secretRow(pc, ch.pushover.user_set, "user or group key", ch.pushover, "user_new");
    pc.appendChild(el("div", "note",
      "Two different credentials. The application token is the one you create at " +
      "pushover.net/apps/build; the user key is on your own dashboard. Swapped, " +
      "Pushover reports an invalid application token, which reads as a bad token " +
      "rather than as the pair being the wrong way round."));
    testRow(pc, "pushover");
    body.appendChild(pc);
  }
  if (ch.webhook) {
    var hc = el("div", "card");
    hc.appendChild(el("div", "title", "Webhook"));
    var hf = el("div", "fields");
    hf.appendChild(labelled("Enabled", check(ch.webhook, "enabled")));
    hf.appendChild(labelled("URL", bind(ch.webhook, "url")));
    hf.appendChild(labelled("Skip certificate check", check(ch.webhook, "insecure_skip_verify")));
    hc.appendChild(hf);
    secretRow(hc, ch.webhook.secret_set, "signing secret", ch.webhook, "secret_new");
    hc.appendChild(el("div", "note",
      "One JSON POST per alert, to anything you run. With a signing secret set, " +
      "each request carries an HMAC your receiver can check -- without one, " +
      "anybody who learns the URL can feed it false alarms."));
    testRow(hc, "webhook");
    body.appendChild(hc);
  }

  var anyEnabled = ["ntfy", "email", "pushover", "webhook"].some(function (k) {
    return ch[k] && ch[k].enabled;
  });
  if (!anyEnabled) {
    body.appendChild(el("div", "empty",
      "No channel is enabled. Incidents will still be tracked, and nobody will be told."));
  }

  body.appendChild(el("h3", null, "Quiet hours"));
  var qc = el("div", "card");
  var q = draft.quiet_hours || (draft.quiet_hours = {});
  var qf = el("div", "fields");
  qf.appendChild(labelled("Enabled", check(q, "enabled")));
  qf.appendChild(labelled("Start (HH:MM)", bind(q, "start")));
  qf.appendChild(labelled("End (HH:MM)", bind(q, "end")));
  qf.appendChild(labelled("Time zone (IANA name)", bind(q, "zone")));
  qc.appendChild(qf);
  qc.appendChild(el("div", "note",
    "Quiet hours never apply to critical. That control does not exist."));
  body.appendChild(qc);

  body.appendChild(el("h3", null, "Web"));
  var wc = el("div", "card");
  var w = draft.web || (draft.web = {});
  var wf = el("div", "fields");
  wf.appendChild(labelled("Listen address", bind(w, "listen")));
  wf.appendChild(labelled("Acknowledgement base URL", bind(w, "ack_base_url")));
  wf.appendChild(labelled("Acknowledgement-only listener (blank = none)", bind(w, "ack_listen")));
  wc.appendChild(wf);
  wc.appendChild(el("div", "note",
    "The acknowledgement-only listener is the one to forward a port to. A NAT " +
    "forward cannot pick a path, so forwarding to the main listen address " +
    "publishes the whole status page along with it; this one serves /ack/ and " +
    "nothing else."));
  var wr = el("div", "row");
  wr.appendChild(badge(w.ack_key_set ? "ack signing key set" : "ack signing key not set",
    w.ack_key_set ? "on" : "off"));
  wc.appendChild(wr);
  wc.appendChild(el("div", "note",
    "A listen address change takes effect when the service restarts."));
  body.appendChild(wc);

  body.appendChild(el("h3", null, "Escalation"));
  renderPolicies(body, draft);

  body.appendChild(el("h3", null, "Rules"));
  renderRules(body, draft);

  if ((draft.plaintext_fields || []).length) {
    var pc = el("div", "card");
    pc.appendChild(el("div", "delivery-error",
      "Unprotected credentials were found in the config file: " +
      draft.plaintext_fields.join(", ") +
      ". Treat them as exposed and rotate them; saving re-protects what is there."));
    body.appendChild(pc);
  }

  var msg = el("div", "msg");
  var save = el("button", "act primary", "Save settings");
  save.addEventListener("click", function () {
    msg.className = "msg"; msg.textContent = "";
    save.disabled = true;
    api("POST", "api/settings", draft).then(function (res) {
      save.disabled = false;
      if (!res.ok) {
        msg.className = "msg err";
        msg.textContent = res.data.error || "the save was refused";
        return;
      }
      msg.className = "msg ok";
      msg.textContent = "Saved.";
      refreshSettings();
    });
  });
  var bar = el("div", "formbar"); bar.appendChild(save);
  body.appendChild(bar);
  body.appendChild(msg);

  body.appendChild(el("h3", null, "Password"));
  var pwc = el("div", "card signin");
  var cur = el("input"); cur.type = "password"; cur.autocomplete = "current-password";
  var neu = el("input"); neu.type = "password"; neu.autocomplete = "new-password";
  pwc.appendChild(labelled("Current password", cur));
  pwc.appendChild(labelled("New password (at least " + state.minPassword + " characters)", neu));
  var pmsg = el("div", "msg");
  var pbtn = el("button", "act", "Change password");
  pbtn.addEventListener("click", function () {
    pmsg.className = "msg"; pmsg.textContent = "";
    api("POST", "api/password", { current: cur.value, password: neu.value }).then(function (res) {
      if (!res.ok) {
        pmsg.className = "msg err";
        pmsg.textContent = res.data.error || "that did not work";
        return;
      }
      cur.value = ""; neu.value = "";
      pmsg.className = "msg ok";
      pmsg.textContent = "Changed. Every other session is now signed out.";
      refreshStatus();
    });
  });
  var pbar = el("div", "formbar"); pbar.appendChild(pbtn);
  pwc.appendChild(pbar); pwc.appendChild(pmsg);
  body.appendChild(pwc);
}

// ---------- audit ----------

function refreshAudit() {
  var body = byId("audit-body");
  api("GET", "api/audit?limit=200").then(function (res) {
    if (res.status === 401) { renderSignIn(body); return; }
    if (!res.ok) {
      clear(body);
      body.appendChild(el("div", "card err", res.data.error || "could not load the audit log"));
      return;
    }
    clear(body);
    var entries = res.data.entries || [];
    if (!entries.length) { body.appendChild(el("div", "empty", "Nothing recorded yet.")); return; }
    var t = table(["When", "Kind", "Actor", "Summary"]);
    entries.forEach(function (e) {
      var row = t.tBodies[0].insertRow();
      row.insertCell().textContent = stamp(e.at);
      row.insertCell().textContent = e.kind;
      row.insertCell().textContent = e.actor || "—";
      var c = row.insertCell();
      c.textContent = e.summary;
      var extra = [];
      if (e.incident_id) extra.push("incident " + e.incident_id);
      if (e.fields) {
        Object.keys(e.fields).forEach(function (k) { extra.push(k + "=" + e.fields[k]); });
      }
      if (extra.length) c.appendChild(el("div", "muted small", extra.join("  ·  ")));
    });
    body.appendChild(wrap(t));
  });
}

// testRow adds a "send a test" button to a channel card.
//
// It reports what happened to THIS attempt, including the channel's own error
// text. "535 authentication failed" tells somebody exactly what to change;
// "could not send" tells them to open a support ticket.
//
// The button sends against the SAVED configuration, not the form in front of
// it -- so it says so, because testing a token you have typed but not saved
// and being told it failed is a confusing half-hour.
function testRow(card, name) {
  var row = el("div", "row");
  var btn = el("button", "act", "Send a test");
  var out = el("span", "muted small");
  row.appendChild(btn);
  row.appendChild(out);
  card.appendChild(row);
  card.appendChild(el("div", "note",
    "Tests the SAVED settings. Save first if you have just changed something."));

  btn.addEventListener("click", function () {
    btn.disabled = true;
    out.className = "muted small";
    out.textContent = "sending...";
    api("POST", "/api/channels/" + encodeURIComponent(name) + "/test").then(function (r) {
      btn.disabled = false;
      if (r.ok && r.data && r.data.ok) {
        out.className = "ok small";
        out.textContent = r.data.detail || "sent";
        return;
      }
      out.className = "err small";
      out.textContent = (r.data && r.data.error) || "failed";
    });
  });
}

// ---------- setup ----------

// The checklist. It is a tab of its own rather than a line on the health page
// because the two answer different questions: health says what is WRONG, and
// this says what has never been DONE. A product that has simply not been
// finished looks perfectly healthy.
function refreshSetup() {
  var body = byId("setup-body");
  api("GET", "/api/checklist").then(function (r) {
    clear(body);
    if (!r.ok || !r.data || !r.data.available) {
      body.appendChild(el("p", "muted", "No checklist available from this build."));
      return;
    }
    var d = r.data;

    var banner = el("div", "card");
    if (d.ready) {
      banner.appendChild(el("p", "", "This installation can raise and deliver an alarm."));
    } else {
      banner.appendChild(badge("not ready", "crit"));
      banner.appendChild(el("p", "",
        "Nothing can be delivered yet. The steps marked TODO below are what is missing."));
    }
    if (!d.authenticated) {
      banner.appendChild(el("p", "muted",
        "Sign in to see the webhook URLs. They are credentials, so they are not " +
        "shown to a signed-out viewer."));
    }
    body.appendChild(banner);

    (d.steps || []).forEach(function (s, i) {
      var card = el("div", "card");
      var head = el("div", "row");
      head.appendChild(badge(s.status, statusClass(s.status)));
      head.appendChild(el("strong", "", (i + 1) + ". " + s.title));
      card.appendChild(head);

      if (s.state) card.appendChild(el("p", "muted", "Now: " + s.state));
      if (s.status !== "done") {
        if (s.why) card.appendChild(el("p", "", s.why));
        if (s.how && s.how.length) {
          var ol = el("ol", "how");
          s.how.forEach(function (h) { ol.appendChild(el("li", "", h)); });
          card.appendChild(ol);
        }
      }
      body.appendChild(card);
    });
  });
}

function statusClass(status) {
  if (status === "done") return "ok";
  if (status === "todo") return "crit";
  if (status === "unverified") return "warn";
  return "";
}

// ---------- shell ----------

function refreshTab() {
  if (state.tab === "incidents") refreshIncidents();
  else if (state.tab === "setup") refreshSetup();
  else if (state.tab === "settings") refreshSettings();
  else if (state.tab === "audit") refreshAudit();
}
function refreshAll() { refreshStatus(); refreshTab(); }

function selectTab(name) {
  state.tab = name;
  var tabs = document.querySelectorAll("nav.tabs button");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].setAttribute("aria-selected", tabs[i].getAttribute("data-tab") === name ? "true" : "false");
  }
  ["incidents", "setup", "health", "settings", "audit"].forEach(function (t) {
    byId("tab-" + t).hidden = (t !== name);
  });
  refreshTab();
}

document.addEventListener("DOMContentLoaded", function () {
  var tabs = document.querySelectorAll("nav.tabs button");
  for (var i = 0; i < tabs.length; i++) {
    (function (b) {
      b.addEventListener("click", function () { selectTab(b.getAttribute("data-tab")); });
    })(tabs[i]);
  }
  refreshAll();
  // A wall display is left on this page for months. Polling is what keeps it
  // honest, and the interval is short because the board IS the product.
  setInterval(function () {
    refreshStatus();
    if (state.tab === "incidents") refreshIncidents();
  }, REFRESH_MS);
});

// ---------- escalation policies ----------
//
// Escalation was readable and not editable: the only way to change the ladder
// that decides whether anybody is told a SECOND time was to hand-edit YAML.
//
// Two views over the same data. The guided one asks the question people
// actually have -- who gets told, how often does it keep asking, when does it
// give up -- and edits a single-stage ladder. The advanced one exposes the
// ladder itself, because "ntfy now, ntfy and email after fifteen minutes" is
// the whole point of the feature and cannot be said any other way.

var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var CHANNEL_NAMES = ["ntfy", "email", "pushover", "webhook"];

// DEFAULT_LADDERS mirrors escalate.DefaultPolicies, so a severity the config
// does not override can still be SHOWN. Displayed as "default" rather than
// written into the file: materialising every default the first time somebody
// opens this page would freeze today's defaults into the installation for ever.
var DEFAULT_LADDERS = {
  critical: { stages: [{ after: "0s", channels: ["ntfy"] }, { after: "2m", channels: ["ntfy", "email"] }], repeat_every: "5m", give_up_after: "never" },
  high: { stages: [{ after: "0s", channels: ["ntfy"] }, { after: "15m", channels: ["ntfy", "email"] }], repeat_every: "30m", give_up_after: "4h" },
  medium: { stages: [{ after: "0s", channels: ["ntfy"] }], repeat_every: "2h", give_up_after: "12h" },
  low: { stages: [{ after: "0s", channels: ["ntfy"] }], give_up_after: "24h", respect_quiet_hours: true },
  info: { stages: [{ after: "0s", channels: ["ntfy"] }], respect_quiet_hours: true }
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

function boxFor(list, name, onChange) {
  var i = el("input");
  i.type = "checkbox";
  i.style.width = "auto";
  i.checked = (list || []).indexOf(name) >= 0;
  i.addEventListener("change", function () { onChange(i.checked); });
  return i;
}

function toggleIn(list, name, on) {
  var at = list.indexOf(name);
  if (on && at < 0) list.push(name);
  if (!on && at >= 0) list.splice(at, 1);
}

// enabledChannels reads the channel section of the draft being edited, not the
// saved config: someone who enables ntfy and then edits escalation in the same
// visit is entitled to put ntfy on a rung.
function enabledChannels(draft) {
  var ch = draft.channels || {};
  return CHANNEL_NAMES.filter(function (n) { return ch[n] && ch[n].enabled; });
}

function renderPolicies(body, draft) {
  var pols = draft.policies || (draft.policies = {});
  var card = el("div", "card");
  card.appendChild(el("div", "muted small",
    "What happens after an alarm is raised, and how long it keeps asking."));

  var live = enabledChannels(draft);
  if (!live.length) {
    card.appendChild(el("div", "note",
      "No channel is enabled, so there is nothing to escalate ON to. Enable one " +
      "above and save, then come back."));
  }

  var advanced = el("input");
  advanced.type = "checkbox";
  advanced.style.width = "auto";
  advanced.checked = policiesNeedAdvanced(pols);
  var advRow = el("div", "row");
  advRow.appendChild(labelled("Advanced: edit the escalation ladder itself", advanced));
  card.appendChild(advRow);

  var panel = el("div");
  card.appendChild(panel);
  body.appendChild(card);

  var draw = function () {
    clear(panel);
    SEVERITIES.forEach(function (sev) {
      panel.appendChild(policyCard(sev, pols, advanced.checked, draw, live));
    });
  };
  advanced.addEventListener("change", draw);
  draw();
}

// policiesNeedAdvanced reports whether anything configured cannot be shown in
// the guided form. Opening the simple view over a multi-stage ladder and then
// saving would silently flatten it, so the editor opens in whichever mode can
// represent what is already there.
function policiesNeedAdvanced(pols) {
  for (var sev in pols) {
    if (!Object.prototype.hasOwnProperty.call(pols, sev)) continue;
    var p = pols[sev];
    if (p && p.stages && p.stages.length > 1) return true;
  }
  return false;
}

function policyCard(sev, pols, advanced, redraw, live) {
  var overridden = Object.prototype.hasOwnProperty.call(pols, sev);
  var p = overridden ? pols[sev] : DEFAULT_LADDERS[sev];

  var c = el("div", "card");
  var head = el("div", "row");
  head.appendChild(badge(sev, "sev-" + sev));
  head.appendChild(el("div", "grow"));
  head.appendChild(badge(overridden ? "customised" : "default", overridden ? "on" : ""));
  c.appendChild(head);

  // Editing a default must turn it into an override FIRST, or the edit lands
  // on the shared template object and changes every severity at once.
  // Materialising a default has to filter it to channels that are actually
  // enabled, exactly as config.filterToEnabled does when the daemon builds the
  // shipped defaults at runtime.
  //
  // Without that, ticking one box in the simple view wrote out the two-stage
  // default verbatim -- including a second rung naming a channel this
  // installation does not have -- and the save was refused citing "stage 1",
  // a thing the simple view never showed and gave no way to fix.
  // Materialises WITHOUT redrawing.
  //
  // Redrawing here re-rendered the panel before the caller had applied its
  // change, so the freshly drawn checkbox showed the pre-change model and the
  // model then moved underneath it: the box read ticked while the stage it
  // stood for had no channels, and the save was refused for a state the screen
  // said was not there. Callers that need the card redrawn do it AFTER their
  // mutation, which is the only order in which the two can agree.
  var own = function () {
    if (!overridden) {
      pols[sev] = filterLadder(clone(DEFAULT_LADDERS[sev]), live);
      overridden = true;
    }
    return pols[sev];
  };

  if (!advanced) {
    var stages = (p.stages && p.stages.length) ? p.stages : [{ after: "0s", channels: [] }];
    var first = stages[0];
    c.appendChild(el("div", "label", "Tell me on"));
    var chRow = el("div", "row");
    (live.length ? live : []).forEach(function (name) {
      chRow.appendChild(labelled(name, boxFor(first.channels, name, function (on) {
        var t = own();
        if (!t.stages || !t.stages.length) t.stages = [{ after: "0s", channels: [] }];
        toggleIn(t.stages[0].channels || (t.stages[0].channels = []), name, on);
        redraw();
      })));
    });
    c.appendChild(chRow);

    var f = el("div", "fields");
    f.appendChild(labelled("Keep asking every (blank = ask once)",
      durationField(p, "repeat_every", own)));
    f.appendChild(labelled("Give up after (never = keep going)",
      durationField(p, "give_up_after", own)));
    c.appendChild(f);

    if (stages.length > 1) {
      c.appendChild(el("div", "note",
        "This severity has " + stages.length + " stages. The simple view edits the " +
        "first; tick Advanced to see the rest."));
    }
  } else {
    (p.stages || []).forEach(function (st, idx) {
      var sc = el("div", "card");
      var sf = el("div", "fields");
      sf.appendChild(labelled(idx === 0 ? "Straight away (0s)" : "After",
        durationField(st, "after", own)));
      sc.appendChild(sf);
      var r = el("div", "row");
      (live.length ? live : []).forEach(function (name) {
        r.appendChild(labelled(name, boxFor(st.channels, name, function (on) {
          own();
          toggleIn(st.channels || (st.channels = []), name, on);
          redraw();
        })));
      });
      sc.appendChild(r);
      var rm = el("button", "act", "Remove this stage");
      rm.addEventListener("click", function () {
        own().stages.splice(idx, 1);
        redraw();
      });
      var rb = el("div", "formbar"); rb.appendChild(rm);
      sc.appendChild(rb);
      c.appendChild(sc);
    });

    var addBar = el("div", "formbar");
    var add = el("button", "act", "Add a stage");
    add.addEventListener("click", function () {
      var t = own();
      t.stages = t.stages || [];
      t.stages.push({ after: "15m", channels: [] });
      redraw();
    });
    addBar.appendChild(add);
    c.appendChild(addBar);

    var af = el("div", "fields");
    af.appendChild(labelled("Repeat every", durationField(p, "repeat_every", own)));
    af.appendChild(labelled("Give up after", durationField(p, "give_up_after", own)));
    c.appendChild(af);
  }

  var q = el("input");
  q.type = "checkbox";
  q.style.width = "auto";
  q.checked = !!p.respect_quiet_hours;
  q.disabled = (sev === "critical");
  q.addEventListener("change", function () {
    own().respect_quiet_hours = q.checked;
    redraw();
  });
  var qr = el("div", "row");
  qr.appendChild(labelled("Respect quiet hours", q));
  if (sev === "critical") {
    qr.appendChild(el("span", "muted small",
      "Quiet hours never apply to critical. That control does not exist."));
  }
  c.appendChild(qr);

  if (overridden) {
    var reset = el("button", "act", "Back to the default");
    reset.addEventListener("click", function () { delete pols[sev]; redraw(); });
    var rb2 = el("div", "formbar"); rb2.appendChild(reset);
    c.appendChild(rb2);
  }
  return c;
}

// filterLadder drops rungs that point at channels this installation does not
// have, and drops a rung left with nothing to deliver to.
//
// Stage delays are kept as they are: a ladder whose first rung was dropped now
// starts later than zero, which is correct, because the rung that would have
// fired immediately had nowhere to send anything.
function filterLadder(p, live) {
  var out = [];
  (p.stages || []).forEach(function (st) {
    var keep = (st.channels || []).filter(function (c) { return live.indexOf(c) >= 0; });
    if (keep.length) out.push({ after: st.after, channels: keep });
  });
  p.stages = out.length ? out : [{ after: "0s", channels: [] }];
  return p;
}

// durationField edits a Go duration string, and says what one looks like
// rather than silently accepting "5" and meaning five nanoseconds.
function durationField(obj, key, own) {
  var i = el("input");
  i.type = "text";
  i.placeholder = "30s, 5m, 2h";
  i.value = (obj[key] === undefined || obj[key] === null) ? "" : obj[key];
  i.addEventListener("input", function () { own()[key] = i.value.trim(); });
  return i;
}

// ---------- rules ----------
//
// Rules were a textarea of raw JSON, which is hand-editing YAML with different
// punctuation. The guided form covers what a rule almost always is: one
// source, one thing that happened, and either silence it or change how loudly
// it is treated. Advanced exposes the full pattern lists, which do a thing the
// simple form cannot -- match several values, with trailing-* prefixes.

var SOURCE_NAMES = ["protect", "access", "network", "internal"];
var SEVERITY_CHOICES = ["", "critical", "high", "medium", "low", "info"];

function renderRules(body, draft) {
  var rules = draft.rules || (draft.rules = []);
  var card = el("div", "card");
  card.appendChild(el("div", "muted small",
    "Change how loudly something is treated, or silence it. Rules are applied " +
    "in order, and the first match wins."));

  var advanced = el("input");
  advanced.type = "checkbox";
  advanced.style.width = "auto";
  advanced.checked = rulesNeedAdvanced(rules);
  var ar = el("div", "row");
  ar.appendChild(labelled("Advanced: match several values, and use * prefixes", advanced));
  card.appendChild(ar);

  var panel = el("div");
  card.appendChild(panel);

  var draw = function () {
    clear(panel);
    if (!rules.length) {
      panel.appendChild(el("div", "empty",
        "No rules. Every event is treated as its source proposed."));
    }
    rules.forEach(function (r, idx) {
      panel.appendChild(ruleCard(r, idx, rules, advanced.checked, draw));
    });
    var bar = el("div", "formbar");
    var add = el("button", "act primary", "Add a rule");
    add.addEventListener("click", function () {
      rules.push({ name: "", sources: [], conditions: [], entities: [] });
      draw();
    });
    bar.appendChild(add);
    panel.appendChild(bar);
  };
  advanced.addEventListener("change", draw);
  draw();
  body.appendChild(card);
}

// rulesNeedAdvanced reports whether any rule matches more than one value, or
// uses a prefix pattern. The guided form would flatten those to the first
// entry, so it does not get to open over them.
function rulesNeedAdvanced(rules) {
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i] || {};
    var lists = [r.sources || [], r.conditions || [], r.entities || []];
    for (var j = 0; j < lists.length; j++) {
      if (lists[j].length > 1) return true;
      if (lists[j].length === 1 && String(lists[j][0]).indexOf("*") >= 0) return true;
    }
  }
  return false;
}

function ruleCard(r, idx, rules, advanced, redraw) {
  var c = el("div", "card");
  var f = el("div", "fields");
  f.appendChild(labelled("Name (shown in the audit record)", bind(r, "name")));
  c.appendChild(f);

  if (!advanced) {
    var g = el("div", "fields");
    g.appendChild(labelled("When the source is", selectInto(r, "sources", SOURCE_NAMES)));
    g.appendChild(labelled("and what happened is", firstOf(r, "conditions")));
    g.appendChild(labelled("on (camera, door, blank = any)", firstOf(r, "entities")));
    c.appendChild(g);
  } else {
    var h = el("div", "fields");
    h.appendChild(labelled("Sources (comma separated, * allowed)", bindList(r, "sources")));
    h.appendChild(labelled("Conditions (comma separated, * allowed)", bindList(r, "conditions")));
    h.appendChild(labelled("Entities (comma separated, * allowed)", bindList(r, "entities")));
    c.appendChild(h);
    c.appendChild(el("div", "note",
      "An empty list matches anything. A trailing * matches by prefix, so " +
      "\"doorbell*\" covers every condition starting with it."));
  }

  var act = el("div", "fields");
  var ig = el("input");
  ig.type = "checkbox";
  ig.style.width = "auto";
  ig.checked = !!r.ignore;
  ig.addEventListener("change", function () { r.ignore = ig.checked; redraw(); });
  act.appendChild(labelled("Silence it entirely", ig));
  if (!r.ignore) {
    var sel = el("select");
    SEVERITY_CHOICES.forEach(function (s) {
      var o = document.createElement("option");
      o.value = s;
      o.textContent = s === "" ? "leave as the source proposed" : s;
      if ((r.severity || "") === s) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("change", function () { r.severity = sel.value; });
    act.appendChild(labelled("Treat it as", sel));
  }
  c.appendChild(act);

  if (r.ignore) {
    // The validator refuses a blanket ignore, and finding that out at save
    // time -- after filling the form in -- is worse than being told here.
    var narrow = (r.sources || []).length || (r.conditions || []).length ||
      (r.entities || []).length;
    c.appendChild(el("div", narrow ? "note" : "delivery-error",
      narrow
        ? "This silences only what it matches above."
        : "An ignore rule must narrow what it silences by source, condition or " +
        "entity. As written this would silence everything, and the save will be refused."));
  }

  var bar = el("div", "formbar");
  var rm = el("button", "act", "Remove");
  rm.addEventListener("click", function () { rules.splice(idx, 1); redraw(); });
  bar.appendChild(rm);
  if (idx > 0) {
    var up = el("button", "act", "Move up");
    up.addEventListener("click", function () {
      var t = rules[idx - 1]; rules[idx - 1] = rules[idx]; rules[idx] = t; redraw();
    });
    bar.appendChild(up);
  }
  c.appendChild(bar);
  return c;
}

// selectInto edits a one-element list with a dropdown, for the guided view.
function selectInto(obj, key, choices) {
  var sel = el("select");
  var cur = (obj[key] || [])[0] || "";
  var opts = [""].concat(choices);
  opts.forEach(function (s) {
    var o = document.createElement("option");
    o.value = s;
    o.textContent = s === "" ? "any" : s;
    if (cur === s) o.selected = true;
    sel.appendChild(o);
  });
  sel.addEventListener("change", function () {
    obj[key] = sel.value === "" ? [] : [sel.value];
  });
  return sel;
}

// firstOf edits the first entry of a list as a plain text box.
function firstOf(obj, key) {
  var i = el("input");
  i.type = "text";
  i.placeholder = "any";
  i.value = (obj[key] || [])[0] || "";
  i.addEventListener("input", function () {
    var v = i.value.trim();
    obj[key] = v === "" ? [] : [v];
  });
  return i;
}
