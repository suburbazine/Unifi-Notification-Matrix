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
  svc.appendChild(card);
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
  (draft.consoles || []).forEach(function (c) {
    var card = el("div", "card");
    var f = el("div", "fields");
    f.appendChild(labelled("Name", bind(c, "name")));
    f.appendChild(labelled("Host", bind(c, "host")));
    f.appendChild(labelled("Certificate fingerprint (SHA-256)", bind(c, "fingerprint")));
    card.appendChild(f);
    var r = el("div", "row");
    if (c.api_key_credential) {
      r.appendChild(el("span", "muted small",
        "service credential " + c.api_key_credential + " overrides the key in the file"));
    }
    if (c.insecure_skip_verify) r.appendChild(badge("chain validation off", ""));
    r.appendChild(el("span", "muted small", "sources: " + (c.sources || []).join(", ")));
    card.appendChild(r);
    secretRow(card, c.api_key_set, "API key", c, "api_key_new");
    card.appendChild(el("div", "note",
      "The stored key is never sent to this page, only whether one exists."));
    body.appendChild(card);
  });
  if (!(draft.consoles || []).length) {
    body.appendChild(el("div", "empty", "No consoles configured."));
  }

  body.appendChild(el("h3", null, "Channels"));
  var ch = draft.channels || (draft.channels = {});
  if (ch.ntfy) {
    var nc = el("div", "card");
    nc.appendChild(el("div", "title", "ntfy"));
    var nf = el("div", "fields");
    nf.appendChild(labelled("Enabled", check(ch.ntfy, "enabled")));
    nf.appendChild(labelled("Server URL", bind(ch.ntfy, "server_url")));
    nf.appendChild(labelled("Topic", bind(ch.ntfy, "topic")));
    nc.appendChild(nf);
    secretRow(nc, ch.ntfy.token_set, "token", ch.ntfy, "token_new");
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
    body.appendChild(ec);
  }
  if (!ch.ntfy && !ch.email) {
    body.appendChild(el("div", "empty", "No channels configured. An alarm has nowhere to go."));
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
  wc.appendChild(wf);
  var wr = el("div", "row");
  wr.appendChild(badge(w.ack_key_set ? "ack signing key set" : "ack signing key not set",
    w.ack_key_set ? "on" : "off"));
  wc.appendChild(wr);
  wc.appendChild(el("div", "note",
    "A listen address change takes effect when the service restarts."));
  body.appendChild(wc);

  body.appendChild(el("h3", null, "Rules"));
  var rc = el("div", "card");
  var ta = document.createElement("textarea");
  ta.value = JSON.stringify(draft.rules || [], null, 2);
  ta.spellcheck = false;
  rc.appendChild(labelled("Rules (JSON list; the YAML on disk stays the source of truth)", ta));
  rc.appendChild(el("div", "note",
    "An ignore rule must narrow what it silences, or the save is refused."));
  body.appendChild(rc);

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
    try { draft.rules = JSON.parse(ta.value || "[]"); }
    catch (e) {
      msg.className = "msg err";
      msg.textContent = "Rules are not valid JSON: " + e.message;
      return;
    }
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

// ---------- shell ----------

function refreshTab() {
  if (state.tab === "incidents") refreshIncidents();
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
  ["incidents", "health", "settings", "audit"].forEach(function (t) {
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
