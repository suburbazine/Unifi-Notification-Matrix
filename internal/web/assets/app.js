// The operator interface. Plain DOM, no framework, no build step.
//
// Everything user-supplied goes in through textContent rather than innerHTML:
// incident titles come from UniFi, which means they come from whoever named a
// camera, and this page is the one place that data is rendered.
"use strict";

var REFRESH_MS = 5000;
// ready and todo come from the status poll (api/status "setup"), so the
// header, the Setup tab's count and the first-run landing all read the same
// two numbers. serviceState is the service manager's word for the daemon
// ("running", "stopped", "not installed"), kept so a Save can offer to
// restart without asking Health first. section is the Settings section the
// hash named (#settings/channels), if any.
var state = {
  authed: false, setupRequired: false, minPassword: 12, tab: "incidents",
  section: "", ready: true, todo: 0, serviceState: "", setupKnown: false
};

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

// ---------- visual primitives ----------
//
// Everything below is shared by every tab. A renderer that wants to show a
// state, an icon, an explanation or an empty screen calls one of these rather
// than assembling class strings, so that a colour or a glyph is decided in
// ONE place and the style sheet's tone system (style.css, section 11) is the
// only mapping from meaning to colour.
//
//   toneClass(x)                     "is-ok" | "is-warn" | "is-err" | "is-info" | "is-muted"
//   icon(name, cls, label)           inline <svg>; decorative unless label given
//   why(text, opts)                  the "why?" disclosure, see below
//   callout(text, tone, title)       a bordered, tinted note with a glyph
//   stateBlock(kind, opts)           empty / loading / error blocks
//   emptyState / loadingState / errorState   shorthands for the above
//   lede(iconName, question, figure) a tab's one-line header
//   setLede(tab, iconName, question, figure)  ...placed into #lede-<tab>
//   segmentBar(tones, label)         "4 of 7" as a bar, one segment per step
//   pipeline(nodes)                  console -> here -> channels -> phone
//   setTabCount(tab, text, tone)     the little pill on a tab button
//   copyButton(text, label)          copies a credential, works over plain http

// toneClass turns whatever a caller has -- a checklist status, a channel
// state, a severity, a bare tone name -- into the one class the style sheet
// understands. Unknown words are muted rather than an error: a new server
// status must never make the UI throw.
function toneClass(x) {
  switch (String(x || "").toLowerCase()) {
    case "ok": case "on": case "done": case "reporting": case "running":
    case "delivered": case "ready": case "live": case "good": case "success":
      return "is-ok";
    case "warn": case "warning": case "unverified": case "acknowledged":
    case "silent": case "high": case "held": case "pending": case "stale":
      return "is-warn";
    case "err": case "error": case "crit": case "critical": case "todo":
    case "off": case "failing": case "failed": case "alerting": case "open":
    case "missing": case "stopped": case "not ready":
      return "is-err";
    case "info": case "accent": case "medium": case "resolved": case "delivering":
    case "active": case "in progress": case "customised": case "customized":
      return "is-info";
    default:
      return "is-muted";
  }
}

// ICONS: every glyph on a 24x24 grid, drawn as strokes with round caps and
// joins at one weight (set by .icon in style.css), and no fills except the
// deliberate dots. They are strings of SVG path data rather than markup so
// nothing here is ever parsed as HTML. Each entry is one or more path "d"
// attributes; a leading "o" marks a circle as "o cx cy r".
//
// Drawn here rather than taken from an icon set so the twelve the interface
// needs share one hand, and so the CSP (script-src 'self', no external
// assets) is satisfied without a new file for handleAsset to serve.
var ICONS = {
  // the twelve the interface is built around
  camera:   ["M3 8.5A1.5 1.5 0 0 1 4.5 7H8l1.5-2.5h5L16 7h3.5A1.5 1.5 0 0 1 21 8.5V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z", "o 12 13.5 3.5"],
  door:     ["M5 21V4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v17", "M3 21h18", "M15 12h.01"],
  network:  ["M9 3h6v5H9z", "M3 16h6v5H3z", "M15 16h6v5h-6z", "M12 8v3", "M6 16v-2a1.5 1.5 0 0 1 1.5-1.5h9A1.5 1.5 0 0 1 18 14v2"],
  bell:     ["M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15z", "M10 21a2 2 0 0 0 4 0"],
  envelope: ["M3 6.5A1.5 1.5 0 0 1 4.5 5h15A1.5 1.5 0 0 1 21 6.5v11a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z", "M3 8l9 6 9-6"],
  phone:    ["M5 3h3.5l2 5-2.5 1.5a11 11 0 0 0 6.5 6.5L16 13.5l5 2V19a2 2 0 0 1-2 2A16 16 0 0 1 3 5a2 2 0 0 1 2-2z"],
  plug:     ["M9 2v6", "M15 2v6", "M6 8h12v3a6 6 0 0 1-12 0z", "M12 17v5"],
  check:    ["M5 12.5l4.5 4.5L19 7"],
  warning:  ["M12 3.5 21.5 20h-19z", "M12 10v4.5", "M12 17.5h.01"],
  clock:    ["o 12 12 9", "M12 7v5l3 2"],
  shield:   ["M12 3l8 3v6c0 4.8-3.4 8-8 9-4.6-1-8-4.2-8-9V6z", "M9 12l2 2 4-4"],
  gear:     ["M19.3 9.8L21.8 10.1L21.8 13.9L19.3 14.2L18.7 15.6L20.3 17.6L17.6 20.3L15.6 18.7L14.2 19.3L13.9 21.8L10.1 21.8L9.8 19.3L8.4 18.7L6.4 20.3L3.7 17.6L5.3 15.6L4.7 14.2L2.2 13.9L2.2 10.1L4.7 9.8L5.3 8.4L3.7 6.4L6.4 3.7L8.4 5.3L9.8 4.7L10.1 2.2L13.9 2.2L14.2 4.7L15.6 5.3L17.6 3.7L20.3 6.4L18.7 8.4Z", "o 12 12 3"],
  // and the ones the primitives themselves need
  chevron:  ["M9 6l6 6-6 6"],
  info:     ["o 12 12 9", "M12 11v5", "M12 8h.01"],
  x:        ["M6 6l12 12", "M18 6L6 18"],
  arrow:    ["M4 12h16", "M14 6l6 6-6 6"],
  activity: ["M3 12h4l3-7 4 14 3-7h4"],
  list:     ["M5 4.5h14a1.5 1.5 0 0 1 1.5 1.5v13a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V6A1.5 1.5 0 0 1 5 4.5z", "M8 4v2", "M16 4v2", "M8.5 13l2.5 2.5 5-5"],
  link:     ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"],
  copy:     ["M9 9h10a1.5 1.5 0 0 1 1.5 1.5v10A1.5 1.5 0 0 1 19 22H9a1.5 1.5 0 0 1-1.5-1.5v-10A1.5 1.5 0 0 1 9 9z", "M5 15V4.5A1.5 1.5 0 0 1 6.5 3H16"],
  key:      ["o 8 14 4", "M11 11l9-9", "M16 6l2 2", "M18.5 3.5l2 2"],
  power:    ["M12 3v9", "M6.3 7.3a8 8 0 1 0 11.4 0"],
  refresh:  ["M20 12a8 8 0 1 1-2.3-5.7", "M20 4v5h-5"],
  server:   ["M4 5h16v5H4z", "M4 14h16v5H4z", "M8 7.5h.01", "M8 16.5h.01"],
  home:     ["M4 11l8-7 8 7v9a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1z"],
  help:     ["o 12 12 9", "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .8-1 1.5V14", "M12 17h.01"]
};

var SVG_NS = "http://www.w3.org/2000/svg";

// icon returns an inline <svg class="icon"> for one of the names in ICONS.
// Decorative by default (aria-hidden), because it nearly always sits beside
// the word it illustrates; pass a label when it stands alone -- a bare
// warning triangle in a table cell -- and it becomes role="img".
// cls is appended to the class list: "sm" / "lg" for size, a tone class
// for colour, "chev" for the accordion chevron that rotates.
function icon(name, cls, label) {
  var d = ICONS[name] || ICONS.help;
  var svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("focusable", "false");
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  d.forEach(function (p) {
    var node;
    if (p.charAt(0) === "o") {
      var v = p.split(" ");
      node = document.createElementNS(SVG_NS, "circle");
      node.setAttribute("cx", v[1]); node.setAttribute("cy", v[2]); node.setAttribute("r", v[3]);
    } else {
      node = document.createElementNS(SVG_NS, "path");
      node.setAttribute("d", p);
    }
    svg.appendChild(node);
  });
  return svg;
}

// fill puts text or a node into a container. Every primitive below takes
// "text" that may be a string OR a ready-made node, so a caller can hand
// over a paragraph with a link in it without the primitive growing options.
function fill(node, content) {
  if (content === undefined || content === null) return node;
  if (content.nodeType) node.appendChild(content);
  else node.textContent = String(content);
  return node;
}

// why -- the "why?" disclosure.
//
//   lab.appendChild(why("Renaming this hook reissues its credentials..."));
//   row.appendChild(why(text, "what's this?"));          // custom trigger label
//   row.appendChild(why(text, { label: "why?", tone: "warn" }));
//
// It returns ONE node: a small trigger button and the explanation, hidden
// until pressed. Put it inside the label or title of the thing it explains;
// for a checkbox row, append it to the row (not the label) and the style
// sheet drops the body to its own line under the pair.
//
// Chosen over a native title= tooltip and over a floating popover, and the
// reasons are in style.css beside .why. In short: a tooltip never shows on a
// phone or on keyboard focus; a popover covers the control it explains and
// its text is absent from the document until opened, which would blind the
// snapshot harness that guards this UI's copy. This is a real <button>, so
// it works by tap, click and keyboard, and announces its expanded state.
var whySeq = 0;
function why(text, opts) {
  if (typeof opts === "string") opts = { label: opts };
  opts = opts || {};
  var wrap = el("span", "why");
  var btn = el("button", "why-btn");
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");
  var id = "why-" + (++whySeq);
  btn.setAttribute("aria-controls", id);
  btn.appendChild(icon("info", "sm"));
  btn.appendChild(document.createTextNode(opts.label || "why?"));
  var body = fill(el("span", "why-body" + (opts.tone ? " " + toneClass(opts.tone) : "")), text);
  body.id = id;
  body.hidden = true;
  btn.addEventListener("click", function (ev) {
    // The trigger often sits inside a <label>; without this the click
    // would also land on the label and focus (or toggle) its control.
    ev.preventDefault(); ev.stopPropagation();
    var open = body.hidden;
    body.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  wrap.appendChild(btn);
  wrap.appendChild(body);
  return wrap;
}

// callout: a warning or fact that belongs beside one control, rendered as
// a bordered, tinted block with a glyph. tone is ok | warn | err | info
// (default info). Text may contain newlines; they are kept.
function callout(text, tone, title) {
  var t = toneClass(tone || "info");
  var box = el("div", "callout " + t);
  var glyph = t === "is-ok" ? "check" : (t === "is-err" || t === "is-warn") ? "warning" : "info";
  box.appendChild(icon(glyph));
  var inner = el("div", "grow");
  if (title) inner.appendChild(el("span", "callout-title", title));
  inner.appendChild(fill(el("span", "callout-body"), text));
  box.appendChild(inner);
  return box;
}

// stateBlock: an empty, loading or error state that looks designed.
//
//   stateBlock("empty", { icon: "camera", title: "Nothing is being watched",
//                         text: "...", tone: "warn",
//                         action: { label: "Set up a console", href: "#setup" } })
//   stateBlock("loading", { text: "Loading incidents…" })
//   stateBlock("error",   { text: "could not load settings", action: { label: "Retry", onClick: fn } })
//
// opts.compact renders one row instead of a centred block, for a state that
// sits inside a card rather than standing in for one. An action may be an
// href (a hash link to another tab) or an onClick; primary: true fills it.
function stateBlock(kind, opts) {
  opts = opts || {};
  var tone = opts.tone || (kind === "error" ? "err" : "muted");
  var box = el("div", "state " + toneClass(tone) + (opts.compact ? " compact" : ""));
  box.setAttribute("role", kind === "error" ? "alert" : "status");
  if (kind === "loading") {
    box.appendChild(el("span", "spinner"));
    box.appendChild(el("div", "state-text", opts.text || "Loading…"));
    return box;
  }
  box.appendChild(icon(opts.icon || (kind === "error" ? "warning" : "info")));
  var body = el("div", opts.compact ? "grow" : "");
  if (opts.title) body.appendChild(el("div", "state-title", opts.title));
  if (opts.text) body.appendChild(fill(el("div", "state-text"), opts.text));
  box.appendChild(body);
  if (opts.action) {
    var bar = el("div", "formbar");
    var a = opts.action;
    var b;
    if (a.href) {
      b = el("a", "act" + (a.primary ? " primary" : ""), a.label);
      b.href = a.href;
    } else {
      b = el("button", "act" + (a.primary ? " primary" : ""), a.label);
      b.type = "button";
      if (a.onClick) b.addEventListener("click", a.onClick);
    }
    if (a.icon) b.insertBefore(icon(a.icon), b.firstChild);
    bar.appendChild(b);
    box.appendChild(bar);
  }
  return box;
}
function emptyState(title, text, action, extra) {
  var o = extra || {};
  o.title = title; o.text = text; o.action = action;
  return stateBlock("empty", o);
}
function loadingState(text) { return stateBlock("loading", { text: text }); }
function errorState(text, retry) {
  return stateBlock("error", {
    title: "That did not load", text: text,
    action: retry ? { label: "Try again", onClick: retry, icon: "refresh" } : null
  });
}

// lede: a tab's one-line header -- glyph, the question the tab answers,
// and the live figure that answers it ("2 alerting · 1 acknowledged").
// figure may be a string or a node (a row of badges, say). tone colours
// the glyph, so Health can go amber when a channel is failing.
function lede(iconName, question, figure, tone) {
  var box = el("div", "lede" + (tone ? " " + toneClass(tone) : ""));
  box.appendChild(icon(iconName));
  var txt = el("div", "grow");
  txt.appendChild(el("div", "lede-q", question));
  if (figure !== undefined && figure !== null && figure !== "") {
    txt.appendChild(fill(el("div", "lede-fig"), figure));
  }
  box.appendChild(txt);
  return box;
}
// setLede fills the mount index.html leaves at the top of each tab.
function setLede(tab, iconName, question, figure, tone) {
  var mount = byId("lede-" + tab);
  if (!mount) return null;
  clear(mount);
  var l = lede(iconName, question, figure, tone);
  mount.appendChild(l);
  return l;
}

// segmentBar: one segment per item, each in its tone. Pass what the
// bar means as the label, because six coloured rectangles say nothing to
// a screen reader.
function segmentBar(tones, label) {
  var bar = el("div", "segments");
  bar.setAttribute("role", "img");
  if (label) bar.setAttribute("aria-label", label);
  (tones || []).forEach(function (t) { bar.appendChild(el("span", "seg " + toneClass(t))); });
  return bar;
}

// pipeline: nodes = [{ icon, title, sub, tone }], drawn left to right with
// arrows between (top to bottom at phone width, by CSS).
function pipeline(nodes) {
  var box = el("div", "pipeline");
  (nodes || []).forEach(function (n, i) {
    if (i > 0) {
      var link = el("span", "link");
      link.appendChild(icon("arrow"));
      box.appendChild(link);
    }
    var node = el("div", "node " + toneClass(n.tone));
    node.appendChild(icon(n.icon || "info"));
    node.appendChild(el("div", "node-title", n.title));
    if (n.sub) node.appendChild(fill(el("div", "node-sub"), n.sub));
    box.appendChild(node);
  });
  return box;
}

// setTabCount puts a small pill on a tab button ("Setup 3"), or removes it
// when text is empty. The tone says whether the number is good news.
function setTabCount(tab, text, tone) {
  var btn = document.querySelector ? document.querySelector('nav.tabs button[data-tab="' + tab + '"]') : null;
  if (!btn) return;
  var pill = btn.querySelector(".count");
  if (!text && text !== 0) { if (pill) btn.removeChild(pill); return; }
  if (!pill) { pill = el("span", "count"); btn.appendChild(pill); }
  pill.className = "count " + toneClass(tone);
  pill.textContent = String(text);
}

// copyButton copies text to the clipboard and says so for a moment.
//
// navigator.clipboard exists only in a secure context, and this page is
// usually plain http on a LAN -- so on the very installs that need it most
// the modern API is simply undefined. The old execCommand path still works
// there, so it is the fallback rather than an error message.
function copyButton(text, label) {
  var b = el("button", "act small");
  b.type = "button";
  b.appendChild(icon("copy"));
  var word = document.createTextNode(label || "Copy");
  b.appendChild(word);
  b.addEventListener("click", function () {
    var value = typeof text === "function" ? text() : text;
    var done = function (okay) {
      word.textContent = okay ? "Copied" : "Select and copy";
      setTimeout(function () { word.textContent = label || "Copy"; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () { done(true); }, function () { done(false); });
      return;
    }
    var ta = document.createElement("textarea");
    ta.value = value; ta.setAttribute("readonly", "");
    ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    var okay = false;
    try { okay = document.execCommand("copy"); } catch (e) { okay = false; }
    document.body.removeChild(ta);
    done(okay);
  });
  return b;
}

// ---------- incidents ----------

// ENTITY_ICONS maps the entity kind the rule engine title-cases into the
// detail ("Camera: Front Door Cam") onto a glyph.
var ENTITY_ICONS = {
  camera: "camera", door: "door", site: "network", service: "server",
  sensor: "plug", light: "plug", chime: "bell", client: "network"
};

// incidentDetail splits the stored detail into prose and the facts appended
// after it, and renders them differently.
//
// The rule engine builds a detail by putting the source's own description
// first and then appending "Camera: Front Door Cam", "At: <RFC3339>" and
// "Rule: <names>" on their own lines. That shape is right for an email and
// wrong for a screen: the stored text is canonical and goes out in every
// notification, so it is parsed for presentation here rather than changed at
// the source, where it would alter what arrives on somebody's phone.
//
// Parsed from the END and only while lines keep matching "Word: value", so a
// description that happens to contain a colon cannot be eaten. Anything not
// recognised stays in the prose, which is the safe direction: the worst case
// is that it looks exactly as it did before.
function incidentDetail(card, detail) {
  var lines = String(detail).split(/\r?\n/);
  var facts = [];
  while (lines.length > 1) {
    var m = /^([A-Z][A-Za-z ]{0,18}): (.+)$/.exec(lines[lines.length - 1]);
    if (!m) break;
    facts.unshift({ key: m[1], value: m[2] });
    lines.pop();
    if (facts.length >= 4) break;
  }

  var prose = lines.join("\n").trim();
  if (prose) card.appendChild(el("div", "detail", prose));
  if (!facts.length) return;

  var row = el("div", "facts");
  facts.forEach(function (f) {
    var k = f.key.toLowerCase();
    var chip = el("span", "fact");
    if (k === "at" || k === "received") {
      // The stored form is RFC 3339 in UTC, which is correct in a
      // notification and unreadable on a screen where every other time is
      // local. Shown local, with the original kept on hover -- and the
      // engine's distinction preserved, because "received" means the source
      // supplied no time of its own and scrubbing footage to it would send
      // somebody to a moment that means nothing.
      chip.appendChild(icon("clock", "sm"));
      var when = new Date(f.value);
      chip.appendChild(el("span", "", (k === "received" ? "received " : "") +
        (isNaN(when.getTime()) ? f.value : when.toLocaleString())));
      chip.setAttribute("title", f.key + ": " + f.value);
    } else if (k === "rule") {
      chip.appendChild(icon("list", "sm"));
      chip.appendChild(el("span", "", "rule: " + f.value));
    } else {
      chip.appendChild(icon(ENTITY_ICONS[k] || "info", "sm"));
      chip.appendChild(el("span", "", f.value));
      chip.setAttribute("title", f.key);
    }
    row.appendChild(chip);
  });
  card.appendChild(row);
}

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
  head.appendChild(el("span", "muted small", incidentAge(inc)));
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
  if (inc.detail) incidentDetail(card, inc.detail);

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

// incidentAge says how long an incident has been what it is. "3m old" on
// a closed card read as if the incident were three minutes old, when it was
// closed two hours ago and had been open for a day; the verb makes the
// number mean something. age_seconds counts from opening, so a closed card
// measures from closed_at instead.
function incidentAge(inc) {
  if (inc.state === "closed" && inc.closed_at) {
    var t = new Date(inc.closed_at).getTime();
    if (!isNaN(t)) return "closed " + age((Date.now() - t) / 1000) + " ago";
    return "closed";
  }
  return "open " + age(inc.age_seconds);
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
    var nOpen = 0, nDone = 0, nAlert = 0, nAcked = 0;
    list.forEach(function (inc) {
      if (inc.state === "closed") { recent.appendChild(incidentCard(inc, false)); nDone++; }
      else {
        open.appendChild(incidentCard(inc, true)); nOpen++;
        if (inc.state === "acknowledged") nAcked++; else nAlert++;
      }
    });

    // The lede: the tab's question and the live answer to it.
    var fig = el("span", "cluster");
    fig.appendChild(badge(nAlert + " alerting", nAlert ? "is-err" : "is-muted"));
    fig.appendChild(badge(nAcked + " acknowledged", nAcked ? "is-warn" : "is-muted"));
    fig.appendChild(el("span", "", "· " + nDone + " closed recently"));
    setLede("incidents", "bell", "What is happening now.", fig,
      nAlert ? "err" : (nAcked ? "warn" : "ok"));

    if (!nOpen) {
      // Nothing open means one of two very different things, and the empty
      // state has to say which: on a set-up installation it is good news
      // and Health confirms it; on one watching nothing it is the absence
      // of a product, and the button goes to Setup.
      if (state.setupKnown && !state.ready) {
        open.appendChild(emptyState("Nothing is being watched yet",
          "There are no incidents because nothing can raise one. Setup says what is missing.",
          { label: "Finish setup", href: "#setup", primary: true, icon: "list" },
          { icon: "warning", tone: "warn" }));
      } else {
        open.appendChild(emptyState("Nothing open",
          "Health confirms the sources are actually reporting -- silence is only good news if they are.",
          { label: "Check Health", href: "#health", icon: "activity" },
          { icon: "check", tone: "ok" }));
      }
    }
    if (!nDone) recent.appendChild(el("div", "empty", "Nothing closed recently."));
  });
}

// ---------- health ----------

// channelState reduces a channel's five counters to the one word an
// operator is asking for, with the numbers as a detail line underneath.
// "Queued 0 / 256 · Dropped 0 · Sending no" was the row before, and reading
// it meant knowing which of five columns to look at first. Held back is
// its own state and must not look like either of the others: the channel
// is not delivering, and it is not being attempted.
function channelState(c) {
  var held = c.backing_off_until && new Date(c.backing_off_until) > new Date();
  if (!c.enabled) return { word: "off", tone: "muted" };
  if (held) {
    return { word: "held back until " + new Date(c.backing_off_until).toLocaleTimeString(),
             tone: "warn", held: true };
  }
  if (c.last_error || c.dropped > 0) return { word: "failing", tone: "err" };
  if (c.in_flight || c.pending > 0) return { word: "delivering", tone: "info" };
  return { word: "idle", tone: "ok" };
}

function renderHealth(h) {
  var sources = (h && h.sources) || [];
  var channels = (h && h.channels) || [];
  var reporting = sources.filter(function (x) { return !x.silent; }).length;
  // NEVER CONNECTED IS NOT SILENCE. Silent is a source that was working and
  // stopped; this one has never reached its console since the daemon started,
  // which on a misconfigured installation is every source it has -- and the
  // board used to render that as green.
  var never = sources.filter(function (x) { return x.never_connected; }).length;
  var silent = sources.length - reporting - never;
  var failing = channels.filter(function (c) { return channelState(c).tone === "err"; }).length;
  var held = channels.filter(function (c) { return channelState(c).held; }).length;

  // The lede. Health answers "is the machinery working", and the figure is
  // the two counts that decide it.
  var fig = el("span", "cluster");
  fig.appendChild(badge(reporting + (reporting === 1 ? " source" : " sources") + " reporting",
    reporting ? "is-ok" : "is-muted"));
  if (silent) fig.appendChild(badge(silent + " silent", "is-warn"));
  if (never) fig.appendChild(badge(never + " never connected", "is-err"));
  if (failing) fig.appendChild(badge(failing + (failing === 1 ? " channel" : " channels") + " failing", "is-err"));
  if (held) fig.appendChild(badge(held + " held back", "is-warn"));
  if (!failing && !held && channels.length) {
    fig.appendChild(el("span", "", "· " + channels.length + (channels.length === 1 ? " channel" : " channels") + " ready"));
  }
  setLede("health", "activity", "Is the machinery working.", fig,
    failing || never || (!sources.length) ? "err" : (silent || held ? "warn" : "ok"));

  var srcs = byId("health-sources"); clear(srcs);
  if (!sources.length) {
    srcs.appendChild(emptyState("No sources are configured",
      "Nothing is being watched, so nothing can be raised. A console with at " +
      "least one source to watch is the first step.",
      { label: "Go to Setup", href: "#setup", primary: true, icon: "list" },
      { icon: "camera", tone: "warn" }));
  } else {
    // "Silent after", not "expected within": the column is the length of
    // silence at which a source is reported silent, and the old heading
    // read as a promise of when the next event would come.
    var t = table(["Source", "Last seen", "Silent after", "State"]);
    sources.forEach(function (s) {
      var row = t.tBodies[0].insertRow();
      row.insertCell().textContent = s.name;
      row.insertCell().textContent = s.last_seen
        ? stamp(s.last_seen) + " (" + age(s.age_seconds) + " ago)" : "never";
      row.insertCell().textContent = s.expected_within_seconds
        ? age(s.expected_within_seconds) : "\u2014";
      var c = row.insertCell();
      c.appendChild(s.never_connected
        ? badge("no contact", "is-err")
        : badge(s.silent ? "silent" : "reporting", s.silent ? "is-warn" : "is-ok"));
      if (s.detail) c.appendChild(el("div", "muted small", s.detail));
    });
    srcs.appendChild(wrap(t));
  }

  var chs = byId("health-channels"); clear(chs);
  if (!channels.length) {
    chs.appendChild(emptyState("No channels are configured",
      "An alarm has nowhere to go. Enable at least one channel under Settings.",
      { label: "Open Channels", href: "#settings/channels", primary: true, icon: "bell" },
      { icon: "bell", tone: "warn" }));
  } else {
    var ct = table(["Channel", "State", "Last error"]);
    channels.forEach(function (c) {
      var st = channelState(c);
      var row = ct.tBodies[0].insertRow();
      row.insertCell().textContent = c.name;
      var sc = row.insertCell();
      sc.appendChild(badge(st.word, toneClass(st.tone)));
      // The numbers, muted, under the word they add up to.
      var detail = "queued " + c.pending + " / " + c.depth + " \u00b7 dropped " + c.dropped +
        (c.in_flight ? " \u00b7 sending now" : "");
      sc.appendChild(el("div", (c.dropped > 0 ? "err" : "muted") + " small", detail));
      if (st.held) {
        sc.appendChild(el("div", "warn small",
          "after " + c.consecutive_fails + " failures in a row; next attempt " +
          stamp(c.backing_off_until)));
      }
      var e = row.insertCell();
      e.textContent = c.last_error || "\u2014";
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
  if (lines.length) card.appendChild(el("div", "muted small", lines.join("  \u00b7  ")));
  if (s.unclean_previous_exit) {
    card.appendChild(el("div", "delivery-error",
      "The last exit was unclean \u2014 a crash, or a power cut."));
  }

  // WHERE SOMEBODY IS ALREADY ASKING THE RIGHT QUESTION.
  //
  // This card answers "will this come back on its own", which is one step
  // away from "and would anybody know if it did not". On an installation that
  // shares fate with the equipment it watches, the honest answer to the
  // second is no -- and unlike the banner, this one can say what to do about
  // it, because reaching this card took a password.
  if (state.selfWatch && state.selfWatch.at_risk) {
    card.appendChild(callout(
      "This daemon runs on the equipment it is watching, so it shares fate " +
      "with it: a reboot, a wedge or a power cut takes the alarm about that " +
      "down too, and the restart settings above cannot help \u2014 nothing " +
      "would be left to act on them.\n\n" +
      "Pair a peer at another site under Settings \u2192 Peer link and each " +
      "installation will see the other go quiet. This notice clears itself " +
      "when something outside this machine is watching.",
      "warn", "Nothing outside this machine is watching it"));
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
      b.addEventListener("click", function () { serviceAction(action, b, msg); });
      bar.appendChild(b);
    });
    card.appendChild(bar);
    card.appendChild(msg);
  }
  svc.appendChild(card);
  if (state.authed) renderUpdate(svc);
}

// serviceAction asks the service manager for one action and reports into
// msg. Shared by the Health tab's buttons and the "Restart now" a Save
// offers, so the two cannot describe the same restart differently.
function serviceAction(action, button, msg) {
  if (button) button.disabled = true;
  msg.className = "msg";
  msg.textContent = "asking the service manager to " + action + "\u2026";
  api("POST", "api/service", { action: action }).then(function (res) {
    if (button) button.disabled = false;
    if (!res.ok) {
      msg.className = "msg err";
      msg.textContent = (res.data && res.data.error) || (action + " failed");
      return;
    }
    // A restart or a stop takes THIS page's server down with it, so there
    // is no success response worth waiting for -- saying what happens next is
    // the honest description.
    //
    // STOPPED IS NOT RESTARTING, and this said it was. Every action but
    // "start" shared one message about the page going quiet "while it
    // restarts", so an operator who had deliberately stopped their monitoring
    // was told it was on its way back. It is not. Nothing is watched until
    // somebody starts it again, and on this product that is the one sentence
    // that must never be wrong.
    if (action === "start") {
      msg.className = "msg ok";
      msg.textContent = "started.";
      setTimeout(refreshAll, 6000);
      return;
    }
    if (action === "stop") {
      // Deliberately not the success colour. The action succeeded; the state
      // it leaves behind is one nothing is watching, and a green line saying
      // so reads as reassurance.
      msg.className = "msg warn";
      msg.textContent = "stopped. Nothing is being watched until you start it " +
        "again. This page is served by the service, so it will stop " +
        "responding in a moment — that is expected, not a second fault.";
      // No refresh scheduled: there is nothing to come back to, and a page
      // that reloads itself into an error looks like something went wrong
      // beyond what was asked for.
      return;
    }
    msg.className = "msg ok";
    msg.textContent = "asked. This page will go quiet for a few seconds while it restarts.";
    setTimeout(refreshAll, 6000);
  });
}

// restartOffer is what a Save appends when the change it just made only
// takes effect after a restart: the sentence, and the button, together.
// The old message said "changes take effect when the service restarts" and
// the restart button was on another tab -- the operator was sent away from
// the thing they had just saved to finish saving it. Nothing is offered
// when the daemon is not a service (a terminal run is restarted from the
// terminal) or the viewer is not signed in.
function restartOffer(what) {
  var box = el("div", "restart-offer callout is-info");
  box.appendChild(icon("power"));
  var inner = el("div", "grow");
  inner.appendChild(el("span", "callout-title", "Saved. " + (what || "This change") +
    " takes effect when the service restarts."));
  var body = el("div", "callout-body");
  if (state.authed && state.serviceState && state.serviceState !== "not installed") {
    body.appendChild(el("span", "", "The daemon is still running the old configuration until then. "));
    var bar = el("div", "formbar");
    var b = el("button", "act primary small", "Restart now");
    b.type = "button";
    b.appendChild(icon("refresh"));
    var msg = el("div", "msg");
    b.addEventListener("click", function () { serviceAction("restart", b, msg); });
    bar.appendChild(b);
    body.appendChild(bar);
    body.appendChild(msg);
  } else {
    body.appendChild(el("span", "", "Restart the daemon to apply it" +
      (state.authed ? "." : "; sign in to do that from here.")));
  }
  inner.appendChild(body);
  box.appendChild(inner);
  return box;
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
// wrap puts a table in a card, inside a horizontal scroller: the health and
// audit tables are wider than a phone, and a table that cannot scroll on its
// own pushes the whole page sideways instead.
function wrap(t) {
  var d = el("div", "card");
  var sx = el("div", "scroll-x");
  sx.appendChild(t);
  d.appendChild(sx);
  return d;
}

// ---------- status ----------

// refreshStatus polls api/status and redraws everything that is on every
// screen: the headline badge, the session control, the Setup tab's count,
// the demo banner and the Health tab. done, when given, runs after the
// first successful answer (the landing decision waits on it).
function refreshStatus(done) {
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
    var su = d.setup || {};
    state.setupKnown = !!su.available;
    state.ready = su.available ? !!su.ready : true;
    state.todo = su.todo || 0;
    state.serviceState = (d.health && d.health.service && d.health.service.state) || "";

    // The headline. Alerting beats everything; then open; then -- before
    // "all clear" -- whether there is anything here to be clear ABOUT. An
    // installation watching nothing has no incidents, and "all clear" in
    // green was the first thing a fresh install said about itself.
    var c = d.incidents || {};
    if (c.alerting > 0) {
      h.textContent = c.alerting + " alerting"; h.className = "badge solid is-err"; h.href = "#incidents";
    } else if (c.open > 0) {
      h.textContent = c.open + " open"; h.className = "badge is-warn"; h.href = "#incidents";
    } else if (state.setupKnown && !state.ready) {
      h.textContent = "not set up"; h.className = "badge is-warn"; h.href = "#setup";
    } else {
      h.textContent = "all clear"; h.className = "badge on"; h.href = "#incidents";
    }

    // The count on the Setup tab: how many steps are stopping or degrading
    // delivery. Red while nothing can be delivered, amber once it can but a
    // step is still open, gone when there is nothing to do.
    if (state.setupKnown && state.todo > 0) {
      setTabCount("setup", state.todo, state.ready ? "warn" : "err");
    } else {
      setTabCount("setup", "");
    }

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
    renderDemoBanner(d.demo);
    state.selfWatch = d.self_watch || {};
    renderSelfWatchBanner(state.selfWatch);
    renderHealth(d.health);
    if (wasAuthed !== state.authed) refreshTab();
    if (done) done();
  });
}

// ---------- sign in / setup ----------

// labelled pairs a caption with a control. The optional third argument is
// the explanation that belongs AT this control -- the warning that renaming
// a hook reissues its credentials, say -- and it is rendered as a why()
// disclosure beside the caption, so it leaves the screen without leaving
// the field. Pass a string, or the options why() takes.
function labelled(text, input, help, key) {
  var d = document.createElement("div");
  // A checkbox reads as "[x] thing", not as a caption with a box under it.
  // Stacking them made a row of toggles look like a row of headings with
  // stray boxes, which is most of what the escalation editor is.
  if (input && input.type === "checkbox") {
    d.className = "checkrow";
    var lab = el("label", null, text);
    d.appendChild(input);
    d.appendChild(lab);
    // On the row, not in the label: the style sheet drops the body to its
    // own line under the pair, where a label's nowrap would have crushed it.
    if (help) d.appendChild(typeof help === "string" ? why(help) : why(help.text, help));
    return d;
  }
  var cap = el("label", null, text);
  // The config key, in mono beside the human name, for the fields the Setup
  // instructions name by key: "set web.ack_listen to auto" was impossible to
  // follow when the form called that field "Acknowledgement-only listener".
  if (key) cap.appendChild(el("span", "key", key));
  if (help) cap.appendChild(typeof help === "string" ? why(help) : why(help.text, help));
  d.appendChild(cap);
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
    // The checklist's password step knows the thing this card did not: on
    // a service install that token was printed to a console that does not
    // exist, and the route is a command instead. Its instructions are
    // rendered here, at the field asking for the token, from the same
    // source Setup uses -- so the two cannot disagree.
    var howMount = el("div", "");
    card.appendChild(howMount);
    api("GET", "/api/checklist").then(function (r) {
      if (!r.ok || !r.data || !r.data.steps) return;
      r.data.steps.forEach(function (st) {
        if (st.key !== "password" || !st.how || !st.how.length) return;
        if (st.state) howMount.appendChild(callout(st.state, "warn", "Now"));
        howMount.appendChild(referenceTopic("How to get past this", st.how));
      });
    });
    var tok = keepOutOfPasswordManagers(el("input")); tok.type = "text";
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

// The Settings page is one page with a section rail, and every section
// has its own Save.
//
// It was one long scroll with one Save at the bottom: the button for the
// Consoles card sat six screens below it, Escalation told the operator to
// "enable a channel above and save, then come back", and a Setup step that
// said "Open Settings" landed at the top of all of it. Now each section
// posts ONLY the keys it owns. The server leaves an absent section alone --
// TestSavingOneTabLeavesEveryOtherSectionAlone pins that -- which is the
// property that makes a page of partial saves safe to have at all.
//
// Webhooks lives here too, as a section, and was a tab. A hook's URL and
// header rendered on two tabs with two explanations, and the tab's Save
// knew nothing about the console typed in on the other one.
var SETTINGS_SECTIONS = [
  { key: "consoles",   title: "Consoles",    icon: "camera" },
  { key: "channels",   title: "Channels",    icon: "bell" },
  { key: "webhooks",   title: "Webhooks",    icon: "link" },
  { key: "link",       title: "Peer link",   icon: "plug" },
  { key: "escalation", title: "Escalation",  icon: "activity" },
  { key: "rules",      title: "Rules",       icon: "list" },
  { key: "quiet",      title: "Quiet hours", icon: "clock" },
  { key: "probe",      title: "Probe",       icon: "network" },
  { key: "web",        title: "Web",         icon: "gear" },
  { key: "password",   title: "Password",    icon: "key" }
];

// settingsCtx is the page being edited: the draft the inputs mutate, the
// last-saved view, the hook credentials, and a redraw per section. Module
// level because hookTestControls (arming test mode) needs to redraw the
// webhooks section from outside the renderer.
var settingsCtx = null;

function refreshSettings() {
  var body = byId("settings-body");
  // The settings API deliberately never returns a hook's token -- it
  // returns token_set, like every other credential -- so the URL an Alarm
  // Manager rule needs is not in it. The checklist is the one endpoint that
  // renders those, and only to a signed-in caller. Both are fetched so the
  // URL is on the screen where the hook is CREATED.
  // /api/link comes along for the ride rather than on its own poll: the
  // pairing section is part of this page, and a second request that can fail
  // separately would give it a second loading state to be in.
  Promise.all([api("GET", "api/settings"), api("GET", "/api/checklist"),
    api("GET", "/api/link"), api("GET", "/api/rules/review")])
    .then(function (both) {
    var res = both[0], list = both[1], lk = both[2], rv = both[3];
    if (res.status === 401) {
      setLede("settings", "gear", "Change what it does.", "");
      settingsCtx = null;
      renderSignIn(body);
      return;
    }
    if (!res.ok) {
      clear(body);
      body.appendChild(errorState(res.data.error || "could not load settings", refreshSettings));
      return;
    }
    renderSettings(body, res.data, hookCredsFrom(list), (lk.ok && lk.data) || {},
      (rv.ok && rv.data) || {});
  });
}

// hookCredsFrom indexes the checklist's hooks by name.
function hookCredsFrom(list) {
  var creds = {};
  if (list && list.ok && list.data && list.data.hooks) {
    list.data.hooks.forEach(function (h) { creds[h.name] = h; });
  }
  return creds;
}

// refreshWebhooks redraws the webhooks section with fresh credentials.
// Called after test mode is armed or ended, so the notice and the counts
// on the hook card follow the server.
function refreshWebhooks() {
  if (!settingsCtx) { refreshSettings(); return; }
  api("GET", "/api/checklist").then(function (list) {
    if (!settingsCtx) return;
    settingsCtx.creds = hookCredsFrom(list);
    settingsCtx.redraw("webhooks");
  });
}

function renderSettings(body, s, creds, linkState, review) {
  clear(body);
  // A working copy: the inputs edit this, and this is what gets posted back
  // -- one section at a time.
  var draft = JSON.parse(JSON.stringify(s));
  var ctx = { draft: draft, saved: s, creds: creds || {}, link: linkState || {},
    review: review || {}, sections: {} };
  ctx.redraw = function (key) {
    var sc = ctx.sections[key];
    if (!sc) return;
    clear(sc.body);
    SECTION_RENDERERS[key](sc.body, ctx);
  };
  settingsCtx = ctx;

  settingsLede(s);

  if ((draft.plaintext_fields || []).length) {
    body.appendChild(callout(
      "Unprotected credentials were found in the config file: " +
      draft.plaintext_fields.join(", ") +
      ". Treat them as exposed and rotate them; saving re-protects what is there.",
      "err", "Plaintext credentials"));
  }

  var page = el("div", "railed");
  var rail = el("nav", "rail");
  rail.setAttribute("aria-label", "Settings sections");
  SETTINGS_SECTIONS.forEach(function (sec) {
    var a = el("a", null, sec.title);
    a.href = "#settings/" + sec.key;
    a.setAttribute("data-section", sec.key);
    rail.appendChild(a);
  });
  page.appendChild(rail);

  var col = el("div", "sections");
  SETTINGS_SECTIONS.forEach(function (sec) {
    col.appendChild(settingsSection(ctx, sec));
  });
  page.appendChild(col);
  body.appendChild(page);

  watchRail();
  if (state.section) {
    scrollToSection(state.section);
    // Once more a moment later: the demo banner and the lede arrive from
    // the status poll after this render and push the page down, and on a
    // phone that was enough to leave #settings/escalation at the top of
    // Consoles.
    setTimeout(function () {
      if (state.tab === "settings" && state.section) scrollToSection(state.section);
    }, 300);
  } else {
    markRail(SETTINGS_SECTIONS[0].key);
  }
}

// settingsLede: the tab's question and a count of what is configured.
function settingsLede(s) {
  var ch = s.channels || {};
  var on = ["ntfy", "email", "pushover", "voice"].filter(function (k) { return ch[k] && ch[k].enabled; }).length;
  var outs = (ch.webhooks || []).filter(function (w) { return w.enabled; }).length;
  var parts = [
    (s.consoles || []).length + ((s.consoles || []).length === 1 ? " console" : " consoles"),
    (on + outs) + " of " + (4 + (ch.webhooks || []).length) + " channels enabled",
    (s.hooks || []).length + ((s.hooks || []).length === 1 ? " UniFi rule" : " UniFi rules"),
    (s.rules || []).length + ((s.rules || []).length === 1 ? " rule" : " rules")
  ];
  setLede("settings", "gear", "Change what it does.", parts.join(" \u00b7 "));
}

// settingsSection builds one section: heading, body, and the Save bar for
// it. The body is what redraw() refills; the bar is built once so a Save's
// message survives the redraw it triggers.
function settingsSection(ctx, sec) {
  var root = el("section", "settings-section");
  root.id = "settings-" + sec.key;
  var h = el("h2");
  h.appendChild(icon(sec.icon));
  h.appendChild(document.createTextNode(sec.title));
  root.appendChild(h);
  var body = el("div", "section-body");
  root.appendChild(body);
  var foot = el("div", "section-foot");
  root.appendChild(foot);
  ctx.sections[sec.key] = { root: root, body: body, foot: foot };
  ctx.redraw(sec.key);
  var save = SECTION_SAVES[sec.key];
  if (save) foot.appendChild(saveBar(ctx, sec, save));
  return root;
}

// saveBar is one section's Save button, its message, and -- because every
// section here is read once at start -- the restart offer that follows a
// successful save. On success the section is redrawn from the server's
// answer, so "token set" badges and freshly issued hook URLs appear, and
// the OTHER sections are left exactly as typed.
function saveBar(ctx, sec, save) {
  var box = el("div", "");
  var bar = el("div", "formbar");
  var btn = el("button", "act primary", "Save " + sec.title.toLowerCase());
  btn.type = "button";
  var msg = el("div", "msg");
  var notice = el("div", "");
  btn.addEventListener("click", function () {
    msg.className = "msg"; msg.textContent = "";
    clear(notice);
    btn.disabled = true;
    api("POST", "api/settings", save.payload(ctx)).then(function (res) {
      btn.disabled = false;
      if (!res.ok) {
        msg.className = "msg err";
        msg.textContent = (res.data && res.data.error) || "the save was refused";
        return;
      }
      var fresh = (res.data && res.data.settings) || null;
      var finish = function () {
        if (fresh) { ctx.saved = fresh; save.apply(ctx, fresh); settingsLede(fresh); }
        ctx.redraw(sec.key);
        (save.also || []).forEach(function (k) { ctx.redraw(k); });
        notice.appendChild(restartOffer(save.restart));
        refreshStatus();
      };
      if (save.refetchCreds) {
        api("GET", "/api/checklist").then(function (list) { ctx.creds = hookCredsFrom(list); finish(); });
      } else {
        finish();
      }
    });
  });
  bar.appendChild(btn);
  box.appendChild(bar);
  box.appendChild(msg);
  box.appendChild(notice);
  return box;
}

// SECTION_SAVES: what each Save posts, and how the draft is refreshed from
// the answer. The payload shapes are load-bearing: the webhooks one is what
// TestSavingOneTabLeavesEveryOtherSectionAlone parses, byte for byte.
var SECTION_SAVES = {
  consoles: {
    payload: function (ctx) { return { consoles: ctx.draft.consoles || [] }; },
    apply: function (ctx, fresh) { ctx.draft.consoles = clone(fresh.consoles || []); },
    restart: "A console change"
  },
  channels: {
    payload: function (ctx) {
      var ch = ctx.draft.channels || {};
      return { channels: { ntfy: ch.ntfy, email: ch.email, pushover: ch.pushover, voice: ch.voice } };
    },
    apply: function (ctx, fresh) {
      var ch = ctx.draft.channels || (ctx.draft.channels = {});
      var fc = fresh.channels || {};
      ["ntfy", "email", "pushover", "voice"].forEach(function (k) { ch[k] = clone(fc[k] || { enabled: false }); });
    },
    also: ["escalation"],
    restart: "A channel change"
  },
  webhooks: {
    payload: function (ctx) {
      var draft = ctx.draft;
      return {
        hooks: draft.hooks || [],
        channels: { webhooks: (draft.channels && draft.channels.webhooks) || [] }
      };
    },
    apply: function (ctx, fresh) {
      ctx.draft.hooks = clone(fresh.hooks || []);
      var ch = ctx.draft.channels || (ctx.draft.channels = {});
      ch.webhooks = clone((fresh.channels && fresh.channels.webhooks) || []);
    },
    also: ["escalation"],
    refetchCreds: true,
    restart: "A webhook change"
  },
  escalation: {
    payload: function (ctx) { return { policies: ctx.draft.policies || {} }; },
    apply: function (ctx, fresh) { ctx.draft.policies = clone(fresh.policies || {}); },
    restart: "An escalation change"
  },
  rules: {
    payload: function (ctx) { return { rules: ctx.draft.rules || [] }; },
    apply: function (ctx, fresh) { ctx.draft.rules = clone(fresh.rules || []); },
    restart: "A rule change"
  },
  quiet: {
    payload: function (ctx) { return { quiet_hours: ctx.draft.quiet_hours || {} }; },
    apply: function (ctx, fresh) { ctx.draft.quiet_hours = clone(fresh.quiet_hours || {}); },
    restart: "A quiet hours change"
  },
  web: {
    payload: function (ctx) {
      var w = ctx.draft.web || {};
      return { web: { listen: w.listen || "", ack_base_url: w.ack_base_url || "",
        ack_listen: w.ack_listen || "", link_listen: w.link_listen || "" } };
    },
    apply: function (ctx, fresh) { ctx.draft.web = clone(fresh.web || {}); },
    restart: "A listen address change"
  }
};

// SECTION_RENDERERS fill a section's body from the draft. Each is given the
// whole context, because the escalation matrix's columns are the channels
// enabled in the draft and the rules editor wants the vocabulary the server
// sent alongside the settings.
var SECTION_RENDERERS = {
  consoles: renderConsolesSection,
  probe: renderProbeSection,
  channels: renderChannelsSection,
  webhooks: renderWebhooksSection,
  escalation: function (body, ctx) {
    // The view choice (matrix or ladders) lives on the context so a Save,
    // which redraws the section, does not flip the operator out of the
    // matrix they were just using.
    ctx.escView = ctx.escView || {};
    renderPolicies(body, ctx.draft, ctx.saved, ctx.escView);
  },
  rules: function (body, ctx) {
    var s = ctx.saved;
    // The review goes ABOVE the editor. A rule that no longer points at
    // anything is not something you find by reading the list -- it looks
    // exactly like a rule that works -- so it has to be the first thing on
    // the section rather than a note under it.
    body.appendChild(reviewCard(ctx.review));
    renderRules(body, ctx.draft, s.conditions || [], s.entities || []);
  },
  quiet: renderQuietSection,
  link: renderLinkSection,
  web: renderWebSection,
  password: renderPasswordSection
};

function renderConsolesSection(body, ctx) {
  var draft = ctx.draft;
  var consoles = draft.consoles || (draft.consoles = []);
  consoles.forEach(function (c, idx) {
    var card = el("div", "card");
    var f = el("div", "fields");
    f.appendChild(labelled("Name", bind(c, "name")));
    f.appendChild(labelled("Host or IP address", bind(c, "host")));
    var fpInput = bind(c, "fingerprint");
    f.appendChild(labelled("Certificate fingerprint (SHA-256, optional)", fpInput));
    card.appendChild(f);
    card.appendChild(fingerprintOffer(c, fpInput, ctx));

    // Sources were displayed as a comma-joined string and could only be
    // changed by editing YAML -- on the setting that decides whether anything
    // is watched at all. A console with no source is polled for nothing and
    // looks entirely healthy doing it.
    card.appendChild(el("div", "label", "Sources to watch"));
    var sr = el("div", "row");
    ["protect", "access", "network"].forEach(function (name) {
      sr.appendChild(labelled(name, inList(c, "sources", name)));
    });
    card.appendChild(sr);

    var ir = el("div", "row");
    // THE ADVICE USED TO BE IMPOSSIBLE TO FOLLOW. "Leave the check on and
    // paste a fingerprint" cannot connect to a console whose certificate is
    // signed by nothing: the chain verifier refuses before the pin is
    // consulted. An operator who pinned a console found it would not connect
    // and recovered by turning this on, which looks like being told to
    // weaken something to make the product work.
    //
    // A pin now replaces the chain check, so with a fingerprint set this
    // control decides nothing -- and says so rather than leaving somebody to
    // wonder which of the two is in charge.
    var pinned = !!(c.fingerprint || "").trim();
    ir.appendChild(labelled("Skip certificate check", check(c, "insecure_skip_verify"),
      pinned
        ? { text: "This console is pinned, so this setting changes nothing: the " +
            "fingerprint above is checked after every handshake and a console " +
            "that presents anything else is refused. That is a stricter check " +
            "than the usual one, not a weaker one.",
            label: "pinned — no effect", tone: "ok" }
        : { text: "A UniFi console's certificate is self-signed, so the usual " +
            "answer is to paste its SHA-256 fingerprint above: that pins this " +
            "one console and replaces the ordinary check. With no fingerprint, " +
            "turning this on accepts ANY certificate, which is the state an " +
            "attacker on your network needs.",
            label: "why not just skip?", tone: "warn" }));
    card.appendChild(ir);

    if (c.api_key_credential) {
      var cr = el("div", "row");
      cr.appendChild(el("span", "muted small",
        "service credential " + c.api_key_credential + " overrides the key in the file"));
      card.appendChild(cr);
    }
    secretRow(card, c.api_key_set, "API key", c, "api_key_new");
    card.appendChild(el("div", "note",
      "The stored key is never sent to this page, only whether one exists. " +
      "Protect, Access and Network each issue their OWN key — one key does " +
      "not cover the others, so the key above is used only where no key for " +
      "that application is set below."));
    appKeyRows(card, c);

    var rm = el("button", "act", "Remove this console");
    rm.type = "button";
    rm.addEventListener("click", function () {
      consoles.splice(idx, 1);
      ctx.redraw("consoles");
    });
    var rb = el("div", "formbar"); rb.appendChild(rm);
    card.appendChild(rb);
    body.appendChild(card);
  });
  if (!consoles.length) {
    body.appendChild(emptyState("No consoles configured",
      "Nothing is being watched. Add the console, with the API key it issued.",
      null, { icon: "camera", tone: "warn", compact: true }));
  }
  var addCon = el("button", "act" + (consoles.length ? "" : " primary"), "Add a console");
  addCon.type = "button";
  addCon.addEventListener("click", function () {
    consoles.push({ name: "", host: "", sources: ["protect"], api_key_set: false });
    ctx.redraw("consoles");
  });
  var addBar = el("div", "formbar"); addBar.appendChild(addCon);
  body.appendChild(addBar);
}

// enabledBox is a channel's Enabled checkbox. It redraws the escalation
// matrix when toggled, because the matrix's columns are the enabled
// channels and a box ticked here should appear there without a round trip.
function enabledBox(ctx, obj) {
  var b = check(obj, "enabled");
  b.addEventListener("change", function () { ctx.redraw("escalation"); });
  return b;
}

function renderChannelsSection(body, ctx) {
  var draft = ctx.draft;
  var ch = draft.channels || (draft.channels = {});
  // Every channel card is rendered whether or not the config already has one,
  // so a channel can be ADDED here rather than only edited. Before this, a
  // channel absent from the file was invisible in the interface and the only
  // way to add one was to hand-edit YAML -- which is exactly the person this
  // interface exists for.
  ch.ntfy = ch.ntfy || { enabled: false };
  ch.email = ch.email || { enabled: false, recipients: [] };
  ch.pushover = ch.pushover || { enabled: false };
  ch.voice = ch.voice || { enabled: false, recipients: [] };

  var nc = el("div", "card");
  nc.appendChild(channelTitle("bell", "ntfy", ch.ntfy.enabled));
  var nf = el("div", "fields");
  nf.appendChild(labelled("Enabled", enabledBox(ctx, ch.ntfy)));
  var nurl = bind(ch.ntfy, "server_url");
  // The default is real and usable, so it is shown as the placeholder rather
  // than left as an empty box somebody has to know how to fill.
  nurl.placeholder = "https://ntfy.sh  (leave blank for the public server)";
  nf.appendChild(labelled("Server URL", nurl));
  nf.appendChild(labelled("Topic", bind(ch.ntfy, "topic"),
    { text: "Treat the topic name as a password. A guessable topic on the public " +
      "ntfy.sh server is readable by anybody who guesses it.", label: "why?", tone: "warn" }));
  nc.appendChild(nf);
  secretRow(nc, ch.ntfy.token_set, "token", ch.ntfy, "token_new");
  testRow(nc, "ntfy");
  body.appendChild(nc);

  var ec = el("div", "card");
  ec.appendChild(channelTitle("envelope", "Email", ch.email.enabled));
  var ef = el("div", "fields");
  ef.appendChild(labelled("Enabled", enabledBox(ctx, ch.email)));
  ef.appendChild(labelled("Host", bind(ch.email, "host")));
  ef.appendChild(labelled("Port", bind(ch.email, "port", true)));
  ef.appendChild(labelled("TLS", pick(ch.email, "tls", ["auto", "starttls", "implicit", "none"], "auto (default)")));
  ef.appendChild(labelled("Username", bind(ch.email, "username")));
  ef.appendChild(labelled("From", bind(ch.email, "from")));
  ef.appendChild(labelled("Recipients (comma separated)", bindList(ch.email, "recipients")));
  ec.appendChild(ef);
  secretRow(ec, ch.email.password_set, "password", ch.email, "password_new");
  testRow(ec, "email");
  body.appendChild(ec);

  var pc = el("div", "card");
  pc.appendChild(channelTitle("phone", "Pushover", ch.pushover.enabled));
  var pf = el("div", "fields");
  pf.appendChild(labelled("Enabled", enabledBox(ctx, ch.pushover)));
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

  var vc = el("div", "card");
  vc.appendChild(channelTitle("phone", "Voice call (Twilio)", ch.voice.enabled));
  var vf = el("div", "fields");
  vf.appendChild(labelled("Enabled", enabledBox(ctx, ch.voice)));
  var vfrom = bind(ch.voice, "from");
  vfrom.placeholder = "+15552223214";
  vf.appendChild(labelled("Caller ID", vfrom));
  var vto = bindList(ch.voice, "recipients");
  vto.placeholder = "+15558675310, +15558675311";
  vf.appendChild(labelled("Numbers to call (comma separated)", vto));
  vf.appendChild(labelled("Voice", pick(ch.voice, "voice", VOICE_SAY_VOICES, "man (default)")));
  vf.appendChild(labelled("Language", pick(ch.voice, "language", VOICE_SAY_LANGUAGES, "en-US (default)")));
  vc.appendChild(vf);
  secretRow(vc, ch.voice.account_sid_set, "account SID", ch.voice, "account_sid_new");
  secretRow(vc, ch.voice.auth_token_set, "auth token", ch.voice, "auth_token_new");
  vc.appendChild(el("div", "note",
    "Two credentials from the Twilio console, and they are easy to swap. The " +
    "account SID is the one that starts AC; the auth token is the other. The " +
    "wrong way round, Twilio answers permission denied, which reads as a bad " +
    "token rather than as the pair being reversed."));
  // The cost and the trial-account trap, as a callout: this is the one
  // channel where a misconfiguration costs money or rings nobody.
  vc.appendChild(callout(
    "Every number here is a BILLED PHONE CALL, to every number, every time a " +
    "rung naming voice fires -- including each repeat. Write numbers as + then " +
    "the country code with no spaces, dashes or brackets (+15558675310). On a " +
    "Twilio trial account the caller ID and every number called must be " +
    "verified in the console first, and Twilio plays its own message asking " +
    "for a keypress before the alert is spoken -- so on a trial account an " +
    "unattended phone hears nothing at all.", "warn", "Billed, per call"));
  vc.appendChild(el("div", "note",
    "The call speaks the alert and hangs up. There is no way to acknowledge " +
    "from the handset, so the ladder keeps escalating until somebody " +
    "acknowledges here or from a link in another channel."));
  // Not decoration: voice is on NO default ladder, so a site that enables it
  // here and stops has a channel that is configured, healthy, tested, and
  // will never place a call.
  var ladderNote = el("span", "");
  ladderNote.appendChild(document.createTextNode(
    "VOICE IS ON NO DEFAULT ESCALATION LADDER. Enabling it here is not enough: " +
    "tick voice on a row of the "));
  var esc = el("a", null, "escalation matrix");
  esc.href = "#settings/escalation";
  ladderNote.appendChild(esc);
  ladderNote.appendChild(document.createTextNode(
    ", or it will never ring anybody. That is deliberate -- telephoning " +
    "somebody at 3am is not something to switch on for every installation by default."));
  vc.appendChild(callout(ladderNote, "info", "Then put it on a rung"));
  // The generic "Sent." line the server prints after a test is untrue for
  // this channel, because no call was placed. The truth is printed here
  // instead.
  testRow(vc, "voice", {
    button: "Check the credentials",
    note: "This button does NOT place a call. A test that costs money and " +
      "wakes somebody is not a harmless test, so it checks the account SID " +
      "and auth token against Twilio instead. It does not prove the caller ID " +
      "can dial your numbers -- only a real alert does that.",
    success: "Credentials accepted by Twilio. No call was placed and nobody's " +
      "phone rang. This does not prove the caller ID can reach your numbers."
  });
  body.appendChild(vc);

  // Outbound webhook endpoints are under Webhooks, with the inbound ones:
  // they are the same idea pointing opposite ways.
  var anyEnabled = ["ntfy", "email", "pushover", "voice"].some(function (k) {
    return ch[k] && ch[k].enabled;
  }) || (ch.webhooks || []).some(function (w) { return w.enabled; });
  if (!anyEnabled) {
    body.appendChild(emptyState("No channel is enabled",
      "Incidents will still be tracked, and nobody will be told.",
      null, { icon: "bell", tone: "warn", compact: true }));
  }
}

// channelTitle is a channel card's heading: glyph, name, and whether it is
// on -- so a scroll down the section reads which channels are live without
// finding each Enabled box.
function channelTitle(iconName, name, enabled) {
  var t = el("div", "card-title");
  t.appendChild(icon(iconName));
  t.appendChild(document.createTextNode(name));
  t.appendChild(badge(enabled ? "on" : "off", enabled ? "on" : "is-muted"));
  return t;
}

function renderWebhooksSection(body, ctx) {
  var draft = ctx.draft, s = ctx.saved, creds = ctx.creds;
  // Vocabulary from the rest of the product: UniFi has "alarm rules", and
  // the arrow says which way the data goes without a preposition to misread.
  body.appendChild(el("h3", null, "UniFi alarm rules (UniFi \u2192 here)"));
  body.appendChild(el("p", "",
    "WAN outages, threat detections, PoE faults and Protect's own hardware " +
    "alarms are not readable by any API. They exist ONLY as Alarm Manager " +
    "rules that push to a URL, and no API can create those rules -- so these " +
    "endpoints are the only way those alarms reach this product at all."));
  renderHooks(body, draft, s.hook_conditions || [], creds || {});

  body.appendChild(el("h3", null, "Push to your own systems (here \u2192 you)"));
  body.appendChild(el("p", "",
    "One JSON POST per alert, to anything you run. Each endpoint has a name, " +
    "and an escalation rung refers to it by that name -- so a home automation " +
    "box and an on-call service can be told about different severities."));
  renderOutboundWebhooks(body, draft);
}

function renderQuietSection(body, ctx) {
  var draft = ctx.draft;
  var qc = el("div", "card");
  var q = draft.quiet_hours || (draft.quiet_hours = {});
  var qf = el("div", "fields");
  qf.appendChild(labelled("Enabled", check(q, "enabled")));
  qf.appendChild(labelled("Start (HH:MM)", bind(q, "start")));
  qf.appendChild(labelled("End (HH:MM)", bind(q, "end")));
  // Worth saying that this is not only about quiet hours. It is also the
  // clock every alert is announced in -- a voice call speaks a bare "at 3:14
  // PM" with no zone in it -- and an operator whose quiet hours are switched
  // off would otherwise have no reason to set it at all.
  qf.appendChild(labelled("Time zone (IANA name)", bind(q, "zone"),
    "The site's wall clock. Used for quiet hours AND for the times in your " +
    "alerts, so set it even if quiet hours are off. Leave it blank and this " +
    "machine's own clock is used, which is right when the machine sits at the " +
    "site and wrong when it is a server in a datacentre running on UTC. " +
    "Example: America/New_York."));
  qc.appendChild(qf);
  qc.appendChild(el("div", "note",
    "Held alerts are delivered when the window ends. Only severities whose " +
    "row in the escalation matrix respects quiet hours are held."));
  qc.appendChild(callout("Quiet hours never apply to critical. That control does not exist.", "info"));
  body.appendChild(qc);
}

function renderWebSection(body, ctx) {
  var draft = ctx.draft;
  var wc = el("div", "card");
  var w = draft.web || (draft.web = {});
  var wf = el("div", "fields");
  var listen = bind(w, "listen");
  listen.placeholder = "0.0.0.0:8330";
  wf.appendChild(labelled("Listen on", listen,
    "Where this page and the acknowledgement links are served. 0.0.0.0:8330 " +
    "means every interface; a single address means only that one, so " +
    "127.0.0.1 stops answering.", "web.listen"));
  var ackUrl = bind(w, "ack_base_url");
  ackUrl.placeholder = "http://192.168.1.50:8330";
  // The warning belongs AT this field: a blank here does not stop alerts,
  // it strips the acknowledge link off every one of them.
  wf.appendChild(labelled("Ack link address", ackUrl,
    { text: "The address put into every alert's acknowledge link -- this " +
      "machine as a phone reaches it, not 127.0.0.1. Blank means alerts carry " +
      "no acknowledge link at all, and the only way to stop one is this page.",
      label: "blank?", tone: "warn" }, "web.ack_base_url"));
  var ackListen = bind(w, "ack_listen");
  ackListen.placeholder = "blank = none \u00b7 auto \u00b7 0.0.0.0:PORT";
  // The warning belongs AT this field, for the same reason as the one above:
  // the natural thing to type here is the public hostname being forwarded,
  // and that names an address this machine does not have -- which stopped a
  // real service and took this page down with it.
  wf.appendChild(labelled("Ack-only listener", ackListen,
    { text: "Where THIS MACHINE listens for acknowledgements: \"auto\", or " +
      "0.0.0.0 and a port. Never your public hostname -- that goes in Ack " +
      "link address above. A second listener starts that serves ONLY /ack/, " +
      "and that is the port to forward from outside, if you must: a NAT " +
      "forward cannot pick a path, so forwarding the main listen address " +
      "publishes the whole status page along with it.",
      label: "public name?", tone: "warn" }, "web.ack_listen"));

  // THE FIELD THE PEER LINK SECTION SENDS PEOPLE TO. It has to sit here, and
  // it has to be named the same way in both places: the only other thing on
  // this screen with "link address" in its label is the ACK one, which is
  // what an operator following that instruction set instead -- and then
  // restarted, and found the Peer link section unchanged, because nothing
  // had changed.
  var linkListen = bind(w, "link_listen");
  linkListen.placeholder = "blank = none · auto · 0.0.0.0:PORT";
  wf.appendChild(labelled("Peer link address", linkListen,
    { text: "Where THIS MACHINE listens for a paired product: \"auto\", or " +
      "0.0.0.0 and a port. A third listener starts that serves ONLY /link/, " +
      "over TLS with its own certificate. Blank means no peer can pair, and " +
      "clearing it cuts off any that already have -- they hold this address. " +
      "It takes a restart, and the Peer link section stays empty until then.",
      label: "paired already?", tone: "warn" }, "web.link_listen"));
  wc.appendChild(wf);
  var wr = el("div", "row");
  wr.appendChild(badge(w.ack_key_set ? "ack signing key set" : "ack signing key not set",
    w.ack_key_set ? "on" : "off"));
  wr.appendChild(el("span", "muted small",
    "Minted on first start. Not editable here: rotating it would invalidate every link already sent."));
  wc.appendChild(wr);
  body.appendChild(wc);
}

function renderPasswordSection(body, ctx) {
  var pwc = el("div", "card signin");
  var cur = el("input"); cur.type = "password"; cur.autocomplete = "current-password";
  var neu = el("input"); neu.type = "password"; neu.autocomplete = "new-password";
  pwc.appendChild(labelled("Current password", cur));
  pwc.appendChild(labelled("New password (at least " + state.minPassword + " characters)", neu));
  var pmsg = el("div", "msg");
  var pbtn = el("button", "act primary", "Change password");
  pbtn.type = "button";
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

// ---- peer link ----

// linkCountdown is the ticker under a live pairing code. Module level and
// cleared before every redraw, because the section redraws on its own after
// each action and two tickers on one code count down at twice the rate.
var linkCountdown = null;
function stopLinkCountdown() {
  if (linkCountdown) { clearInterval(linkCountdown); linkCountdown = null; }
}

// refreshLink refetches pairing state and redraws only that section, so
// offering a code does not throw away whatever else is typed on the page.
function refreshLink() {
  if (!settingsCtx) { refreshSettings(); return; }
  api("GET", "/api/link").then(function (res) {
    if (!settingsCtx) return;
    settingsCtx.link = (res.ok && res.data) || {};
    settingsCtx.redraw("link");
  });
}

// renderLinkSection is the pairing click-path.
//
// It exists because the routes did not add up to a thing an operator could
// do: a code could be generated with a signed-in POST and there was no button
// anywhere, so the first pair of this product with another needed a terminal
// and a hand-written request. A connector nobody can start is a connector
// nobody has.
function renderLinkSection(body, ctx) {
  stopLinkCountdown();
  var st = ctx.link || {};

  // No listener is not a failure, and saying so in the language of failure
  // would send somebody looking for a broken thing. There is simply nowhere
  // for a peer to pair TO until an address is set.
  if (!st.available) {
    body.appendChild(callout(
      "No peer link listener is running, so there is nowhere for another " +
      "product to pair. Set the peer link address in Web — the field is " +
      "called \"Peer link address\", not the ack one above it — then " +
      "restart and come back here.", "info", "Nothing is listening"));
    body.appendChild(el("div", "note",
      "A peer link lets another Xtremission product -- Sentry, for door " +
      "events -- raise incidents here instead of running its own alerting. " +
      "It is optional and nothing depends on it."));
    return;
  }

  // What the peer needs, and the fingerprint in full: it is the value the
  // peer PINS, and a truncated one is something somebody pastes and then
  // wonders about.
  var where = el("div", "card");
  where.appendChild(el("div", "card-title", "What the peer needs"));
  where.appendChild(el("div", "label", "Address"));
  where.appendChild(credRow(st.address || "", true));
  where.appendChild(el("div", "label", "Certificate fingerprint (SHA-256)"));
  where.appendChild(credRow(st.fingerprint || "", true));
  where.appendChild(el("div", "note",
    "The peer pins this fingerprint, and proves at pairing that it saw this " +
    "exact certificate. That is what stops anything terminating TLS in " +
    "between from pairing in your place, so hand it over the way you would a " +
    "password -- and if the peer reports a different one, stop."));
  body.appendChild(where);

  body.appendChild(pairingCard(st));

  // Who is paired, and -- the part that is otherwise invisible -- whether
  // each one is actually serving what it claimed.
  var peers = st.peers || [];
  var pc = el("div", "card");
  pc.appendChild(el("div", "card-title", "Paired products"));
  if (!peers.length) {
    pc.appendChild(el("div", "muted", "Nothing is paired."));
  } else {
    peers.forEach(function (p) { pc.appendChild(peerCard(p)); });
  }
  body.appendChild(pc);

  // ABOVE the receipts, deliberately. Without it, a peer shipping a new
  // condition is a run of identical refusals in a log, and the only way
  // forward was a text editor.
  body.appendChild(proposalsCard(st.proposals || []));

  body.appendChild(receiptsCard(st.receipts || [], st.since_seconds || 0));
}

// proposalsCard is what a peer is asking to be allowed to send.
//
// The vocabulary a peer may use is closed, and stays closed: a condition
// outside the approved manifest is refused rather than bucketed, because a
// silent catch-all recreates the open vocabulary a closed one exists to
// prevent. This does not widen what arrives. It changes what SAYING YES costs.
//
// Before it, a peer shipping a twelfth condition meant opening config.yaml on
// the operator's machine, or re-pairing the product -- which rotates a working
// credential in order to fix a spelling, and is how a second site's peer gets
// revoked by accident.
function proposalsCard(list) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Waiting for your decision"));
  if (!list.length) {
    card.appendChild(el("div", "muted",
      "No peer is sending anything it has not declared."));
    return card;
  }
  card.appendChild(el("div", "muted small",
    "These events were REFUSED and stay refused until you approve them. A " +
    "peer's next release usually does this: it has learned to report " +
    "something your approved list does not have a name for."));
  list.forEach(function (p) { card.appendChild(proposalRow(p)); });
  return card;
}

function proposalRow(p) {
  var row = el("div", "card");
  var head = el("div", "row");
  head.appendChild(badge(p.product, "is-muted"));
  head.appendChild(el("strong", "grow", p.condition));
  // The count, not just the fact. One refusal is a peer's author testing
  // something; forty-seven is a door that has been reporting a real condition
  // to nobody for two days.
  head.appendChild(badge(p.count + " refused", p.count > 1 ? "is-warn" : "is-muted"));
  row.appendChild(head);

  if (p.title) {
    row.appendChild(el("div", "muted small",
      "Its own words for the last one: “" + p.title + "”"));
  }
  row.appendChild(el("div", "muted small",
    "First tried " + stamp(p.first) + ", last " + stamp(p.last) + "."));

  // What was NOT listed. A card showing four proposals and silently dropping
  // ninety tells the operator their peer sends four things it does not
  // declare.
  if (p.unusable) {
    row.appendChild(callout(p.unusable + " other name" + (p.unusable === 1 ? "" : "s") +
      " from this peer cannot be approved at all: a condition has to begin " +
      "with the product's own name. That is a bug at its end, not a decision " +
      "for you.", "warn"));
  }
  if (p.overflowed) {
    row.appendChild(callout(p.overflowed + " further name" +
      (p.overflowed === 1 ? " was" : "s were") + " turned away because this " +
      "list is full. Something at its end is generating condition names.", "warn"));
  }

  row.appendChild(proposalForm(p));
  return row;
}

// proposalForm is the decision. The MEANING is required and starts empty of
// anything the peer wrote, because a meaning nobody wrote is a meaning nobody
// reviewed -- and this sentence is what the next person reads when the alarm
// goes off at three in the morning.
function proposalForm(p) {
  var box = el("div", "");

  var meaning = keepOutOfPasswordManagers(el("input"));
  meaning.type = "text";
  meaning.placeholder = p.title || "what this means, in your own words";
  box.appendChild(labelled("What does it mean?", meaning,
    "Required. You are approving this sentence, not the peer's."));

  var sev = el("select");
  ["critical", "high", "medium", "low", "info"].forEach(function (v) {
    var o = document.createElement("option");
    o.value = v; o.textContent = v;
    if (v === p.severity) o.selected = true;
    sev.appendChild(o);
  });
  box.appendChild(labelled("Treat it as", sev,
    "The peer proposed " + (p.severity || "nothing usable") + ". Your rules " +
    "can still change it."));

  var mom = el("input");
  mom.type = "checkbox";
  mom.style.width = "auto";
  box.appendChild(labelled("It is momentary: it clears by itself", mom,
    "Tick this for something that comes and goes on its own. An incident " +
    "that cleared before its first rung is then not delivered at all, which " +
    "is right for a busy condition and wrong for one that matters."));

  box.appendChild(el("div", "note",
    "A condition that should hand a capability BACK to this product while it " +
    "is raised — “alive, but cannot see the doors” — cannot be set here. That " +
    "belongs with the whole manifest at pairing, where the peer declares it."));

  var bar = el("div", "formbar");
  var msg = el("div", "msg");

  var ok = el("button", "act primary small", "Approve it");
  ok.type = "button";
  ok.addEventListener("click", function () {
    var m = meaning.value.trim();
    if (!m) {
      msg.className = "msg err";
      fill(msg, "Write what it means first. A condition with no meaning " +
        "cannot be reviewed by anybody later, including you.");
      meaning.focus();
      return;
    }
    ok.disabled = true;
    msg.className = "msg";
    fill(msg, "");
    api("POST", "/api/link/peers/" + encodeURIComponent(p.product) + "/conditions", {
      condition: p.condition, meaning: m, severity: sev.value,
      momentary: mom.checked
    }).then(function (res) {
      ok.disabled = false;
      if (!res.ok) {
        msg.className = "msg err";
        fill(msg, (res.data && res.data.error) || "that could not be approved");
        return;
      }
      afterAmendment(p.condition);
    });
  });

  var no = el("button", "act small", "Not now");
  no.type = "button";
  no.addEventListener("click", function () {
    no.disabled = true;
    api("DELETE", "/api/link/peers/" + encodeURIComponent(p.product) +
      "/conditions/" + encodeURIComponent(p.condition)).then(function () {
      afterAmendment("");
    });
  });

  bar.appendChild(ok);
  bar.appendChild(no);
  box.appendChild(bar);
  box.appendChild(msg);
  box.appendChild(el("div", "note",
    "“Not now” only clears it from this list. The peer goes on sending it and " +
    "the question comes back, because a peer that keeps sending something is " +
    "a fact about the peer rather than something to hide."));
  return box;
}

// afterAmendment re-reads the link state and, when something was approved,
// says what still has to happen.
//
// The notice goes in the section FOOT for the same reason the rule review's
// does: redraw() refills the body, so anything appended to the card is
// detached the moment the list is rebuilt -- and the one sentence that matters
// would be appended to an element no longer on the page.
function afterAmendment(approved) {
  var ctx = settingsCtx;
  if (!ctx) { refreshSettings(); return; }
  api("GET", "/api/link").then(function (res) {
    if (settingsCtx !== ctx) return;
    if (res.ok) ctx.link = res.data || {};
    ctx.redraw("link");
    if (!approved) return;
    var sec = ctx.sections.link;
    if (sec && sec.foot) {
      clear(sec.foot);
      sec.foot.appendChild(restartOffer("Approving " + approved + ", and that"));
    }
  });
}

// pairingCard offers a code, or shows the one on offer with its clock.
function pairingCard(st) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Pair a product"));
  var msg = el("div", "msg");
  var bar = el("div", "formbar");

  if (st.code) {
    card.appendChild(el("div", "label", "Pairing code"));
    card.appendChild(credRow(st.code, true));

    var left = el("div", "note");
    var secs = st.expires_seconds || 0;
    // Counted down to the second rather than through age(), which rounds to
    // the minute: the operator is typing this into another machine against a
    // ten-minute clock, and "1m" covering anything from 61 to 119 seconds is
    // the difference between finishing and starting again.
    var mmss = function (n) {
      var m = Math.floor(n / 60), sec = n % 60;
      return m + ":" + (sec < 10 ? "0" : "") + sec;
    };
    var tick = function () {
      left.textContent = secs > 0
        ? "Expires in " + mmss(secs) + ". One use only."
        : "Expired. Offer another.";
      if (secs <= 0) { stopLinkCountdown(); refreshLink(); return; }
      secs--;
    };
    tick();
    stopLinkCountdown();
    linkCountdown = setInterval(tick, 1000);
    card.appendChild(left);

    var cancel = el("button", "act danger", "Cancel this code");
    cancel.type = "button";
    cancel.addEventListener("click", function () {
      cancel.disabled = true;
      api("DELETE", "/api/link/code").then(function (res) {
        cancel.disabled = false;
        if (!res.ok) {
          msg.className = "msg err";
          msg.textContent = (res.data && res.data.error) || "that was refused";
          return;
        }
        refreshLink();
      });
    });
    bar.appendChild(cancel);
  } else {
    var offer = el("button", "act primary", "Offer a pairing code");
    offer.type = "button";
    offer.addEventListener("click", function () {
      offer.disabled = true;
      msg.className = "msg"; msg.textContent = "";
      api("POST", "/api/link/code", {}).then(function (res) {
        offer.disabled = false;
        if (!res.ok) {
          msg.className = "msg err";
          msg.textContent = (res.data && res.data.error) || "that was refused";
          return;
        }
        refreshLink();
      });
    });
    bar.appendChild(offer);
  }

  card.appendChild(bar);
  card.appendChild(msg);
  // Said plainly, because every one of these is a way the pairing is not what
  // the operator thinks it is.
  card.appendChild(el("div", "note",
    "Type the code into the other product along with the address and " +
    "fingerprint above. It lasts ten minutes, works once, and is voided " +
    "after five wrong answers. Pairing hands that product a credential that " +
    "can raise alarms here and take over a capability, so give it out the " +
    "way you would a password and cancel it if you change your mind."));
  return card;
}

// peerCard is one paired product, and whether it is really serving.
function peerCard(p) {
  var card = el("div", "card");
  var head = el("div", "row");
  head.appendChild(el("span", "title", p.product));
  if (p.capability) {
    // Holding is NOT liveness, and this is the only place that difference is
    // visible. A peer can be alive, heartbeating and unable to see a single
    // door, and in that state every other indicator on this interface reads
    // healthy -- which is exactly the state where nobody is watching.
    head.appendChild(badge(p.holding
      ? "serving " + p.capability
      : "not serving " + p.capability, p.holding ? "ok" : "warn"));
  }
  card.appendChild(head);
  if (p.capability && !p.holding) {
    card.appendChild(el("div", "note", p.why
      ? "Why: " + p.why + ". Until it serves again, this product's own " +
        "sources are raising " + p.capability + " events as usual."
      : "It has not taken the capability over yet, so this product's own " +
        "sources are still raising " + p.capability + " events."));
  }
  var meta = el("div", "muted small",
    p.link_id + " · " + p.conditions +
    (p.conditions === 1 ? " condition" : " conditions"));
  card.appendChild(meta);

  var rm = el("button", "act danger", "Forget this product");
  rm.type = "button";
  var rmsg = el("div", "msg");
  rm.addEventListener("click", function () {
    if (!window.confirm(
      "Forget \"" + p.product + "\"?\n\n" +
      "Its credential is deleted here, so everything it sends from then on " +
      "is refused and it cannot pair again without a new code. Any capability " +
      "it was serving comes straight back to this product's own sources.")) {
      return;
    }
    rm.disabled = true;
    api("DELETE", "/api/link/peers/" + encodeURIComponent(p.product)).then(function (res) {
      rm.disabled = false;
      if (!res.ok) {
        rmsg.className = "msg err";
        rmsg.textContent = (res.data && res.data.error) || "that was refused";
        return;
      }
      refreshLink();
      refreshStatus();
    });
  });
  var rbar = el("div", "formbar"); rbar.appendChild(rm);
  card.appendChild(rbar);
  card.appendChild(rmsg);
  return card;
}

// LINK_CAUSES turns a refusal's label into what to do about it.
//
// The label is what the server counts by; this is what the operator reads.
// "unknown-link-id" is precise and tells somebody standing at the screen
// nothing, and the difference between a peer whose credential we do not have
// and a peer that disagrees with us about the key is two entirely different
// afternoons -- which is exactly why the two are distinguished here and
// deliberately NOT distinguished on the wire.
var LINK_CAUSES = {
  "method-not-allowed": "Something used the wrong HTTP method. Every route here but the identify probe takes a signed POST.",
  "no-such-route": "Something asked for a path that does not exist here. Most often a scanner; occasionally a peer built against a different version.",
  "body-unreadable": "The request body could not be read. Usually a connection that died mid-send.",
  "body-over-limit": "The body was larger than an event is allowed to be. Nothing here sends anything that size.",
  "unsigned": "It sent no signature at all. That is usually something other than a peer knocking on the port.",
  "malformed-auth": "Its authentication headers were missing or unreadable.",
  "unknown-link-id": "It used a credential this installation has no record of. Either it was paired somewhere else, or you have forgotten it here and it has not been told.",
  "bad-signature": "Its credential is one we know and the signature did not match it. The two ends disagree about the key, so pair again rather than hunting for a typo.",
  "clock-skew": "Its clock is too far from this machine's. Fix the time on one of them; signed requests expire on purpose.",
  "replayed-nonce": "It reused a request identifier. Ordinarily a retry gone wrong, and the refusal is what stops it counting twice.",
  "nonce-table-full": "It sent far more than expected in five minutes. Nothing is lost, but something on that end is looping.",
  "no-peer-for-link": "It authenticated against a credential with no product behind it. That should not be possible; tell somebody.",
  "malformed-envelope": "It authenticated and then sent something that is not an event.",
  "invalid-envelope": "It sent something outside the manifest you approved — a severity, a state or a field that does not match what it declared.",
  "undeclared-condition": "It sent a condition its approved manifest does not contain, and the event was refused. Usually its next release doing something new. There is nothing to fix at the other end: the proposal is above, with what it means and what it wants to raise, and approving it is what lets the next one through.",
  "envelope-version": "It speaks a different version of the link protocol. Nothing is wrong with your setup; one of the two products needs upgrading.",
  "over-the-rate-limit": "It sent far more in a minute than any working peer does. Nothing is lost — it will retry — but something on that end is looping, or somebody has a credential they should not.",
  "store-failed": "This machine could not record the event id. The peer will retry.",
  "ingest-failed": "This machine could not take the event. It was refused so the peer retries rather than assuming it landed.",
  "pairing-unavailable": "Pairing is not possible on this build.",
  "pairing-body": "Its pairing request was unreadable or too large.",
  "pairing-none-offered": "It tried to pair with no code on offer. Press Offer a pairing code first.",
  "pairing-code-expired": "The code had run out. Offer another.",
  "pairing-code-used": "The code had already been used. They are single-use; offer another.",
  "pairing-code-voided": "The code was voided after five wrong answers. Offer another -- and if the product at the other end believes it is typing the right one, look at the two below this.",
  "pairing-bad-proof": "It did not prove it knew the code. A mistyped code, or the wrong product.",
  "pairing-fingerprint-mismatch": "IT SAW A DIFFERENT CERTIFICATE. Something is terminating TLS between you and it. This is not a typo and it is not a configuration mistake; stop and find out what is in the middle.",
  "pairing-manifest": "It did not declare what it would send, so there is nothing to approve.",
  "pairing-store-failed": "The pairing worked and this machine could not save it, so the peer was told it failed. Nothing was granted.",
  "identify-window-closed": "Something asked what this port is while no pairing code was on offer. It was told nothing. If that was your other product looking for this one, offer a code and let it look again."
};

// receiptsCard is the reason a refusal is readable at all.
//
// The link port answers EVERY failure with a bare 404 and an empty body --
// unknown link id, wrong signature, stale clock, replayed nonce, mismatched
// fingerprint, absent route, all identical -- because an endpoint that tells
// them apart tells an attacker which half to keep working on. That is right
// on the wire and useless to the operator, who is then debugging a number.
// This is the other side of the trade: the real reason, on a page that
// already needs a password.
function receiptsCard(rs, sinceSeconds) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "What peers have done here"));

  // THESE ARE IN MEMORY AND START EMPTY AT EVERY RESTART, and the empty state
  // has to say so. It used to read "nothing has reached the link listener yet
  // -- a peer that appears to be trying and is not here is not reaching this
  // machine at all", which is true of a fresh install and a lie two minutes
  // after a restart. Confidently wrong advice is worse than none: it sends
  // somebody to check firewalls and ports while nothing is wrong.
  var window_ = sinceSeconds
    ? "in the " + age(sinceSeconds) + " since this service started"
    : "since this service started";
  if (!rs.length) {
    card.appendChild(el("div", "muted",
      "Nothing has reached the link listener " + window_ + ". If a peer has " +
      "been trying for longer than that, restart it or wait for its next " +
      "heartbeat before concluding it cannot reach this machine."));
    card.appendChild(el("div", "note",
      "This list is kept in memory, so a restart empties it. It is not the " +
      "audit log, which survives."));
    return card;
  }
  card.appendChild(el("div", "note", "The last " + rs.length +
    (rs.length === 1 ? " request" : " requests") + " " + window_ +
    ". Kept in memory, so a restart empties this."));
  var t = table(["When", "Result", "Route", "Why"]);
  t.className = "audit";
  rs.forEach(function (r) {
    var row = t.tBodies[0].insertRow();
    if (!r.accepted) row.className = "is-err";
    row.insertCell().textContent = stamp(r.at);
    var rc = row.insertCell();
    rc.appendChild(badge(r.accepted ? (r.duplicate ? "duplicate" : "accepted") : "refused",
      r.accepted ? (r.duplicate ? "" : "ok") : "err"));
    row.insertCell().textContent = r.route || "";
    var why = row.insertCell();
    // The plain-English answer first, because that is what somebody standing
    // at this screen came for; the server's own sentence under it, because it
    // carries the specifics -- how far off the clock was, what the envelope
    // got wrong -- that no fixed translation can.
    var said = LINK_CAUSES[r.cause];
    if (said) why.appendChild(el("div", r.accepted ? "" : "audit-error", said));
    if (r.reason && r.reason !== said) {
      why.appendChild(el("div", said ? "muted small" : (r.accepted ? "" : "audit-error"), r.reason));
    }
    if (!r.accepted && r.link_id) why.appendChild(el("div", "muted small", r.link_id));
  });
  var sx = el("div", "scroll-x");
  sx.appendChild(t);
  card.appendChild(sx);
  return card;
}

// ---- the rail ----

// markRail lights the rail entry for one section.
function markRail(section) {
  var links = document.querySelectorAll ? document.querySelectorAll(".rail a[data-section]") : [];
  for (var i = 0; i < links.length; i++) {
    if (links[i].getAttribute("data-section") === section) links[i].setAttribute("aria-current", "true");
    else links[i].removeAttribute("aria-current");
  }
}

// watchRail keeps the rail's current entry on the section in view as the
// page scrolls. One listener for the page's life; it does nothing unless
// Settings is showing. The section whose top is nearest the header wins,
// measured against a line just below the header that comes down to meet the
// last sections as the page runs out of scroll.
var railWatched = false;
function watchRail() {
  if (railWatched || !window.addEventListener) return;
  railWatched = true;
  var pending = false;
  var update = function () {
    pending = false;
    if (state.tab !== "settings" || !settingsCtx) return;
    // The reference line: just under the header, or just under the top of the
    // viewport if the header is not there. Clamped at 0 because the bottom
    // edge is only a sensible line to measure from while the header is
    // actually stuck; a header that has scrolled away reports a bottom of
    // -5469, and a reference line that far above the viewport marks whatever
    // section the reader passed several screens ago. That is a real bug this
    // page shipped with (a body of `height:100%` confined the header's sticky
    // box to one screenful), and the clamp is what makes the rail correct
    // whether or not sticky is working at this width.
    var bar = document.querySelector("header.bar");
    var rect = bar && bar.getBoundingClientRect ? bar.getBoundingClientRect() : null;
    var top = (rect ? Math.max(0, rect.bottom) : 0) + 24;
    // The last sections on the page can never be brought up to that line:
    // the document runs out of scroll before their tops get there. On an
    // 800x600 window Password is the final section and its top stops 254px
    // down the screen with nothing below it, so the rail said "Web" while
    // the reader was at the end and could go no further.
    //
    // So over the final screenful the line comes down to meet them, reaching
    // the bottom of the viewport exactly as the scroll runs out. Both the
    // line and the content are moving the same way, which keeps the rail
    // going forward and never back, and it gives every trailing section a
    // turn rather than jumping to the last one -- at 1280x900 two sections
    // are stranded below the line at the end, not one, and Quiet hours was
    // skipped entirely by a rule that only rescued the final section.
    //
    // Only where there is scroll to run out of. On a Settings page short
    // enough to fit one screen the line stays where it is and the first
    // section is still the answer.
    var doc = document.documentElement;
    var y = window.pageYOffset !== undefined ? window.pageYOffset : doc.scrollTop;
    var left = doc.scrollHeight - window.innerHeight - y;
    var line = top;
    if (doc.scrollHeight > window.innerHeight) line = Math.max(top, window.innerHeight - left);

    var current = null;
    SETTINGS_SECTIONS.forEach(function (sec) {
      var sc = settingsCtx.sections[sec.key];
      if (!sc || !sc.root.getBoundingClientRect) return;
      if (sc.root.getBoundingClientRect().top <= line) current = sec.key;
    });
    markRail(current || SETTINGS_SECTIONS[0].key);
  };
  window.addEventListener("scroll", function () {
    if (pending) return;
    pending = true;
    if (window.requestAnimationFrame) window.requestAnimationFrame(update); else update();
  }, { passive: true });
}

// keepOutOfPasswordManagers marks a field that is NOT the operator's own
// login, so a password manager does not stuff it.
//
// A settings page full of credentials is a page full of things that look like
// a login form to a heuristic: an ntfy token, a console API key and a webhook
// signing secret are all masked inputs sitting near a hostname. Filled with a
// saved password they quietly replace a working credential with a wrong one,
// and nothing fails until an alarm does.
//
// autocomplete="off" alone does not do it -- Chrome and Google Password
// Manager deliberately ignore it on password fields, on the reasoning that
// sites use it to be annoying. So this says the same thing four ways, one per
// manager that documents an opt-out, and gives the field a name no heuristic
// can match. The SIGN-IN and CHANGE-PASSWORD fields deliberately do not use
// this: those genuinely are the operator's password and a manager should
// offer to fill and save them.
var noFillSeq = 0;
function keepOutOfPasswordManagers(input) {
  noFillSeq++;
  // A name that is not "password", "token", "key" or anything else a filler
  // looks for. Unique per field, so nothing can be remembered against it.
  input.name = "f" + noFillSeq + "-" + Math.random().toString(36).slice(2, 8);
  input.id = input.name;
  input.setAttribute("autocomplete", "off");
  input.setAttribute("data-lpignore", "true");   // LastPass
  input.setAttribute("data-1p-ignore", "");      // 1Password
  input.setAttribute("data-bwignore", "");       // Bitwarden
  input.setAttribute("data-form-type", "other"); // Dashlane
  return input;
}

function bind(obj, key, numeric) {
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = numeric ? "number" : "text";
  i.value = (obj[key] === undefined || obj[key] === null) ? "" : obj[key];
  i.addEventListener("input", function () {
    obj[key] = numeric ? (i.value === "" ? 0 : Number(i.value)) : i.value;
  });
  return i;
}
// bindList edits a comma-separated list. `seen`, when given, attaches the
// observed-entity suggestions -- a datalist still completes the value being
// typed after the last comma, so it helps in the advanced editor too.
function bindList(obj, key, seen) {
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = "text";
  i.value = (obj[key] || []).join(", ");
  if (seen && seen.length) i.setAttribute("list", entityDatalist(seen));
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
// pick binds a string setting to a CONSTRAINED dropdown.
//
// A free-text box is the wrong control for the spoken voice and its language.
// Twilio accepts the request and answers 201 whatever is in them, and an
// unusable value only fails when <Say> runs -- so a typo produces a call that
// connects, says nothing and hangs up, while this interface shows a clean
// success.
//
// A value already in the config that is not on the list is kept and shown
// rather than silently dropped: somebody who set a named Polly voice by hand
// should not lose it by opening this page.

// The two Basic-tier voices. They are billed at NOTHING per character and they
// are valid with every language Twilio's basic text-to-speech speaks, which is
// why only these two are offered. The Polly and Google voices sound better,
// are billed per 100 characters of script on every call to every number on
// every escalation rung, and each pairs with one fixed language: a voice and a
// locale that disagree make the alert fail AFTER Twilio has accepted the call.
var VOICE_SAY_VOICES = ["man", "woman"];

// The locales those two voices speak.
var VOICE_SAY_LANGUAGES = [
  "en-US", "en-GB", "en-AU", "en-CA", "en-IN",
  "fr-FR", "fr-CA", "de-DE", "es-ES", "es-MX", "it-IT",
  "nl-NL", "pt-BR", "pt-PT", "da-DK", "sv-SE", "nb-NO",
  "pl-PL", "ru-RU", "ja-JP", "ko-KR", "zh-CN"
];

// fingerprintOffer: read the certificate this console is presenting, and show
// it to somebody who is deciding whether to pin it.
//
// TRUST-ON-FIRST-USE IS AN OPERATOR ACTION. The button reads and SHOWS; it
// does not fill the field, and accepting the value is a second click followed
// by an ordinary save. A button that pinned what it had just read would be
// the machine performing the decision, and a client that learns a pin by
// itself has no protection on the one connection an attacker would target.
//
// It exists because the warning beside every unpinned console has always said
// "notifymatrix will show you its fingerprint", and nothing did.
function fingerprintOffer(c, input, ctx) {
  var box = el("div", "stack");
  var bar = el("div", "formbar");
  var msg = el("div", "msg");

  var go = el("button", "act small", "Read the certificate");
  go.type = "button";
  go.addEventListener("click", function () {
    var host = (c.host || "").trim();
    if (!host) {
      msg.className = "msg warn";
      msg.textContent = "Fill in the host first — that is the address this reads.";
      return;
    }
    go.disabled = true;
    msg.className = "msg";
    msg.textContent = "reading …";
    api("POST", "api/consoles/fingerprint", { host: host }).then(function (res) {
      go.disabled = false;
      if (!res.ok) {
        // Verbatim: "not a local address", "connection refused" and "no TLS
        // there" are three different problems with the address just typed.
        msg.className = "msg err";
        msg.textContent = (res.data && res.data.error) || "could not read a certificate there";
        return;
      }
      clear(msg);
      msg.className = "msg";
      msg.appendChild(el("div", "mono", res.data.fingerprint));
      msg.appendChild(el("div", "muted small",
        "This is whatever is answering at " + host + " right now. Worth " +
        "confirming against the console's own interface before you pin it."));
      var use = el("button", "act small primary", "Use this fingerprint");
      use.type = "button";
      use.addEventListener("click", function () {
        c.fingerprint = res.data.fingerprint;
        input.value = res.data.fingerprint;
        use.disabled = true;
        use.textContent = "filled in — save to pin it";
      });
      var ub = el("div", "formbar");
      ub.appendChild(use);
      msg.appendChild(ub);
    });
  });

  bar.appendChild(go);
  box.appendChild(bar);
  box.appendChild(msg);
  return box;
}

// appKeyRows: one key per application, which is how UniFi issues them.
//
// THE NOTE ABOVE HAS ALWAYS SAID SO. "Protect, Access and Network each issue
// their OWN key" was on this screen while the screen offered exactly one
// field, so an operator who read it carefully still had nowhere to put the
// second key -- and on a real site the Protect key went in, Access answered
// 401, and the board could only report that Access was not talking.
//
// Only the applications this console is set to watch get a row. A console
// watching Protect alone has one key to think about, and three boxes would
// invite pasting the same key into all of them.
function appKeyRows(card, c) {
  var watched = c.sources || [];
  var any = false;
  ["protect", "access", "network"].forEach(function (product) {
    if (watched.indexOf(product) < 0) return;
    any = true;
    var isSet = !!c[product + "_key_set"];
    var row = el("div", "row");
    row.appendChild(badge(isSet ? product + " key set" : product + " uses the key above",
      isSet ? "on" : "off"));
    if (isSet) {
      // Without this, a key pasted into the wrong application can only be
      // taken back by editing the file -- and "leave blank to keep what is
      // stored" means blanking the box cannot mean remove.
      var clear = el("button", "act small", "Use the key above instead");
      clear.type = "button";
      clear.addEventListener("click", function () {
        c.clear_keys = (c.clear_keys || []).concat([product]);
        c[product + "_key_new"] = "";
        clear.disabled = true;
        clear.textContent = "will be removed on save";
      });
      row.appendChild(clear);
    }
    card.appendChild(row);
    var i = keepOutOfPasswordManagers(el("input"));
    i.type = "password";
    i.placeholder = "leave blank to keep what is stored";
    i.addEventListener("input", function () { c[product + "_key_new"] = i.value; });
    card.appendChild(labelled("Replace " + product + " key", i));
  });
  if (any) {
    card.appendChild(el("div", "note",
      "Each of these comes from that application's own integrations screen in " +
      "UniFi, not from the console's. A key from the wrong one is answered 401 " +
      "by the right one, which reads here as the application being down."));
  }
}

function secretRow(card, isSet, label, obj, key) {
  var r = el("div", "row");
  r.appendChild(badge(isSet ? label + " set" : label + " not set", isSet ? "on" : "off"));
  card.appendChild(r);
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = "password";
  i.placeholder = "leave blank to keep what is stored";
  i.addEventListener("input", function () { obj[key] = i.value; });
  card.appendChild(labelled("Replace " + label, i));
}

// ---------- audit ----------

// AUDIT_KINDS turns the stored kind into something a person reads, with a
// tone so a failed delivery does not look like a routine save.
//
// The kinds are machine identifiers -- "alert.failed", "incident.recurred" --
// and they were rendered raw in a column of their own. They are the record's
// vocabulary, not the operator's, and the one row that matters most on this
// page looked exactly like the two hundred that do not.
var AUDIT_KINDS = {
  "event":                 { label: "Event",                icon: "list",    tone: "is-muted" },
  "incident.opened":       { label: "Alarm raised",         icon: "warning", tone: "is-warn" },
  "incident.updated":      { label: "Alarm updated",        icon: "list",    tone: "is-muted" },
  "incident.recurred":     { label: "Alarm returned",       icon: "refresh", tone: "is-warn" },
  "incident.ignored":      { label: "Silenced by a rule",   icon: "x",       tone: "is-muted" },
  "alert.sent":            { label: "Delivered",            icon: "check",   tone: "is-ok" },
  "alert.failed":          { label: "Delivery failed",      icon: "warning", tone: "is-err" },
  "alert.held":            { label: "Held for quiet hours", icon: "clock",   tone: "is-info" },
  "incident.acknowledged": { label: "Acknowledged",         icon: "check",   tone: "is-info" },
  "incident.resolved":     { label: "Condition cleared",    icon: "check",   tone: "is-ok" },
  "incident.closed":       { label: "Closed",               icon: "x",       tone: "is-muted" },
  "config.changed":        { label: "Settings changed",     icon: "gear",    tone: "is-info" },
  "auth":                  { label: "Sign-in",              icon: "key",     tone: "is-info" },
  "service":               { label: "Service",              icon: "power",   tone: "is-muted" }
};

// FIELD_LABELS names the structured fields in words. They were rendered as
// "channel=email  ·  error=dial tcp: lookup smtp.example.com: no such host",
// which is a debug dump: the reader has to know the schema to read the row.
var FIELD_LABELS = {
  channel: "channel", client: "from", hook: "hook", entity: "about",
  changed: "sections", action: "action", reason: "reason", until: "until",
  version: "version", detail: "detail", event: "event", error: "error"
};

function auditKind(kind) {
  return AUDIT_KINDS[kind] || { label: kind || "—", icon: "list", tone: "is-muted" };
}

function refreshAudit() {
  var body = byId("audit-body");
  api("GET", "api/audit?limit=200").then(function (res) {
    if (res.status === 401) {
      setLede("activity", "clock", "What happened, and who did it.", "");
      renderSignIn(body); return;
    }
    if (!res.ok) {
      clear(body);
      body.appendChild(errorState(res.data.error || "could not load the audit log", refreshAudit));
      return;
    }
    clear(body);
    var entries = res.data.entries || [];
    var failures = entries.filter(function (e) { return auditKind(e.kind).tone === "is-err"; }).length;
    setLede("activity", "clock", "What happened, and who did it.",
      entries.length ? entries.length + " recent" + (failures ? " · " + failures + " failed" : "") : "");
    if (!entries.length) {
      body.appendChild(emptyState("Nothing recorded yet",
        "Every alarm, delivery, acknowledgement, save and restart lands here.",
        null, { icon: "clock" }));
      return;
    }

    // A filter, because two hundred rows with no way through them is a log
    // file with borders. "Only failures" is first because it is the reason
    // somebody opens this page at 3am.
    var filterText = "";
    var failuresOnly = false;
    var listWrap = el("div", "");

    var bar = el("div", "cluster audit-filter");
    var search = keepOutOfPasswordManagers(el("input"));
    search.type = "search";
    search.placeholder = "Filter by anything on the row";
    search.addEventListener("input", function () {
      filterText = search.value.trim().toLowerCase();
      draw();
    });
    bar.appendChild(search);

    var onlyFail = el("button", "act small", "Only failures" + (failures ? " (" + failures + ")" : ""));
    onlyFail.disabled = failures === 0;
    onlyFail.addEventListener("click", function () {
      failuresOnly = !failuresOnly;
      onlyFail.className = failuresOnly ? "act small primary" : "act small";
      draw();
    });
    bar.appendChild(onlyFail);
    body.appendChild(bar);
    body.appendChild(listWrap);

    function matches(e) {
      var k = auditKind(e.kind);
      if (failuresOnly && k.tone !== "is-err") return false;
      if (!filterText) return true;
      var hay = [e.summary, e.actor, e.kind, k.label, e.incident_id].join(" ");
      if (e.fields) {
        Object.keys(e.fields).forEach(function (f) { hay += " " + f + " " + e.fields[f]; });
      }
      return hay.toLowerCase().indexOf(filterText) >= 0;
    }

    function draw() {
      clear(listWrap);
      var shown = entries.filter(matches);
      if (!shown.length) {
        listWrap.appendChild(emptyState("Nothing matches",
          "No entry in the last " + entries.length + " matches that.",
          { label: "Clear the filter", onClick: function () {
            search.value = ""; filterText = ""; failuresOnly = false;
            onlyFail.className = "act small"; draw();
          } }, { icon: "list", compact: true }));
        return;
      }
      var t = table(["When", "What", "Who", "Detail"]);
      t.className = "audit";
      shown.forEach(function (e) { auditRow(t, e); });
      listWrap.appendChild(wrap(t));
    }
    draw();
  });
}

function auditRow(t, e) {
  var k = auditKind(e.kind);
  var row = t.tBodies[0].insertRow();
  if (k.tone === "is-err") row.className = "is-err";

  row.insertCell().textContent = stamp(e.at);

  var kc = row.insertCell();
  var b = badge(k.label, k.tone);
  b.insertBefore(icon(k.icon, "sm"), b.firstChild);
  kc.appendChild(b);

  row.insertCell().textContent = e.actor || "—";

  var c = row.insertCell();
  c.appendChild(el("div", "", e.summary));

  // The error is the thing somebody came here to read, so it is not one of
  // the key=value pairs; it gets the treatment a failure gets everywhere else.
  if (e.fields && e.fields.error) {
    c.appendChild(el("div", "audit-error", e.fields.error));
  }

  var pairs = el("div", "audit-fields");
  var any = false;
  if (e.fields) {
    Object.keys(e.fields).sort().forEach(function (f) {
      if (f === "error") return;
      any = true;
      var pair = el("span", "pair");
      pair.appendChild(el("span", "pair-k", FIELD_LABELS[f] || f));
      pair.appendChild(el("span", "pair-v", e.fields[f]));
      pairs.appendChild(pair);
    });
  }
  if (e.incident_id) {
    any = true;
    // A link, because the record and the board were unreachable from each
    // other despite every entry carrying the id.
    var a = el("a", "pair");
    a.href = "#incidents";
    a.appendChild(el("span", "pair-k", "incident"));
    a.appendChild(el("span", "pair-v", String(e.incident_id).slice(0, 8)));
    a.setAttribute("title", e.incident_id);
    pairs.appendChild(a);
  }
  if (any) c.appendChild(pairs);
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
// opts is for the one channel whose test does not send anything. Voice checks
// credentials rather than telephoning somebody, so it needs its own button
// label, its own note and its own success sentence: the server prints one
// generic "Sent. If it does not arrive..." line for every channel, and for a
// call that was deliberately never placed that line is simply untrue.
function testRow(card, name, opts) {
  opts = opts || {};
  var row = el("div", "row");
  var btn = el("button", "act", opts.button || "Send a test");
  var out = el("span", "muted small");
  row.appendChild(btn);
  row.appendChild(out);
  card.appendChild(row);
  card.appendChild(el("div", "note",
    "Tests the SAVED settings. Save first if you have just changed something."));
  if (opts.note) card.appendChild(el("div", "note", opts.note));

  btn.addEventListener("click", function () {
    btn.disabled = true;
    out.className = "muted small";
    out.textContent = opts.button ? "checking..." : "sending...";
    api("POST", "/api/channels/" + encodeURIComponent(name) + "/test").then(function (r) {
      btn.disabled = false;
      if (r.ok && r.data && r.data.ok) {
        out.className = "ok small";
        out.textContent = opts.success || r.data.detail || "sent";
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
//
// It is drawn as onboarding, not as a status list. The first version rendered
// every step as a card with everything in it open at once: seven "why"
// paragraphs, forty-odd instruction lines, the acknowledgement step alone
// twelve items long, all at one weight -- and the hook credentials the text
// kept calling "below" were rendered above step 1. Now there is a progress
// header, one accordion row per step with only the first unfinished one
// open, warnings drawn as callouts between the numbered actions, reference
// material folded behind its title, and the credentials inside the step that
// tells you to paste them.

// Where each step is finished. Setup can say what is missing, but the fixing
// happens on another tab, and a step that cannot take you there is a status
// line rather than a step. Keyed by the step's key from the server, so a
// reworded title moves nothing. The hrefs land on the one Settings section
// that finishes the step, not the top of the page.
var SETUP_GO = {
  console:  { href: "#settings/consoles",   label: "Open Consoles" },
  sources:  { href: "#settings/consoles",   label: "Open Consoles" },
  channel:  { href: "#settings/channels",   label: "Open Channels" },
  ack:      { href: "#settings/web",        label: "Open Web settings" },
  hooks:    { href: "#settings/webhooks",   label: "Open Webhooks" },
  password: { href: "#settings",            label: "Set the password" },
  service:  { href: "#health",              label: "Open Health" }
};

function refreshSetup() {
  var body = byId("setup-body");
  api("GET", "/api/checklist").then(function (r) {
    clear(body);
    if (!r.ok || !r.data || !r.data.available) {
      setLede("setup", "list", "What was never finished.", "");
      body.appendChild(emptyState("No checklist available from this build",
        "This build does not report a setup checklist, so there is nothing to show here."));
      return;
    }
    var d = r.data;
    var steps = orderSteps(d.steps || []);
    body.appendChild(setupProgress(d, steps));

    // One step open: the first that is not done, preferring a blocking one
    // over an optional one. A fresh install used to open all seven, which is
    // the wall; a finished install opens none.
    var openKey = firstToDo(steps);
    steps.forEach(function (s) {
      body.appendChild(setupStep(s, {
        open: s.key === openKey,
        startHere: s.hoisted,
        hooks: d.hooks || [],
        authed: d.authenticated
      }));
    });
  });
}

// orderSteps keeps the server's order except for the password step, which
// is hoisted to the top while it is not done. On the web it is the FIRST
// thing an operator needs -- every other step's "Open Settings" lands on the
// sign-in form -- and the server lists it sixth because the CLI reader, who
// already has a terminal, does not need it first.
function orderSteps(steps) {
  var out = steps.slice();
  for (var i = 0; i < out.length; i++) {
    if (out[i].key === "password" && out[i].status !== "done") {
      var pw = out.splice(i, 1)[0];
      pw.hoisted = true;
      out.unshift(pw);
      break;
    }
  }
  return out;
}

// firstToDo picks which step opens: the first todo, else the first
// unverified, else the first optional. Todo before optional because an
// optional step listed earlier ("one channel is fine, two is better") must
// not open in front of the step that is stopping delivery.
function firstToDo(steps) {
  var order = ["todo", "unverified", "optional"];
  for (var i = 0; i < order.length; i++) {
    for (var j = 0; j < steps.length; j++) {
      if (steps[j].status === order[i]) return steps[j].key;
    }
  }
  return null;
}

// setupProgress is the header: "4 of 7 done" as a figure and a bar, whether
// the installation is ready, and the pipeline -- console -> this machine ->
// channels -> your phone -- with each node in the tone of the step that
// proves it. The pipeline is the picture that makes the checklist's order
// obvious: an alarm has to get all the way along it, and a red node is where
// it stops.
function setupProgress(d, steps) {
  var card = el("div", "card setup-progress");
  var total = steps.length;
  var done = steps.filter(function (s) { return s.status === "done"; }).length;
  var todo = steps.filter(function (s) { return s.status === "todo"; }).length;
  var figure = done + " of " + total + " done";
  var tone = d.ready ? (done === total ? "ok" : "info") : "err";

  setLede("setup", "list", "What was never finished.", figure, tone);

  var top = el("div", "row top");
  var fig = el("div", "");
  fig.appendChild(el("div", "figure", done + " of " + total));
  fig.appendChild(el("div", "kpi-label", "steps done"));
  top.appendChild(fig);
  var side = el("div", "grow");
  if (d.ready) {
    side.appendChild(callout("This installation can raise and deliver an alarm." +
      (done < total ? " The steps still open improve it; none of them is stopping an alarm." : ""), "ok",
      done === total ? "Everything is done" : "Ready"));
  } else {
    side.appendChild(callout("Nothing can be delivered yet. The steps marked TODO below are what is missing" +
      (todo ? " -- " + todo + " of them." : "."), "err", "Not ready"));
  }
  top.appendChild(side);
  card.appendChild(top);

  card.appendChild(segmentBar(steps.map(function (s) { return s.status; }),
    figure + ": one segment per step, green done, red to do, amber unverified, grey optional"));

  card.appendChild(pipeline(pipelineNodes(steps)));

  // The credentials are gated, and this is the only line that says so; the
  // first version promised them to a signed-in reader and then rendered them
  // nowhere at all.
  if (!d.authenticated && d.hooks && d.hooks.length) {
    card.appendChild(el("div", "note",
      "Sign in to see the webhook URLs. They are credentials, so they are not " +
      "shown to a signed-out viewer."));
  }
  return card;
}

// pipelineNodes joins the four stations of an alarm to the steps that prove
// each one. The console node answers for the console, the sources AND the
// Alarm Manager rules: all three are "does the console speak to us", and a
// console with nothing to watch and no rules is one that never does.
//
// A node names the step that is holding it. The node read "UniFi console:
// to do" while the step "Add your UniFi console" read DONE, because the
// node was toned by three steps and labelled with one of them -- a
// contradiction on the screen meant to make the order obvious. Now the
// sub-line says "to do: alarm rules", which is what it measures.
var STEP_SHORT = {
  console: "console", sources: "sources", hooks: "alarm rules",
  service: "service", channel: "channel", ack: "ack link", password: "password"
};
function pipelineNodes(steps) {
  var by = {};
  steps.forEach(function (s) { by[s.key] = s; });
  var rank = { todo: 3, unverified: 2, optional: 1, done: 0 };
  var worst = function (keys) {
    var w = "done", wk = null;
    keys.forEach(function (k) {
      var st = by[k] ? by[k].status : "done";
      if ((rank[st] || 0) > (rank[w] || 0)) { w = st; wk = k; }
    });
    return { status: w, key: wk };
  };
  var word = { done: "done", todo: "to do", unverified: "unverified", optional: "optional" };
  var node = function (iconName, title, keys) {
    var w = worst(keys);
    var sub = word[w.status] || w.status;
    // Name the culprit only when the node stands for more than one step;
    // "Channels: to do: channel" would say the same thing twice.
    if (w.key && keys.length > 1 && w.status !== "done") sub += ": " + (STEP_SHORT[w.key] || w.key);
    return { icon: iconName, title: title, sub: sub, tone: w.status };
  };
  return [
    node("camera", "UniFi console", ["console", "sources", "hooks"]),
    node("server", "This machine", ["service"]),
    node("bell", "Channels", ["channel"]),
    node("phone", "Your phone", ["ack"])
  ];
}

// setupGlyph is the status as a shape, for the row's leading icon -- a
// check, a warning, a clock for "configured but never seen working", a
// circle for optional -- so a row says its state before its colour does.
function setupGlyph(status) {
  if (status === "done") return "check";
  if (status === "todo") return "warning";
  if (status === "unverified") return "clock";
  return "info";
}

// setupStep is one accordion row: glyph, title, state, chevron in the
// summary; what is true now, why it matters, the actions, any reference
// topic, the hook credentials (on the hooks step) and a button to the tab
// that finishes it in the body. A <details>, because it works with no
// script at all and its open state is one attribute the renderer sets.
function setupStep(s, opts) {
  opts = opts || {};
  var det = el("details", "step " + toneClass(s.status));
  if (opts.open) det.open = true;
  det.setAttribute("data-step", s.key || "");

  var sum = el("summary");
  sum.appendChild(icon(setupGlyph(s.status)));
  sum.appendChild(el("span", "step-title", s.title));
  if (opts.startHere) sum.appendChild(badge("start here", "info"));
  sum.appendChild(badge(s.status, statusClass(s.status)));
  // The state, truncated to the room left on the row. The full text is the
  // first line of the body; this is so a collapsed done step still reads
  // "1 console(s) configured" and not just DONE.
  if (s.state) sum.appendChild(el("span", "step-state", s.state));
  sum.appendChild(icon("chevron", "chev"));
  det.appendChild(sum);

  // Three parts. The lead is what is true now and why it matters; the "do"
  // is the instructions, the reference topics and (on the hooks step) the
  // credentials; the go is the button to the section that finishes it. On
  // a phone they stack in that order. On a wide screen the lead and the
  // button take the left column and the instructions the right, because an
  // open step used to leave half of a 1280px row empty: a 64-character
  // measure is right for reading and wrong for a card that is 1100px wide.
  var body = el("div", "body");
  var lead = el("div", "step-lead stack");
  if (s.state) {
    var now = el("div", "step-now");
    now.appendChild(el("span", "dot " + toneClass(s.status)));
    now.appendChild(el("span", "step-now-k", "Now"));
    now.appendChild(el("span", "", s.state));
    lead.appendChild(now);
  }
  if (s.why) lead.appendChild(el("p", "step-why", s.why));
  body.appendChild(lead);

  var work = el("div", "step-do stack");
  if (s.how && s.how.length) work.appendChild(howList(s.how));
  (s.reference || []).forEach(function (t) {
    work.appendChild(referenceTopic(t.title, t.lines));
  });
  // The credentials live INSIDE the step whose instructions say "paste the
  // URL below", so that "below" is true. They used to render above step 1.
  if (s.key === "hooks" && opts.hooks && opts.hooks.length) {
    work.appendChild(hooksCard(opts.hooks, opts.authed));
  }
  if (work.firstChild) body.appendChild(work);

  var go = SETUP_GO[s.key];
  if (go) {
    var bar = el("div", "formbar step-go");
    var a = el("a", "act" + (s.status === "done" ? "" : " primary"));
    a.href = go.href;
    a.appendChild(document.createTextNode(go.label));
    a.appendChild(icon("arrow"));
    bar.appendChild(a);
    body.appendChild(bar);
  }
  det.appendChild(body);
  return det;
}

// howList draws the instruction lines with their weight. Actions are the
// numbered list; a warning or an aside breaks the list and sits between as
// a callout, and the numbering continues after it -- so the acknowledgement
// step reads "1, 2, 3, then a bordered IF YOU MUST FORWARD A PORT, then 4",
// rather than twelve items at one weight of which three were things to do.
// Accepts plain strings too (an action each), for callers that predate the
// kinds.
function howList(lines) {
  var box = el("div", "how-list");
  var ol = null, n = 0;
  (lines || []).forEach(function (l) {
    if (typeof l === "string") l = { text: l, kind: "action" };
    if (l.kind === "warning" || l.kind === "aside") {
      ol = null;
      box.appendChild(callout(l.text, l.kind === "warning" ? "warn" : "info"));
      return;
    }
    if (!ol) {
      ol = el("ol", "how");
      if (n) { ol.setAttribute("start", String(n + 1)); ol.start = n + 1; }
      box.appendChild(ol);
    }
    n++;
    ol.appendChild(el("li", "", l.text));
  });
  return box;
}

// referenceTopic folds a titled block of reference lines behind its title.
// Reachable from the step it belongs to -- one tap, no other tab -- which is
// the rule for anything that leaves the primary screen.
function referenceTopic(title, lines) {
  var det = el("details", "aside");
  var sum = el("summary");
  sum.appendChild(icon("help"));
  sum.appendChild(el("span", "grow", title));
  sum.appendChild(icon("chevron", "chev"));
  det.appendChild(sum);
  var body = el("div", "body");
  body.appendChild(howList(lines));
  det.appendChild(body);
  return det;
}

// testModeNotice is the one sentence that must appear everywhere a hook is
// shown while its test mode is armed: the hook is accepting real alarms and
// throwing them away, which is the one state this product must never let
// somebody be in without knowing. Shared by the Setup credentials card and
// the Webhooks tab so the two cannot say different things.
function testModeNotice(cr) {
  var armed = cr && cr.test_armed_until && !/^0001/.test(cr.test_armed_until);
  if (!armed) return null;
  var when = new Date(cr.test_armed_until);
  return callout("Alarms arriving here are being accepted and THROWN AWAY -- a real " +
    "alarm at this hook would raise nothing right now. It ends by itself.",
    "warn", "TEST MODE until " + when.toLocaleTimeString());
}

// evidenceBadges says whether anything has ever actually arrived through a
// hook. Evidence beats configuration: a rule that looks perfect at the UniFi
// end and has never fired is the failure this panel exists to make visible.
function evidenceBadges(cr) {
  var out = [];
  if (!cr) return out;
  if (cr.count > 0) out.push(badge(cr.count + " received", "ok"));
  else out.push(badge("nothing received yet", "warn"));
  if (cr.rejected > 0) out.push(badge(cr.rejected + " rejected", "crit"));
  if (cr.test_armed_until && !/^0001/.test(cr.test_armed_until)) out.push(badge("test mode", "warn"));
  return out;
}

// hookTestControls answers the two questions a new hook actually raises, and
// they are different questions needing different buttons -- so they are
// drawn as two panels, each with its button and what pressing it proves.
//
//   CAN UNIFI REACH US?   Arm test mode, press Test on the rule, watch the
//                         count rise. Nothing is raised, nobody is woken, and
//                         there is no incident to close afterwards.
//   AND THEN WHAT?        Fire a test alarm. It goes through the real rules,
//                         the real ladder and the real channels, so a phone
//                         really rings -- the half that an arriving alarm does
//                         not prove until the night it matters.
//
// Test mode is rendered loudly while armed. A hook in test mode is accepting
// real alarms and discarding them, which is the one state this product must
// never let somebody be in without knowing.
function hookTestControls(h, cr) {
  var wrap = el("div", "stack");
  var name = (h.name || "").trim();
  var armed = cr.test_armed_until && !/^0001/.test(cr.test_armed_until);

  var notice = testModeNotice(cr);
  if (notice) wrap.appendChild(notice);
  if (cr.test_count > 0) {
    wrap.appendChild(el("div", "note",
      cr.test_count + " arrival(s) accepted and discarded in test mode" +
      (cr.last_test_at && !/^0001/.test(cr.last_test_at)
        ? ", last at " + new Date(cr.last_test_at).toLocaleTimeString() : "") +
      ". Counted apart from real arrivals, so testing cannot make an untried " +
      "hook look proven."));
  }

  var msg = el("div", "msg");
  var grid = el("div", "grid-2 test-panels");

  var reach = el("div", "card test-panel");
  reach.appendChild(el("div", "title", "Can the console reach this machine?"));
  var tm = el("button", "act" + (armed ? "" : " primary"), armed ? "End test mode" : "Test mode for 15 minutes");
  tm.type = "button";
  tm.addEventListener("click", function () {
    tm.disabled = true;
    msg.className = "msg"; msg.textContent = "";
    api("POST", "/api/hooks/" + encodeURIComponent(name) + "/test-mode",
        { minutes: armed ? 0 : 15 }).then(function (res) {
      tm.disabled = false;
      if (!res.ok) {
        msg.className = "msg err";
        msg.textContent = (res.data && res.data.error) || "that was refused";
        return;
      }
      msg.textContent = (res.data && res.data.detail) || "Done.";
      refreshWebhooks();
    });
  });
  var rb = el("div", "formbar"); rb.appendChild(tm); reach.appendChild(rb);
  reach.appendChild(el("div", "note",
    "Test mode proves the console can reach this machine. Arm it, then press " +
    "Test on the rule in UniFi: arrivals are counted and thrown away, nothing " +
    "is raised and nobody is woken."));
  grid.appendChild(reach);

  var told = el("div", "card test-panel");
  told.appendChild(el("div", "title", "And is somebody actually told?"));
  var fire = el("button", "act", "Fire a test alarm");
  fire.type = "button";
  fire.addEventListener("click", function () {
    // Confirmed, because this one is not free: it pages whoever the ladder
    // pages, and with voice on a rung it places a billed phone call.
    if (!window.confirm(
      "Raise a real incident for \"" + name + "\"?\n\n" +
      "It goes through your rules, your escalation ladder and your channels, " +
      "so it will notify whoever a genuine alarm would -- including any phone " +
      "call, which costs money. It keeps escalating until you acknowledge or " +
      "close it.")) {
      return;
    }
    fire.disabled = true;
    msg.className = "msg"; msg.textContent = "";
    api("POST", "/api/hooks/" + encodeURIComponent(name) + "/fire", {}).then(function (res) {
      fire.disabled = false;
      if (!res.ok) {
        msg.className = "msg err";
        msg.textContent = (res.data && res.data.error) || "that was refused";
        return;
      }
      msg.textContent = (res.data && res.data.detail) || "Raised.";
      refreshStatus();
    });
  });
  var fb = el("div", "formbar"); fb.appendChild(fire); told.appendChild(fb);
  told.appendChild(el("div", "note",
    "Firing a test alarm proves that when an alarm arrives, somebody is " +
    "actually told -- which depends on your rules, ladder and channels, and " +
    "is the part an arriving alarm does not prove until it matters. It raises " +
    "a real incident and a phone really rings."));
  grid.appendChild(told);
  wrap.appendChild(grid);

  // The reconciliation. The Setup step says pressing Test in UniFi raises a
  // real incident; this tab offers a mode in which it raises nothing. Both
  // are true, and this is the line that says when each applies.
  wrap.appendChild(el("div", "note",
    "UniFi's own Test button on the rule sends a real alarm. With test mode " +
    "armed it is counted above and discarded; with test mode off it raises a " +
    "real incident, exactly as a genuine alarm would."));
  wrap.appendChild(msg);
  return wrap;
}

// hooksCard renders what an Alarm Manager rule needs: the URL, the header, and
// whether anything has ever actually arrived through it.
//
// BOTH the URL and the header are credentials -- the token is in the path and
// the bearer is in the header -- which is why the server only sends them to a
// signed-in caller, and why they are rendered as selectable text rather than
// as a link. A hook URL in browser history, in a referer, or in a chat window
// where somebody pasted "the link" is a way to raise false alarms on this
// installation.
function hooksCard(hooks, authed) {
  var card = el("div", "card hooks");
  var title = el("div", "card-title");
  title.appendChild(icon("link"));
  title.appendChild(document.createTextNode("URLs and headers for the rules"));
  card.appendChild(title);
  card.appendChild(el("p", "",
    "Paste each URL and header into the matching UniFi Alarm Manager rule. " +
    "No API can create those rules, so this is the only way the alarms they " +
    "carry reach this product at all. Hooks are added under Settings > Webhooks."));

  hooks.forEach(function (h) {
    var box = el("div", "card hook");
    var head = el("div", "row");
    head.appendChild(el("strong", "", h.name));
    if (h.product) head.appendChild(badge(h.product, ""));
    evidenceBadges(h).forEach(function (b) { head.appendChild(b); });
    box.appendChild(head);

    var notice = testModeNotice(h);
    if (notice) box.appendChild(notice);

    if (!authed) {
      box.appendChild(el("div", "note",
        "Sign in to see this hook's URL and header."));
      card.appendChild(box);
      return;
    }

    box.appendChild(el("div", "label", "URL"));
    box.appendChild(credRow(h.url || "(not available)", !!h.url));
    if (h.header_name) {
      var hl = el("div", "label", "Header");
      // The warning belongs AT the header, because the mistake it stops is
      // pasting the URL and skipping this.
      hl.appendChild(why("Both are passwords. The header is not optional -- a URL " +
        "travels through the console backup, browser history and every proxy " +
        "log on the path, and a header does not.", { label: "why both?", tone: "warn" }));
      box.appendChild(hl);
      box.appendChild(credRow(h.header_name + ": " + h.header_value, true));
    }
    if (h.last_reject) {
      box.appendChild(callout("Last refusal: " + h.last_reject, "err"));
    }
    card.appendChild(box);
  });
  return card;
}

// credRow is a credential with a Copy button beside it. The text is still
// selectable -- the button is a convenience and the clipboard API is absent
// on plain http, which is what most of these installs are.
function credRow(text, copyable) {
  var row = el("div", "cred-row");
  row.appendChild(el("pre", "cred", text));
  if (copyable) row.appendChild(copyButton(text));
  return row;
}

// statusClass maps a checklist status to the badge's legacy tone class.
function statusClass(status) {
  if (status === "done") return "ok";
  if (status === "todo") return "crit";
  if (status === "unverified") return "warn";
  if (status === "optional") return "optional";
  return "";
}

// ---------- shell ----------

function refreshTab() {
  if (state.tab === "incidents") refreshIncidents();
  else if (state.tab === "setup") refreshSetup();
  else if (state.tab === "settings") refreshSettings();
  else if (state.tab === "activity") refreshAudit();
}
function refreshAll() { refreshStatus(); refreshTab(); }

var TAB_NAMES = ["incidents", "health", "setup", "settings", "activity"];

// Old hashes keep working. "webhooks" was a tab and is a Settings section
// now; "audit" was the Activity tab's old name. A link somebody wrote down
// or pasted into a runbook must not land on an empty board.
var HASH_ALIASES = { webhooks: "settings/webhooks", audit: "activity" };

// routeFromHash reads #health, #settings/channels and friends: a tab, and
// for Settings an optional section after the slash. An operator telling
// somebody else to "look at Health" should be able to send them there, and
// a Setup step should be able to land on the one Settings section that
// finishes it rather than at the top of a long page.
//
// An unknown or absent fragment returns no tab at all; the caller decides
// where to land, because the right default depends on whether the
// installation is set up yet (see landingTab).
function routeFromHash() {
  var h = (location.hash || "").replace(/^#/, "").toLowerCase();
  if (HASH_ALIASES[h]) h = HASH_ALIASES[h];
  var parts = h.split("/");
  var tab = parts[0], section = parts[1] || "";
  if (TAB_NAMES.indexOf(tab) < 0) return { tab: "", section: "" };
  return { tab: tab, section: tab === "settings" ? section : "" };
}
// tabFromHash is the old name for the same question, kept for callers that
// only want the tab.
function tabFromHash() { return routeFromHash().tab; }

// landingTab: Setup while the installation cannot deliver, the board once
// it can. A fresh install used to land on an empty board that said "check
// Health", and Health said "no sources are configured" and pointed nowhere.
function landingTab() {
  return (state.setupKnown && !state.ready) ? "setup" : "incidents";
}

function selectTab(name, section) {
  // The pairing code's clock belongs to a section that is about to be
  // hidden. Left running it would keep ticking, expire, and refetch pairing
  // state for a page nobody is looking at.
  if (name !== "settings") stopLinkCountdown();
  state.tab = name;
  state.section = section || "";
  var want = name + (state.section ? "/" + state.section : "");
  if (location.hash.replace(/^#/, "") !== want) {
    // replaceState rather than a hash assignment: this must not add an entry
    // to the history for every tab click, or Back becomes useless.
    try { history.replaceState(null, "", "#" + want); } catch (e) { /* file:// */ }
  }
  var tabs = document.querySelectorAll("nav.tabs button");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].setAttribute("aria-selected", tabs[i].getAttribute("data-tab") === name ? "true" : "false");
  }
  TAB_NAMES.forEach(function (t) {
    byId("tab-" + t).hidden = (t !== name);
  });
  refreshTab();
}

// scrollToSection lands on a Settings section once it exists. The sections
// are rendered after a fetch, so this is called from the renderer as well
// as from the hash handler; scroll-margin-top in the style sheet keeps the
// heading out from under the sticky header.
function scrollToSection(section) {
  if (!section) return;
  var target = byId("settings-" + section);
  if (!target || !target.scrollIntoView) return;
  target.scrollIntoView({ block: "start" });
  markRail(section);
}

document.addEventListener("DOMContentLoaded", function () {
  var tabs = document.querySelectorAll("nav.tabs button");
  for (var i = 0; i < tabs.length; i++) {
    (function (b) {
      b.addEventListener("click", function () { selectTab(b.getAttribute("data-tab")); });
    })(tabs[i]);
  }
  window.addEventListener("hashchange", function () {
    var r = routeFromHash();
    if (!r.tab) return;
    if (r.tab === state.tab && r.tab === "settings") {
      // Same tab, different section: a rail click. Scroll, do not redraw --
      // redrawing would throw away whatever is typed in the other sections.
      state.section = r.section;
      scrollToSection(r.section);
      return;
    }
    selectTab(r.tab, r.section);
  });

  // The first status poll decides where to land when the URL says nothing:
  // it carries whether the installation is set up. Until it answers, the
  // board is shown (it is the page a wall display wants), and if the answer
  // is "not ready" the page moves to Setup once, before anybody has read
  // the board. A hash in the URL always wins.
  var r = routeFromHash();
  if (r.tab) {
    selectTab(r.tab, r.section);
    refreshStatus();
  } else {
    selectTab("incidents");
    refreshStatus(function () {
      if (landingTab() !== state.tab) selectTab(landingTab());
    });
  }
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
// The built-in channels. Outbound webhooks are added by name at render time,
// because how many there are and what they are called is configuration.
var CHANNEL_NAMES = ["ntfy", "email", "pushover", "voice"];

// DEFAULT_LADDERS mirrors escalate.DefaultPolicies, so a severity the config
// does not override can still be SHOWN. Displayed as "default" rather than
// written into the file: materialising every default the first time somebody
// opens this page would freeze today's defaults into the installation for ever.
// Keys are quoted so this table is valid JSON and a Go test can parse it and
// compare it against escalate.DefaultPolicies directly. It drifted once: info
// omitted give_up_after, so the card promised "keep going" for a default that
// actually gives up after an hour -- and the first edit of that card wrote a
// policy that really did keep going. A change of behaviour from opening a page
// and pressing save.
var DEFAULT_LADDERS = {
  "critical": { "stages": [{ "after": "0s", "channels": ["ntfy"] }, { "after": "2m", "channels": ["ntfy", "email"] }], "repeat_every": "5m", "give_up_after": "never" },
  "high": { "stages": [{ "after": "0s", "channels": ["ntfy"] }, { "after": "15m", "channels": ["ntfy", "email"] }], "repeat_every": "30m", "give_up_after": "4h" },
  "medium": { "stages": [{ "after": "0s", "channels": ["ntfy"] }], "repeat_every": "2h", "give_up_after": "12h" },
  "low": { "stages": [{ "after": "0s", "channels": ["ntfy"] }], "give_up_after": "24h", "respect_quiet_hours": true },
  "info": { "stages": [{ "after": "0s", "channels": ["ntfy"] }], "give_up_after": "1h", "respect_quiet_hours": true }
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
  var out = CHANNEL_NAMES.filter(function (n) { return ch[n] && ch[n].enabled; });
  // Every outbound webhook is addressable by its own name, so the escalation
  // editor has to offer them alongside the built-ins rather than a single
  // "webhook".
  (ch.webhooks || []).forEach(function (w) {
    if (w.enabled && w.name && out.indexOf(w.name) < 0) out.push(w.name);
  });
  return out;
}

// renderPolicies draws the escalation editor: the matrix in the simple
// view, one structured ladder per severity in the advanced one. saved is
// the last-saved settings, so the matrix can warn when a column is a
// channel enabled in the draft but not yet saved -- a ladder naming it
// would be refused. view remembers which editor is open across redraws.
function renderPolicies(body, draft, saved, view) {
  var pols = draft.policies || (draft.policies = {});
  var card = el("div", "card");
  card.appendChild(el("p", "",
    "Who is told when an alarm of each severity is raised, how often it keeps " +
    "asking until somebody acknowledges, and when it gives up."));

  var live = enabledChannels(draft);
  var savedLive = enabledChannels(saved || {});
  if (!live.length) {
    var none = el("span", "");
    none.appendChild(document.createTextNode("No channel is enabled, so there is nothing to escalate on to. "));
    var a = el("a", null, "Enable one under Channels");
    a.href = "#settings/channels";
    none.appendChild(a);
    none.appendChild(document.createTextNode(" and it appears here as a column."));
    card.appendChild(callout(none, "warn", "Nothing to tick"));
  }
  var unsaved = live.filter(function (n) { return savedLive.indexOf(n) < 0; });
  if (unsaved.length) {
    card.appendChild(callout(unsaved.join(", ") + " " + (unsaved.length === 1 ? "is" : "are") +
      " enabled under Channels but not saved yet. Save channels first, or a " +
      "ladder naming " + (unsaved.length === 1 ? "it" : "them") + " will be refused.", "warn"));
  }

  var advanced = el("input");
  advanced.type = "checkbox";
  advanced.style.width = "auto";
  // The matrix is the default view, always. The editor used to open in the
  // advanced view whenever a ladder had more than one stage, on the theory
  // that the simple view would flatten it on save -- but the matrix edits
  // only the first stage and carries the rest through untouched, marking
  // the row "+1 stage". And the shipped defaults for critical and high ARE
  // two-stage ladders, so ticking one box in the matrix and saving made the
  // matrix vanish on the next visit, on first use, for everybody.
  view = view || {};
  advanced.checked = !!view.advanced;
  advanced.addEventListener("change", function () { view.advanced = advanced.checked; });
  var advRow = el("div", "row");
  advRow.appendChild(labelled("Advanced: edit the escalation ladder itself", advanced,
    "A ladder can have several stages -- ntfy now, ntfy and email after fifteen " +
    "minutes. The matrix edits the first stage of each; the advanced view " +
    "edits every stage."));
  card.appendChild(advRow);

  var panel = el("div");
  card.appendChild(panel);
  body.appendChild(card);

  var draw = function () {
    clear(panel);
    if (advanced.checked) {
      SEVERITIES.forEach(function (sev) {
        panel.appendChild(policyCard(sev, pols, draw, live));
      });
    } else {
      panel.appendChild(policyMatrix(pols, live, draw));
    }
  };
  advanced.addEventListener("change", draw);
  draw();
}

// ownerOf returns the function that makes a severity's policy editable.
//
// Editing a default must turn it into an override FIRST, or the edit lands
// on the shared template object and changes every severity at once.
// Materialising a default has to filter it to channels that are actually
// enabled, exactly as config.filterToEnabled does when the daemon builds the
// shipped defaults at runtime. Without that, ticking one box in the simple
// view wrote out the two-stage default verbatim -- including a second rung
// naming a channel this installation does not have -- and the save was
// refused citing "stage 1", a thing the simple view never showed.
//
// It materialises WITHOUT redrawing. Redrawing here re-rendered the panel
// before the caller had applied its change, so the freshly drawn checkbox
// showed the pre-change model and the model then moved underneath it.
// Callers redraw AFTER their mutation, which is the only order in which the
// two can agree.
function ownerOf(sev, pols, live) {
  return function () {
    if (!Object.prototype.hasOwnProperty.call(pols, sev)) {
      pols[sev] = filterLadder(clone(DEFAULT_LADDERS[sev]), live);
    }
    return pols[sev];
  };
}

// policyMatrix is THE matrix: severities down, channels across, a checkbox
// where they meet, and beside each row how often it repeats and when it
// gives up. It is one screen instead of five identical cards, and it is the
// product's mental model drawn as a picture -- the thing the name promised
// and nothing showed.
function policyMatrix(pols, live, redraw) {
  var box = el("div", "scroll-x");
  var t = document.createElement("table");
  t.className = "matrix";
  var head = t.createTHead().insertRow();
  var th = function (text, cls) {
    var h = document.createElement("th");
    h.textContent = text;
    if (cls) h.className = cls;
    head.appendChild(h);
    return h;
  };
  th("Severity");
  live.forEach(function (name) { th(name, "chan"); });
  th("Repeat every", "dur");
  th("Give up after", "dur");
  th("Quiet hours");
  th("");
  var tb = t.createTBody();

  var multi = [];
  SEVERITIES.forEach(function (sev) {
    var overridden = Object.prototype.hasOwnProperty.call(pols, sev);
    var p = overridden ? pols[sev] : DEFAULT_LADDERS[sev];
    var own = ownerOf(sev, pols, live);
    var stages = (p.stages && p.stages.length) ? p.stages : [{ after: "0s", channels: [] }];
    var first = stages[0];
    if (stages.length > 1) multi.push({ sev: sev, n: stages.length });

    var row = tb.insertRow();
    row.className = "sev-" + sev + (overridden ? " customised" : "");
    var sc = row.insertCell();
    sc.appendChild(badge(sev, "sev-" + sev));
    if (stages.length > 1) sc.appendChild(badge("+" + (stages.length - 1) + " stage" + (stages.length > 2 ? "s" : ""), "info"));

    live.forEach(function (name) {
      var c = row.insertCell();
      var b = boxFor(first.channels, name, function (on) {
        var tgt = own();
        if (!tgt.stages || !tgt.stages.length) tgt.stages = [{ after: "0s", channels: [] }];
        toggleIn(tgt.stages[0].channels || (tgt.stages[0].channels = []), name, on);
        redraw();
      });
      b.setAttribute("aria-label", "tell " + name + " on " + sev);
      c.appendChild(b);
    });

    var rc = row.insertCell();
    var rep = durationField(p, "repeat_every", own);
    rep.placeholder = "once";
    rep.setAttribute("aria-label", sev + ": repeat every");
    rc.appendChild(rep);
    var gc = row.insertCell();
    var giveUp = durationField(p, "give_up_after", own);
    giveUp.placeholder = "never";
    giveUp.setAttribute("aria-label", sev + ": give up after");
    gc.appendChild(giveUp);

    var qc = row.insertCell();
    var q = el("input");
    q.type = "checkbox";
    q.checked = !!p.respect_quiet_hours;
    q.disabled = (sev === "critical");
    q.setAttribute("aria-label", sev + ": respect quiet hours");
    if (sev === "critical") q.title = "Quiet hours never apply to critical. That control does not exist.";
    q.addEventListener("change", function () {
      own().respect_quiet_hours = q.checked;
      redraw();
    });
    qc.appendChild(q);

    var st = row.insertCell();
    st.className = "rowstate";
    st.appendChild(badge(overridden ? "customised" : "default", overridden ? "info" : "is-muted"));
    if (overridden) {
      var reset = el("button", "act ghost small", "reset");
      reset.type = "button";
      reset.title = "Back to the default";
      reset.addEventListener("click", function () { delete pols[sev]; redraw(); });
      st.appendChild(reset);
    }
  });
  box.appendChild(t);

  var wrap = el("div", "matrix-wrap");
  wrap.appendChild(box);
  var legend = el("div", "note");
  legend.textContent = "A tick means that channel is told the moment an alarm of that " +
    "severity is raised. Repeat every: how often it keeps asking until somebody " +
    "acknowledges (blank = once). Give up after: when it stops (never = keep going). " +
    "Critical never respects quiet hours.";
  wrap.appendChild(legend);
  multi.forEach(function (m) {
    wrap.appendChild(el("div", "note",
      m.sev + " has " + m.n + " stages. The matrix edits the first; tick Advanced to see the rest."));
  });
  return wrap;
}

// policyCard is one severity in the advanced view: every stage of its
// ladder, the repeat and give-up, and quiet hours.
function policyCard(sev, pols, redraw, live) {
  var overridden = Object.prototype.hasOwnProperty.call(pols, sev);
  var p = overridden ? pols[sev] : DEFAULT_LADDERS[sev];
  var own = ownerOf(sev, pols, live);

  var c = el("div", "card");
  var head = el("div", "row");
  head.appendChild(badge(sev, "sev-" + sev));
  head.appendChild(el("div", "grow"));
  head.appendChild(badge(overridden ? "customised" : "default", overridden ? "info" : "is-muted"));
  c.appendChild(head);

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
    rm.type = "button";
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
  add.type = "button";
  add.addEventListener("click", function () {
    var t = own();
    t.stages = t.stages || [];
    t.stages.push({ after: "15m", channels: [] });
    redraw();
  });
  addBar.appendChild(add);
  c.appendChild(addBar);

  var af = el("div", "fields");
  af.appendChild(labelled("Repeat every (blank = ask once)", durationField(p, "repeat_every", own)));
  af.appendChild(labelled("Give up after (never = keep going)", durationField(p, "give_up_after", own)));
  c.appendChild(af);

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
    reset.type = "button";
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
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = "text";
  i.placeholder = "30s, 5m, 2h";
  i.value = (obj[key] === undefined || obj[key] === null) ? "" : obj[key];
  i.addEventListener("input", function () { own()[key] = i.value.trim(); });
  return i;
}

// ---------- rule review ----------
//
// The other direction. Everything else on this page reports on what arrived;
// this reports on what was CONFIGURED and never matched -- the set nothing
// else can see, because a rule that points at a device which no longer
// answers to that id produces no event, no error and no entry anywhere. It
// simply never fires, and the board stays green.
//
// A UniFi device id is generated AT ADOPTION TIME, so re-adopting a hub gives
// every door and camera under it a new id and silently detaches every rule
// naming one. The MAC is the only identifier that survives both that and a
// rename, and the permanent record keeps it -- which is what lets this card
// offer a specific replacement rather than just a worry.

function reviewCard(rev) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Do these rules still point at anything?"));

  // "NOTHING IS WRONG" AND "NOTHING WAS CHECKED" LOOK IDENTICAL ON A SCREEN
  // AND ARE OPPOSITE FACTS. A failed read of the record has to say so; shown
  // as a clean result it would be the most reassuring thing this card can
  // display, produced by the one case where it knows nothing at all.
  if (!rev || !rev.available) {
    card.appendChild(callout(
      (rev && rev.detail) || "The rules have not been checked against what " +
      "this site has.", "warn", "Not checked"));
    return card;
  }

  var findings = rev.findings || [];
  if (!findings.length) {
    card.appendChild(stateBlock("empty", {
      icon: "check", tone: "ok", compact: true,
      title: "Every rule points at something this site has had",
      text: "Checked against " + rev.known + " " +
        (rev.known === 1 ? "thing" : "things") + " this product has ever seen " +
        "an event about."
    }));
    return card;
  }

  card.appendChild(el("div", "muted small",
    "Checked against " + rev.known + " " + (rev.known === 1 ? "thing" : "things") +
    " this product has ever seen an event about. A rule that matches nothing " +
    "does not fail — it just never fires."));

  // Superseded first: it is the one with evidence behind it and a button that
  // does something. Sorting the weaker findings above it would bury the only
  // row anybody can act on.
  //
  // RANKS START AT 1, NOT 0. The first version used 0 for superseded and
  // `order[s] || 9` for the default, so the highest-priority finding scored a
  // falsy 0, fell through to 9, and sorted LAST -- putting the only row with
  // a button under three that have none. Every test passed; the screen is
  // what said otherwise.
  var order = { superseded: 1, unknown: 2, silent: 3 };
  var rank = function (f) { return order[f.status] || 9; };
  findings.slice().sort(function (a, b) {
    return rank(a) - rank(b);
  }).forEach(function (f) { card.appendChild(findingRow(f)); });
  return card;
}

function findingRow(f) {
  var row = el("div", "card");
  var head = el("div", "row");
  head.appendChild(badge(f.status === "superseded" ? "re-adopted?" :
    f.status === "unknown" ? "never seen" : "gone quiet",
    f.status === "superseded" ? "is-warn" : "is-muted"));
  head.appendChild(el("strong", "grow", f.reference));
  row.appendChild(head);
  row.appendChild(el("div", "muted small", "in rule “" + f.rule + "”"));

  row.appendChild(el("div", "", explainFinding(f)));
  (f.successors || []).forEach(function (sc) {
    row.appendChild(successorOffer(f, sc));
  });
  return row;
}

function explainFinding(f) {
  if (f.status === "superseded") {
    return "Last reported " + quietFor(f) + ". Something that looks like the " +
      "same device is reporting now under a different id — which is what a " +
      "re-adoption does: the id is generated when the hardware is adopted, so " +
      "adopting it again makes a new one and leaves this rule pointing at the " +
      "old one.";
  }
  if (f.status === "unknown") {
    return f.pattern
      ? "This pattern matches nothing this product has seen. That is fine if " +
        "the devices it is for have not fired yet; it is a typo otherwise."
      : "Nothing this product has ever seen an event about is called this. " +
        "A rename does this, and so does a typo — and neither one fails, so " +
        "the rule has simply never matched.";
  }
  return "Still resolves, to something last heard from " + quietFor(f) +
    ", with nothing that looks like a replacement. A door nobody opens for a " +
    "month looks exactly like this, so it may be nothing.";
}

// afterRepoint redraws the section from the server and says what still has to
// happen.
//
// THE NOTICE GOES IN THE SECTION FOOT, NOT IN THE CARD. The first version put
// it in the button's own message and then redrew the section, which detaches
// that node -- so the write succeeded, the finding vanished, and the one
// sentence that mattered was appended to an element no longer on the page.
// The operator was left believing the gate was watched again. The foot is
// built once, outside what redraw() refills, which is the whole reason
// settingsSection has one.
//
// Both the review and the settings are re-read: the review because the
// finding should now be gone, and the settings because the rule the editor
// below is showing has just changed underneath it. Refetching one and not
// the other would leave the form contradicting the card above it.
function afterRepoint(newID) {
  var ctx = settingsCtx;
  if (!ctx) { refreshSettings(); return; }
  Promise.all([api("GET", "/api/rules/review"), api("GET", "api/settings")])
    .then(function (both) {
      if (settingsCtx !== ctx) return; // the page was rebuilt underneath us
      var rv = both[0], st = both[1];
      if (rv.ok) ctx.review = rv.data || {};
      if (st.ok && st.data) {
        ctx.saved = st.data;
        ctx.draft.rules = clone(st.data.rules || []);
      }
      ctx.redraw("rules");
      var sec = ctx.sections.rules;
      if (sec && sec.foot) {
        clear(sec.foot);
        sec.foot.appendChild(restartOffer("The rule now points at " + newID +
          ", and that"));
        if (SECTION_SAVES.rules) {
          sec.foot.appendChild(saveBar(ctx, { key: "rules", title: "Rules" },
            SECTION_SAVES.rules));
        }
      }
      refreshStatus();
    });
}

function quietFor(f) {
  if (!f.last_seen) return "some time ago";
  if (f.quiet_days >= 1) return f.quiet_days + " day" + (f.quiet_days === 1 ? "" : "s") + " ago";
  return "today, at " + stamp(f.last_seen);
}

// successorOffer is the button, and the WORDING OF THE BUTTON IS THE POINT.
//
// A MAC match is evidence: it is the one identifier that survives both a
// rename and a re-adoption. A name match is a hint. Presenting them as the
// same offer would invite somebody to take the weaker answer without knowing
// they were choosing.
function successorOffer(f, sc) {
  var box = el("div", "row");
  var strong = sc.on === "mac";
  box.appendChild(badge(strong ? "same MAC" : "same name", strong ? "is-ok" : "is-muted"));

  var text = el("div", "grow");
  text.appendChild(el("div", "", (sc.name ? sc.name + " — " : "") + sc.id));
  text.appendChild(el("div", "muted small", strong
    ? "The same hardware address, on a newer id. This is the identifier that " +
      "survives both a rename and a re-adoption."
    : "The same name, on a newer id. Weaker than a hardware address: two " +
      "devices can share a name."));
  box.appendChild(text);

  var b = el("button", "act" + (strong ? " primary" : "") + " small", "Point the rule here");
  b.type = "button";
  var msg = el("div", "msg");
  b.addEventListener("click", function () {
    b.disabled = true;
    msg.className = "msg";
    fill(msg, "");
    api("POST", "/api/rules/repoint", {
      rule_index: f.rule_index, rule: f.rule, from: f.reference, to: sc.id
    }).then(function (res) {
      if (!res.ok) {
        b.disabled = false;
        msg.className = "msg err";
        fill(msg, (res.data && res.data.error) || "that could not be applied");
        return;
      }
      afterRepoint(sc.id);
    });
  });
  var bar = el("div", "formbar");
  bar.appendChild(b);
  box.appendChild(bar);

  var outer = el("div", "");
  outer.appendChild(box);
  outer.appendChild(msg);
  return outer;
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

function renderRules(body, draft, vocab, seen) {
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
      panel.appendChild(emptyState("No rules",
        "Every event is treated as its source proposed. A rule can silence a " +
        "noisy camera or make one door critical.",
        null, { icon: "list", compact: true }));
    }
    rules.forEach(function (r, idx) {
      panel.appendChild(ruleCard(r, idx, rules, advanced.checked, draw, vocab || [], seen || []));
    });
    var bar = el("div", "formbar");
    var add = el("button", "act" + (rules.length ? "" : " primary"), "Add a rule");
    add.type = "button";
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

// entityField is free text WITH suggestions, and the split matters.
//
// No fixed list can supply this one: camera and door names belong to the site,
// not to this build. The only honest suggestions are the things events have
// actually been about -- so they come from what the running daemon has seen,
// and an empty list on a fresh install is the truth rather than a gap.
//
// It stays free text because an operator may legitimately write a rule for a
// camera that has not fired yet, or use a * prefix. A dropdown here would be a
// list pretending to be exhaustive about somebody else's building.
function entityField(r, seen) {
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = "text";
  i.placeholder = "any";
  i.value = (r.entities || [])[0] || "";
  i.setAttribute("list", entityDatalist(seen));
  i.addEventListener("input", function () {
    var v = i.value.trim();
    r.entities = v === "" ? [] : [v];
  });

  var wrap = el("div", "");
  wrap.appendChild(i);
  if (!(seen || []).length) {
    wrap.appendChild(el("div", "note",
      "No suggestions yet: nothing has produced an event since this daemon " +
      "started. Names appear here once they do. A rule matches an entity by " +
      "its name or its id, and either works."));
  }
  return wrap;
}

// entityDatalist builds (once) the shared <datalist> of observed entities.
//
// Both the NAME and the ID are offered, because a rule matches either and they
// answer different needs: the name is what a person recognises, and the id is
// what survives somebody renaming a camera.
var entityListID = "";
function entityDatalist(seen) {
  if (entityListID) {
    var old = document.getElementById(entityListID);
    if (old && old.parentNode) old.parentNode.removeChild(old);
  }
  entityListID = "entities-seen";
  var dl = document.createElement("datalist");
  dl.id = entityListID;
  var added = {};
  (seen || []).forEach(function (e) {
    [e.name, e.id].forEach(function (v) {
      if (!v || added[v]) return;
      added[v] = true;
      var o = document.createElement("option");
      o.value = v;
      o.label = (e.name && e.id && v === e.id ? e.name + " " : "") +
        "(" + e.source + (e.kind ? " " + e.kind : "") + ")";
      dl.appendChild(o);
    });
  });
  document.body.appendChild(dl);
  return entityListID;
}

// conditionPicker offers the vocabulary instead of asking somebody to guess it.
//
// Source and Severity have always been dropdowns here. Condition -- the one
// field with a fixed, finite, already-loaded vocabulary -- was a text box with
// the placeholder "any", and a typo in it does not fail: the rule silently
// never matches. A rule written to silence a noisy camera goes on not
// silencing it, and nothing anywhere says so.
//
// Grouped, because thirty-nine flat entries is a list nobody reads, and each
// option carries what it MEANS rather than just its name. Anything already in
// the config is kept selectable even if this build no longer lists it, so
// opening the page cannot quietly rewrite a rule somebody relies on.
function conditionPicker(r, vocab) {
  var cur = (r.conditions || [])[0] || "";
  var sel = el("select");

  var anyOpt = document.createElement("option");
  anyOpt.value = "";
  anyOpt.textContent = "anything";
  sel.appendChild(anyOpt);

  var groups = {}, order = [];
  (vocab || []).forEach(function (c) {
    if (!groups[c.group]) { groups[c.group] = []; order.push(c.group); }
    groups[c.group].push(c);
  });

  var known = false;
  order.forEach(function (g) {
    var og = document.createElement("optgroup");
    og.label = g;
    groups[g].forEach(function (c) {
      var o = document.createElement("option");
      o.value = c.name;
      o.textContent = c.name + " — " + c.meaning;
      if (c.name === cur) { o.selected = true; known = true; }
      og.appendChild(o);
    });
    sel.appendChild(og);
  });

  // A value this build does not know -- an older config, or a hand-edited
  // file. Kept and marked rather than silently dropped on the next save.
  if (cur !== "" && !known) {
    var og2 = document.createElement("optgroup");
    og2.label = "In your configuration, not in this build";
    var o2 = document.createElement("option");
    o2.value = cur;
    o2.textContent = cur + " — this build does not emit this; the rule will never match";
    o2.selected = true;
    og2.appendChild(o2);
    sel.appendChild(og2);
  }

  var meaning = el("div", "note", "");
  var describe = function () {
    var v = sel.value;
    if (v === "") {
      meaning.textContent = "Matches every condition from the chosen source.";
      return;
    }
    var found = null;
    (vocab || []).forEach(function (c) { if (c.name === v) found = c; });
    if (!found) {
      meaning.textContent = "This build does not emit " + v + ", so this rule will never match.";
      return;
    }
    meaning.textContent = found.meaning +
      (found.sources && found.sources.length
        ? "  Emitted by: " + found.sources.join(", ") + "."
        : "  No source emits this directly -- it arrives only on an inbound webhook you point at it.");
  };
  sel.addEventListener("change", function () {
    var v = sel.value;
    r.conditions = v === "" ? [] : [v];
    describe();
  });
  describe();

  var wrap = el("div", "");
  wrap.appendChild(sel);
  wrap.appendChild(meaning);
  return wrap;
}

// conditionReference lists the whole vocabulary for the Advanced editor, where
// the field is free text because that is where * prefixes live.
//
// Collapsed, so it is available without being in the way. It says what it is
// and what it is NOT: these are the conditions a rule can match, which is not
// the same as everything a console might send.
function conditionReference(vocab) {
  var d = document.createElement("details");
  var sum = document.createElement("summary");
  sum.textContent = "Every condition this build can match (" + (vocab || []).length + ")";
  d.appendChild(sum);

  d.appendChild(el("div", "note",
    "These are the conditions a rule can match, because rules match this " +
    "build's vocabulary. That is not the same as everything your UniFi might " +
    "send: firmware emits types this build does not map, and those are counted " +
    "as unrecognised rather than becoming a condition. Run \"notifymatrix " +
    "probe\" to ask your own console what it actually exposes."));

  var lastGroup = "";
  (vocab || []).forEach(function (c) {
    if (c.group !== lastGroup) {
      d.appendChild(el("div", "label", c.group));
      lastGroup = c.group;
    }
    var row = el("div", "note");
    var name = el("code", "cond", c.name);
    row.appendChild(name);
    row.appendChild(document.createTextNode(" — " + c.meaning +
      (c.sources && c.sources.length ? "  (" + c.sources.join(", ") + ")" : "  (inbound webhook only)")));
    d.appendChild(row);
  });
  return d;
}

function ruleCard(r, idx, rules, advanced, redraw, vocab, seen) {
  var c = el("div", "card");
  var f = el("div", "fields");
  f.appendChild(labelled("Name (shown in the audit record)", bind(r, "name")));
  c.appendChild(f);

  if (!advanced) {
    var g = el("div", "fields");
    g.appendChild(labelled("When the source is", selectInto(r, "sources", SOURCE_NAMES)));
    g.appendChild(labelled("and what happened is", conditionPicker(r, vocab)));
    g.appendChild(labelled("on (camera, door, blank = any)", entityField(r, seen)));
    c.appendChild(g);
  } else {
    var h = el("div", "fields");
    h.appendChild(labelled("Sources (comma separated, * allowed)", bindList(r, "sources")));
    h.appendChild(labelled("Conditions (comma separated, * allowed)", bindList(r, "conditions")));
    h.appendChild(labelled("Entities (comma separated, * allowed)", bindList(r, "entities", seen)));
    c.appendChild(h);
    c.appendChild(el("div", "note",
      "An empty list matches anything. A trailing * matches by prefix, so " +
      "\"doorbell*\" covers every condition starting with it."));
    c.appendChild(conditionReference(vocab));
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

  // A window or a severity shift can be set in the configuration file and has
  // no control here yet. Saying so matters: the editor round-trips both
  // untouched, so without this line the rule would look simpler than it is --
  // and picking "Treat it as" on a rule that shifts severity produces a
  // refusal naming a shift the operator cannot see anywhere on the page.
  if (r.window || r.elevate) {
    var extra = [];
    if (r.window) {
      extra.push("active " + (r.window.start || "?") + "-" + (r.window.end || "?") +
        " in the site's time zone; outside those hours this rule does nothing");
    }
    if (r.elevate) {
      extra.push(r.elevate > 0
        ? "raises severity by " + r.elevate + " tier" + (r.elevate === 1 ? "" : "s")
        : "lowers severity by " + (-r.elevate) + " tier" + (r.elevate === -1 ? "" : "s"));
    }
    c.appendChild(el("div", "note",
      "Set in the configuration file: " + extra.join("; ") +
      ". Edit it there; this page leaves it alone."));
  }

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
  var i = keepOutOfPasswordManagers(el("input"));
  i.type = "text";
  i.placeholder = "any";
  i.value = (obj[key] || [])[0] || "";
  i.addEventListener("input", function () {
    var v = i.value.trim();
    obj[key] = v === "" ? [] : [v];
  });
  return i;
}

// ---------- inbound hooks ----------
//
// One endpoint per UniFi Alarm Manager rule. Alarm Manager rules can only be
// made in the UniFi UI -- no API creates them -- so this end cannot set them
// up; what it can do is own the endpoint each one posts to, and say what an
// arrival there MEANS.
//
// The URL and the Authorization header come from the checklist, not the
// settings view: they are credentials, the settings API never returns a
// token, and the checklist is the one endpoint that gates them behind a
// session. They are shown here, on the card for the hook they belong to.

var HOOK_PRODUCTS = ["network", "protect", "access"];
var HOOK_SEVERITIES = ["", "critical", "high", "medium", "low", "info"];

function renderHooks(body, draft, conditions, creds) {
  var hooks = draft.hooks || (draft.hooks = []);
  var card = el("div", "card");
  card.appendChild(el("p", "",
    "One endpoint per Alarm Manager rule. Add it here, then paste its URL and " +
    "header into the rule -- both are shown on the hook's own card below."));

  var panel = el("div", "stack");
  card.appendChild(panel);

  var draw = function () {
    clear(panel);
    if (!hooks.length) {
      panel.appendChild(emptyState("No inbound hooks",
        "Network alarms have no other way in: the Integration API publishes no " +
        "events at all, so anything from Alarm Manager arrives here or not at all.",
        null, { icon: "link", compact: true }));
    }
    hooks.forEach(function (h, idx) {
      panel.appendChild(hookCard(h, idx, hooks, conditions, draw, creds || {}));
    });
    var bar = el("div", "formbar");
    var add = el("button", "act primary", "Add a hook");
    add.type = "button";
    add.addEventListener("click", function () {
      hooks.push({ name: "", product: "network", condition: conditions[0] || "" });
      draw();
    });
    bar.appendChild(add);
    panel.appendChild(bar);
  };
  draw();
  body.appendChild(card);
}

// The name is the handle the credentials are carried by -- the browser is
// never sent a token, so it cannot send one back, and a renamed hook is
// indistinguishable from a new one. It therefore gets fresh credentials and
// its old URL stops working, which the console will not tell anybody: the
// rule keeps posting to a dead endpoint and the alarms it carried simply
// stop arriving. It is said AT the name field, as a disclosure, because that
// is the control the mistake is made at; it used to be a grid cell that
// looked like another field.
var HOOK_RENAME_WARNING =
  "Renaming this hook issues new credentials and its current URL stops " +
  "working. The Alarm Manager rule would keep posting to the old one and " +
  "those alarms would stop arriving, silently. Re-paste the new URL and " +
  "header from this card afterwards.";

function hookCard(h, idx, hooks, conditions, redraw, creds) {
  var c = el("div", "card hook");
  var ready = h.token_set && h.bearer_set;
  var cr = ready ? creds[(h.name || "").trim()] : null;

  var head = el("div", "row");
  head.appendChild(el("strong", "grow", (h.name || "").trim() || "New hook"));
  // "URL issued" rather than "endpoint live": the badge answers whether
  // there is a URL to paste yet, which is the only thing it knows.
  head.appendChild(badge(ready ? "URL issued" : "URL issued on save", ready ? "on" : "off"));
  evidenceBadges(cr).forEach(function (b) { head.appendChild(b); });
  c.appendChild(head);

  var f = el("div", "fields");
  f.appendChild(labelled("Name (match the Alarm Manager rule)", bind(h, "name"),
    (h.token_set || h.bearer_set) ? { text: HOOK_RENAME_WARNING, label: "before renaming", tone: "warn" } : null));
  f.appendChild(labelled("UniFi application", pick(h, "product", HOOK_PRODUCTS, null)));
  f.appendChild(labelled("Alarm type", pick(h, "condition", conditions, null),
    "What an arrival at this URL means. The rule at the UniFi end decides when " +
    "to post; this decides what the post is recorded as."));
  f.appendChild(labelled("Severity", pick(h, "severity", HOOK_SEVERITIES, "high (default)")));
  var ent = bind(h, "entity");
  ent.placeholder = "blank = the rule's name";
  f.appendChild(labelled("Device or place (optional)", ent,
    "What the alarm is about -- a WAN name, a switch, a site. Blank uses the " +
    "rule's name."));
  c.appendChild(f);

  if (!ready) {
    c.appendChild(el("div", "note",
      "Its URL and header are created when you save, and appear here afterwards."));
  } else if (cr && cr.url) {
    // Shown HERE, on the card for the hook it belongs to. It used to say
    // "appear on the Setup tab", and the Setup tab did not render them either:
    // the interface promised a credential in one place, pointed at another,
    // and showed it in neither. The only way to get the URL was a terminal.
    var creds1 = el("div", "stack");
    var notice = testModeNotice(cr);
    if (notice) creds1.appendChild(notice);
    var ul = el("div", "");
    ul.appendChild(el("div", "label", "URL for the Alarm Manager rule"));
    ul.appendChild(credRow(cr.url, true));
    if (cr.header_name) {
      var hl = el("div", "label", "Header the rule must send");
      hl.appendChild(why("Both are passwords. The header is not optional -- a URL " +
        "travels through the console backup, browser history and every proxy " +
        "log on the path, and a header does not.", { label: "why both?", tone: "warn" }));
      ul.appendChild(hl);
      ul.appendChild(credRow(cr.header_name + ": " + cr.header_value, true));
    }
    creds1.appendChild(ul);
    // Evidence, not configuration. A rule that looks right at the UniFi end
    // and has never fired is the failure this is here to make visible.
    if (cr.count > 0) {
      creds1.appendChild(el("div", "note",
        cr.count + " alarm(s) have arrived through this hook."));
    } else {
      creds1.appendChild(callout(
        "Nothing has arrived through this hook yet. Until something does, " +
        "the rule at the UniFi end is unproven -- it can look perfectly " +
        "correct there and deliver nothing.", "warn"));
    }
    if (cr.rejected > 0) {
      creds1.appendChild(callout(
        cr.rejected + " request(s) were refused" +
        (cr.last_reject ? ": " + cr.last_reject : "") +
        ". That is usually the header being absent or wrong.", "err"));
    }
    creds1.appendChild(hookTestControls(h, cr));
    c.appendChild(creds1);
  } else {
    c.appendChild(el("div", "note",
      "Its URL and header exist. Save and restart the service if they are " +
      "not shown here yet -- hooks are built when the daemon starts."));
  }

  // Regenerating is destructive in a way that is easy not to see coming: the
  // console keeps posting to the old URL and this end keeps refusing, so the
  // rule looks fine at the UniFi end and silently delivers nothing.
  var reg = el("input");
  reg.type = "checkbox";
  reg.checked = !!h.regenerate;
  reg.addEventListener("change", function () { h.regenerate = reg.checked; redraw(); });
  c.appendChild(labelled("Replace its URL and header on save", reg,
    { text: "The Alarm Manager rule pointing at the old URL stops working until " +
            "you re-paste the new URL and header from this card.", tone: "warn" }));
  if (h.regenerate) {
    c.appendChild(callout(
      "This breaks the Alarm Manager rule pointing at the old URL. The console " +
      "will keep posting and this end will keep refusing, which looks like " +
      "nothing happening rather than like an error. Re-paste the new URL and " +
      "header from this card afterwards.", "err", "On save"));
  }

  var bar = el("div", "formbar");
  var rm = el("button", "act", "Remove");
  rm.type = "button";
  rm.addEventListener("click", function () { hooks.splice(idx, 1); redraw(); });
  bar.appendChild(rm);
  if (ready) {
    // At the button, not under the card: it is the consequence of pressing
    // this one control.
    bar.appendChild(why(
      "Removing this stops accepting anything at its URL. The Alarm Manager rule " +
      "will keep posting into a refusal until you delete it in UniFi too.",
      { label: "what happens?", tone: "warn" }));
  }
  c.appendChild(bar);
  return c;
}

// pick is a dropdown over a fixed list, with an optional label for the empty
// choice. A fixed list because these values become part of a stored dedup key:
// a typo would make an alarm that never merges with itself and nags separately
// for ever.
// pick is a <select> over a fixed list.
//
// THERE WERE TWO OF THESE, declared in the same file with the same name, and
// the later one won for every caller. They behaved differently: one always
// offered a blank entry so a value could be cleared back to its default, the
// other never did. The casualty was the voice channel -- VOICE_SAY_VOICES is
// ["man","woman"] with no blank member, so once a voice was chosen there was
// no way to return it to the default, and the "man (default)" label the caller
// passed was never rendered at all. HOOK_SEVERITIES happens to carry its own
// "" member, which is why that dropdown looked fine and hid the bug.
//
// One function now, doing both jobs:
//   blankLabel non-null -> a blank entry is offered, labelled with it
//   blankLabel null     -> the choice is mandatory (a hook's product must be
//                          one of three; "no product" is not a hook)
// and, either way, a value the server sent that this page does not know about
// stays visible and selected, or opening the form would silently change it on
// the next save.
function pick(obj, key, choices, blankLabel) {
  var sel = el("select");
  var cur = obj[key] || "";
  var seen = false;
  var opts = (choices || []).slice();
  if (blankLabel != null && opts.indexOf("") < 0) opts.unshift("");
  opts.forEach(function (s) {
    var o = document.createElement("option");
    o.value = s;
    o.textContent = s === "" ? (blankLabel || "any") : s;
    if (cur === s) { o.selected = true; seen = true; }
    sel.appendChild(o);
  });
  // A value the server offered but this page does not know about must still be
  // visible, or opening the form would silently change it on the next save.
  if (!seen && cur !== "") {
    var o2 = document.createElement("option");
    o2.value = cur;
    o2.textContent = cur + " (from the configuration)";
    o2.selected = true;
    sel.appendChild(o2);
  }
  sel.addEventListener("change", function () { obj[key] = sel.value; });
  return sel;
}

// renderDemoBanner marks a demo instance on every screen.
//
// Served by the API rather than baked into the page, so it is the DAEMON that
// decides -- a page cannot claim to be real by being reloaded, and a
// screenshot is not the only thing carrying the warning.
function renderDemoBanner(text) {
  var existing = byId("demo-banner");
  if (!text) {
    if (existing) existing.parentNode.removeChild(existing);
    return;
  }
  if (existing) { existing.textContent = text; return; }
  var b = el("div", "banner is-err", text);
  b.id = "demo-banner";
  document.body.insertBefore(b, document.body.firstChild);
}

// renderSelfWatchBanner says, on every screen, that a quiet board here cannot
// be trusted.
//
// THE BOARD IS THE THING THAT LIES. When the daemon runs on the equipment it
// watches, "all clear" and "this died an hour ago and cannot tell you" render
// identically -- and the second one is the state this whole product exists to
// refuse. Nothing else on any screen would ever reveal it, because the symptom
// is silence.
//
// Shown SIGNED OUT as well as in, which is the wall-display case and the one
// that most needs it. The server decides, so a page cannot claim to be safe by
// being reloaded and a screenshot carries the warning too -- the same
// reasoning as the demo banner above.
//
// It clears itself. The problem is not where the daemon runs, it is that
// nothing outside this machine would notice it stop, and pairing a peer
// elsewhere makes that false. An operator who fixes it watches this go away
// rather than reading that it is fixed.
function renderSelfWatchBanner(sw) {
  var existing = byId("selfwatch-banner");
  if (!sw || !sw.at_risk || !sw.detail) {
    if (existing) existing.parentNode.removeChild(existing);
    return;
  }
  if (existing) { existing.textContent = sw.detail; return; }
  var b = el("div", "banner is-warn", sw.detail);
  b.id = "selfwatch-banner";
  // Under the demo banner when both are present: fabricated data is the more
  // urgent thing to know about a screen.
  var demo = byId("demo-banner");
  if (demo && demo.nextSibling) {
    document.body.insertBefore(b, demo.nextSibling);
  } else if (demo) {
    document.body.appendChild(b);
  } else {
    document.body.insertBefore(b, document.body.firstChild);
  }
}

// ---------- the capability probe ----------
//
// TWO THINGS THIS DOES THAT THE COMMAND CANNOT.
//
// It refuses BEFORE the window. A console with no API key answers every
// request with its login page, and a run against one spends its capture
// window -- the minute somebody spends deliberately walking past their own
// cameras -- learning nothing. The daemon knows which consoles have keys, so
// the page can say so instead of letting somebody find out afterwards.
//
// And it holds the instruction up while it is true. "Trigger it NOW" is a
// line scrolled past in a terminal and a live panel here.
//
// WHAT IT DELIBERATELY DOES NOT DO IS SUBMIT ANYTHING. Download hands over a
// file. Contributing it is a separate, manual act, after somebody has read
// the bytes -- which is the same order the command enforces by printing the
// whole file before it will talk about contributing.

var probeUI = { data: null, poll: null, reading: null, text: {}, msg: "" };

function loadProbe() {
  return api("GET", "api/probe").then(function (res) {
    probeUI.data = res.ok ? res.data : {
      available: false, consoles: [], reports: [],
      detail: (res.data && res.data.error) || "the probe could not be read"
    };
    if (settingsCtx) settingsCtx.redraw("probe");
    probePoll();
  });
}

// Polled only while a run is listening, and only while somebody is looking at
// the tab. A daemon that is otherwise sitting still should not acquire a
// permanent timer because a page was left open on another tab.
function probePoll() {
  if (probeUI.poll) { clearTimeout(probeUI.poll); probeUI.poll = null; }
  var st = probeUI.data;
  if (!st || !st.running || state.tab !== "settings") return;
  probeUI.poll = setTimeout(loadProbe, 1500);
}

function renderProbeSection(body, ctx) {
  if (!probeUI.data) {
    body.appendChild(stateBlock("loading", { text: "Asking what this console can be probed for…" }));
    loadProbe();
    return;
  }
  var st = probeUI.data;

  body.appendChild(el("p", "note",
    "The probe asks your console which endpoints answer and listens on each " +
    "push socket, then writes a file saying what this build does not handle " +
    "and what it expects that your firmware does not have. It talks to local " +
    "addresses only, and every name, address and identifier is replaced " +
    "before anything is written."));

  if (!st.available) {
    body.appendChild(callout(st.detail || "This build cannot run a probe.", "warn",
      "Not available here"));
    return;
  }

  body.appendChild(probeReadinessCard(st));
  body.appendChild(probeRunCard(st));
  body.appendChild(probeReportsCard(st));
  if (probeUI.reading) body.appendChild(probeReaderCard(st));
}

// What has to be true before the button does anything. Rendered even when
// everything is fine, because "which console am I about to survey" is the
// other question somebody has at this moment.
function probeReadinessCard(st) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Before it runs"));

  var consoles = st.consoles || [];
  if (!consoles.length) {
    card.appendChild(stateBlock("empty", {
      icon: "camera", tone: "warn", compact: true,
      title: "No console is configured",
      text: "The probe asks a console what it can do, so there has to be one to ask.",
      action: { label: "Add a console", href: "#settings/consoles" }
    }));
    return card;
  }

  var list = el("div", "stack");
  consoles.forEach(function (c) {
    var row = el("div", "row");
    row.appendChild(icon(c.has_key ? "check" : "warning", c.has_key ? "ok" : "warn"));
    var text = el("div", "grow");
    text.appendChild(el("div", "title", c.name || c.host));
    text.appendChild(el("div", "muted small",
      c.host + " · " + (c.has_key
        ? "API key saved"
        : "no API key — it would only reach the login page")));
    row.appendChild(text);
    list.appendChild(row);
  });
  card.appendChild(list);

  if (st.blocked) {
    var box = callout(st.blocked, "warn", "It cannot run yet");
    card.appendChild(box);
    var go = el("a", "act small", "Open Consoles");
    go.href = "#settings/consoles";
    card.appendChild(go);
  }
  return card;
}

// The run itself, and the instruction that only matters for the ninety
// seconds it is on screen.
function probeRunCard(st) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Run one"));

  if (st.running) {
    // A RUN HAS TWO HALVES AND ONLY ONE OF THEM WANTS YOU TO DO ANYTHING.
    // It walks the endpoints first, which takes no participation, and only
    // then opens the sockets. Told to go and trigger something during the
    // sweep, somebody is back at their desk by the moment it would have
    // counted.
    var lines = st.lines || [];
    var last = "", socket = "";
    for (var i = lines.length - 1; i >= 0; i--) {
      if (lines[i] && lines[i].trim()) { last = lines[i]; break; }
    }
    for (i = lines.length - 1; i >= 0; i--) {
      if (lines[i] && lines[i].indexOf("listening on ") === 0) {
        socket = lines[i].slice("listening on ".length);
        break;
      }
    }
    var capturing = last.indexOf("TRIGGER") === 0;

    if (capturing) {
      card.appendChild(callout(
        "Trigger what you want captured NOW — walk past a camera, open " +
        "a door, press a doorbell. Several event classes do not exist unless " +
        "somebody does something, and this window is the only chance this " +
        "run has to see one.",
        "warn", socket ? "Listening on " + socket : "It is listening"));
    } else {
      card.appendChild(callout(
        "It is asking the console which endpoints answer. Nothing to do yet " +
        "— this panel will say when to go and trigger something.",
        "info", "Surveying"));
    }

    // The instruction is the callout above; repeating it in the log buries
    // the line that says which socket is open under a paragraph of it.
    var shown = [];
    lines.forEach(function (l) { if (l.indexOf("TRIGGER") !== 0) shown.push(l); });
    card.appendChild(el("pre", "probe-log", shown.slice(-14).join("\n")));


    var stopBar = el("div", "formbar");
    var stop = el("button", "act", "Stop");
    stop.addEventListener("click", function () {
      stop.disabled = true;
      api("POST", "api/probe/stop").then(loadProbe);
    });
    stopBar.appendChild(stop);
    card.appendChild(stopBar);
    return card;
  }

  var bar = el("div", "formbar");

  var withKeys = (st.consoles || []).filter(function (c) { return c.has_key; });
  var pick = el("select");
  withKeys.forEach(function (c) {
    var o = el("option", null, c.name || c.host);
    o.value = c.name || "";
    pick.appendChild(o);
  });
  if (withKeys.length > 1) bar.appendChild(labelled("Console", pick));

  var window_ = el("select");
  [[30, "30 seconds"], [60, "1 minute"], [90, "90 seconds"], [180, "3 minutes"]]
    .forEach(function (pair) {
      var o = el("option", null, pair[1]);
      o.value = String(pair[0]);
      window_.appendChild(o);
    });
  window_.value = "30";
  bar.appendChild(labelled("Listen for", window_,
    "Several event classes only exist while somebody is triggering them, so " +
    "this is how long you have to go and do that."));

  var run = el("button", "act primary", "Run the probe");
  run.disabled = !st.ready;
  run.addEventListener("click", function () {
    run.disabled = true;
    probeUI.msg = "";
    api("POST", "api/probe/run", {
      console: withKeys.length ? (pick.value || (withKeys[0].name || "")) : "",
      seconds: parseInt(window_.value, 10)
    }).then(function (res) {
      if (!res.ok) {
        // Shown verbatim. Everything this refuses is something the operator
        // chose, and a generic failure would leave a button that does
        // nothing for a reason nobody can see.
        probeUI.msg = (res.data && res.data.error) || "the probe could not start";
        if (settingsCtx) settingsCtx.redraw("probe");
        return;
      }
      loadProbe();
    });
  });
  bar.appendChild(run);
  card.appendChild(bar);

  if (probeUI.msg) card.appendChild(el("div", "msg err", probeUI.msg));

  // The verdict on the last run, which is the thing worth knowing about it.
  if (st.error) {
    card.appendChild(callout(st.error, "err", "The last run could not happen"));
  } else if (st.last_report && !st.last_authenticated) {
    card.appendChild(callout(
      "Nothing came back as an API answer — the requests were refused, or " +
      "the console never answered at all — so that report describes what " +
      "this build went looking for and nothing about your console. It is " +
      "kept, but there is nothing in it worth contributing.",
      "warn", "The last run never got in"));
  } else if (st.last_report) {
    card.appendChild(callout(
      "The last run reached the console. Its report is below.", "ok", "Done"));
  }
  return card;
}

function probeReportsCard(st) {
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", "Reports"));

  var reports = st.reports || [];
  if (!reports.length) {
    card.appendChild(stateBlock("empty", {
      icon: "list", compact: true,
      title: "No reports yet",
      text: "A run writes one file per go, and they stay on this machine."
    }));
    return card;
  }

  var list = el("div", "stack");
  reports.forEach(function (r) {
    var row = el("div", "row");
    row.appendChild(icon(r.authenticated ? "check" : "warning",
      r.authenticated ? "ok" : "warn"));

    var text = el("div", "grow");
    text.appendChild(el("div", "title mono", r.name));
    var detail = stamp(r.at) + " · " + probeSize(r.size) + " · " +
      r.findings + (r.findings === 1 ? " finding" : " findings");
    if (r.unreadable) {
      detail += " · " + r.unreadable;
    } else if (!r.authenticated) {
      detail += " · nothing was authenticated";
    }
    text.appendChild(el("div", "muted small", detail));
    row.appendChild(text);

    var read = el("button", "act small", "Read it");
    read.addEventListener("click", function () { probeRead(r.name); });
    row.appendChild(read);

    list.appendChild(row);
  });
  card.appendChild(list);
  return card;
}

function probeSize(n) {
  if (!n) return "0 bytes";
  if (n < 1024) return n + " bytes";
  if (n < 1024 * 1024) return Math.round(n / 1024) + " KB";
  return (n / (1024 * 1024)).toFixed(1) + " MB";
}

function probeRead(name) {
  probeUI.reading = name;
  if (probeUI.text[name] !== undefined) {
    if (settingsCtx) settingsCtx.redraw("probe");
    return;
  }
  fetch("api/probe/reports/" + encodeURIComponent(name), { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.text() : null; })
    .then(function (t) {
      probeUI.text[name] = t === null ? "" : t;
      if (settingsCtx) settingsCtx.redraw("probe");
    });
}

// READING COMES BEFORE CONTRIBUTING, and the order is the point.
//
// The command prints the entire file before it will so much as tell you where
// to send it. A page that offered a Contribute button would undo that, so
// there is no such button: there is the file, on screen, and a download.
// What happens after the download is the operator's, done by hand, knowing
// what is in it.
function probeReaderCard(st) {
  var name = probeUI.reading;
  var card = el("div", "card");
  card.appendChild(el("div", "card-title", name));

  var meta = null;
  (st.reports || []).forEach(function (r) { if (r.name === name) meta = r; });

  if (meta && !meta.authenticated) {
    card.appendChild(callout(
      "Nothing in this run came back as an API answer, so what follows is a " +
      "list of what this build asked for rather than anything about your " +
      "console. There is no contribution in it.",
      "warn", "This one got nowhere"));
  }

  card.appendChild(el("p", "note",
    "This is the whole file, exactly as it would be published. Read it before " +
    "you decide to contribute it. It should contain no camera names, no door " +
    "names, no MAC addresses and no IP addresses — only field names, types, " +
    "UniFi's own vocabulary and your console's firmware version. If anything " +
    "in it identifies your site, that is a bug in this tool and reporting it " +
    "matters more than the contribution does."));

  var text = probeUI.text[name];
  if (text === undefined) {
    card.appendChild(stateBlock("loading", { text: "Reading it…", compact: true }));
    return card;
  }
  card.appendChild(el("pre", "probe-file", text || "(empty)"));

  card.appendChild(el("p", "note",
    "Nothing is uploaded from this page. Download saves the .jsonl file to " +
    "this browser; contributing it means opening an issue and attaching that " +
    "file yourself, which is deliberately a separate act."));

  var bar = el("div", "formbar");
  var dl = el("a", "act primary", "Download the .jsonl");
  dl.href = "api/probe/reports/" + encodeURIComponent(name) + "/download";
  dl.setAttribute("download", name);
  bar.appendChild(dl);

  if (!meta || meta.authenticated) {
    var issue = el("a", "act", "Open an issue to attach it to");
    issue.href = "https://github.com/suburbazine/Unifi-Notification-Matrix/issues/new";
    issue.target = "_blank";
    issue.rel = "noopener noreferrer";
    bar.appendChild(issue);
  }

  var close = el("button", "act", "Close");
  close.addEventListener("click", function () {
    probeUI.reading = null;
    if (settingsCtx) settingsCtx.redraw("probe");
  });
  bar.appendChild(close);
  card.appendChild(bar);
  return card;
}

// ---------- outbound webhooks ----------
//
// OUT -- one or more endpoints this pushes an alert document to, each
// addressable by name from an escalation rung. Rendered under Webhooks in
// Settings beside the inbound hooks, because they are the same idea
// pointing opposite ways and an operator thinking about one is thinking
// about both.

function renderOutboundWebhooks(body, draft) {
  var chans = draft.channels || (draft.channels = {});
  var list = chans.webhooks || (chans.webhooks = []);
  var card = el("div", "card");
  var panel = el("div", "stack");
  card.appendChild(panel);

  var draw = function () {
    clear(panel);
    if (!list.length) {
      panel.appendChild(emptyState("Nothing is pushed out",
        "Incidents are still tracked and still delivered through whatever " +
        "channels you have enabled.", null, { icon: "plug", compact: true }));
    }
    list.forEach(function (h, idx) {
      panel.appendChild(outboundCard(h, idx, list, draw));
    });
    var bar = el("div", "formbar");
    var add = el("button", "act primary", "Add an endpoint");
    add.type = "button";
    add.addEventListener("click", function () {
      list.push({ name: "", enabled: true, url: "", headers: {} });
      draw();
    });
    bar.appendChild(add);
    panel.appendChild(bar);
  };
  draw();
  body.appendChild(card);
}

function outboundCard(h, idx, list, redraw) {
  var c = el("div", "card");
  var head = el("div", "row");
  head.appendChild(el("strong", "grow", (h.name || "").trim() || "New endpoint"));
  head.appendChild(badge(h.enabled ? "enabled" : "disabled", h.enabled ? "on" : "off"));
  c.appendChild(head);

  var f = el("div", "fields");
  // The rename warning belongs at the name field, as a disclosure, for the
  // same reason as the inbound one: it is the control the mistake is made at.
  f.appendChild(labelled("Name (an escalation rung refers to this)", bind(h, "name"),
    h.secret_set ? { text: "Renaming this endpoint drops its signing secret, because the secret is " +
      "carried across by name. A receiver that checks signatures would start " +
      "rejecting real alarms. Set it again below if you rename it.",
      label: "before renaming", tone: "warn" } : null));
  f.appendChild(labelled("URL", bind(h, "url")));
  c.appendChild(f);

  var r = el("div", "row");
  r.appendChild(labelled("Enabled", check(h, "enabled")));
  r.appendChild(labelled("Skip certificate check", check(h, "insecure_skip_verify"),
    "Accepts any certificate the receiver presents. Only for a receiver on " +
    "your own network with a self-signed certificate."));
  c.appendChild(r);

  secretRow(c, h.secret_set, "signing secret", h, "secret_new");
  c.appendChild(el("div", "note",
    "With a signing secret set, each request carries an HMAC over the " +
    "timestamp and body that your receiver can check. Without one, anybody " +
    "who learns the URL can feed it false alarms -- and the URL itself is " +
    "often a credential, because most receivers put a token in it."));

  // Static headers, for receivers that want an API key or a routing hint.
  var hlab = el("div", "label", "Extra headers");
  hlab.appendChild(why(
    "For receivers that want an API key or a routing hint. The signature and " +
    "timestamp headers cannot be overridden here -- setting them by hand " +
    "breaks every receiver's verification, in the direction where the " +
    "receiver rejects real alarms.", "which headers?"));
  c.appendChild(hlab);
  var hdrs = h.headers || (h.headers = {});
  var hp = el("div");
  var drawHeaders = function () {
    clear(hp);
    Object.keys(hdrs).forEach(function (k) {
      var row = el("div", "row");
      var kv = keepOutOfPasswordManagers(el("input")); kv.type = "text"; kv.value = k;
      var vv = keepOutOfPasswordManagers(el("input")); vv.type = "text"; vv.value = hdrs[k];
      kv.addEventListener("change", function () {
        var val = hdrs[k];
        delete hdrs[k];
        if (kv.value.trim()) hdrs[kv.value.trim()] = val;
        drawHeaders();
      });
      vv.addEventListener("input", function () { hdrs[k] = vv.value; });
      var kc = labelled("Header", kv); kc.className = "grow";
      var vc = labelled("Value", vv); vc.className = "grow";
      row.appendChild(kc);
      row.appendChild(vc);
      var rm = el("button", "act small", "Remove");
      rm.type = "button";
      rm.addEventListener("click", function () { delete hdrs[k]; drawHeaders(); });
      row.appendChild(rm);
      hp.appendChild(row);
    });
    var addH = el("button", "act small", "Add a header");
    addH.type = "button";
    addH.addEventListener("click", function () {
      var n = 1;
      while (hdrs["header-" + n] !== undefined) n++;
      hdrs["header-" + n] = "";
      drawHeaders();
    });
    var b = el("div", "formbar"); b.appendChild(addH);
    hp.appendChild(b);
  };
  drawHeaders();
  c.appendChild(hp);

  if (h.name) testRow(c, h.name);

  var bar = el("div", "formbar");
  var rm = el("button", "act", "Remove this endpoint");
  rm.type = "button";
  rm.addEventListener("click", function () { list.splice(idx, 1); redraw(); });
  bar.appendChild(rm);
  c.appendChild(bar);
  return c;
}
