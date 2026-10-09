/**
 * Wolf Clan — Cloudflare Worker
 *
 * Serves the static site AND acts as the API/data layer:
 *  - Owner login (password stored in KV, checked here, never shipped to the client)
 *  - Signed session cookie (HMAC-SHA256) for the owner
 *  - Add/remove clan members (owner only)
 *  - Start/stop "recording" mode (owner only)
 *  - Poll ArchMC lifesteal kills for every member (throttled to ~once/60s,
 *    triggered by incoming requests rather than a cron trigger)
 *  - Serve current stats (kills or recording-mode deltas) to everyone
 *
 * KV namespace binding expected: env.wolfclan
 *
 * KV keys used:
 *   password          -> plaintext owner password (never sent to client)
 *   session_secret     -> random secret used to HMAC-sign session cookies
 *   members             -> JSON array of ArchMC usernames, e.g. ["WolfJTA","Foo"]
 *   recording            -> "1" if recording mode is active, absent/other otherwise
 *   recording_start        -> JSON map { username: killsAtRecordingStart }
 *   kills:<username>          -> latest cached total lifesteal kills for that user
 *   last_poll                   -> ms timestamp of the last upstream poll
 */

const POLL_INTERVAL_MS = 60_000;
const SESSION_COOKIE = "wolfclan_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

// ---------- small helpers ----------

function json(data, init = {}) {
  // Build headers with a real Headers instance so entries from a Headers
  // object passed in init.headers (e.g. one holding set-cookie, which can
  // have multiple values) are preserved. Spreading a Headers instance with
  // {...headers} silently produces {} since its entries aren't own
  // enumerable properties — that was dropping the login/logout cookie.
  const headers = new Headers(init.headers || {});
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(data), {
    ...init,
    headers,
  });
}

function badRequest(msg, status = 400) {
  return json({ error: msg }, { status });
}

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  const parts = header.split(/;\s*/);
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq);
    const v = part.slice(eq + 1);
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function sign(secret, value) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return bufToHex(sig);
}

async function makeSessionToken(secret) {
  const expires = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payload = `owner.${expires}`;
  const sig = await sign(secret, payload);
  return `${payload}.${sig}`;
}

async function verifySessionToken(secret, token) {
  if (!token) return false;
  const lastDot = token.lastIndexOf(".");
  if (lastDot === -1) return false;
  const payload = token.slice(0, lastDot);
  const sig = token.slice(lastDot + 1);
  const expected = await sign(secret, payload);
  if (sig.length !== expected.length) return false;
  // constant-time-ish compare
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  if (diff !== 0) return false;

  const [, expiresStr] = payload.split(".");
  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;
  return true;
}

function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bufToHex(bytes.buffer);
}

async function getOrCreateSessionSecret(env) {
  let secret = await env.wolfclan.get("session_secret");
  if (!secret) {
    secret = randomSecret();
    await env.wolfclan.put("session_secret", secret);
  }
  return secret;
}

async function isOwner(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return false;
  const secret = await getOrCreateSessionSecret(env);
  return verifySessionToken(secret, token);
}

async function getMembers(env) {
  const raw = await env.wolfclan.get("members");
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

async function setMembers(env, members) {
  await env.wolfclan.put("members", JSON.stringify(members));
}

async function isRecording(env) {
  const v = await env.wolfclan.get("recording");
  return v === "1";
}

// ---------- ArchMC polling ----------

async function fetchLifestealKills(username) {
  const url = `https://siteapi.arch.mc/profiles/complete/username/${encodeURIComponent(username)}`;
  const res = await fetch(url, {
    headers: { accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(`ArchMC API returned ${res.status} for ${username}`);
  }
  const data = await res.json();
  const kills = data?.gamemodeStats?.lifesteal?.kills;
  if (typeof kills !== "number") {
    throw new Error(`No lifesteal kills field for ${username}`);
  }
  return kills;
}

/**
 * Poll every member's current total kills from ArchMC and cache them in KV.
 * Throttled: only actually hits the upstream API if POLL_INTERVAL_MS has
 * elapsed since the last poll. Safe to call on every incoming request.
 */
async function maybePoll(env) {
  const lastPollRaw = await env.wolfclan.get("last_poll");
  const lastPoll = lastPollRaw ? Number(lastPollRaw) : 0;
  const now = Date.now();
  if (now - lastPoll < POLL_INTERVAL_MS) {
    return; // too soon, skip
  }

  // Claim this poll slot immediately to reduce duplicate polls from
  // concurrent requests racing each other.
  await env.wolfclan.put("last_poll", String(now));

  const members = await getMembers(env);
  if (members.length === 0) return;

  const results = await Promise.allSettled(
    members.map(async (username) => {
      const kills = await fetchLifestealKills(username);
      return { username, kills };
    })
  );

  for (const r of results) {
    if (r.status === "fulfilled") {
      await env.wolfclan.put(`kills:${r.value.username}`, String(r.value.kills));
    }
    // On failure we just keep the last cached value for that member.
  }
}

async function getCachedKills(env, username) {
  const raw = await env.wolfclan.get(`kills:${username}`);
  const n = raw ? Number(raw) : 0;
  return Number.isFinite(n) ? n : 0;
}

async function buildStats(env) {
  const members = await getMembers(env);
  const recording = await isRecording(env);

  let recordingStart = {};
  if (recording) {
    const raw = await env.wolfclan.get("recording_start");
    try {
      recordingStart = raw ? JSON.parse(raw) : {};
    } catch {
      recordingStart = {};
    }
  }

  const rows = [];
  for (const username of members) {
    const total = await getCachedKills(env, username);
    let value;
    if (recording) {
      const startVal = recordingStart[username];
      const base = typeof startVal === "number" ? startVal : total;
      value = Math.max(0, total - base); // clamp at zero
    } else {
      value = total;
    }
    rows.push({ username, kills: value, total });
  }

  rows.sort((a, b) => b.kills - a.kills);

  return {
    mode: recording ? "recording" : "regular",
    rows,
  };
}

// ---------- API routes ----------

async function handleApi(request, env, url) {
  const path = url.pathname;

  if (path === "/api/stats" && request.method === "GET") {
    await maybePoll(env);
    const stats = await buildStats(env);
    return json(stats);
  }

  if (path === "/api/login" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return badRequest("Invalid JSON body");
    }
    const password = String(body.password ?? "");
    const stored = await env.wolfclan.get("password");
    if (stored === null) {
      return badRequest("No password configured", 500);
    }
    if (password !== stored) {
      return badRequest("Incorrect password", 401);
    }
    const secret = await getOrCreateSessionSecret(env);
    const token = await makeSessionToken(secret);
    const headers = new Headers();
    headers.append(
      "set-cookie",
      `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
    );
    return json({ ok: true }, { headers });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const headers = new Headers();
    headers.append(
      "set-cookie",
      `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
    );
    return json({ ok: true }, { headers });
  }

  if (path === "/api/session" && request.method === "GET") {
    const owner = await isOwner(request, env);
    return json({ owner });
  }

  // Everything below requires owner auth.
  const owner = await isOwner(request, env);
  if (!owner) {
    return badRequest("Not authenticated", 401);
  }

  if (path === "/api/members" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return badRequest("Invalid JSON body");
    }
    const username = String(body.username ?? "").trim();
    if (!username) return badRequest("username required");

    // Validate the username actually resolves on ArchMC before adding.
    try {
      await fetchLifestealKills(username);
    } catch (e) {
      return badRequest(`Could not verify ArchMC username "${username}": ${e.message}`);
    }

    const members = await getMembers(env);
    if (!members.includes(username)) {
      members.push(username);
      await setMembers(env, members);
    }
    // Seed the cache immediately so the member appears right away.
    try {
      const kills = await fetchLifestealKills(username);
      await env.wolfclan.put(`kills:${username}`, String(kills));
    } catch {
      /* ignore, will be picked up on next poll */
    }
    return json({ ok: true, members });
  }

  if (path === "/api/members" && request.method === "DELETE") {
    let body;
    try {
      body = await request.json();
    } catch {
      return badRequest("Invalid JSON body");
    }
    const username = String(body.username ?? "").trim();
    if (!username) return badRequest("username required");

    const members = (await getMembers(env)).filter((m) => m !== username);
    await setMembers(env, members);
    await env.wolfclan.delete(`kills:${username}`);
    return json({ ok: true, members });
  }

  if (path === "/api/recording/start" && request.method === "POST") {
    await maybePoll(env); // make sure cached totals are fresh before snapshotting
    const members = await getMembers(env);
    const snapshot = {};
    for (const username of members) {
      snapshot[username] = await getCachedKills(env, username);
    }
    await env.wolfclan.put("recording_start", JSON.stringify(snapshot));
    await env.wolfclan.put("recording", "1");
    return json({ ok: true });
  }

  if (path === "/api/recording/stop" && request.method === "POST") {
    await env.wolfclan.delete("recording");
    return json({ ok: true });
  }

  return badRequest("Not found", 404);
}

// ---------- static site ----------

function renderPage() {
  return HTML_PAGE;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (e) {
        return json({ error: e.message || "Internal error" }, { status: 500 });
      }
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(renderPage(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

// ---------- HTML/CSS/JS for the page itself ----------

const HTML_PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Wolf Clan — Lifesteal Leaderboard</title>
<style>
  :root {
    --bg: #0b0d10;
    --bg-elevated: #14171b;
    --border: #23262b;
    --text: #e8e9eb;
    --text-dim: #8b9099;
    --accent: #5b8cff;
    --accent-dim: #2a3a66;
    --danger: #e0556f;
    --success: #3fbf7f;
    --bar-grad-start: #5b8cff;
    --bar-grad-end: #8f6bff;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    background: radial-gradient(circle at top, #11141a 0%, var(--bg) 60%);
    color: var(--text);
    min-height: 100vh;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 28px;
    border-bottom: 1px solid var(--border);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .brand-mark {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: linear-gradient(135deg, var(--bar-grad-start), var(--bar-grad-end));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 15px;
  }

  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.15;
  }

  .brand-text strong {
    font-size: 16px;
    letter-spacing: 0.2px;
  }

  .brand-text span {
    font-size: 12px;
    color: var(--text-dim);
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 5px 10px;
    border-radius: 999px;
    border: 1px solid var(--border);
    color: var(--text-dim);
    margin-right: 10px;
  }

  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-dim);
  }

  .status-pill.recording .status-dot {
    background: var(--danger);
    box-shadow: 0 0 0 0 rgba(224, 85, 111, 0.6);
    animation: pulse 1.6s infinite;
  }

  .status-pill.recording { color: var(--danger); border-color: rgba(224,85,111,0.4); }

  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(224, 85, 111, 0.5); }
    70% { box-shadow: 0 0 0 6px rgba(224, 85, 111, 0); }
    100% { box-shadow: 0 0 0 0 rgba(224, 85, 111, 0); }
  }

  .header-actions {
    display: flex;
    align-items: center;
  }

  button {
    font-family: inherit;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--bg-elevated);
    color: var(--text);
    padding: 9px 16px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    transition: border-color 0.15s, background 0.15s, transform 0.08s;
  }

  button:hover { border-color: #3a3f47; }
  button:active { transform: scale(0.98); }

  .btn-accent {
    background: linear-gradient(135deg, var(--bar-grad-start), var(--bar-grad-end));
    border: none;
    color: white;
  }

  .btn-danger {
    background: transparent;
    border-color: rgba(224,85,111,0.4);
    color: var(--danger);
  }

  main {
    max-width: 860px;
    margin: 0 auto;
    padding: 36px 24px 80px;
  }

  h1 {
    font-size: 22px;
    margin: 0 0 4px;
  }

  .subtitle {
    color: var(--text-dim);
    font-size: 13px;
    margin-bottom: 28px;
  }

  .panel {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 20px;
  }

  .panel h2 {
    font-size: 14px;
    margin: 0 0 16px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }

  .bar-row {
    display: grid;
    grid-template-columns: 140px 1fr 56px;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .bar-name {
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .bar-rank {
    color: var(--text-dim);
    font-weight: 400;
    margin-right: 6px;
  }

  .bar-track {
    position: relative;
    height: 22px;
    background: #1b1e23;
    border-radius: 6px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--bar-grad-start), var(--bar-grad-end));
    border-radius: 6px;
    transition: width 0.5s ease;
    min-width: 2px;
  }

  .bar-value {
    font-size: 13px;
    font-weight: 700;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .empty-state {
    color: var(--text-dim);
    font-size: 13px;
    padding: 24px 0;
    text-align: center;
  }

  /* Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(5,6,8,0.6);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }

  .modal-backdrop.open { display: flex; }

  .modal {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 14px;
    width: 92%;
    max-width: 420px;
    padding: 24px;
  }

  .modal h3 {
    margin: 0 0 16px;
    font-size: 16px;
  }

  .modal input {
    width: 100%;
    padding: 10px 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: #0f1115;
    color: var(--text);
    font-size: 14px;
    margin-bottom: 10px;
    font-family: inherit;
  }

  .modal input:focus { outline: none; border-color: var(--accent); }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 16px;
  }

  .error-text {
    color: var(--danger);
    font-size: 12px;
    min-height: 16px;
    margin: -2px 0 6px;
  }

  .member-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .member-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 13px;
  }

  .member-row button {
    padding: 4px 10px;
    font-size: 12px;
  }

  .add-member-row {
    display: flex;
    gap: 8px;
    margin-top: 14px;
  }

  .add-member-row input {
    flex: 1;
    padding: 9px 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: #0f1115;
    color: var(--text);
    font-size: 13px;
    font-family: inherit;
  }

  .hidden { display: none !important; }

  .owner-bar {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .small-note {
    font-size: 11px;
    color: var(--text-dim);
    margin-top: 10px;
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-mark">W</div>
    <div class="brand-text">
      <strong>Wolf Clan</strong>
      <span>Lifesteal leaderboard</span>
    </div>
  </div>
  <div class="header-actions">
    <span id="statusPill" class="status-pill">
      <span class="status-dot"></span>
      <span id="statusLabel">Regular mode</span>
    </span>

    <div id="ownerBar" class="owner-bar hidden">
      <button id="recordBtn" class="btn-accent">Start Recording</button>
      <button id="manageBtn">Manage Members</button>
      <button id="logoutBtn" class="btn-danger">Log out</button>
    </div>

    <button id="loginBtn">Log in</button>
  </div>
</header>

<main>
  <h1 id="leaderboardTitle">Total Lifesteal Kills</h1>
  <p class="subtitle" id="leaderboardSubtitle">Updated automatically from ArchMC. Refreshes roughly once a minute.</p>

  <div class="panel">
    <h2 id="panelHeading">Standings</h2>
    <div id="bars"></div>
    <div id="emptyState" class="empty-state hidden">No clan members added yet.</div>
  </div>
</main>

<!-- Login modal -->
<div id="loginModal" class="modal-backdrop">
  <div class="modal">
    <h3>Owner Login</h3>
    <div id="loginError" class="error-text"></div>
    <input id="passwordInput" type="password" placeholder="Password" autocomplete="current-password" />
    <div class="modal-actions">
      <button id="loginCancel">Cancel</button>
      <button id="loginSubmit" class="btn-accent">Log in</button>
    </div>
  </div>
</div>

<!-- Manage members modal -->
<div id="manageModal" class="modal-backdrop">
  <div class="modal">
    <h3>Manage Clan Members</h3>
    <div id="manageError" class="error-text"></div>
    <div id="memberList" class="member-list"></div>
    <div class="add-member-row">
      <input id="newMemberInput" type="text" placeholder="ArchMC username" autocomplete="off" />
      <button id="addMemberBtn" class="btn-accent">Add</button>
    </div>
    <p class="small-note">Adding a member verifies the username against ArchMC first.</p>
    <div class="modal-actions">
      <button id="manageClose">Close</button>
    </div>
  </div>
</div>

<script>
(function () {
  "use strict";

  const el = (id) => document.getElementById(id);

  const statusPill = el("statusPill");
  const statusLabel = el("statusLabel");
  const ownerBar = el("ownerBar");
  const loginBtn = el("loginBtn");
  const recordBtn = el("recordBtn");
  const manageBtn = el("manageBtn");
  const logoutBtn = el("logoutBtn");
  const bars = el("bars");
  const emptyState = el("emptyState");
  const leaderboardTitle = el("leaderboardTitle");
  const leaderboardSubtitle = el("leaderboardSubtitle");
  const panelHeading = el("panelHeading");

  const loginModal = el("loginModal");
  const loginError = el("loginError");
  const passwordInput = el("passwordInput");
  const loginCancel = el("loginCancel");
  const loginSubmit = el("loginSubmit");

  const manageModal = el("manageModal");
  const manageError = el("manageError");
  const memberList = el("memberList");
  const newMemberInput = el("newMemberInput");
  const addMemberBtn = el("addMemberBtn");
  const manageClose = el("manageClose");

  let isOwner = false;
  let isRecording = false;
  let currentMembers = [];

  function openModal(modal) { modal.classList.add("open"); }
  function closeModal(modal) { modal.classList.remove("open"); }

  async function api(path, opts) {
    const res = await fetch(path, {
      ...opts,
      headers: { "content-type": "application/json", ...(opts && opts.headers) },
      credentials: "same-origin",
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const msg = (data && data.error) || ("Request failed (" + res.status + ")");
      throw new Error(msg);
    }
    return data;
  }

  function renderBars(rows) {
    bars.innerHTML = "";
    if (!rows.length) {
      emptyState.classList.remove("hidden");
      return;
    }
    emptyState.classList.add("hidden");

    const max = Math.max(1, ...rows.map((r) => r.kills));

    rows.forEach((row, i) => {
      const wrap = document.createElement("div");
      wrap.className = "bar-row";

      const name = document.createElement("div");
      name.className = "bar-name";
      name.innerHTML = '<span class="bar-rank">#' + (i + 1) + '</span>' + escapeHtml(row.username);

      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      const pct = Math.max(2, Math.round((row.kills / max) * 100));
      fill.style.width = pct + "%";
      track.appendChild(fill);

      const value = document.createElement("div");
      value.className = "bar-value";
      value.textContent = row.kills;

      wrap.appendChild(name);
      wrap.appendChild(track);
      wrap.appendChild(value);
      bars.appendChild(wrap);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function applyMode(mode) {
    isRecording = mode === "recording";
    statusPill.classList.toggle("recording", isRecording);
    statusLabel.textContent = isRecording ? "Recording" : "Regular mode";
    leaderboardTitle.textContent = isRecording ? "New Kills (Recording)" : "Total Lifesteal Kills";
    panelHeading.textContent = isRecording ? "Standings — new kills since recording started" : "Standings — all-time";
    leaderboardSubtitle.textContent = isRecording
      ? "Recording in progress. Showing kills gained since the owner started recording."
      : "Updated automatically from ArchMC. Refreshes roughly once a minute.";
    recordBtn.textContent = isRecording ? "Stop Recording" : "Start Recording";
  }

  async function refreshStats() {
    try {
      const data = await api("/api/stats");
      applyMode(data.mode);
      renderBars(data.rows);
    } catch (e) {
      console.error("Failed to load stats", e);
    }
  }

  async function refreshSession() {
    try {
      const data = await api("/api/session");
      isOwner = !!data.owner;
    } catch (e) {
      isOwner = false;
    }
    ownerBar.classList.toggle("hidden", !isOwner);
    loginBtn.classList.toggle("hidden", isOwner);
  }

  // ---- Login ----
  loginBtn.addEventListener("click", () => {
    loginError.textContent = "";
    passwordInput.value = "";
    openModal(loginModal);
    passwordInput.focus();
  });
  loginCancel.addEventListener("click", () => closeModal(loginModal));

  async function doLogin() {
    loginError.textContent = "";
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ password: passwordInput.value }) });
      closeModal(loginModal);
      await refreshSession();
      await refreshStats();
    } catch (e) {
      loginError.textContent = e.message;
    }
  }
  loginSubmit.addEventListener("click", doLogin);
  passwordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });

  logoutBtn.addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" });
    await refreshSession();
  });

  // ---- Recording ----
  recordBtn.addEventListener("click", async () => {
    try {
      if (isRecording) {
        await api("/api/recording/stop", { method: "POST" });
      } else {
        await api("/api/recording/start", { method: "POST" });
      }
      await refreshStats();
    } catch (e) {
      alert(e.message);
    }
  });

  // ---- Manage members ----
  manageBtn.addEventListener("click", async () => {
    manageError.textContent = "";
    await loadMembers();
    openModal(manageModal);
  });
  manageClose.addEventListener("click", () => closeModal(manageModal));

  async function loadMembers() {
    try {
      const data = await api("/api/stats");
      currentMembers = data.rows.map((r) => r.username);
      renderMemberList();
    } catch (e) {
      manageError.textContent = e.message;
    }
  }

  function renderMemberList() {
    memberList.innerHTML = "";
    if (!currentMembers.length) {
      const p = document.createElement("div");
      p.className = "small-note";
      p.textContent = "No members yet.";
      memberList.appendChild(p);
      return;
    }
    currentMembers.forEach((username) => {
      const row = document.createElement("div");
      row.className = "member-row";
      const name = document.createElement("span");
      name.textContent = username;
      const removeBtn = document.createElement("button");
      removeBtn.className = "btn-danger";
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", async () => {
        try {
          await api("/api/members", { method: "DELETE", body: JSON.stringify({ username }) });
          currentMembers = currentMembers.filter((m) => m !== username);
          renderMemberList();
          await refreshStats();
        } catch (e) {
          manageError.textContent = e.message;
        }
      });
      row.appendChild(name);
      row.appendChild(removeBtn);
      memberList.appendChild(row);
    });
  }

  addMemberBtn.addEventListener("click", async () => {
    const username = newMemberInput.value.trim();
    if (!username) return;
    manageError.textContent = "";
    addMemberBtn.disabled = true;
    addMemberBtn.textContent = "Adding...";
    try {
      const data = await api("/api/members", { method: "POST", body: JSON.stringify({ username }) });
      currentMembers = data.members;
      newMemberInput.value = "";
      renderMemberList();
      await refreshStats();
    } catch (e) {
      manageError.textContent = e.message;
    } finally {
      addMemberBtn.disabled = false;
      addMemberBtn.textContent = "Add";
    }
  });
  newMemberInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addMemberBtn.click(); });

  // ---- Boot ----
  (async function init() {
    await refreshSession();
    await refreshStats();
    setInterval(refreshStats, 60 * 1000);
  })();
})();
</script>

</body>
</html>`;
