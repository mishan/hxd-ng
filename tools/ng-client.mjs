#!/usr/bin/env node
// Interactive Hotline-ng test client. Zero dependencies on Node 22+
// (built-in WebSocket); on older Node it falls back to the `ws` package —
// run `npm install` in tools/ once. Speaks the MVP protocol from
// docs/hotline-ng.md and exercises the parts a real mobile app will lean
// on hardest: login, live events, and detach/resume across dropped
// connections.
//
//   node tools/ng-client.mjs ws://127.0.0.1:5700 [options]
//     --login <name>      account login (omit for guest)
//     --password <pw>     account password
//     --nick <nick>       requested nickname
//     --icon <n>          legacy icon id
//
// Once connected, type to chat. Commands:
//   /msg <who> <txt> private message (nick or uid)
//   /me <text>       action-style chat
//   /nick <nick>     change nickname
//   /icon <n>        change icon
//   /users           re-request the roster (sync)
//   /drop            kill the socket WITHOUT logout — tests detach; the
//                    client auto-reconnects with resume after a moment
//   /wait <secs>     with /drop: stay down this long before resuming
//   /logout          end the session properly and exit
//   /quit            exit without logout (session lingers if detachable)

import * as readline from "node:readline";

// Node 22+ has WebSocket built in; older Nodes borrow it from `ws`
// (which implements the same addEventListener/event.data surface).
let WebSocketImpl = globalThis.WebSocket;
if (!WebSocketImpl) {
  try {
    ({ WebSocket: WebSocketImpl } = await import("ws"));
  } catch {
    console.error(
      "No WebSocket available: use Node 22+, or run `npm install` in tools/ " +
        "to get the `ws` fallback.",
    );
    process.exit(1);
  }
}

const args = process.argv.slice(2);
const url = args.find((a) => !a.startsWith("--")) ?? "ws://127.0.0.1:5700";
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const identity = {
  login: opt("login") ?? "",
  password: opt("password") ?? "",
  nick: opt("nick") ?? "ng-tester",
  icon: Number(opt("icon") ?? 128),
};

// --- session state -------------------------------------------------------
let ws = null;
let nextId = 1;
const pending = new Map(); // id -> {resolve, reject, method}
let session = null; // { session, token }
let lastSeq = 0;
let detachInfo = null; // { grace } | null
const roster = new Map(); // uid -> user object, kept fresh from events
let intentionalClose = false;
let reloginOnClose = false;
let resumeDelayMs = 1000;

const ts = () => new Date().toISOString().slice(11, 19);
const say = (...a) => console.log(`[${ts()}]`, ...a);

function request(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject, method });
    ws.send(JSON.stringify({ id, req: method, params }));
  });
}

function rosterReset(users) {
  roster.clear();
  for (const u of users) roster.set(u.uid, u);
}

/// /msg target: a uid, or a case-insensitive nick (must be unambiguous).
function resolveTarget(word) {
  if (/^\d+$/.test(word)) return Number(word);
  const matches = [...roster.values()].filter(
    (u) => u.nick.toLowerCase() === word.toLowerCase(),
  );
  if (matches.length === 1) return matches[0].uid;
  say(matches.length === 0 ? `no user "${word}"` : `"${word}" is ambiguous, use a uid`);
  return null;
}

function showUser(u) {
  const flags = [u.admin ? "admin" : null, u.status !== "active" ? u.status : null]
    .filter(Boolean)
    .join(",");
  return `${u.nick}(${u.uid}${flags ? " " + flags : ""})`;
}

function handleEvent({ seq, ev, data }) {
  lastSeq = seq;
  switch (ev) {
    case "chat":
      if (data.style === "action") say(`*** ${data.from.nick} ${data.text}`);
      else say(`<${data.from.nick}> ${data.text}`);
      break;
    case "notice":
      say(`-!- ${data.text}`);
      break;
    case "broadcast":
      say(`*** BROADCAST from ${data.from.nick}: ${data.text}`);
      break;
    case "user_joined":
      roster.set(data.user.uid, data.user);
      say(`--> ${showUser(data.user)} joined`);
      break;
    case "user_changed":
      roster.set(data.user.uid, data.user);
      say(`--- ${showUser(data.user)} changed`);
      break;
    case "user_parted":
      roster.delete(data.uid);
      say(`<-- uid ${data.uid} left`);
      break;
    case "subject":
      say(`-!- subject: ${data.subject}`);
      break;
    case "msg":
      say(`[PM] <${data.from.nick}> ${data.text}`);
      break;
    case "kicked":
      say(`-!- you were kicked`);
      intentionalClose = true;
      break;
    default:
      say(`(event ${ev} seq=${seq})`, JSON.stringify(data));
  }
}

function connect(kind) {
  ws = new WebSocketImpl(url);
  ws.addEventListener("open", async () => {
    try {
      if (kind === "resume" && session) {
        const r = await request("resume", { ...session, last_seq: lastSeq });
        say(`resumed (replayed ${r.replay})`);
      } else {
        const r = await request("login", identity);
        session = { session: r.session, token: r.token };
        lastSeq = r.seq;
        detachInfo = r.detach;
        rosterReset(r.users);
        say(
          `logged in as ${showUser(r.self)} on "${r.server.name}"` +
            (detachInfo ? ` (detach grace ${detachInfo.grace}s)` : " (no detach)"),
        );
        say(`users: ${r.users.map(showUser).join(", ")}`);
        if (r.server.subject) say(`subject: ${r.server.subject}`);
      }
    } catch (e) {
      if (e?.code === "resync_required") {
        say("resume gap too large; syncing fresh");
        const r = await request("sync");
        lastSeq = r.seq;
        rosterReset(r.users);
        say(`users: ${r.users.map(showUser).join(", ")}`);
      } else if (e?.code === "session_expired") {
        // Route the reconnect through the close handler — closing fires a
        // close event on THIS socket, and reconnecting before it lands
        // would make that handler see a null session and exit.
        say("session expired; logging in fresh");
        session = null;
        lastSeq = 0;
        reloginOnClose = true;
        ws.close();
      } else {
        say("handshake failed:", e?.code ?? e, e?.text ?? "");
        process.exit(1);
      }
    }
  });

  ws.addEventListener("message", (m) => {
    const msg = JSON.parse(m.data);
    if (msg.ev !== undefined) return handleEvent(msg);
    const p = pending.get(msg.reply);
    if (!p) return say("stray reply", m.data);
    pending.delete(msg.reply);
    if (msg.error) p.reject(msg.error);
    else p.resolve(msg.ok);
  });

  ws.addEventListener("close", () => {
    pending.forEach((p) => p.reject({ code: "closed" }));
    pending.clear();
    if (intentionalClose) process.exit(0);
    if (reloginOnClose) {
      reloginOnClose = false;
      connect("login");
      return;
    }
    if (session && detachInfo) {
      say(`connection lost; resuming in ${resumeDelayMs}ms (last_seq=${lastSeq})`);
      setTimeout(() => connect("resume"), resumeDelayMs);
      resumeDelayMs = 1000;
    } else {
      say("connection lost; session not detachable, exiting");
      process.exit(1);
    }
  });

  ws.addEventListener("error", () => {}); // close handler does the work
}

// --- stdin ---------------------------------------------------------------
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  line = line.trim();
  if (!line) return;
  if (!ws || ws.readyState !== 1) {
    say("not connected yet, ignoring input");
    return;
  }
  try {
    if (line === "/drop") {
      say("dropping socket (no logout) — detach test");
      ws.close();
    } else if (line.startsWith("/wait ")) {
      resumeDelayMs = Number(line.slice(6)) * 1000;
      say(`next resume delayed ${resumeDelayMs}ms`);
    } else if (line === "/logout") {
      intentionalClose = true;
      await request("logout");
      ws.close();
    } else if (line === "/quit") {
      intentionalClose = true;
      ws.close();
    } else if (line === "/users") {
      const r = await request("sync");
      lastSeq = r.seq;
      rosterReset(r.users);
      say(`users: ${r.users.map(showUser).join(", ")}`);
    } else if (line.startsWith("/msg ")) {
      const rest = line.slice(5).trim();
      const space = rest.indexOf(" ");
      if (space < 0) {
        say("usage: /msg <nick|uid> <text>");
        return;
      }
      const to = resolveTarget(rest.slice(0, space));
      if (to !== null) {
        await request("msg", { to, text: rest.slice(space + 1) });
        say(`[PM to ${to}] sent`);
      }
    } else if (line.startsWith("/me ")) {
      await request("chat", { text: line.slice(4), style: "action" });
    } else if (line.startsWith("/nick ")) {
      await request("nick", { nick: line.slice(6) });
    } else if (line.startsWith("/icon ")) {
      await request("nick", { icon: Number(line.slice(6)) });
    } else if (line.startsWith("/")) {
      say("unknown command");
    } else {
      await request("chat", { text: line });
    }
  } catch (e) {
    say("error:", e?.code ?? e, e?.text ?? "");
  }
});

say(`connecting to ${url} ...`);
connect("login");
