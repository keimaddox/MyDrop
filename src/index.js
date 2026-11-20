import { DurableObject } from "cloudflare:workers";

const MAX_ROOM_CONNECTIONS = 12;
const MAX_CONNS_PER_IP = 8;
const MAX_CONN_ATTEMPTS_PER_IP_PER_MIN = 30;
const MAX_WS_MESSAGE_BYTES = 128 * 1024;
const MAX_SIGNAL_BYTES = 32 * 1024;
const MAX_RELAY_BYTES = 112 * 1024;
const MAX_MESSAGES_PER_SECOND = 40;
const MAX_FILES_PER_TRANSFER = 10;
const MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_TRANSFER_SIZE = 100 * 1024 * 1024;
const MAX_TEXT_LENGTH = 16 * 1024;
const MAX_RELAY_CHUNK_B64_LEN = 96 * 1024;
const ROOM_CODE_RE = /^[a-zA-Z0-9_-]{3,48}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      if (request.method !== "GET") {
        return securityHeaders(new Response("Method Not Allowed", { status: 405 }));
      }
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return securityHeaders(new Response("Expected WebSocket", { status: 426 }));
      }
      if (!isValidSameOrigin(request)) {
        return securityHeaders(new Response("Forbidden Origin", { status: 403 }));
      }

      const code = url.searchParams.get("room");
      if (code && !ROOM_CODE_RE.test(code)) {
        return securityHeaders(new Response("Invalid room code", { status: 400 }));
      }

      // Public rooms remain open; room codes are grouping keys, not passwords.
      const ip = sanitizeIp(request.headers.get("CF-Connecting-IP") || "unknown");
      const ipRoomKey = roomFromIp(ip);

      // Enforce per-IP connection rate limit across custom rooms via the client's IP room DO
      if (code) {
        const ipLimiterStub = env.ROOMS.get(env.ROOMS.idFromName(ipRoomKey));
        const limitRes = await ipLimiterStub.fetch(
          new Request("https://internal/check-rate", {
            method: "POST",
            headers: { "X-Client-IP": ip },
          })
        );
        if (limitRes.status === 429) {
          return securityHeaders(new Response("Too many connection attempts", { status: 429 }));
        }
      }

      const roomKey = code ? "code:" + code.toLowerCase() : ipRoomKey;
      const stub = env.ROOMS.get(env.ROOMS.idFromName(roomKey));
      return stub.fetch(request);
    }

    if (url.pathname === "/ice") {
      if (request.method !== "GET") {
        return securityHeaders(new Response("Method Not Allowed", { status: 405 }));
      }
      if (!isValidSameOrigin(request)) {
        return securityHeaders(new Response("Forbidden Origin", { status: 403 }));
      }

      const iceServers = [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ];

      if (env.TURN_TOKEN_ID && env.TURN_API_TOKEN) {
        try {
          const res = await fetch(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.TURN_TOKEN_ID)}/credentials/generate-ice-credentials`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.TURN_API_TOKEN}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ ttl: 3600 }),
              signal: AbortSignal.timeout(4000),
            }
          );
          if (res.ok) {
            const data = await res.json();
            if (data.iceServers) {
              const turn = Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
              return securityHeaders(
                Response.json(
                  { iceServers: [...iceServers, ...turn] },
                  { headers: { "Cache-Control": "no-store" } }
                )
              );
            }
          }
        } catch {
          // STUN remains available if TURN credential generation is temporarily unavailable.
        }
      }
      return securityHeaders(
        Response.json({ iceServers }, { headers: { "Cache-Control": "no-store" } })
      );
    }

    if (url.pathname === "/share-target" && request.method === "POST") {
      if (!isValidSameOrigin(request)) {
        return securityHeaders(new Response("Forbidden Origin", { status: 403 }));
      }
      return securityHeaders(Response.redirect(new URL("/", url).toString(), 303));
    }

    return securityHeaders(await env.ASSETS.fetch(request));
  },
};

function isValidSameOrigin(request) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  const secFetchSite = request.headers.get("Sec-Fetch-Site");
  if (origin && origin !== url.origin) return false;
  if (secFetchSite && secFetchSite !== "same-origin" && secFetchSite !== "none") return false;
  return true;
}

function sanitizeIp(rawIp) {
  if (typeof rawIp !== "string") return "unknown";
  const trimmed = rawIp.trim().slice(0, 64);
  if (!/^[0-9a-fA-F:.,]+$/.test(trimmed)) return "unknown";
  return trimmed.split(",")[0].trim() || "unknown";
}

function securityHeaders(response) {
  if (!response || response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; worker-src 'self'; manifest-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https: wss: ws: stun: turn:; media-src 'self' blob:; upgrade-insecure-requests");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// IPv4 is grouped by address; IPv6 is grouped by /64.
function roomFromIp(ip) {
  const clean = sanitizeIp(ip);
  if (!clean.includes(":")) return "v4:" + clean;
  if (clean.includes(".")) {
    const lastColon = clean.lastIndexOf(":");
    return "v4:" + clean.slice(lastColon + 1);
  }
  const parts = clean.split("::");
  if (parts.length > 2) return "v6:invalid";
  const [head = "", tail = ""] = parts;
  const h = head ? head.split(":").filter(Boolean) : [];
  const t = tail ? tail.split(":").filter(Boolean) : [];
  if (h.length + t.length > 8) return "v6:invalid";
  const fillCount = Math.max(0, 8 - h.length - t.length);
  const full = [...h, ...Array(fillCount).fill("0"), ...t];
  return "v6:" + full.slice(0, 4).map((seg) => seg.toLowerCase().padStart(4, "0")).join(":");
}

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ipAttemptCounts = new Map();
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong")
    );
  }

  checkIpAttemptRate(ip) {
    const nowMin = Math.floor(Date.now() / 60000);
    if (this.ipAttemptCounts.size > 256) {
      for (const [k, v] of this.ipAttemptCounts) {
        if (v.window !== nowMin) this.ipAttemptCounts.delete(k);
      }
    }
    const entry = this.ipAttemptCounts.get(ip);
    if (!entry || entry.window !== nowMin) {
      this.ipAttemptCounts.set(ip, { window: nowMin, count: 1 });
      return true;
    }
    entry.count += 1;
    return entry.count <= MAX_CONN_ATTEMPTS_PER_IP_PER_MIN;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/check-rate" && request.method === "POST") {
      const ip = sanitizeIp(request.headers.get("X-Client-IP") || "unknown");
      if (!this.checkIpAttemptRate(ip)) {
        return new Response("Too many connection attempts", { status: 429 });
      }
      return new Response("OK", { status: 200 });
    }

    const ip = sanitizeIp(request.headers.get("CF-Connecting-IP") || "unknown");
    if (!this.checkIpAttemptRate(ip)) {
      return new Response("Too many connection attempts", { status: 429 });
    }

    const active = this.ctx.getWebSockets().filter((s) => s.deserializeAttachment()?.id);
    if (active.length >= MAX_ROOM_CONNECTIONS) {
      return new Response("Room is full", { status: 429 });
    }

    const sameIpActive = active.filter((s) => s.deserializeAttachment()?.ip === ip);
    if (sameIpActive.length >= MAX_CONNS_PER_IP) {
      return new Response("Too many connections from this IP", { status: 429 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    // Never trust client-provided IDs or display names.
    const me = {
      id: crypto.randomUUID(),
      name: randomName(),
      device: detectDevice(request.headers.get("User-Agent") || ""),
      ip,
      rateWindow: Math.floor(Date.now() / 1000),
      rateCount: 0,
    };

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment(me);
    server.send(JSON.stringify({ type: "welcome", id: me.id, name: me.name, device: me.device }));
    this.broadcastPeers();

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    if (raw === "ping") return;
    if (typeof raw !== "string" || raw.length > MAX_WS_MESSAGE_BYTES) {
      try { ws.close(1009, "message too large"); } catch {}
      return;
    }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || (msg.type !== "signal" && msg.type !== "relay")) return;
    if (typeof msg.to !== "string" || !UUID_RE.test(msg.to)) return;

    const from = ws.deserializeAttachment();
    if (!from?.id || msg.to === from.id) return;

    const now = Math.floor(Date.now() / 1000);
    const current = ws.deserializeAttachment();
    if (current.rateWindow !== now) {
      current.rateWindow = now;
      current.rateCount = 0;
    }
    current.rateCount += 1;
    ws.serializeAttachment(current);
    if (current.rateCount > MAX_MESSAGES_PER_SECOND) {
      try { ws.close(1008, "rate limit"); } catch {}
      return;
    }

    if (!msg.data || typeof msg.data !== "object") return;
    let dataBytes;
    try { dataBytes = new TextEncoder().encode(JSON.stringify(msg.data)).byteLength; } catch { return; }
    const limit = msg.type === "signal" ? MAX_SIGNAL_BYTES : MAX_RELAY_BYTES;
    if (dataBytes > limit) return;

    if (msg.type === "signal") {
      if (!isValidSignalPayload(msg.data)) return;
    } else {
      if (!isValidRelayPayload(msg.data)) return;
    }

    for (const peer of this.ctx.getWebSockets()) {
      const peerInfo = peer.deserializeAttachment();
      if (peerInfo?.id !== msg.to) continue;
      try {
        peer.send(JSON.stringify({ type: msg.type, from: from.id, data: msg.data }));
      } catch {
        try { peer.close(1011, "send failed"); } catch {}
        this.broadcastPeers(peer);
      }
      break;
    }
  }

  async webSocketClose(ws) {
    try { ws.close(1000, "bye"); } catch {}
    this.broadcastPeers(ws);
  }

  async webSocketError(ws) {
    this.broadcastPeers(ws);
  }

  broadcastPeers(exclude) {
    const sockets = this.ctx.getWebSockets()
      .filter((s) => s !== exclude && s.deserializeAttachment()?.id);
    const all = sockets.map((s) => s.deserializeAttachment());
    for (const s of sockets) {
      const me = s.deserializeAttachment();
      try {
        s.send(JSON.stringify({
          type: "peers",
          peers: all.filter((p) => p.id !== me.id).map(({ id, name, device }) => ({ id, name, device })),
        }));
      } catch {}
    }
  }
}

function isValidSignalPayload(data) {
  if (!data || typeof data !== "object" || typeof data.type !== "string") return false;
  if (data.type === "offer" || data.type === "answer") {
    const desc = data.sdp || data.description;
    return Boolean(desc && typeof desc === "object" && typeof desc.sdp === "string" && desc.sdp.length <= MAX_SIGNAL_BYTES);
  }
  if (data.type === "ice") {
    return Boolean(data.candidate && typeof data.candidate === "object" && typeof data.candidate.candidate === "string");
  }
  return false;
}

function isValidRelayPayload(data) {
  if (!data || typeof data !== "object" || typeof data.type !== "string") return false;
  switch (data.type) {
    case "text":
      return typeof data.text === "string" && data.text.length > 0 && data.text.length <= MAX_TEXT_LENGTH;
    case "file-request": {
      if (typeof data.transferId !== "string" || data.transferId.length > 80) return false;
      if (!Array.isArray(data.files) || data.files.length < 1 || data.files.length > MAX_FILES_PER_TRANSFER) return false;
      let total = 0;
      for (const f of data.files) {
        if (!f || typeof f !== "object") return false;
        if (typeof f.name !== "string" || f.name.length < 1 || f.name.length > 255) return false;
        if (!Number.isSafeInteger(f.size) || f.size < 0 || f.size > MAX_FILE_SIZE) return false;
        if (f.mime !== undefined && (typeof f.mime !== "string" || f.mime.length > 255)) return false;
        total += f.size;
      }
      return total <= MAX_TRANSFER_SIZE;
    }
    case "file-response":
      return (
        typeof data.transferId === "string" &&
        data.transferId.length > 0 &&
        data.transferId.length <= 80 &&
        typeof data.accepted === "boolean"
      );
    case "header":
      return (
        typeof data.transferId === "string" &&
        data.transferId.length > 0 &&
        data.transferId.length <= 80 &&
        typeof data.name === "string" &&
        data.name.length > 0 &&
        data.name.length <= 255 &&
        Number.isSafeInteger(data.size) &&
        data.size >= 0 &&
        data.size <= MAX_FILE_SIZE &&
        (data.mime === undefined || (typeof data.mime === "string" && data.mime.length <= 255))
      );
    case "chunk":
      return (
        typeof data.data === "string" &&
        data.data.length > 0 &&
        data.data.length <= MAX_RELAY_CHUNK_B64_LEN &&
        data.data.length % 4 === 0 &&
        BASE64_RE.test(data.data)
      );
    default:
      return false;
  }
}

function randomName() {
  const animals = ["แมว", "หมา", "นกฮูก", "ปลาวาฬ", "กระต่าย", "เพนกวิน", "ช้าง", "หมีแพนด้า"];
  const colors = ["สีแดง", "สีฟ้า", "สีเขียว", "สีม่วง", "สีส้ม", "สีชมพู", "สีทอง", "สีเงิน"];
  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  return `${pick(animals)}${pick(colors)}`;
}

function detectDevice(ua) {
  if (/iPhone|Android.+Mobile/i.test(ua)) return "phone";
  if (/iPad|Android|Tablet/i.test(ua)) return "tablet";
  return "desktop";
}

