import { DurableObject } from "cloudflare:workers";

const MAX_ROOM_CONNECTIONS = 12;
const MAX_WS_MESSAGE_BYTES = 64 * 1024;
const MAX_SIGNAL_BYTES = 32 * 1024;
const MAX_RELAY_BYTES = 48 * 1024;
const MAX_MESSAGES_PER_SECOND = 40;
const ROOM_CODE_RE = /^[a-zA-Z0-9_-]{3,48}$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }

      const code = url.searchParams.get("room");
      if (code && !ROOM_CODE_RE.test(code)) {
        return new Response("Invalid room code", { status: 400 });
      }

      // Public rooms remain open; room codes are grouping keys, not passwords.
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const roomKey = code ? "code:" + code.toLowerCase() : roomFromIp(ip);
      const stub = env.ROOMS.get(env.ROOMS.idFromName(roomKey));
      return stub.fetch(request);
    }

    if (url.pathname === "/ice") {
      const iceServers = [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ];

      if (env.TURN_TOKEN_ID && env.TURN_API_TOKEN) {
        try {
          const res = await fetch(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_TOKEN_ID}/credentials/generate-ice-credentials`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.TURN_API_TOKEN}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ ttl: 3600 }),
            }
          );
          if (res.ok) {
            const data = await res.json();
            if (data.iceServers) {
              const turn = Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
              return securityHeaders(Response.json({ iceServers: [...iceServers, ...turn] }));
            }
          }
        } catch {
          // STUN remains available if TURN credential generation is temporarily unavailable.
        }
      }
      return securityHeaders(Response.json({ iceServers }));
    }

    if (url.pathname === "/share-target" && request.method === "POST") {
      return securityHeaders(Response.redirect(new URL("/", url).toString(), 303));
    }

    return securityHeaders(await env.ASSETS.fetch(request));
  },
};

function securityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https: wss: stun: turn:; media-src 'self' blob:; upgrade-insecure-requests");
  if (new URL(response.url || "https://mydrop.invalid").protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// IPv4 is grouped by address; IPv6 is grouped by /64.
function roomFromIp(ip) {
  if (!ip.includes(":")) return "v4:" + ip;
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const full = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  return "v6:" + full.slice(0, 4).join(":");
}

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong")
    );
  }

  async fetch(request) {
    const active = this.ctx.getWebSockets().filter((s) => s.deserializeAttachment()?.id);
    if (active.length >= MAX_ROOM_CONNECTIONS) {
      return new Response("Room is full", { status: 429 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    // Never trust client-provided IDs or display names.
    const me = {
      id: crypto.randomUUID(),
      name: randomName(),
      device: detectDevice(request.headers.get("User-Agent") || ""),
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
    if (typeof msg.to !== "string" || !/^[0-9a-f-]{36}$/i.test(msg.to)) return;

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

    let dataBytes;
    try { dataBytes = new TextEncoder().encode(JSON.stringify(msg.data)).byteLength; } catch { return; }
    const limit = msg.type === "signal" ? MAX_SIGNAL_BYTES : MAX_RELAY_BYTES;
    if (!msg.data || dataBytes > limit) return;

    if (msg.type === "signal") {
      if (!["offer", "answer", "ice"].includes(msg.data.type)) return;
      if (msg.data.type === "ice" && !msg.data.candidate) return;
      if (["offer", "answer"].includes(msg.data.type) && !msg.data.description && !msg.data.sdp) return;
    } else {
      if (typeof msg.data.type !== "string" ||
          !["chunk", "text", "file-request", "file-response", "header"].includes(msg.data.type)) return;
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
