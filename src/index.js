import { DurableObject } from "cloudflare:workers";

// ---------- Worker หลัก ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }
      // ใช้ room code ถ้ามี (?room=xxx) ไม่งั้นจัดห้องตาม Public IP
      const code = url.searchParams.get("room");
      const ip = request.headers.get("CF-Connecting-IP") || "local";
      const roomKey = code ? "code:" + code.toLowerCase() : roomFromIp(ip);

      const stub = env.ROOMS.get(env.ROOMS.idFromName(roomKey));
      return stub.fetch(request);
    }

    // คืนค่า ICE servers (ใช้ Cloudflare TURN อัตโนมัติถ้าตั้งค่า TURN_TOKEN_ID / TURN_API_TOKEN ไว้)
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
              body: JSON.stringify({ ttl: 86400 }),
            }
          );
          if (res.ok) {
            const data = await res.json();
            if (data.iceServers) {
              const turn = Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
              return Response.json({ iceServers: [...iceServers, ...turn] });
            }
          }
        } catch {}
      }
      return Response.json({ iceServers });
    }

    // Fallback กรณี Share Target POST มาถึง Worker โดยตรงก่อน SW ทำงาน
    if (url.pathname === "/share-target" && request.method === "POST") {
      return Response.redirect(new URL("/", url).toString(), 303);
    }

    return env.ASSETS.fetch(request);
  },
};

// IPv4 ใช้ทั้ง IP / IPv6 ใช้แค่ /64 prefix
// (มือถือแต่ละเครื่องใน Wi-Fi เดียวกันได้ IPv6 คนละตัว แต่ prefix เดียวกัน)
function roomFromIp(ip) {
  if (!ip.includes(":")) return "v4:" + ip;
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const full = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  return "v6:" + full.slice(0, 4).join(":");
}

// ---------- Durable Object: 1 ตัว = 1 ห้อง ----------
export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // ตอบ ping อัตโนมัติ โดยไม่ต้องปลุก DO (ประหยัดโควตา)
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong")
    );
  }

  async fetch(request) {
    const url = new URL(request.url);
    const reqId = url.searchParams.get("id");
    const reqName = url.searchParams.get("name");
    const { 0: client, 1: server } = new WebSocketPair();
    const me = {
      id: reqId || crypto.randomUUID(),
      name: reqName || randomName(),
      device: detectDevice(request.headers.get("User-Agent") || ""),
    };

    // ปิด socket เดิมที่ค้างอยู่หากอุปกรณ์เดิมเชื่อมต่อเข้ามาใหม่
    for (const old of this.ctx.getWebSockets()) {
      if (old.deserializeAttachment()?.id === me.id) {
        old.serializeAttachment({ id: null });
        try { old.close(1000, "replaced"); } catch {}
      }
    }

    this.ctx.acceptWebSocket(server); // Hibernation API
    server.serializeAttachment(me);
    server.send(JSON.stringify({ type: "welcome", ...me }));
    this.broadcastPeers();

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string") return;
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if ((msg.type !== "signal" && msg.type !== "relay") || !msg.to) return;

    const from = ws.deserializeAttachment();
    if (!from?.id) return;
    for (const peer of this.ctx.getWebSockets()) {
      if (peer.deserializeAttachment()?.id === msg.to) {
        try {
          peer.send(JSON.stringify({ type: msg.type, from: from.id, data: msg.data }));
        } catch {
          try { peer.close(1011, "dead"); } catch {}
          this.broadcastPeers(peer);
        }
        break;
      }
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
    const sockets = this.ctx
      .getWebSockets()
      .filter((s) => s !== exclude && s.deserializeAttachment()?.id);
    const byId = new Map();
    for (const s of sockets) {
      const info = s.deserializeAttachment();
      if (info?.id) byId.set(info.id, info);
    }
    const all = [...byId.values()];

    for (const s of sockets) {
      const me = s.deserializeAttachment();
      try {
        s.send(JSON.stringify({ type: "peers", peers: all.filter((p) => p.id !== me.id) }));
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
