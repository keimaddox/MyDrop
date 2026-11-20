import { DurableObject } from "cloudflare:workers";

// ================= Security Configuration & Limits =================
export const SERVER_LIMITS = {
  ROOM_CODE_MIN_LEN: 3,
  ROOM_CODE_MAX_LEN: 64,
  MAX_PEERS_PER_ROOM: 30,
  MAX_CONNS_PER_IP: 8,
  MAX_CONN_ATTEMPTS_PER_IP_PER_MIN: 30,
  MAX_ICE_REQ_PER_IP_PER_MIN: 20,
  MAX_WS_MESSAGE_CHARS: 131072, // 128 KB max raw JSON frame (fits 64KB AES-GCM chunk in base64, well below DO 1 MiB limit)
  MAX_SIGNAL_CHARS: 32768,      // 32 KB max WebRTC SDP/ICE signaling frame
  MAX_CONTROL_MSG_PER_10S: 120, // Max 120 signaling/control/chunk-ack messages per 10s window
  MAX_CHUNK_MSG_PER_10S: 4000,  // Max 4000 encrypted chunk messages per 10s window (~250 MB/10s over Relay)
  MAX_RELAY_BYTES_PER_MIN: 750 * 1024 * 1024, // Max ~500MB plaintext (~700MB base64) per minute per WS over Relay
  MAX_FILES_PER_TRANSFER: 20,   // Max files index bound validated on relay chunks
  MAX_RELAY_CHUNK_INDEX: 1000000, // Max chunk index supported on relay frames
  RECONNECT_TTL_MS: 60000,      // 60s window for authenticated token reconnect
  MAX_RECONNECT_CACHE_SIZE: 200, // Max cached reconnect tokens per room DO
  TURN_CREDENTIAL_TTL: 3600,    // 1 hour short-lived TURN credentials
};

const ROOM_CODE_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECONNECT_TOKEN_REGEX = /^[0-9a-f]{64}$/i;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

const ALLOWED_SIGNAL_TYPES = new Set(["offer", "answer", "ice", "e2ee-init", "e2ee-ack", "e2ee-confirm"]);
const ALLOWED_RELAY_TYPES = new Set(["e2ee-init", "e2ee-ack", "e2ee-confirm", "enc-control", "enc-chunk"]);

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

// Apply standard HTTP security headers to all Worker responses
export function withSecurityHeaders(response, request) {
  if (!response || response.status === 101) return response;
  const headers = new Headers(response.headers);
  let csp = CONTENT_SECURITY_POLICY;

  if (request) {
    const url = new URL(request.url);
    const isHttps = url.protocol === "https:";
    const wsOrigin = `${isHttps ? "wss:" : "ws:"}//${url.host}`;
    csp = CONTENT_SECURITY_POLICY.replace("connect-src 'self'", `connect-src 'self' ${wsOrigin}`);
    if (isHttps && !isLocalHost(url.hostname)) {
      headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }
  }
  headers.set("Content-Security-Policy", csp);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  );
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function isLocalHost(hostname) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
  );
}

// Validate Origin and Sec-Fetch-Site to prevent Cross-Site WebSocket Hijacking (CSWSH) & cross-origin abuse
export function isValidSameOrigin(request, requireOriginHeader = false) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  const secFetchSite = request.headers.get("Sec-Fetch-Site");

  if (requireOriginHeader && !origin) {
    return false;
  }
  if (origin && origin !== url.origin) {
    return false;
  }
  if (secFetchSite && secFetchSite !== "same-origin" && secFetchSite !== "none") {
    return false;
  }
  return true;
}

export function validateRoomCode(code) {
  if (code === null || code === undefined || code === "") return { valid: true, normalized: "" };
  if (typeof code !== "string") return { valid: false, normalized: "" };
  const trimmed = code.trim();
  if (!trimmed) return { valid: true, normalized: "" };
  if (!ROOM_CODE_REGEX.test(trimmed)) return { valid: false, normalized: "" };
  return { valid: true, normalized: trimmed.toLowerCase() };
}

// ---------- Worker หลัก ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Enforce HTTPS in production environments using authoritative URL protocol
    if (
      url.protocol === "http:" &&
      !isLocalHost(url.hostname) &&
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
    ) {
      const httpsUrl = new URL(request.url);
      httpsUrl.protocol = "https:";
      return withSecurityHeaders(Response.redirect(httpsUrl.toString(), 301), request);
    }

    // 1. WebSocket Signaling & Encrypted Relay Endpoint
    if (url.pathname === "/ws") {
      if (request.method !== "GET") {
        return withSecurityHeaders(new Response("Method Not Allowed", { status: 405 }), request);
      }
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return withSecurityHeaders(new Response("Expected WebSocket", { status: 426 }), request);
      }
      if (!isValidSameOrigin(request, true)) {
        return withSecurityHeaders(new Response("Forbidden Origin", { status: 403 }), request);
      }

      // Optional Cloudflare Rate Limiting binding support if configured in wrangler.jsonc
      const ip = sanitizeIp(request.headers.get("CF-Connecting-IP") || "local");
      if (env.WS_RATE_LIMITER && typeof env.WS_RATE_LIMITER.limit === "function") {
        try {
          const { success } = await env.WS_RATE_LIMITER.limit({ key: `ws:${ip}` });
          if (!success) {
            return withSecurityHeaders(new Response("Too Many Requests", { status: 429 }), request);
          }
        } catch {}
      }

      const rawRoom = url.searchParams.get("room");
      const roomCheck = validateRoomCode(rawRoom);
      if (!roomCheck.valid) {
        return withSecurityHeaders(
          new Response("Invalid room code (use 3-64 alphanumeric, '-' or '_' characters)", { status: 400 }),
          request
        );
      }

      const ipRoomKey = roomFromIp(ip);
      // Enforce global per-IP connection rate limit across all custom rooms via the client's IP room DO
      if (roomCheck.normalized) {
        const ipLimiterStub = env.ROOMS.get(env.ROOMS.idFromName(ipRoomKey));
        const ipLimitRes = await ipLimiterStub.fetch(
          new Request("https://internal/check-ws-limit", {
            method: "POST",
            headers: { "X-Client-IP": ip },
          })
        );
        if (ipLimitRes.status === 429) {
          return withSecurityHeaders(new Response("Too many connection attempts", { status: 429 }), request);
        }
      }

      const roomKey = roomCheck.normalized ? "code:" + roomCheck.normalized : ipRoomKey;
      const stub = env.ROOMS.get(env.ROOMS.idFromName(roomKey));
      return stub.fetch(request);
    }

    // 2. ICE / TURN Credentials Endpoint
    if (url.pathname === "/ice") {
      if (request.method !== "GET") {
        return withSecurityHeaders(new Response("Method Not Allowed", { status: 405 }), request);
      }
      if (!isValidSameOrigin(request, false)) {
        return withSecurityHeaders(new Response("Forbidden", { status: 403 }), request);
      }

      const ip = sanitizeIp(request.headers.get("CF-Connecting-IP") || "local");
      if (env.ICE_RATE_LIMITER && typeof env.ICE_RATE_LIMITER.limit === "function") {
        try {
          const { success } = await env.ICE_RATE_LIMITER.limit({ key: `ice:${ip}` });
          if (!success) {
            return withSecurityHeaders(new Response("Too Many Requests", { status: 429 }), request);
          }
        } catch {}
      }

      const iceServers = [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ];

      if (env.TURN_TOKEN_ID && env.TURN_API_TOKEN) {
        try {
          // Enforce per-IP rate limit on TURN credential generation using the user's IP room DO
          const limiterStub = env.ROOMS.get(env.ROOMS.idFromName(roomFromIp(ip)));
          const limitRes = await limiterStub.fetch(new Request("https://internal/check-ice-limit", {
            method: "POST",
            headers: { "X-Client-IP": ip },
          }));
          if (limitRes.status === 429) {
            return withSecurityHeaders(
              Response.json({ iceServers }, { headers: { "Cache-Control": "no-store" } }),
              request
            );
          }

          const res = await fetch(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.TURN_TOKEN_ID)}/credentials/generate-ice-credentials`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.TURN_API_TOKEN}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ ttl: SERVER_LIMITS.TURN_CREDENTIAL_TTL }),
              signal: AbortSignal.timeout(4000),
            }
          );
          if (res.ok) {
            const data = await res.json();
            const validatedTurn = sanitizeIceServers(data?.iceServers);
            if (validatedTurn.length > 0) {
              return withSecurityHeaders(
                Response.json(
                  { iceServers: [...iceServers, ...validatedTurn] },
                  { headers: { "Cache-Control": "no-store, no-cache, must-revalidate" } }
                ),
                request
              );
            }
          }
        } catch {
          // Fail safely back to STUN without leaking internal errors or tokens
        }
      }

      return withSecurityHeaders(
        Response.json(
          { iceServers },
          { headers: { "Cache-Control": "no-store, no-cache, must-revalidate" } }
        ),
        request
      );
    }

    // 3. Fallback กรณี Share Target POST มาถึง Worker โดยตรงก่อน SW ทำงาน
    if (url.pathname === "/share-target") {
      if (request.method !== "POST") {
        return withSecurityHeaders(new Response("Method Not Allowed", { status: 405 }), request);
      }
      if (!isValidSameOrigin(request, false)) {
        return withSecurityHeaders(new Response("Forbidden", { status: 403 }), request);
      }
      return withSecurityHeaders(Response.redirect(new URL("/", url).toString(), 303), request);
    }

    // 4. Static Assets
    if (request.method !== "GET" && request.method !== "HEAD") {
      return withSecurityHeaders(new Response("Method Not Allowed", { status: 405 }), request);
    }
    const assetRes = await env.ASSETS.fetch(request);
    return withSecurityHeaders(assetRes, request);
  },
};

function sanitizeIp(rawIp) {
  if (typeof rawIp !== "string") return "local";
  const trimmed = rawIp.trim().slice(0, 64);
  if (!/^[0-9a-fA-F:.,]+$/.test(trimmed)) return "local";
  return trimmed.split(",")[0].trim() || "local";
}

// Safely group IPv4 by full IP and IPv6 by /64 prefix without RangeError on malformed addresses
export function roomFromIp(ip) {
  const clean = sanitizeIp(ip);
  if (!clean.includes(":")) return "v4:" + clean;

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.1)
  if (clean.includes(".")) {
    const lastColon = clean.lastIndexOf(":");
    return "v4:" + clean.slice(lastColon + 1);
  }

  const parts = clean.split("::");
  if (parts.length > 2) return "v6:invalid";
  const [head = "", tail = ""] = parts;
  const h = head ? head.split(":").filter(Boolean).slice(0, 8) : [];
  const t = tail ? tail.split(":").filter(Boolean).slice(0, 8) : [];
  const fillCount = Math.max(0, 8 - h.length - t.length);
  const full = [...h, ...Array(fillCount).fill("0"), ...t].slice(0, 8);
  return "v6:" + full.slice(0, 4).map((seg) => seg.toLowerCase().padStart(4, "0")).join(":");
}

function sanitizeIceServers(rawServers) {
  if (!rawServers) return [];
  const list = Array.isArray(rawServers) ? rawServers : [rawServers];
  const valid = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const rawUrls = Array.isArray(item.urls) ? item.urls : typeof item.urls === "string" ? [item.urls] : [];
    const safeUrls = rawUrls.filter(
      (u) => typeof u === "string" && u.length <= 256 && /^(stun|turn|turns):[a-zA-Z0-9._:-]+(\?[a-zA-Z0-9=&_-]+)?$/.test(u)
    );
    if (!safeUrls.length) continue;
    const entry = { urls: safeUrls };
    if (typeof item.username === "string" && item.username.length <= 256) {
      entry.username = item.username;
    }
    if (typeof item.credential === "string" && item.credential.length <= 256) {
      entry.credential = item.credential;
    }
    valid.push(entry);
  }
  return valid;
}

// ---------- Durable Object: 1 ตัว = 1 ห้อง ----------
export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ipConnectHistory = new Map(); // ip -> number[] (timestamps)
    this.ipIceHistory = new Map();     // ip -> number[] (timestamps)
    this.rateState = new Map();        // peerId -> { windowStart, controlCount, chunkCount, byteWindowStart, relayBytes, violations }
    this.reconnectCache = new Map();   // token -> { id, name, device, ip, expiresAt }

    // ตอบ ping อัตโนมัติ โดยไม่ต้องปลุก DO (ประหยัดโควตา)
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong")
    );
  }

  pruneStaleState(now = Date.now()) {
    for (const [token, session] of this.reconnectCache) {
      if (now > session.expiresAt) this.reconnectCache.delete(token);
    }
    for (const [ip, times] of this.ipConnectHistory) {
      const recent = times.filter((t) => now - t < 60000);
      if (recent.length === 0) this.ipConnectHistory.delete(ip);
      else this.ipConnectHistory.set(ip, recent);
    }
    for (const [ip, times] of this.ipIceHistory) {
      const recent = times.filter((t) => now - t < 60000);
      if (recent.length === 0) this.ipIceHistory.delete(ip);
      else this.ipIceHistory.set(ip, recent);
    }
  }

  checkIpRate(map, ip, maxPerMin, now = Date.now()) {
    this.pruneStaleState(now);
    const times = map.get(ip) || [];
    if (times.length >= maxPerMin) return false;
    times.push(now);
    map.set(ip, times);
    return true;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const now = Date.now();

    // Internal rate-limit check for /ice TURN credential generation
    if (url.pathname === "/check-ice-limit" && request.method === "POST") {
      const ip = sanitizeIp(request.headers.get("X-Client-IP") || "local");
      const allowed = this.checkIpRate(this.ipIceHistory, ip, SERVER_LIMITS.MAX_ICE_REQ_PER_IP_PER_MIN, now);
      return new Response(allowed ? "OK" : "Rate limit exceeded", { status: allowed ? 200 : 429 });
    }

    // Internal global per-IP WebSocket connection rate-limit check across custom rooms
    if (url.pathname === "/check-ws-limit" && request.method === "POST") {
      const ip = sanitizeIp(request.headers.get("X-Client-IP") || "local");
      const allowed = this.checkIpRate(this.ipConnectHistory, ip, SERVER_LIMITS.MAX_CONN_ATTEMPTS_PER_IP_PER_MIN, now);
      return new Response(allowed ? "OK" : "Rate limit exceeded", { status: allowed ? 200 : 429 });
    }

    const ip = sanitizeIp(request.headers.get("CF-Connecting-IP") || "local");

    // 1. Enforce per-IP connection attempt rate limit
    if (!this.checkIpRate(this.ipConnectHistory, ip, SERVER_LIMITS.MAX_CONN_ATTEMPTS_PER_IP_PER_MIN, now)) {
      return withSecurityHeaders(new Response("Too many connection attempts", { status: 429 }), request);
    }

    // 2. Reject any attempt by a client to spoof peer ID or display name via query parameters
    if (url.searchParams.has("id") || url.searchParams.has("name")) {
      // Explicitly ignore and disallow client-controlled identity parameters
    }

    const activeSockets = this.ctx.getWebSockets();
    const clientToken = url.searchParams.get("token") || "";
    const clientSubnet = roomFromIp(ip);
    let resumedIdentity = null;

    // 3. Check if this is a legitimate reconnect using a server-issued secret reconnectToken bound to the same IP/subnet
    if (RECONNECT_TOKEN_REGEX.test(clientToken)) {
      // Check active sockets first (fast network switch before old socket closed)
      for (const old of activeSockets) {
        const att = old.deserializeAttachment();
        if (
          att?.id &&
          att.reconnectToken &&
          timingSafeEqual(att.reconnectToken, clientToken) &&
          roomFromIp(att.ip || "local") === clientSubnet
        ) {
          resumedIdentity = { id: att.id, name: att.name };
          old.serializeAttachment({ id: null });
          try { old.close(1000, "replaced"); } catch {}
          break;
        }
      }
      // Or check recently disconnected sessions within 60s TTL
      if (!resumedIdentity) {
        const cached = this.reconnectCache.get(clientToken);
        if (cached && now <= cached.expiresAt && roomFromIp(cached.ip || "local") === clientSubnet) {
          resumedIdentity = { id: cached.id, name: cached.name };
          this.reconnectCache.delete(clientToken);
        }
      }
    }

    // 4. Enforce room capacity and per-IP active connection limits (even on reconnect, after replacing old socket)
    const currentValidSockets = this.ctx.getWebSockets().filter((s) => s.deserializeAttachment()?.id);
    if (currentValidSockets.length >= SERVER_LIMITS.MAX_PEERS_PER_ROOM) {
      return withSecurityHeaders(new Response("Room is full", { status: 503 }), request);
    }
    const sameIpCount = currentValidSockets.filter((s) => s.deserializeAttachment()?.ip === ip).length;
    if (sameIpCount >= SERVER_LIMITS.MAX_CONNS_PER_IP) {
      return withSecurityHeaders(new Response("Too many connections from this IP", { status: 429 }), request);
    }

    // 5. Generate server-controlled identity using CSPRNG
    const existingNames = new Set(
      currentValidSockets.map((s) => s.deserializeAttachment()?.name).filter(Boolean)
    );
    const newReconnectToken = generateSecureToken();
    const me = {
      id: resumedIdentity ? resumedIdentity.id : crypto.randomUUID(),
      name: resumedIdentity ? resumedIdentity.name : uniqueRandomName(existingNames),
      device: detectDevice(request.headers.get("User-Agent") || ""),
    };

    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server); // Hibernation API
    server.serializeAttachment({
      ...me,
      ip,
      reconnectToken: newReconnectToken,
      connectedAt: now,
    });

    this.rateState.set(me.id, {
      windowStart: now,
      controlCount: 0,
      chunkCount: 0,
      byteWindowStart: now,
      relayBytes: 0,
      violations: 0,
    });

    // Send welcome with server-assigned identity and private reconnectToken (never shared with other peers)
    server.send(
      JSON.stringify({
        type: "welcome",
        id: me.id,
        name: me.name,
        device: me.device,
        reconnectToken: newReconnectToken,
      })
    );
    this.broadcastPeers();

    return new Response(null, { status: 101, webSocket: client });
  }

  checkSocketRateLimit(peerId, isChunk, byteLen) {
    const now = Date.now();
    let state = this.rateState.get(peerId);
    if (!state) {
      state = {
        windowStart: now,
        controlCount: 0,
        chunkCount: 0,
        byteWindowStart: now,
        relayBytes: 0,
        violations: 0,
      };
      this.rateState.set(peerId, state);
    }

    if (now - state.windowStart >= 10000) {
      state.windowStart = now;
      state.controlCount = 0;
      state.chunkCount = 0;
    }
    if (now - state.byteWindowStart >= 60000) {
      state.byteWindowStart = now;
      state.relayBytes = 0;
    }

    if (isChunk) {
      state.chunkCount += 1;
      state.relayBytes += byteLen;
      if (
        state.chunkCount > SERVER_LIMITS.MAX_CHUNK_MSG_PER_10S ||
        state.relayBytes > SERVER_LIMITS.MAX_RELAY_BYTES_PER_MIN
      ) {
        state.violations += 1;
        return false;
      }
    } else {
      state.controlCount += 1;
      if (state.controlCount > SERVER_LIMITS.MAX_CONTROL_MSG_PER_10S) {
        state.violations += 1;
        return false;
      }
    }
    return true;
  }

  penalizeSocket(ws, peerId, reason = "Policy violation") {
    const state = this.rateState.get(peerId);
    if (state) {
      state.violations += 1;
      if (state.violations >= 5) {
        this.rateState.delete(peerId);
        ws.serializeAttachment({ id: null });
        try { ws.close(1008, reason); } catch {}
        this.broadcastPeers(ws);
      }
    }
  }

  async webSocketMessage(ws, raw) {
    const from = ws.deserializeAttachment();
    if (!from?.id) {
      try { ws.close(1008, "Unauthenticated socket"); } catch {}
      return;
    }

    // 1. Validate message type and enforce strict maximum frame size BEFORE JSON.parse
    if (typeof raw !== "string" || raw.length === 0 || raw.length > SERVER_LIMITS.MAX_WS_MESSAGE_CHARS) {
      this.penalizeSocket(ws, from.id, "Invalid message size");
      return;
    }

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      this.penalizeSocket(ws, from.id, "Malformed JSON");
      return;
    }

    if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
      this.penalizeSocket(ws, from.id, "Invalid JSON structure");
      return;
    }

    // 2. Reject any message attempting to spoof sender identity ("from" must not be client-specified or mismatch)
    if (msg.from !== undefined && msg.from !== from.id) {
      this.penalizeSocket(ws, from.id, "Sender ID spoofing attempt");
      return;
    }

    // 3. Validate message type ("signal" or "relay" only) and target recipient UUID
    if (msg.type !== "signal" && msg.type !== "relay") {
      this.penalizeSocket(ws, from.id, "Unknown message type");
      return;
    }
    if (typeof msg.to !== "string" || !UUID_REGEX.test(msg.to) || msg.to === from.id) {
      this.penalizeSocket(ws, from.id, "Invalid recipient ID");
      return;
    }

    // 4. Validate payload structure and enforce E2EE-only relay payloads
    const isChunk = msg.type === "relay" && msg.data?.type === "enc-chunk";
    if (!this.checkSocketRateLimit(from.id, isChunk, raw.length)) {
      this.penalizeSocket(ws, from.id, "Rate limit exceeded");
      return;
    }

    if (msg.type === "signal") {
      if (raw.length > SERVER_LIMITS.MAX_SIGNAL_CHARS || !isValidSignalPayload(msg.data)) {
        this.penalizeSocket(ws, from.id, "Invalid signal payload");
        return;
      }
    } else if (msg.type === "relay") {
      if (!isValidRelayPayload(msg.data)) {
        this.penalizeSocket(ws, from.id, "Invalid or unencrypted relay payload");
        return;
      }
    }

    // 5. Verify target peer is currently connected in the SAME room and deliver message bound to server's `from.id`
    for (const peer of this.ctx.getWebSockets()) {
      const peerInfo = peer.deserializeAttachment();
      if (peerInfo?.id === msg.to) {
        try {
          peer.send(
            JSON.stringify({
              type: msg.type,
              from: from.id,
              data: msg.data,
            })
          );
        } catch {
          try { peer.close(1011, "dead"); } catch {}
          this.broadcastPeers(peer);
        }
        return;
      }
    }
  }

  handleDisconnect(ws) {
    const att = ws.deserializeAttachment();
    if (att?.id) {
      this.rateState.delete(att.id);
      if (att.reconnectToken) {
        // Bound reconnectCache size to prevent memory exhaustion from rapid connect/disconnect floods
        while (this.reconnectCache.size >= SERVER_LIMITS.MAX_RECONNECT_CACHE_SIZE) {
          const oldestKey = this.reconnectCache.keys().next().value;
          if (!oldestKey) break;
          this.reconnectCache.delete(oldestKey);
        }
        this.reconnectCache.set(att.reconnectToken, {
          id: att.id,
          name: att.name,
          device: att.device,
          ip: att.ip,
          expiresAt: Date.now() + SERVER_LIMITS.RECONNECT_TTL_MS,
        });
      }
      ws.serializeAttachment({ id: null });
    }
    this.broadcastPeers(ws);

    // Room cleanup when all peers disconnect
    const remaining = this.ctx.getWebSockets().filter((s) => s !== ws && s.deserializeAttachment()?.id);
    if (remaining.length === 0) {
      this.rateState.clear();
      this.pruneStaleState();
    }
  }

  async webSocketClose(ws) {
    try { ws.close(1000, "bye"); } catch {}
    this.handleDisconnect(ws);
  }

  async webSocketError(ws) {
    this.handleDisconnect(ws);
  }

  broadcastPeers(exclude) {
    const sockets = this.ctx
      .getWebSockets()
      .filter((s) => s !== exclude && s.deserializeAttachment()?.id);
    const byId = new Map();
    for (const s of sockets) {
      const info = s.deserializeAttachment();
      if (info?.id) {
        // Expose ONLY public peer metadata (never expose IP or reconnectToken)
        byId.set(info.id, {
          id: info.id,
          name: info.name,
          device: info.device,
        });
      }
    }
    const all = [...byId.values()];

    for (const s of sockets) {
      const me = s.deserializeAttachment();
      if (!me?.id) continue;
      try {
        s.send(
          JSON.stringify({
            type: "peers",
            peers: all.filter((p) => p.id !== me.id),
          })
        );
      } catch {}
    }
  }
}

// Validate WebRTC signaling and ECDH key exchange payloads
export function isValidSignalPayload(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (!ALLOWED_SIGNAL_TYPES.has(data.type)) return false;

  if (data.type === "offer" || data.type === "answer") {
    if (!data.sdp || typeof data.sdp !== "object") return false;
    if (data.sdp.type !== data.type) return false;
    if (typeof data.sdp.sdp !== "string" || data.sdp.sdp.length === 0 || data.sdp.sdp.length > 24576) return false;
    return true;
  }

  if (data.type === "ice") {
    if (!data.candidate || typeof data.candidate !== "object") return false;
    if (typeof data.candidate.candidate !== "string" || data.candidate.candidate.length > 2048) return false;
    return true;
  }

  return isValidE2EEHandshake(data);
}

// Validate Relay payloads: Server ONLY relays E2EE handshakes and AES-GCM encrypted packets
export function isValidRelayPayload(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (!ALLOWED_RELAY_TYPES.has(data.type)) return false;

  if (data.type === "e2ee-init" || data.type === "e2ee-ack" || data.type === "e2ee-confirm") {
    return isValidE2EEHandshake(data);
  }

  if (data.type === "enc-control") {
    if (!Number.isSafeInteger(data.seq) || data.seq < 1) return false;
    if (typeof data.iv !== "string" || data.iv.length !== 16 || !BASE64_REGEX.test(data.iv)) return false;
    if (typeof data.ct !== "string" || data.ct.length < 24 || data.ct.length > 32768 || !BASE64_REGEX.test(data.ct)) {
      return false;
    }
    return true;
  }

  if (data.type === "enc-chunk") {
    if (typeof data.transferId !== "string" || !UUID_REGEX.test(data.transferId)) return false;
    if (
      !Number.isSafeInteger(data.fileIndex) ||
      data.fileIndex < 0 ||
      data.fileIndex >= SERVER_LIMITS.MAX_FILES_PER_TRANSFER
    ) {
      return false;
    }
    if (
      !Number.isSafeInteger(data.chunkIndex) ||
      data.chunkIndex < 0 ||
      data.chunkIndex > SERVER_LIMITS.MAX_RELAY_CHUNK_INDEX
    ) {
      return false;
    }
    if (typeof data.last !== "boolean") return false;
    if (typeof data.iv !== "string" || data.iv.length !== 16 || !BASE64_REGEX.test(data.iv)) return false;
    if (typeof data.ct !== "string" || data.ct.length < 20 || data.ct.length > 96000 || !BASE64_REGEX.test(data.ct)) {
      return false;
    }
    return true;
  }

  return false;
}

function isValidE2EEHandshake(data) {
  if (data.type === "e2ee-init") {
    // Uncompressed P-256 public key is 65 bytes -> 88 base64 chars; nonce is 16 bytes -> 24 base64 chars
    return (
      typeof data.pub === "string" &&
      data.pub.length >= 80 &&
      data.pub.length <= 120 &&
      BASE64_REGEX.test(data.pub) &&
      typeof data.nonce === "string" &&
      data.nonce.length === 24 &&
      BASE64_REGEX.test(data.nonce)
    );
  }
  if (data.type === "e2ee-ack") {
    return (
      typeof data.pub === "string" &&
      data.pub.length >= 80 &&
      data.pub.length <= 120 &&
      BASE64_REGEX.test(data.pub) &&
      typeof data.nonce === "string" &&
      data.nonce.length === 24 &&
      BASE64_REGEX.test(data.nonce) &&
      typeof data.peerNonce === "string" &&
      data.peerNonce.length === 24 &&
      BASE64_REGEX.test(data.peerNonce)
    );
  }
  if (data.type === "e2ee-confirm") {
    return (
      typeof data.iv === "string" &&
      data.iv.length === 16 &&
      BASE64_REGEX.test(data.iv) &&
      typeof data.ct === "string" &&
      data.ct.length >= 24 &&
      data.ct.length <= 256 &&
      BASE64_REGEX.test(data.ct)
    );
  }
  return false;
}

// Cryptographically secure random token (256-bit hex)
function generateSecureToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// Cryptographically secure display name generator using rejection sampling (zero modulo bias)
function cryptoRandomIndex(max) {
  if (!Number.isSafeInteger(max) || max <= 1) return 0;
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  let val;
  do {
    crypto.getRandomValues(buf);
    val = buf[0];
  } while (val >= limit);
  return val % max;
}

export function randomName() {
  const animals = [
    "แมว", "หมา", "นกฮูก", "ปลาวาฬ", "กระต่าย", "เพนกวิน",
    "ช้าง", "หมีแพนด้า", "โลมา", "จิ้งจอก", "โคอาล่า", "นาก",
  ];
  const colors = [
    "สีแดง", "สีฟ้า", "สีเขียว", "สีม่วง", "สีส้ม", "สีชมพู",
    "สีทอง", "สีเงิน", "สีคราม", "สีหยก", "สีขาว", "สีนิล",
  ];
  return `${animals[cryptoRandomIndex(animals.length)]}${colors[cryptoRandomIndex(colors.length)]}`;
}

function uniqueRandomName(existingNames) {
  for (let i = 0; i < 16; i++) {
    const candidate = randomName();
    if (!existingNames.has(candidate)) return candidate;
  }
  return `${randomName()} #${10 + cryptoRandomIndex(90)}`;
}

function detectDevice(ua) {
  if (typeof ua !== "string") return "desktop";
  const safeUa = ua.slice(0, 512);
  if (/iPhone|Android.+Mobile/i.test(safeUa)) return "phone";
  if (/iPad|Android|Tablet/i.test(safeUa)) return "tablet";
  return "desktop";
}
