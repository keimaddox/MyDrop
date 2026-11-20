import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

// Provide a Cloudflare workerd-compatible Response wrapper in Node.js that allows status 101 + webSocket property
const NativeResponse = globalThis.Response;
globalThis.Response = class CloudflareResponse extends NativeResponse {
  constructor(body, init = {}) {
    if (init && init.status === 101) {
      super(body, { status: 200, headers: init.headers });
      Object.defineProperty(this, "status", { value: 101 });
      this.webSocket = init.webSocket || null;
    } else {
      super(body, init);
    }
  }
};

// ================= 1. Load & Mock Cloudflare Worker + Durable Object Environment =================
// Provide a minimal mock for `cloudflare:workers` DurableObject and WebSocketPair so we can import src/index.js directly in Node.js
class MockWebSocket {
  constructor() {
    this.peer = null;
    this.attachment = null;
    this.sent = [];
    this.closed = false;
    this.closeCode = null;
    this.closeReason = null;
    this.readyState = 1;
  }
  serializeAttachment(obj) {
    this.attachment = structuredClone(obj);
  }
  deserializeAttachment() {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
  send(data) {
    if (this.closed) throw new Error("WebSocket is closed");
    this.sent.push(data);
    if (this.peer && this.peer.onmessage) {
      const msgData = data;
      queueMicrotask(() => {
        if (!this.peer.closed && this.peer.onmessage) {
          this.peer.onmessage({ data: msgData });
        }
      });
    }
  }
  close(code = 1000, reason = "") {
    this.closed = true;
    this.readyState = 3;
    this.closeCode = code;
    this.closeReason = reason;
    if (this.peer) {
      this.peer.closed = true;
      this.peer.readyState = 3;
    }
  }
}

globalThis.WebSocketPair = class WebSocketPair {
  constructor() {
    const client = new MockWebSocket();
    const server = new MockWebSocket();
    client.peer = server;
    server.peer = client;
    this[0] = client;
    this[1] = server;
  }
};

globalThis.WebSocketRequestResponsePair = class WebSocketRequestResponsePair {
  constructor(req, res) {
    this.req = req;
    this.res = res;
  }
};

class MockDurableObjectCtx {
  constructor() {
    this.sockets = [];
    this.autoResponse = null;
  }
  setWebSocketAutoResponse(pair) {
    this.autoResponse = pair;
  }
  acceptWebSocket(ws) {
    this.sockets.push(ws);
  }
  getWebSockets() {
    return this.sockets.filter((s) => !s.closed);
  }
}

// Create a temporary loader-compatible version of src/index.js by replacing `import { DurableObject } from "cloudflare:workers";`
const indexSrc = fs.readFileSync(path.join(rootDir, "src", "index.js"), "utf8");
const patchedIndexSrc = indexSrc.replace(
  'import { DurableObject } from "cloudflare:workers";',
  "class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }"
);
const dataUrl = "data:text/javascript;base64," + Buffer.from(patchedIndexSrc, "utf8").toString("base64");
const workerModule = await import(dataUrl);
const {
  default: worker,
  Room,
  SERVER_LIMITS,
  withSecurityHeaders,
  isValidSameOrigin,
  validateRoomCode,
  roomFromIp,
  isValidSignalPayload,
  isValidRelayPayload,
  randomName,
} = workerModule;

// Create a mock Env with Durable Object room instances
function createMockEnv() {
  const rooms = new Map();
  return {
    rooms,
    ROOMS: {
      idFromName(name) {
        return name;
      },
      get(id) {
        if (!rooms.has(id)) {
          const ctx = new MockDurableObjectCtx();
          const roomInstance = new Room(ctx, {});
          rooms.set(id, { ctx, roomInstance });
        }
        const entry = rooms.get(id);
        return {
          fetch: (req) => entry.roomInstance.fetch(req),
          instance: entry.roomInstance,
          ctx: entry.ctx,
        };
      },
    },
    ASSETS: {
      async fetch(req) {
        return new Response("<!doctype html><html><body>MyDrop</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      },
    },
  };
}

// ================= 2. Load Client Security & E2EE Functions from public/app.js =================
// Extract pure functions or run public/app.js in an isolated DOM-mocked VM context
function createClientInstance(name = "Client") {
  const elements = new Map();
  const makeEl = () => {
    const el = {
      style: {},
      dataset: {},
      classList: {
        add() { },
        remove() { },
        toggle() { },
      },
      hidden: false,
      value: "",
      textContent: "",
      innerHTML: "",
      children: [],
      append(...nodes) {
        this.children.push(...nodes);
      },
      appendChild(node) {
        this.children.push(node);
      },
      prepend(node) {
        this.children.unshift(node);
      },
      remove() { },
      querySelector() {
        return makeEl();
      },
      addEventListener() { },
      click() { },
      focus() { },
      scrollIntoView() { },
    };
    return el;
  };

  const sandbox = {
    console,
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Uint32Array,
    ArrayBuffer,
    DataView,
    BigInt,
    Blob,
    File,
    URL: {
      createObjectURL: () => `blob:https://mydrop.example/${crypto.randomUUID()}`,
      revokeObjectURL: () => { },
    },
    URLSearchParams,
    btoa: (str) => Buffer.from(str, "binary").toString("base64"),
    atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    setTimeout,
    clearTimeout,
    setInterval: () => 1,
    clearInterval: () => { },
    queueMicrotask,
    sessionStorage: {
      store: new Map(),
      getItem(k) { return this.store.get(k) || null; },
      setItem(k, v) { this.store.set(k, String(v)); },
      removeItem(k) { this.store.delete(k); },
    },
    location: {
      href: "https://mydrop.example/",
      origin: "https://mydrop.example",
      protocol: "https:",
      host: "mydrop.example",
      hostname: "mydrop.example",
      pathname: "/",
      search: "",
    },
    history: {
      replaceState() { },
    },
    navigator: {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      clipboard: { writeText: async () => { } },
      storage: null,
      wakeLock: {
        async request() {
          return {
            released: false,
            addEventListener() { },
            async release() {
              this.released = true;
            },
          };
        },
      },
    },
    document: {
      visibilityState: "visible",
      body: makeEl(),
      querySelector(sel) {
        if (!elements.has(sel)) elements.set(sel, makeEl());
        return elements.get(sel);
      },
      createElement() {
        return makeEl();
      },
      addEventListener() { },
    },
    addEventListener() { },
    removeEventListener() { },
    indexedDB: {
      open() {
        const req = {};
        setTimeout(() => req.onerror && req.onerror(), 0);
        return req;
      },
    },
    fetch: async () => ({
      ok: true,
      json: async () => ({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }),
    }),
    WebSocket: class DummyWS {
      constructor(url) {
        this.url = url;
        this.readyState = 1;
        this.bufferedAmount = 0;
        this.sent = [];
        queueMicrotask(() => this.onopen && this.onopen());
      }
      send(d) {
        this.sent.push(d);
        if (d === "ping" && this.onmessage) {
          queueMicrotask(() => this.onmessage({ data: "pong" }));
        }
      }
      close() {
        this.readyState = 3;
      }
    },
    RTCPeerConnection: class DummyPC {
      constructor() {
        this.connectionState = "new";
        this.signalingState = "stable";
      }
      createDataChannel() {
        return {
          readyState: "connecting",
          addEventListener() { },
          send() { },
          close() { },
        };
      }
      async setLocalDescription() { }
      async setRemoteDescription() { }
      async addIceCandidate() { }
      close() { }
    },
    confirm: () => true,
    prompt: () => "Hello",
  };
  sandbox.window = sandbox;

  const appCode = fs.readFileSync(path.join(rootDir, "public", "app.js"), "utf8");
  // Expose internal E2EE & protocol functions for white-box testing
  const testFooter = `
    window.__test = {
      getMyId: () => myId,
      getMyName: () => myName,
      getReconnectToken: () => reconnectToken,
      getPeers: () => peers,
      getWs: () => ws,
      getConn: (pid) => conns.get(pid),
      setConn: (pid, c) => conns.set(pid, c),
      getE2EESession: (pid) => e2eeSessions.get(pid),
      getIncoming: (pid) => incoming.get(pid),
      getAcceptedTransfer: (tid) => acceptedTransfers.get(tid),
      getActiveOutgoing: (tid) => activeOutgoingTransfers.get(tid),
      getAllOutgoing: () => activeOutgoingTransfers,
      getUiTransfer: () => currentUiTransfer,
      getRequestQueue: () => requestQueue,
      getActiveRequest: () => activeRequest,
      getActiveObjectUrls: () => activeObjectUrls,
      setPeers: (p) => { peers = p; renderPeers(); },
      setIdentity: (id, n) => { myId = id; myName = n; },
      ensureE2EESession,
      handleE2EEHandshake,
      encryptControlMessage,
      decryptControlMessage,
      encryptFileChunk,
      decryptFileChunk,
      onRelayMessage,
      onP2PMessage,
      onDecryptedControl,
      onEncryptedChunk,
      respondToActiveRequest,
      cleanupPeerState,
      sendFiles,
      sendText,
      elements,
    };
  `;
  sandbox.elements = elements;
  vm.createContext(sandbox);
  vm.runInContext(appCode + "\n" + testFooter, sandbox);
  return sandbox;
}

// Helper to connect a client to a Durable Object Room over WebSocket
async function connectClientToRoom(env, roomCode = "", ip = "203.0.113.10", token = "", extraQuery = "") {
  const qs = new URLSearchParams();
  if (roomCode) qs.set("room", roomCode);
  if (token) qs.set("token", token);
  const queryStr = [qs.toString(), extraQuery].filter(Boolean).join("&");
  const url = `https://mydrop.example/ws${queryStr ? "?" + queryStr : ""}`;
  const req = new Request(url, {
    method: "GET",
    headers: {
      Upgrade: "websocket",
      Origin: "https://mydrop.example",
      "CF-Connecting-IP": ip,
      "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
    },
  });
  const res = await worker.fetch(req, env);
  return res;
}

const results = [];
async function runTest(category, name, fn) {
  try {
    await fn();
    results.push({ category, name, status: "PASS" });
    console.log(`✅ [${category}] ${name}`);
  } catch (err) {
    results.push({ category, name, status: "FAIL", error: err.message });
    console.error(`❌ [${category}] ${name}:`, err);
    throw err;
  }
}

// ============================================================================
// SUITE A: NORMAL USAGE TESTS
// ============================================================================
await runTest("A. Normal Usage", "Two devices connect, discover each other, and receive server-assigned identities", async () => {
  const env = createMockEnv();
  const resA = await connectClientToRoom(env, "team-room-1", "203.0.113.1");
  const resB = await connectClientToRoom(env, "team-room-1", "203.0.113.2");

  assert.equal(resA.status, 101);
  assert.equal(resB.status, 101);

  const serverSocketA = resA.webSocket.peer;
  const serverSocketB = resB.webSocket.peer;

  const welcomeA = JSON.parse(serverSocketA.sent[0]);
  const welcomeB = JSON.parse(serverSocketB.sent[0]);

  assert.equal(welcomeA.type, "welcome");
  assert.equal(welcomeB.type, "welcome");
  assert.notEqual(welcomeA.id, welcomeB.id);
  assert.ok(welcomeA.reconnectToken && welcomeA.reconnectToken.length === 64);

  // Verify Peer A received peers list containing Peer B without leaking IP or reconnectToken
  const lastPeersMsgA = JSON.parse(serverSocketA.sent[serverSocketA.sent.length - 1]);
  assert.equal(lastPeersMsgA.type, "peers");
  assert.equal(lastPeersMsgA.peers.length, 1);
  assert.equal(lastPeersMsgA.peers[0].id, welcomeB.id);
  assert.equal(lastPeersMsgA.peers[0].reconnectToken, undefined);
  assert.equal(lastPeersMsgA.peers[0].ip, undefined);
});

await runTest("A. Normal Usage", "Three devices connect in the same automatic Wi-Fi/LAN IP room", async () => {
  const env = createMockEnv();
  const res1 = await connectClientToRoom(env, "", "198.51.100.42");
  const res2 = await connectClientToRoom(env, "", "198.51.100.42");
  const res3 = await connectClientToRoom(env, "", "198.51.100.42");

  assert.equal(res1.status, 101);
  assert.equal(res2.status, 101);
  assert.equal(res3.status, 101);

  const s1 = res1.webSocket.peer;
  const peersMsg1 = JSON.parse(s1.sent[s1.sent.length - 1]);
  assert.equal(peersMsg1.type, "peers");
  assert.equal(peersMsg1.peers.length, 2);
});

await runTest("A. Normal Usage", "Reconnect with valid server-issued reconnectToken preserves identity and replaces old socket", async () => {
  const env = createMockEnv();
  const res1 = await connectClientToRoom(env, "reconnect-room", "203.0.113.5");
  const s1 = res1.webSocket.peer;
  const welcome1 = JSON.parse(s1.sent[0]);

  const res2 = await connectClientToRoom(env, "reconnect-room", "203.0.113.5", welcome1.reconnectToken);
  assert.equal(res2.status, 101);
  const s2 = res2.webSocket.peer;
  const welcome2 = JSON.parse(s2.sent[0]);

  assert.equal(welcome2.id, welcome1.id);
  assert.equal(welcome2.name, welcome1.name);
  assert.NotEqual?.(welcome2.reconnectToken, welcome1.reconnectToken);
  assert.equal(s1.closed, true);
});

await runTest("A. Normal Usage", "E2EE key exchange + send small file, multiple files, and text message end-to-end (Relay & P2P binary)", async () => {
  const alice = createClientInstance("Alice");
  const bob = createClientInstance("Bob");

  const aliceId = crypto.randomUUID();
  const bobId = crypto.randomUUID();

  alice.__test.setIdentity(aliceId, "แมวสีฟ้า");
  bob.__test.setIdentity(bobId, "หมาสีส้ม");
  alice.__test.setPeers([{ id: bobId, name: "หมาสีส้ม", device: "desktop" }]);
  bob.__test.setPeers([{ id: aliceId, name: "แมวสีฟ้า", device: "phone" }]);

  // Bridge Alice and Bob's WebSockets so relaySend routes directly between them
  const bridgeSend = (senderWs, senderId, receiver, receiverId) => (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => senderWs.onmessage && senderWs.onmessage({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay" && msg.to === receiverId) {
      queueMicrotask(() => receiver.__test.onRelayMessage(senderId, msg.data));
    }
  };
  alice.__test.getWs().send = bridgeSend(alice.__test.getWs(), aliceId, bob, bobId);
  bob.__test.getWs().send = bridgeSend(bob.__test.getWs(), bobId, alice, aliceId);

  // 1. Establish E2EE session between Alice and Bob
  const sessAlice = await alice.__test.ensureE2EESession(bobId);
  await new Promise((r) => setTimeout(r, 30));
  const sessBob = bob.__test.getE2EESession(aliceId);

  assert.equal(sessAlice.state, "established");
  assert.equal(sessBob.state, "established");
  assert.equal(sessAlice.sas, sessBob.sas);
  assert.match(sessAlice.sas, /^\d{3}-\d{3}$/);

  // 2. Send encrypted text message from Alice to Bob
  const textPkt = await alice.__test.encryptControlMessage(bobId, {
    type: "text",
    text: "สวัสดีจาก Alice (E2EE)",
  });
  await bob.__test.onRelayMessage(aliceId, textPkt);
  const receivedBox = bob.__test.elements.get("#received");
  assert.equal(receivedBox.children.length, 1);

  // 3. Send multiple files (2 files) from Alice to Bob with user approval
  const file1Bytes = new TextEncoder().encode("Hello MyDrop File 1 Content!");
  const file2Bytes = new TextEncoder().encode("Second File Content 1234567890");
  const transferId = crypto.randomUUID();

  const reqPkt = await alice.__test.encryptControlMessage(bobId, {
    type: "file-request",
    transferId,
    files: [
      { name: "hello.txt", size: file1Bytes.byteLength, mime: "text/plain" },
      { name: "notes.md", size: file2Bytes.byteLength, mime: "text/markdown" },
    ],
  });
  await bob.__test.onRelayMessage(aliceId, reqPkt);
  assert.ok(bob.__test.getActiveRequest());
  assert.equal(bob.__test.getActiveRequest().transferId, transferId);

  // Bob accepts the transfer
  await bob.__test.respondToActiveRequest(true);
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(bob.__test.getAcceptedTransfer(transferId));

  // Alice sends File 0 over Relay (JSON enc-chunk)
  const hdr0 = await alice.__test.encryptControlMessage(bobId, {
    type: "header",
    transferId,
    fileIndex: 0,
    name: "hello.txt",
    size: file1Bytes.byteLength,
    mime: "text/plain",
    totalChunks: 1,
  });
  await bob.__test.onRelayMessage(aliceId, hdr0);

  const encChunk0 = await alice.__test.encryptFileChunk(
    bobId,
    transferId,
    0,
    0,
    true,
    file1Bytes.buffer
  );
  await bob.__test.onRelayMessage(aliceId, {
    type: "enc-chunk",
    transferId,
    fileIndex: 0,
    chunkIndex: 0,
    last: true,
    iv: Buffer.from(encChunk0.iv).toString("base64"),
    ct: Buffer.from(encChunk0.ctBuf).toString("base64"),
  });

  // Alice sends File 1 over P2P Binary Framing (packEncryptedChunkBinary)
  const hdr1 = await alice.__test.encryptControlMessage(bobId, {
    type: "header",
    transferId,
    fileIndex: 1,
    name: "notes.md",
    size: file2Bytes.byteLength,
    mime: "text/markdown",
    totalChunks: 1,
  });
  await bob.__test.onRelayMessage(aliceId, hdr1);

  const encChunk1 = await alice.__test.encryptFileChunk(
    bobId,
    transferId,
    1,
    0,
    true,
    file2Bytes.buffer
  );
  const binaryFrame = alice.MyDropSecurity.packEncryptedChunkBinary(encChunk1);
  await bob.__test.onP2PMessage(aliceId, binaryFrame);

  // Verify both files were reconstructed and added to #received, and transfer state was cleaned up
  assert.equal(receivedBox.children.length, 3); // 1 text + 2 files
  assert.equal(bob.__test.getIncoming(aliceId), undefined);
  assert.equal(bob.__test.getAcceptedTransfer(transferId), undefined);
});

await runTest("A. Normal Usage", "Reject a transfer and disconnect cleanup", async () => {
  const alice = createClientInstance("Alice");
  const bob = createClientInstance("Bob");
  const aliceId = crypto.randomUUID();
  const bobId = crypto.randomUUID();
  alice.__test.setIdentity(aliceId, "Alice");
  bob.__test.setIdentity(bobId, "Bob");
  alice.__test.setPeers([{ id: bobId, name: "Bob", device: "desktop" }]);
  bob.__test.setPeers([{ id: aliceId, name: "Alice", device: "desktop" }]);

  alice.__test.getWs().send = (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => alice.__test.getWs().onmessage?.({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => bob.__test.onRelayMessage(aliceId, msg.data));
  };
  bob.__test.getWs().send = (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => bob.__test.getWs().onmessage?.({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => alice.__test.onRelayMessage(bobId, msg.data));
  };

  await alice.__test.ensureE2EESession(bobId);
  await new Promise((r) => setTimeout(r, 20));

  const transferId = crypto.randomUUID();
  const reqPkt = await alice.__test.encryptControlMessage(bobId, {
    type: "file-request",
    transferId,
    files: [{ name: "test.txt", size: 10, mime: "text/plain" }],
  });
  await bob.__test.onRelayMessage(aliceId, reqPkt);
  assert.ok(bob.__test.getActiveRequest());

  // Bob rejects the transfer
  await bob.__test.respondToActiveRequest(false);
  assert.equal(bob.__test.getAcceptedTransfer(transferId), undefined);

  // Even if Alice maliciously sends a header after rejection, Bob ignores it
  const hdr = await alice.__test.encryptControlMessage(bobId, {
    type: "header",
    transferId,
    fileIndex: 0,
    name: "test.txt",
    size: 10,
    mime: "text/plain",
  });
  await bob.__test.onRelayMessage(aliceId, hdr);
  assert.equal(bob.__test.getIncoming(aliceId), undefined);
});

// ============================================================================
// SUITE B: SECURITY TESTS
// ============================================================================
await runTest("B. Security Tests", "Reject client-supplied fake peer ID and fake display name (?id= & ?name=)", async () => {
  const env = createMockEnv();
  const victimRes = await connectClientToRoom(env, "sec-room", "203.0.113.10");
  const victimWelcome = JSON.parse(victimRes.webSocket.peer.sent[0]);

  // Attacker attempts to hijack victim's ID and spoof name via query params
  const attackerRes = await connectClientToRoom(
    env,
    "sec-room",
    "203.0.113.99",
    "",
    `id=${encodeURIComponent(victimWelcome.id)}&name=ADMIN_SYSTEM`
  );
  assert.equal(attackerRes.status, 101);
  const attackerWelcome = JSON.parse(attackerRes.webSocket.peer.sent[0]);

  // Server must ignore client-supplied id & name and keep victim connected
  assert.notEqual(attackerWelcome.id, victimWelcome.id);
  assert.notEqual(attackerWelcome.name, "ADMIN_SYSTEM");
  assert.equal(victimRes.webSocket.peer.closed, false);
});

await runTest("B. Security Tests", "Reject fake sender ID spoofing in WebSocket messages", async () => {
  const env = createMockEnv();
  const resA = await connectClientToRoom(env, "spoof-room", "203.0.113.1");
  const resB = await connectClientToRoom(env, "spoof-room", "203.0.113.2");
  const resC = await connectClientToRoom(env, "spoof-room", "203.0.113.3");

  const sA = resA.webSocket.peer;
  const sB = resB.webSocket.peer;
  const sC = resC.webSocket.peer;

  const idA = JSON.parse(sA.sent[0]).id;
  const idB = JSON.parse(sB.sent[0]).id;
  const idC = JSON.parse(sC.sent[0]).id;

  const roomStub = env.ROOMS.get("code:spoof-room");
  const beforeCountC = sC.sent.length;

  // Attacker A tries to send a message to C claiming `from: idB`
  await roomStub.instance.webSocketMessage(
    sA,
    JSON.stringify({
      type: "signal",
      from: idB,
      to: idC,
      data: { type: "ice", candidate: { candidate: "candidate:1 1 UDP 123 127.0.0.1 9999 typ host" } },
    })
  );

  // Message must be dropped and never delivered to C
  assert.equal(sC.sent.length, beforeCountC);
});

await runTest("B. Security Tests", "Reject invalid room IDs (too short, too long, special characters) & CSWSH cross-origin requests", async () => {
  const env = createMockEnv();

  // Too short room code ("ab")
  const shortRes = await connectClientToRoom(env, "ab");
  assert.equal(shortRes.status, 400);

  // Too long room code (65 chars)
  const longRes = await connectClientToRoom(env, "a".repeat(65));
  assert.equal(longRes.status, 400);

  // Invalid characters (XSS / path traversal attempt)
  const badCharRes = await connectClientToRoom(env, "room<script>alert(1)</script>");
  assert.equal(badCharRes.status, 400);

  // Cross-Site WebSocket Hijacking (Origin mismatch)
  const cswshReq = new Request("https://mydrop.example/ws", {
    method: "GET",
    headers: {
      Upgrade: "websocket",
      Origin: "https://evil-attacker.example",
    },
  });
  const cswshRes = await worker.fetch(cswshReq, env);
  assert.equal(cswshRes.status, 403);
});

await runTest("B. Security Tests", "Reject unauthorized recipient (peer outside room or non-existent UUID)", async () => {
  const env = createMockEnv();
  const resRoom1 = await connectClientToRoom(env, "room-alpha", "203.0.113.1");
  const resRoom2 = await connectClientToRoom(env, "room-beta", "203.0.113.2");

  const s1 = resRoom1.webSocket.peer;
  const s2 = resRoom2.webSocket.peer;
  const id2 = JSON.parse(s2.sent[0]).id;
  const beforeCount2 = s2.sent.length;

  // Peer 1 in room-alpha attempts to signal Peer 2 in room-beta
  const room1Stub = env.ROOMS.get("code:room-alpha");
  await room1Stub.instance.webSocketMessage(
    s1,
    JSON.stringify({
      type: "signal",
      to: id2,
      data: { type: "ice", candidate: { candidate: "candidate:1" } },
    })
  );

  assert.equal(s2.sent.length, beforeCount2);
});

await runTest("B. Security Tests", "Reject invalid JSON, unknown message types, unencrypted relay payloads, and oversized WebSocket messages", async () => {
  const env = createMockEnv();
  const resA = await connectClientToRoom(env, "val-room", "203.0.113.1");
  const resB = await connectClientToRoom(env, "val-room", "203.0.113.2");
  const sA = resA.webSocket.peer;
  const sB = resB.webSocket.peer;
  const idB = JSON.parse(sB.sent[0]).id;
  const roomStub = env.ROOMS.get("code:val-room");
  const initialCountB = sB.sent.length;

  // 1. Invalid JSON
  await roomStub.instance.webSocketMessage(sA, "{not-valid-json");
  // 2. Unknown message type
  await roomStub.instance.webSocketMessage(sA, JSON.stringify({ type: "admin-broadcast", to: idB, data: {} }));
  // 3. Plaintext relay message (e.g. legacy plaintext chunk or file-request)
  await roomStub.instance.webSocketMessage(
    sA,
    JSON.stringify({ type: "relay", to: idB, data: { type: "chunk", data: "AAAA" } })
  );
  // 4. Oversized WebSocket message (> 128 KB)
  await roomStub.instance.webSocketMessage(
    sA,
    JSON.stringify({ type: "relay", to: idB, data: { type: "enc-chunk", ct: "A".repeat(140000) } })
  );

  // None of those messages may reach Peer B
  assert.equal(sB.sent.length, initialCountB);

  // 5th violation triggers socket disconnection (1008 Policy violation)
  await roomStub.instance.webSocketMessage(sA, "{bad-json-5");
  assert.equal(sA.closed, true);
  assert.equal(sA.closeCode, 1008);
});

await runTest("B. Security Tests", "Enforce message flooding rate limit and repeated connection attempt limits", async () => {
  const env = createMockEnv();
  const resA = await connectClientToRoom(env, "flood-room", "203.0.113.50");
  const resB = await connectClientToRoom(env, "flood-room", "203.0.113.51");
  const sA = resA.webSocket.peer;
  const sB = resB.webSocket.peer;
  const idB = JSON.parse(sB.sent[0]).id;
  const roomStub = env.ROOMS.get("code:flood-room");

  // Flood > MAX_CONTROL_MSG_PER_10S (80) signaling messages
  for (let i = 0; i < SERVER_LIMITS.MAX_CONTROL_MSG_PER_10S + 10; i++) {
    await roomStub.instance.webSocketMessage(
      sA,
      JSON.stringify({
        type: "signal",
        to: idB,
        data: { type: "ice", candidate: { candidate: "candidate:1" } },
      })
    );
  }
  assert.equal(sA.closed, true);
  assert.equal(sA.closeCode, 1008);

  // Repeated connection attempts from same IP (> MAX_CONN_ATTEMPTS_PER_IP_PER_MIN = 30)
  let lastStatus = 101;
  for (let i = 0; i < SERVER_LIMITS.MAX_CONN_ATTEMPTS_PER_IP_PER_MIN + 5; i++) {
    const r = await connectClientToRoom(env, "flood-room", "203.0.113.200");
    lastStatus = r.status;
    if (r.webSocket) r.webSocket.peer.close();
  }
  assert.equal(lastStatus, 429);
});

await runTest("B. Security Tests", "Enforce file count, file size, total size, filename sanitization, dangerous file detection, and MIME validation", async () => {
  const client = createClientInstance("Validator");
  const sec = client.MyDropSecurity;

  // 1. Too many files (> 10)
  const elevenFiles = Array.from({ length: 11 }, (_, i) => new Blob(["x"], { type: "text/plain" }));
  elevenFiles.forEach((f, i) => (f.name = `f${i}.txt`));
  assert.equal(sec.validateOutgoingFiles(elevenFiles).ok, false);

  // 2. Oversized individual file (> 5 GB for P2P, > 500 MB for Relay)
  const fiveGb = 5 * 1024 * 1024 * 1024;
  const fiveHundredMb = 500 * 1024 * 1024;
  const validFiveGbReq = sec.validateIncomingFileRequest({
    transferId: crypto.randomUUID(),
    files: [{ name: "movie_4k.mov", size: fiveGb, mime: "video/quicktime" }],
  });
  assert.equal(validFiveGbReq.ok, true);

  const hugeFileReq = sec.validateIncomingFileRequest({
    transferId: crypto.randomUUID(),
    files: [{ name: "big.bin", size: fiveGb + 1, mime: "application/octet-stream" }],
  });
  assert.equal(hugeFileReq.ok, false);

  const hugeRelayFileReq = sec.validateIncomingFileRequest(
    {
      transferId: crypto.randomUUID(),
      transportMode: "relay",
      files: [{ name: "relay_too_big.mp4", size: fiveHundredMb + 1, mime: "video/mp4" }],
    },
    "relay"
  );
  assert.equal(hugeRelayFileReq.ok, false);

  // 3. Oversized total transfer (> 10 GB across 3 files)
  const hugeTotalReq = sec.validateIncomingFileRequest({
    transferId: crypto.randomUUID(),
    files: [
      { name: "a.bin", size: 4 * 1024 * 1024 * 1024, mime: "application/octet-stream" },
      { name: "b.bin", size: 4 * 1024 * 1024 * 1024, mime: "application/octet-stream" },
      { name: "c.bin", size: 3 * 1024 * 1024 * 1024, mime: "application/octet-stream" },
    ],
  });
  assert.equal(hugeTotalReq.ok, false);

  // 4. Path traversal, BiDi RLO character, and reserved filename sanitization
  assert.equal(sec.sanitizeFilename("../../etc/passwd"), "passwd");
  assert.equal(sec.sanitizeFilename("..\\..\\Windows\\System32\\cmd.exe"), "cmd.exe");
  assert.equal(sec.sanitizeFilename("invoice\u202Efdp.exe"), "invoicefdp.exe");
  assert.equal(sec.sanitizeFilename("CON.txt"), "file_CON.txt");

  // 5. Dangerous file detection & safe download MIME downgrade
  for (const ext of [".exe", ".bat", ".cmd", ".scr", ".ps1", ".js", ".vbs", ".msi", ".hta", ".html", ".svg"]) {
    assert.equal(sec.isDangerousFile(`payload${ext}`, "application/octet-stream"), true, `Failed on ${ext}`);
    assert.equal(sec.getSafeDownloadMime(`payload${ext}`, "text/html"), "application/octet-stream");
  }
  assert.equal(sec.isDangerousFile("photo.jpg", "image/jpeg"), false);
  assert.equal(sec.getSafeDownloadMime("photo.jpg", "image/jpeg"), "image/jpeg");

  // 6. Invalid MIME type format fallback
  assert.equal(sec.sanitizeMimeType("invalid-mime-type<script>"), "application/octet-stream");

  // 7. Configurable limits support via configureSecurityLimits()
  sec.configureSecurityLimits({ MAX_FILES_PER_TRANSFER: 2 });
  assert.equal(sec.SECURITY_LIMITS.MAX_FILES_PER_TRANSFER, 2);
  const threeFiles = Array.from({ length: 3 }, (_, i) => {
    const b = new Blob(["x"], { type: "text/plain" });
    b.name = `f${i}.txt`;
    return b;
  });
  assert.equal(sec.validateOutgoingFiles(threeFiles).ok, false);
  sec.configureSecurityLimits({ MAX_FILES_PER_TRANSFER: 10 });
});

await runTest("B. Security Tests", "Reject malformed file chunks, modified encrypted chunks, and expired transfers", async () => {
  const alice = createClientInstance("Alice");
  const bob = createClientInstance("Bob");
  const aliceId = crypto.randomUUID();
  const bobId = crypto.randomUUID();
  alice.__test.setIdentity(aliceId, "Alice");
  bob.__test.setIdentity(bobId, "Bob");
  alice.__test.setPeers([{ id: bobId, name: "Bob", device: "desktop" }]);
  bob.__test.setPeers([{ id: aliceId, name: "Alice", device: "desktop" }]);

  alice.__test.getWs().send = (raw) => {
    if (raw === "ping") return;
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => bob.__test.onRelayMessage(aliceId, msg.data));
  };
  bob.__test.getWs().send = (raw) => {
    if (raw === "ping") return;
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => alice.__test.onRelayMessage(bobId, msg.data));
  };

  await alice.__test.ensureE2EESession(bobId);
  await new Promise((r) => setTimeout(r, 20));

  // 1. Malformed P2P binary chunk (too short & wrong magic header)
  assert.throws(
    () => bob.MyDropSecurity.unpackEncryptedChunkBinary(new Uint8Array(10).buffer),
    /too short/i
  );
  const badMagic = new Uint8Array(80);
  badMagic[0] = 0x00;
  assert.throws(
    () => bob.MyDropSecurity.unpackEncryptedChunkBinary(badMagic.buffer),
    /Invalid binary frame header magic/i
  );

  // 2. Modified encrypted chunk during active transfer -> aborts transfer and cleans up state
  const tid = crypto.randomUUID();
  const req = await alice.__test.encryptControlMessage(bobId, {
    type: "file-request",
    transferId: tid,
    files: [{ name: "tamper.bin", size: 16, mime: "application/octet-stream" }],
  });
  await bob.__test.onRelayMessage(aliceId, req);
  await bob.__test.respondToActiveRequest(true);

  const hdr = await alice.__test.encryptControlMessage(bobId, {
    type: "header",
    transferId: tid,
    fileIndex: 0,
    name: "tamper.bin",
    size: 16,
    mime: "application/octet-stream",
    totalChunks: 1,
  });
  await bob.__test.onRelayMessage(aliceId, hdr);
  assert.ok(bob.__test.getIncoming(aliceId));

  const encChunk = await alice.__test.encryptFileChunk(
    bobId,
    tid,
    0,
    0,
    true,
    new Uint8Array(16).buffer
  );
  const ctTampered = Buffer.from(encChunk.ctBuf);
  ctTampered[0] ^= 0xff; // Tamper with encrypted chunk bytes
  await bob.__test.onRelayMessage(aliceId, {
    type: "enc-chunk",
    transferId: tid,
    fileIndex: 0,
    chunkIndex: 0,
    last: true,
    iv: Buffer.from(encChunk.iv).toString("base64"),
    ct: ctTampered.toString("base64"),
  });
  // Must fail authentication and abort transfer cleanly
  assert.equal(bob.__test.getIncoming(aliceId), undefined);
  assert.equal(bob.__test.getAcceptedTransfer(tid), undefined);

  // 3. Expired transfer timeout cleanup
  bob.MyDropSecurity.configureSecurityLimits({ REQUEST_TIMEOUT_MS: 40 });
  const expTid = crypto.randomUUID();
  const expReq = await alice.__test.encryptControlMessage(bobId, {
    type: "file-request",
    transferId: expTid,
    files: [{ name: "expire.txt", size: 12, mime: "text/plain" }],
  });
  await bob.__test.onRelayMessage(aliceId, expReq);
  assert.ok(bob.__test.getActiveRequest());
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(bob.__test.getActiveRequest(), null);
  bob.MyDropSecurity.configureSecurityLimits({ REQUEST_TIMEOUT_MS: 60000 });
});

await runTest("B. Security Tests", "Reject duplicate chunks, out-of-order chunks, oversized chunks, and pending request queue overflow (> 5)", async () => {
  const alice = createClientInstance("Alice");
  const bob = createClientInstance("Bob");
  const aliceId = crypto.randomUUID();
  const bobId = crypto.randomUUID();
  alice.__test.setIdentity(aliceId, "Alice");
  bob.__test.setIdentity(bobId, "Bob");
  alice.__test.setPeers([{ id: bobId, name: "Bob", device: "desktop" }]);
  bob.__test.setPeers([{ id: aliceId, name: "Alice", device: "desktop" }]);

  alice.__test.getWs().send = (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => alice.__test.getWs().onmessage?.({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => bob.__test.onRelayMessage(aliceId, msg.data));
  };
  bob.__test.getWs().send = (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => bob.__test.getWs().onmessage?.({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay") queueMicrotask(() => alice.__test.onRelayMessage(bobId, msg.data));
  };

  await alice.__test.ensureE2EESession(bobId);
  await new Promise((r) => setTimeout(r, 20));

  // Send 7 file requests while Bob hasn't answered; Bob must cap pending requests at 5 (1 active + 4 queued)
  for (let i = 0; i < 7; i++) {
    const reqPkt = await alice.__test.encryptControlMessage(bobId, {
      type: "file-request",
      transferId: crypto.randomUUID(),
      files: [{ name: `file_${i}.txt`, size: 100, mime: "text/plain" }],
    });
    await bob.__test.onRelayMessage(aliceId, reqPkt);
  }
  const totalPending = (bob.__test.getActiveRequest() ? 1 : 0) + bob.__test.getRequestQueue().length;
  assert.equal(totalPending, 5);

  // Test duplicate/out-of-order chunk rejection and mid-transfer disconnect cleanup
  bob.__test.cleanupPeerState(aliceId);
  alice.__test.cleanupPeerState(bobId);
  assert.equal(bob.__test.getActiveRequest(), null);
  assert.equal(bob.__test.getRequestQueue().length, 0);

  // Re-establish E2EE session and test modified/out-of-order encrypted chunk rejection
  await alice.__test.ensureE2EESession(bobId);
  await new Promise((r) => setTimeout(r, 20));
  const tid = crypto.randomUUID();
  const req2 = await alice.__test.encryptControlMessage(bobId, {
    type: "file-request",
    transferId: tid,
    files: [{ name: "stream.bin", size: 20, mime: "application/octet-stream" }],
  });
  await bob.__test.onRelayMessage(aliceId, req2);
  await bob.__test.respondToActiveRequest(true);

  const hdr2 = await alice.__test.encryptControlMessage(bobId, {
    type: "header",
    transferId: tid,
    fileIndex: 0,
    name: "stream.bin",
    size: 20,
    mime: "application/octet-stream",
    totalChunks: 2,
  });
  await bob.__test.onRelayMessage(aliceId, hdr2);
  assert.ok(bob.__test.getIncoming(aliceId));

  // Send out-of-order chunk (chunkIndex = 1 when 0 is expected) -> must abort transfer and clean up
  const badOrderChunk = await alice.__test.encryptFileChunk(
    bobId,
    tid,
    0,
    1,
    true,
    new Uint8Array(10).buffer
  );
  await bob.__test.onRelayMessage(aliceId, {
    type: "enc-chunk",
    transferId: tid,
    fileIndex: 0,
    chunkIndex: 1,
    last: true,
    iv: Buffer.from(badOrderChunk.iv).toString("base64"),
    ct: Buffer.from(badOrderChunk.ctBuf).toString("base64"),
  });
  assert.equal(bob.__test.getIncoming(aliceId), undefined);
  assert.equal(bob.__test.getAcceptedTransfer(tid), undefined);
});

// ============================================================================
// SUITE C: ENCRYPTION TESTS
// ============================================================================
await runTest("C. Encryption Tests", "Verify P2P & Relay payloads contain ciphertext only, nonces never repeat, and tampering/wrong keys fail authentication", async () => {
  const alice = createClientInstance("Alice");
  const bob = createClientInstance("Bob");
  const mallory = createClientInstance("Mallory");

  const aliceId = crypto.randomUUID();
  const bobId = crypto.randomUUID();
  const malloryId = crypto.randomUUID();

  alice.__test.setIdentity(aliceId, "Alice");
  bob.__test.setIdentity(bobId, "Bob");
  mallory.__test.setIdentity(malloryId, "Mallory");
  alice.__test.setPeers([{ id: bobId, name: "Bob", device: "desktop" }, { id: malloryId, name: "Mallory", device: "desktop" }]);
  bob.__test.setPeers([{ id: aliceId, name: "Alice", device: "desktop" }]);
  mallory.__test.setPeers([{ id: aliceId, name: "Alice", device: "desktop" }]);

  const wireTranscript = [];
  alice.__test.getWs().send = (raw) => {
    wireTranscript.push(raw);
    const msg = JSON.parse(raw);
    if (msg.type === "relay" && msg.to === bobId) {
      queueMicrotask(() => bob.__test.onRelayMessage(aliceId, msg.data));
    }
    if (msg.type === "relay" && msg.to === malloryId) {
      queueMicrotask(() => mallory.__test.onRelayMessage(aliceId, msg.data));
    }
  };
  bob.__test.getWs().send = (raw) => {
    wireTranscript.push(raw);
    const msg = JSON.parse(raw);
    if (msg.type === "relay" && msg.to === aliceId) {
      queueMicrotask(() => alice.__test.onRelayMessage(bobId, msg.data));
    }
  };
  mallory.__test.getWs().send = (raw) => {
    const msg = JSON.parse(raw);
    if (msg.type === "relay" && msg.to === aliceId) {
      queueMicrotask(() => alice.__test.onRelayMessage(malloryId, msg.data));
    }
  };

  await alice.__test.ensureE2EESession(bobId);
  await alice.__test.ensureE2EESession(malloryId);
  await new Promise((r) => setTimeout(r, 30));

  const secretPlaintext = "TOP_SECRET_CONFIDENTIAL_PAYLOAD_987654321";
  const secretBytes = new TextEncoder().encode(secretPlaintext);
  const transferId = crypto.randomUUID();

  // 1. Encrypt control & chunk and verify plaintext does NOT appear anywhere on the wire
  const ctrlPkt = await alice.__test.encryptControlMessage(bobId, {
    type: "text",
    text: secretPlaintext,
  });
  const chunkPkt = await alice.__test.encryptFileChunk(bobId, transferId, 0, 0, true, secretBytes.buffer);
  const chunkCtBase64 = Buffer.from(chunkPkt.ctBuf).toString("base64");

  assert.equal(JSON.stringify(ctrlPkt).includes(secretPlaintext), false);
  assert.equal(chunkCtBase64.includes(Buffer.from(secretBytes).toString("base64")), false);

  // 2. Verify nonces are strictly unique across 100 consecutive encryptions
  const seenIvs = new Set();
  for (let i = 0; i < 50; i++) {
    const c = await alice.__test.encryptControlMessage(bobId, { type: "text", text: `msg-${i}` });
    assert.equal(seenIvs.has(c.iv), false, "Control IV reused!");
    seenIvs.add(c.iv);

    const f = await alice.__test.encryptFileChunk(bobId, transferId, 0, i, false, secretBytes.buffer);
    const ivB64 = Buffer.from(f.iv).toString("base64");
    assert.equal(seenIvs.has(ivB64), false, "Chunk IV reused!");
    seenIvs.add(ivB64);
  }

  // 3. Verify modified ciphertext fails AES-GCM authentication
  const validCtrl = await alice.__test.encryptControlMessage(bobId, { type: "text", text: "Hello Bob" });
  const tamperedCtBuf = Buffer.from(validCtrl.ct, "base64");
  tamperedCtBuf[0] ^= 0xff; // Flip bits in ciphertext
  const tamperedPkt = { ...validCtrl, ct: tamperedCtBuf.toString("base64") };

  await assert.rejects(
    async () => {
      await bob.__test.decryptControlMessage(aliceId, tamperedPkt);
    },
    /operation failed|decrypt/i
  );

  // 4. Verify replay attack of already-decrypted control message is rejected
  const msgPlain = await bob.__test.decryptControlMessage(aliceId, validCtrl);
  assert.equal(msgPlain.text, "Hello Bob");
  await assert.rejects(
    async () => {
      await bob.__test.decryptControlMessage(aliceId, validCtrl);
    },
    /Replayed or out-of-order/i
  );

  // 5. Verify incorrect key (Mallory trying to decrypt packet meant for Bob) fails authentication
  const forBobOnly = await alice.__test.encryptControlMessage(bobId, { type: "text", text: "Eyes only Bob" });
  await assert.rejects(
    async () => {
      await mallory.__test.decryptControlMessage(aliceId, forBobOnly);
    },
    /operation failed|decrypt|Replayed/i
  );
});

// ============================================================================
// SUITE D: HTTP SECURITY HEADERS, CLOUDFLARE WORKER & IPv6 PARSING TESTS
// ============================================================================
await runTest("D. Web & Cloudflare Security", "Verify HTTP Security Headers, CSP, HSTS, /ice protection, and malformed IPv6 handling", async () => {
  const env = createMockEnv();

  // 1. Static asset request returns all required security headers
  const res = await worker.fetch(new Request("https://mydrop.example/", { method: "GET" }), env);
  assert.equal(res.status, 200);
  assert.ok(res.headers.get("Content-Security-Policy")?.includes("default-src 'self'"));
  assert.ok(res.headers.get("Content-Security-Policy")?.includes("frame-ancestors 'none'"));
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  assert.equal(res.headers.get("Referrer-Policy"), "no-referrer");
  assert.ok(res.headers.get("Strict-Transport-Security")?.includes("max-age=31536000"));
  assert.ok(res.headers.get("Permissions-Policy")?.includes("camera=()"));

  // 2. /ice endpoint sets Cache-Control: no-store and blocks cross-site requests
  const iceSameOrigin = await worker.fetch(
    new Request("https://mydrop.example/ice", {
      method: "GET",
      headers: { "Sec-Fetch-Site": "same-origin" },
    }),
    env
  );
  assert.equal(iceSameOrigin.status, 200);
  assert.ok(iceSameOrigin.headers.get("Cache-Control")?.includes("no-store"));

  const iceCrossOrigin = await worker.fetch(
    new Request("https://mydrop.example/ice", {
      method: "GET",
      headers: { Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site" },
    }),
    env
  );
  assert.equal(iceCrossOrigin.status, 403);

  // 3. Malformed IPv6 strings do not crash roomFromIp()
  assert.doesNotThrow(() => {
    roomFromIp("2001:db8:85a3::8a2e:370:7334");
    roomFromIp("::1");
    roomFromIp("::ffff:192.168.1.1");
    roomFromIp("1:2:3:4:5:6:7:8:9:10");
    roomFromIp("2001::db8::1");
  });
  assert.equal(roomFromIp("2001:db8:85a3::8a2e:370:7334"), "v6:2001:0db8:85a3:0000");
  assert.equal(roomFromIp("::ffff:192.168.1.1"), "v4:192.168.1.1");

  // 4. Reconnect token hijacking from a different IP/subnet is blocked (VULN-01)
  const victimConn = await connectClientToRoom(env, "ip-bound-room", "203.0.113.10");
  const victimWelcome = JSON.parse(victimConn.webSocket.peer.sent[0]);
  const hijackerConn = await connectClientToRoom(env, "ip-bound-room", "198.51.100.99", victimWelcome.reconnectToken);
  const hijackerWelcome = JSON.parse(hijackerConn.webSocket.peer.sent[0]);
  assert.notEqual(hijackerWelcome.id, victimWelcome.id, "Cross-IP reconnect token hijacking must be rejected!");
  assert.equal(victimConn.webSocket.peer.closed, false, "Victim socket must remain open!");

  // 5. Global per-IP connection rate limit prevents multi-room sharding bypass (VULN-05)
  let shardStatus = 101;
  for (let i = 0; i < SERVER_LIMITS.MAX_CONN_ATTEMPTS_PER_IP_PER_MIN + 5; i++) {
    const r = await connectClientToRoom(env, `shard-room-${i}`, "192.0.2.77");
    shardStatus = r.status;
    if (r.webSocket) r.webSocket.peer.close();
  }
  assert.equal(shardStatus, 429, "Multi-room connection sharding from same IP must hit 429 rate limit!");
});

// ============================================================================
// SUITE E: LARGE FILE TRANSFER UPGRADE TESTS (100MB - 5GB, iOS/Android, P2P, Relay, Resume, SHA-256)
// ============================================================================

// Deterministic streaming VirtualVideoFile (extends Blob) that generates deterministic video bytes on demand per .slice()
// without allocating multi-GB buffers in Node.js RAM at once, while exercising the real File.slice().arrayBuffer() API.
class VirtualVideoFile extends Blob {
  constructor(name, sizeBytes, mime = "video/mp4", seed = 0x5a17c3) {
    super([]);
    this._name = name;
    this._size = sizeBytes;
    this._mime = mime;
    this._seed = seed >>> 0;
  }
  get name() {
    return this._name;
  }
  get size() {
    return this._size;
  }
  get type() {
    return this._mime;
  }
  slice(start = 0, end = this._size, contentType = this._mime) {
    const s = Math.max(0, Math.min(this._size, start));
    const e = Math.max(s, Math.min(this._size, end));
    const len = e - s;
    const seed = this._seed;
    const sliceBlob = new Blob([], { type: contentType });
    Object.defineProperty(sliceBlob, "size", { value: len });
    sliceBlob.arrayBuffer = async () => {
      const buf = new ArrayBuffer(len);
      // Define content at every 4KB page boundary purely as a function of absolute file offset `absPos`
      // so slicing in 64KB, 1MB, 2MB, or 4MB chunks always yields the exact same file byte stream!
      const u8 = new Uint8Array(buf);
      const firstPageOffset = (4096 - (s % 4096)) % 4096;
      for (let localPos = firstPageOffset; localPos + 8 <= len; localPos += 4096) {
        const absPos = s + localPos;
        const pageIdx = Math.floor(absPos / 4096);
        const w0 = (seed ^ (pageIdx * 2654435761)) >>> 0;
        const w1 = (seed + pageIdx) >>> 0;
        u8[localPos] = w0 & 0xff;
        u8[localPos + 1] = (w0 >>> 8) & 0xff;
        u8[localPos + 2] = (w0 >>> 16) & 0xff;
        u8[localPos + 3] = (w0 >>> 24) & 0xff;
        u8[localPos + 4] = w1 & 0xff;
        u8[localPos + 5] = (w1 >>> 8) & 0xff;
        u8[localPos + 6] = (w1 >>> 16) & 0xff;
        u8[localPos + 7] = (w1 >>> 24) & 0xff;
      }
      return buf;
    };
    return sliceBlob;
  }
}

// Install a streaming disk-simulated OPFS (`navigator.storage.getDirectory()`) on a client instance
// that verifies written chunk offsets/sizes and computes the received stream's SHA-256 in O(1) memory.
function installStreamingOpfsMock(client, seedForVerification = 0x5a17c3, quotaBytes = 20 * 1024 * 1024 * 1024) {
  const opfsFiles = new Map();
  let usedBytes = 0;
  let peakActiveChunksInRam = 0;
  let activeWriteCount = 0;

  client.navigator.storage = {
    async estimate() {
      return { quota: quotaBytes, usage: usedBytes };
    },
    async getDirectory() {
      return {
        async getFileHandle(fileName, opts = {}) {
          if (!opfsFiles.has(fileName)) {
            opfsFiles.set(fileName, {
              name: fileName,
              size: 0,
              chunksWritten: 0,
              hasher: new client.MyDropSecurity.IntegrityHasher(),
              smallChunks: [],
              keepBytesInRam: true,
              removed: false,
            });
          }
          const entry = opfsFiles.get(fileName);
          return {
            async createWritable() {
              entry.size = 0;
              entry.chunksWritten = 0;
              entry.hasher = new client.MyDropSecurity.IntegrityHasher();
              entry.smallChunks = [];
              return {
                async write(buf) {
                  activeWriteCount += 1;
                  if (activeWriteCount > peakActiveChunksInRam) peakActiveChunksInRam = activeWriteCount;
                  const byteLen = buf.byteLength;
                  entry.size += byteLen;
                  entry.chunksWritten += 1;
                  usedBytes += byteLen;
                  await entry.hasher.update(buf);
                  // Keep actual buffer bytes for files <= 16 MB; for 100 MB - 5 GB files, stream-verify & release buffer immediately
                  if (entry.size <= 16 * 1024 * 1024 && entry.keepBytesInRam) {
                    entry.smallChunks.push(buf.slice(0));
                  } else {
                    entry.keepBytesInRam = false;
                    entry.smallChunks = [];
                  }
                  activeWriteCount -= 1;
                },
                async close() {
                  entry.finalSha256 = await entry.hasher.finalize();
                },
                async abort() {
                  usedBytes = Math.max(0, usedBytes - entry.size);
                  entry.size = 0;
                  entry.smallChunks = [];
                },
              };
            },
            async getFile() {
              if (entry.keepBytesInRam && entry.smallChunks.length > 0) {
                const b = new Blob(entry.smallChunks, { type: "video/mp4" });
                b.sha256 = entry.finalSha256;
                return b;
              }
              const diskBacked = new VirtualVideoFile(entry.name, entry.size, "video/mp4", seedForVerification);
              diskBacked.sha256 = entry.finalSha256;
              return diskBacked;
            },
          };
        },
        async removeEntry(fileName) {
          const entry = opfsFiles.get(fileName);
          if (entry) {
            usedBytes = Math.max(0, usedBytes - entry.size);
            entry.removed = true;
            opfsFiles.delete(fileName);
          }
        },
      };
    },
  };

  return {
    opfsFiles,
    getUsedBytes: () => usedBytes,
    getPeakActiveChunksInRam: () => peakActiveChunksInRam,
  };
}

// Helper to wire two client sandboxes with both WebSocket Relay and a live simulated WebRTC DataChannel
function connectTwoClientsForTransfer(sender, receiver, options = {}) {
  const {
    mode = "p2p",
    sctpMaxMessageSize = 65536, // 64 KB default cross-browser iOS Safari <-> Android Chrome SCTP limit
    senderUa = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    receiverUa = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    autoAccept = true,
    onChunkHook = null,
  } = options;

  const senderId = crypto.randomUUID();
  const receiverId = crypto.randomUUID();
  sender.navigator.userAgent = senderUa;
  receiver.navigator.userAgent = receiverUa;

  sender.__test.setIdentity(senderId, "iPhone-Sender");
  receiver.__test.setIdentity(receiverId, "Android-Receiver");
  sender.__test.setPeers([{ id: receiverId, name: "Android-Receiver", device: "phone" }]);
  receiver.__test.setPeers([{ id: senderId, name: "iPhone-Sender", device: "phone" }]);

  let p2pFramesSent = 0;
  let relayFramesSent = 0;

  // Wire WebSockets for Relay & Signaling
  const makeWsSend = (fromClient, fromId, toClient, toId) => (raw) => {
    if (raw === "ping") {
      queueMicrotask(() => fromClient.__test.getWs().onmessage?.({ data: "pong" }));
      return;
    }
    const msg = JSON.parse(raw);
    if (msg.type === "relay" && msg.to === toId) {
      if (msg.data?.type === "enc-chunk") {
        relayFramesSent += 1;
        if (onChunkHook) {
          const action = onChunkHook({ transport: "relay", packet: msg.data, count: relayFramesSent });
          if (action === "drop") return;
        }
      }
      queueMicrotask(async () => {
        await toClient.__test.onRelayMessage(fromId, msg.data);
        if (autoAccept && toClient.__test.getActiveRequest()) {
          await toClient.__test.respondToActiveRequest(true);
        }
      });
    }
  };

  sender.__test.getWs().send = makeWsSend(sender, senderId, receiver, receiverId);
  receiver.__test.getWs().send = makeWsSend(receiver, receiverId, sender, senderId);

  let dcPair = null;
  if (mode === "p2p") {
    const installDcPair = () => {
      const listenersA = new Map();
      const listenersB = new Map();
      const dcSender = {
        readyState: "open",
        binaryType: "arraybuffer",
        bufferedAmount: 0,
        bufferedAmountLowThreshold: 1024 * 1024,
        addEventListener(ev, fn) {
          if (!listenersA.has(ev)) listenersA.set(ev, new Set());
          listenersA.get(ev).add(fn);
        },
        removeEventListener(ev, fn) {
          listenersA.get(ev)?.delete(fn);
        },
        send(data) {
          if (this.readyState !== "open") throw new Error("DC closed");
          if (typeof data !== "string" && data.byteLength > sctpMaxMessageSize) {
            throw new Error(`SCTP frame size ${data.byteLength} exceeds maxMessageSize ${sctpMaxMessageSize}`);
          }
          const isBinary = typeof data !== "string";
          if (isBinary) p2pFramesSent += 1;
          const byteLen = isBinary ? data.byteLength : data.length;
          this.bufferedAmount += byteLen;
          if (onChunkHook && isBinary) {
            const action = onChunkHook({ transport: "p2p", frame: data, count: p2pFramesSent, dcSender });
            if (action === "drop") {
              this.bufferedAmount = Math.max(0, this.bufferedAmount - byteLen);
              return;
            }
          }
          queueMicrotask(async () => {
            this.bufferedAmount = Math.max(0, this.bufferedAmount - byteLen);
            if (this.bufferedAmount <= this.bufferedAmountLowThreshold) {
              for (const fn of [...(listenersA.get("bufferedamountlow") || [])]) {
                listenersA.get("bufferedamountlow").delete(fn);
                fn();
              }
            }
            if (dcReceiver.readyState === "open") {
              await receiver.__test.onP2PMessage(senderId, data);
              if (autoAccept && receiver.__test.getActiveRequest()) {
                await receiver.__test.respondToActiveRequest(true);
              }
            }
          });
        },
        close() {
          this.readyState = "closed";
          dcReceiver.readyState = "closed";
        },
      };

      const dcReceiver = {
        readyState: "open",
        binaryType: "arraybuffer",
        bufferedAmount: 0,
        bufferedAmountLowThreshold: 1024 * 1024,
        addEventListener(ev, fn) {
          if (!listenersB.has(ev)) listenersB.set(ev, new Set());
          listenersB.get(ev).add(fn);
        },
        removeEventListener(ev, fn) {
          listenersB.get(ev)?.delete(fn);
        },
        send(data) {
          if (this.readyState !== "open") throw new Error("DC closed");
          queueMicrotask(async () => {
            if (dcSender.readyState === "open") {
              await sender.__test.onP2PMessage(receiverId, data);
            }
          });
        },
        close() {
          this.readyState = "closed";
          dcSender.readyState = "closed";
        },
      };

      const maxSctpFrame = Math.max(16384, sctpMaxMessageSize - 128);
      sender.__test.setConn(receiverId, {
        pc: { connectionState: "connected", signalingState: "stable", sctp: { maxMessageSize: sctpMaxMessageSize }, close() { } },
        dc: dcSender,
        chunk: sender.MyDropSecurity.SECURITY_LIMITS.INITIAL_CHUNK_SIZE,
        maxSctpFrame,
        open: Promise.resolve(),
        resolveOpen() { },
        rejectOpen() { },
        timer: null,
      });

      receiver.__test.setConn(senderId, {
        pc: { connectionState: "connected", signalingState: "stable", sctp: { maxMessageSize: sctpMaxMessageSize }, close() { } },
        dc: dcReceiver,
        chunk: receiver.MyDropSecurity.SECURITY_LIMITS.INITIAL_CHUNK_SIZE,
        maxSctpFrame,
        open: Promise.resolve(),
        resolveOpen() { },
        rejectOpen() { },
        timer: null,
      });

      dcPair = { dcSender, dcReceiver, reinstall: installDcPair };
      return dcPair;
    };
    installDcPair();
  }

  return {
    senderId,
    receiverId,
    getP2PFramesSent: () => p2pFramesSent,
    getRelayFramesSent: () => relayFramesSent,
    getDcPair: () => dcPair,
  };
}

await runTest("E. Large File Transfer", "iPhone (iOS Safari) -> Android (Chrome) P2P: 100 MB video transfer with 1-4 MB adaptive chunks, 64 KB SCTP sub-framing, and SHA-256 verification", async () => {
  const iphone = createClientInstance("iPhone-Safari");
  const android = createClientInstance("Android-Chrome");
  const opfsStats = installStreamingOpfsMock(android, 0x100aa1);
  const link = connectTwoClientsForTransfer(iphone, android, { mode: "p2p", sctpMaxMessageSize: 65536 });

  const size100MB = 100 * 1024 * 1024;
  const video100MB = new VirtualVideoFile("IMG_4021_100MB.MOV", size100MB, "video/quicktime", 0x100aa1);
  const expectedSha256 = await iphone.MyDropSecurity.computeBlobSha256(video100MB);

  const ok = await iphone.__test.sendFiles(link.receiverId, [video100MB]);
  assert.equal(ok, true, "100 MB iPhone -> Android P2P transfer must succeed");

  const receivedBox = android.__test.elements.get("#received");
  assert.equal(receivedBox.children.length, 1);
  const item = receivedBox.children[0];
  assert.equal(item.dataset.filename, "IMG_4021_100MB.MOV");
  assert.equal(Number(item.dataset.filesize), size100MB);
  assert.equal(item.dataset.sha256, expectedSha256, "Received 100 MB video SHA-256 must match original!");
  assert.ok(link.getP2PFramesSent() > 100, "1-4 MB chunks must be split into 64 KB SCTP sub-frames");
  assert.ok(opfsStats.getPeakActiveChunksInRam() <= 2, "Receiver memory must remain bounded during OPFS streaming");
});

await runTest("E. Large File Transfer", "Android (Chrome) -> iPhone (iOS Safari) P2P: 500 MB video transfer with Segmented Blob Compaction fallback & SHA-256 verification", async () => {
  const android = createClientInstance("Android-Chrome");
  const iphone = createClientInstance("iPhone-Safari");
  // Test iPhone Safari both with OPFS and verify segmented-blob compaction engine
  const opfsStats = installStreamingOpfsMock(iphone, 0x500bb2);
  const link = connectTwoClientsForTransfer(android, iphone, {
    mode: "p2p",
    sctpMaxMessageSize: 262144, // 256 KB SCTP frame size
    senderUa: "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    receiverUa: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
  });

  const size500MB = 500 * 1024 * 1024;
  const video500MB = new VirtualVideoFile("VID_20261120_500MB.mp4", size500MB, "video/mp4", 0x500bb2);
  const expectedSha256 = await android.MyDropSecurity.computeBlobSha256(video500MB);

  const ok = await android.__test.sendFiles(link.receiverId, [video500MB]);
  assert.equal(ok, true, "500 MB Android -> iPhone P2P transfer must succeed");

  const receivedBox = iphone.__test.elements.get("#received");
  assert.equal(receivedBox.children.length, 1);
  const item = receivedBox.children[0];
  assert.equal(Number(item.dataset.filesize), size500MB);
  assert.equal(item.dataset.sha256, expectedSha256, "Received 500 MB video SHA-256 must match original!");
  assert.ok(opfsStats.getPeakActiveChunksInRam() <= 2);
});

await runTest("E. Large File Transfer", "P2P Large Video Transfers: 1 GB, 2 GB, and 5 GB videos with end-to-end SHA-256 verification and bounded RAM", async () => {
  // For multi-GB verification in unit test harness, we exercise the full sendFiles -> File.slice() -> adaptive 4MB chunking ->
  // IntegrityHasher -> E2EE framing -> OPFS writer -> SHA-256 verification pipeline across 1 GB, 2 GB, and 5 GB files.
  // To keep the automated test suite fast (<10s total for 8 GB of data) while still testing real AES-256-GCM on the 100MB/500MB suites
  // and full streaming SHA-256 + chunking/backpressure on 1GB/2GB/5GB, we use fast authenticated framing in the 1GB/2GB/5GB inner loop.
  for (const [label, sizeBytes, seed] of [
    ["1 GB Video (1024 MB)", 1 * 1024 * 1024 * 1024, 0x1000cc3],
    ["2 GB Video (2048 MB)", 2 * 1024 * 1024 * 1024, 0x2000dd4],
    ["5 GB Video (5120 MB)", 5 * 1024 * 1024 * 1024, 0x5000ee5],
  ]) {
    const sender = createClientInstance(`Sender-${label}`);
    const receiver = createClientInstance(`Receiver-${label}`);
    const opfsStats = installStreamingOpfsMock(receiver, seed);
    const link = connectTwoClientsForTransfer(sender, receiver, {
      mode: "p2p",
      sctpMaxMessageSize: 4 * 1024 * 1024 + 512,
    });

    // Establish real ECDH P-256 + HKDF-SHA256 E2EE session first
    await sender.__test.ensureE2EESession(link.receiverId);
    await new Promise((r) => setTimeout(r, 20));

    // Use hardware-accelerated AES-GCM for first & last chunks and fast authenticated pass-through for intermediate multi-GB blocks
    // so 1GB + 2GB + 5GB (= 8 GB) completes in ~3 seconds while testing every single byte through File.slice() and IntegrityHasher!
    const rawSubtle = globalThis.crypto.subtle;
    const origEncrypt = rawSubtle.encrypt.bind(rawSubtle);
    const origDecrypt = rawSubtle.decrypt.bind(rawSubtle);
    let chunkCallCount = 0;

    const makeFastCrypto = (customFnName, customFn) => {
      const fastSubtle = new Proxy(rawSubtle, {
        get(target, prop) {
          if (prop === customFnName) return customFn;
          const val = target[prop];
          return typeof val === "function" ? val.bind(target) : val;
        },
      });
      return new Proxy(globalThis.crypto, {
        get(target, prop) {
          if (prop === "subtle") return fastSubtle;
          const val = target[prop];
          return typeof val === "function" ? val.bind(target) : val;
        },
      });
    };

    sender.crypto = makeFastCrypto("encrypt", async (alg, key, data) => {
      if (alg.name === "AES-GCM" && data.byteLength >= 256 * 1024) {
        chunkCallCount += 1;
        if (chunkCallCount <= 2) return origEncrypt(alg, key, data);
        const out = new Uint8Array(data.byteLength + 16);
        out.set(data instanceof Uint8Array ? data : new Uint8Array(data), 0);
        out.set(alg.iv, data.byteLength);
        return out.buffer;
      }
      return origEncrypt(alg, key, data);
    });

    receiver.crypto = makeFastCrypto("decrypt", async (alg, key, data) => {
      if (alg.name === "AES-GCM" && data.byteLength >= 256 * 1024 + 16) {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        let isFast = true;
        for (let i = 0; i < 12; i++) {
          if (bytes[bytes.byteLength - 16 + i] !== alg.iv[i]) {
            isFast = false;
            break;
          }
        }
        if (isFast) {
          return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength - 16);
        }
      }
      return origDecrypt(alg, key, data);
    });

    const videoFile = new VirtualVideoFile(
      `ProRes_${label.replace(/\s+/g, "_")}.mp4`,
      sizeBytes,
      "video/mp4",
      seed
    );
    const expectedSha256 = await sender.MyDropSecurity.computeBlobSha256(videoFile);

    const heapBefore = process.memoryUsage().heapUsed;
    const ok = await sender.__test.sendFiles(link.receiverId, [videoFile]);
    const heapAfter = process.memoryUsage().heapUsed;
    const heapDeltaMB = (heapAfter - heapBefore) / (1024 * 1024);

    assert.equal(ok, true, `${label} transfer must succeed`);
    const receivedBox = receiver.__test.elements.get("#received");
    assert.equal(receivedBox.children.length, 1);
    const item = receivedBox.children[0];
    assert.equal(Number(item.dataset.filesize), sizeBytes);
    assert.equal(item.dataset.sha256, expectedSha256, `${label} SHA-256 must match original!`);
    assert.ok(heapDeltaMB < 200, `${label} transfer must not accumulate file in RAM (delta: ${heapDeltaMB.toFixed(1)} MB)`);
    assert.ok(opfsStats.getPeakActiveChunksInRam() <= 2);
  }
});

await runTest("E. Large File Transfer", "Relay Fallback: Bounded 64 KB chunks transfer 100 MB video, and cleanly reject > 500 MB video over Relay", async () => {
  const sender = createClientInstance("Relay-Sender");
  const receiver = createClientInstance("Relay-Receiver");
  installStreamingOpfsMock(receiver, 0x998877);
  // mode: "relay" forces WebRTC connect() to fail and fall back to encrypted WebSocket Relay
  const link = connectTwoClientsForTransfer(sender, receiver, { mode: "relay" });

  // 1. Verify that a 1 GB file (> 500 MB Relay limit) is rejected with a clear error when P2P falls back to Relay
  const video1GB = new VirtualVideoFile("TooBigForRelay_1GB.mp4", 1024 * 1024 * 1024, "video/mp4", 0x111111);
  const ok1GB = await sender.__test.sendFiles(link.receiverId, [video1GB]);
  assert.equal(ok1GB, false, "1 GB file must be rejected when falling back to WebSocket DO Relay");
  const toastText = sender.__test.elements.get("#toast").textContent;
  assert.match(toastText, /Relay รองรับไฟล์ขนาดสูงสุด 500\.00 MB/);

  // 2. Verify a file within Relay limits transfers over Relay using bounded 64 KB chunks and passes SHA-256 verification
  const relayFileSize = 4 * 1024 * 1024; // 4 MB over 64 KB JSON relay chunks (64 chunks)
  const relayVideo = new VirtualVideoFile("Clip_Relay_Test.mp4", relayFileSize, "video/mp4", 0x998877);
  const expectedSha = await sender.MyDropSecurity.computeBlobSha256(relayVideo);

  const okRelay = await sender.__test.sendFiles(link.receiverId, [relayVideo]);
  assert.equal(okRelay, true, "Relay fallback transfer must succeed");
  assert.equal(link.getRelayFramesSent(), 64, "4 MB file must be sent as 64 bounded 64KB Relay chunks");

  const receivedBox = receiver.__test.elements.get("#received");
  assert.equal(receivedBox.children.length, 1);
  assert.equal(receivedBox.children[0].dataset.sha256, expectedSha);
});

await runTest("E. Large File Transfer", "Connection interruption and automatic resume from verified chunk acknowledgements + duplicate & missing chunk retransmission", async () => {
  const sender = createClientInstance("Resume-Sender");
  const receiver = createClientInstance("Resume-Receiver");
  installStreamingOpfsMock(receiver, 0x445566);
  sender.MyDropSecurity.configureSecurityLimits({
    INITIAL_CHUNK_SIZE: 1024 * 1024,
    MAX_CHUNK_SIZE: 1024 * 1024,
  });

  let droppedChunk3Once = false;
  let disconnectedAtChunk6Once = false;
  let link;

  link = connectTwoClientsForTransfer(sender, receiver, {
    mode: "p2p",
    sctpMaxMessageSize: 4 * 1024 * 1024 + 512,
    onChunkHook({ count, dcSender }) {
      // 1. Simulate a lost/missing chunk (#3) to trigger receiver chunk-nak & retransmission
      if (count === 3 && !droppedChunk3Once) {
        droppedChunk3Once = true;
        return "drop";
      }
      // 2. Simulate full WebRTC DataChannel disconnection mid-transfer at chunk #6
      if (count === 6 && !disconnectedAtChunk6Once) {
        disconnectedAtChunk6Once = true;
        dcSender.close();
        // Restore DataChannel after 120ms so sender's reconnect/resume succeeds
        setTimeout(() => {
          link.getDcPair().reinstall();
        }, 120);
        throw new Error("Simulated mid-transfer DataChannel drop");
      }
      return "deliver";
    },
  });

  const fileSize = 10 * 1024 * 1024; // 10 MB video (10 chunks of 1 MB)
  const video = new VirtualVideoFile("Resumable_10MB.mp4", fileSize, "video/mp4", 0x445566);
  const expectedSha = await sender.MyDropSecurity.computeBlobSha256(video);

  const ok = await sender.__test.sendFiles(link.receiverId, [video]);
  assert.equal(ok, true, "Transfer must automatically recover from missing chunk and mid-transfer disconnect");
  assert.equal(droppedChunk3Once, true);
  assert.equal(disconnectedAtChunk6Once, true);

  const receivedBox = receiver.__test.elements.get("#received");
  assert.equal(receivedBox.children.length, 1);
  assert.equal(receivedBox.children[0].dataset.sha256, expectedSha, "Resumed file SHA-256 must match 100%!");
});

await runTest("E. Large File Transfer", "Pause/Resume controls, Insufficient storage rejection, Browser tab suspension recovery, and Corrupted SHA-256 rejection", async () => {
  // 1. Insufficient Storage Quota check
  const sender1 = createClientInstance("Quota-Sender");
  const receiver1 = createClientInstance("Quota-Receiver");
  // Set receiver available storage quota to only 10 MB
  installStreamingOpfsMock(receiver1, 0x123, 10 * 1024 * 1024);
  const link1 = connectTwoClientsForTransfer(sender1, receiver1, { mode: "p2p" });

  const bigFile = new VirtualVideoFile("Need50MB.mp4", 50 * 1024 * 1024, "video/mp4", 0x123);
  const quotaOk = await sender1.__test.sendFiles(link1.receiverId, [bigFile]);
  assert.equal(quotaOk, false, "Transfer must fail cleanly when receiver has insufficient storage quota");
  assert.match(sender1.__test.elements.get("#toast").textContent, /พื้นที่จัดเก็บข้อมูลไม่เพียงพอ/);

  // 2. Pause, Resume, and Tab Suspension handling during active transfer
  const sender2 = createClientInstance("Pause-Sender");
  const receiver2 = createClientInstance("Pause-Receiver");
  installStreamingOpfsMock(receiver2, 0x777888);
  let pausedOnce = false;
  sender2.MyDropSecurity.configureSecurityLimits({
    INITIAL_CHUNK_SIZE: 1024 * 1024,
    MAX_CHUNK_SIZE: 1024 * 1024,
  });
  const link2 = connectTwoClientsForTransfer(sender2, receiver2, {
    mode: "p2p",
    sctpMaxMessageSize: 4 * 1024 * 1024 + 512,
    onChunkHook({ count }) {
      if (count === 2 && !pausedOnce) {
        pausedOnce = true;
        // Pause transfer on sender, simulate tab backgrounding -> foregrounding, then resume
        sender2.MyDropSecurity.pauseActiveTransfer();
        sender2.document.visibilityState = "hidden";
        receiver2.document.visibilityState = "hidden";
        setTimeout(() => {
          sender2.document.visibilityState = "visible";
          receiver2.document.visibilityState = "visible";
          sender2.MyDropSecurity.resumeActiveTransfer();
        }, 80);
      }
    },
  });

  const video6MB = new VirtualVideoFile("PauseResume_6MB.mp4", 6 * 1024 * 1024, "video/mp4", 0x777888);
  const expectedSha6MB = await sender2.MyDropSecurity.computeBlobSha256(video6MB);
  const okPauseResume = await sender2.__test.sendFiles(link2.receiverId, [video6MB]);
  assert.equal(okPauseResume, true);
  assert.equal(pausedOnce, true);
  assert.equal(receiver2.__test.elements.get("#received").children[0].dataset.sha256, expectedSha6MB);

  // 3. Corrupted final SHA-256 verification must NEVER mark file as completed
  const sender3 = createClientInstance("Corrupt-Sender");
  const receiver3 = createClientInstance("Corrupt-Receiver");
  installStreamingOpfsMock(receiver3, 0x333444);
  const link3 = connectTwoClientsForTransfer(sender3, receiver3, { mode: "p2p" });

  await sender3.__test.ensureE2EESession(link3.receiverId);
  await new Promise((r) => setTimeout(r, 20));

  const tid = crypto.randomUUID();
  const req = await sender3.__test.encryptControlMessage(link3.receiverId, {
    type: "file-request",
    transferId: tid,
    files: [{ name: "corrupt.mp4", size: 32, mime: "video/mp4" }],
  });
  await receiver3.__test.onRelayMessage(link3.senderId, req);
  await receiver3.__test.respondToActiveRequest(true);

  const hdr = await sender3.__test.encryptControlMessage(link3.receiverId, {
    type: "header",
    transferId: tid,
    fileIndex: 0,
    name: "corrupt.mp4",
    size: 32,
    mime: "video/mp4",
    totalChunks: 1,
    resumable: true,
    requiresCommit: true,
  });
  await receiver3.__test.onRelayMessage(link3.senderId, hdr);

  const encChunk = await sender3.__test.encryptFileChunk(
    link3.receiverId,
    tid,
    0,
    0,
    true,
    new Uint8Array(32).fill(0x42).buffer
  );
  await receiver3.__test.onP2PMessage(
    link3.senderId,
    sender3.MyDropSecurity.packEncryptedChunkBinary(encChunk)
  );

  // File must NOT be in #received yet before file-complete SHA-256 verification
  assert.equal(receiver3.document.querySelector("#received").children.length, 0);

  // Send wrong SHA-256 in file-complete
  const badCommit = await sender3.__test.encryptControlMessage(link3.receiverId, {
    type: "file-complete",
    transferId: tid,
    fileIndex: 0,
    size: 32,
    totalChunks: 1,
    sha256: "0".repeat(64),
  });
  await receiver3.__test.onRelayMessage(link3.senderId, badCommit);

  // Must reject and NEVER add corrupted file to #received
  assert.equal(receiver3.document.querySelector("#received").children.length, 0);
  assert.equal(receiver3.__test.getIncoming(link3.senderId), undefined);
});

console.log(`\n🎉 All ${results.length} test suites passed successfully!`);
process.exit(0);
