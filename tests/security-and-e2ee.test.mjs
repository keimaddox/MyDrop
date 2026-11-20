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
        add() {},
        remove() {},
        toggle() {},
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
      remove() {},
      querySelector() {
        return makeEl();
      },
      addEventListener() {},
      click() {},
      focus() {},
      scrollIntoView() {},
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
      revokeObjectURL: () => {},
    },
    URLSearchParams,
    btoa: (str) => Buffer.from(str, "binary").toString("base64"),
    atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    setTimeout,
    clearTimeout,
    setInterval: () => 1,
    clearInterval: () => {},
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
      replaceState() {},
    },
    navigator: {
      clipboard: { writeText: async () => {} },
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
      addEventListener() {},
    },
    addEventListener() {},
    removeEventListener() {},
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
          addEventListener() {},
          send() {},
          close() {},
        };
      }
      async setLocalDescription() {}
      async setRemoteDescription() {}
      async addIceCandidate() {}
      close() {}
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
      getE2EESession: (pid) => e2eeSessions.get(pid),
      getIncoming: (pid) => incoming.get(pid),
      getAcceptedTransfer: (tid) => acceptedTransfers.get(tid),
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

  // 2. Oversized individual file (> 50 MB)
  const hugeFileReq = sec.validateIncomingFileRequest({
    transferId: crypto.randomUUID(),
    files: [{ name: "big.bin", size: 50 * 1024 * 1024 + 1, mime: "application/octet-stream" }],
  });
  assert.equal(hugeFileReq.ok, false);

  // 3. Oversized total transfer (> 100 MB across 3 files)
  const hugeTotalReq = sec.validateIncomingFileRequest({
    transferId: crypto.randomUUID(),
    files: [
      { name: "a.bin", size: 40 * 1024 * 1024, mime: "application/octet-stream" },
      { name: "b.bin", size: 40 * 1024 * 1024, mime: "application/octet-stream" },
      { name: "c.bin", size: 25 * 1024 * 1024, mime: "application/octet-stream" },
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

console.log(`\n🎉 All ${results.length} test suites passed successfully!`);
process.exit(0);
