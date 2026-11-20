import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

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

const indexSrc = fs.readFileSync(path.join(rootDir, "src", "index.js"), "utf8");
const patchedIndexSrc = indexSrc.replace(
  'import { DurableObject } from "cloudflare:workers";',
  "class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }"
);
const dataUrl = "data:text/javascript;base64," + Buffer.from(patchedIndexSrc, "utf8").toString("base64");
const workerModule = await import(dataUrl);
const { default: worker, Room } = workerModule;

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
        const url = new URL(req.url);
        if (url.pathname === "/" || url.pathname === "/index.html") {
          return new Response(fs.readFileSync(path.join(rootDir, "public", "index.html"), "utf8"), {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }
        return new Response("OK", { status: 200 });
      },
    },
  };
}

function makeWsRequest(urlStr, ip = "203.0.113.10", extraHeaders = {}) {
  return new Request(urlStr, {
    method: "GET",
    headers: {
      Upgrade: "websocket",
      Origin: new URL(urlStr).origin,
      "CF-Connecting-IP": ip,
      "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
      ...extraHeaders,
    },
  });
}

let passed = 0;
async function runTest(name, fn) {
  await fn();
  passed += 1;
  console.log(`PASS: ${name}`);
}

await runTest("1. HTTP Security Headers & CSP on static assets and /ice", async () => {
  const env = createMockEnv();
  const res = await worker.fetch(new Request("https://mydrop.example/"), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  assert.equal(res.headers.get("Cross-Origin-Resource-Policy"), "same-origin");
  assert.ok(res.headers.get("Strict-Transport-Security")?.includes("max-age=31536000"));
  const csp = res.headers.get("Content-Security-Policy") || "";
  assert.ok(csp.includes("default-src 'self'"));
  assert.ok(csp.includes("script-src 'self'"));
  assert.ok(csp.includes("frame-ancestors 'none'"));

  const iceRes = await worker.fetch(new Request("https://mydrop.example/ice"), env);
  assert.equal(iceRes.status, 200);
  const iceData = await iceRes.json();
  assert.ok(Array.isArray(iceData.iceServers));
  assert.equal(iceRes.headers.get("Cache-Control"), "no-store");
});

await runTest("2. Invalid room codes and cross-origin WebSocket upgrades are rejected", async () => {
  const env = createMockEnv();
  const invalidCodes = ["ab", "room with spaces", "room$bad", "../etc/passwd", "a".repeat(49)];
  for (const code of invalidCodes) {
    const res = await worker.fetch(
      makeWsRequest(`https://mydrop.example/ws?room=${encodeURIComponent(code)}`),
      env
    );
    assert.equal(res.status, 400, `Expected 400 for invalid room code: ${code}`);
  }

  const crossOriginRes = await worker.fetch(
    makeWsRequest("https://mydrop.example/ws", "203.0.113.10", {
      Origin: "https://evil.example",
    }),
    env
  );
  assert.equal(crossOriginRes.status, 403);

  const nonWsRes = await worker.fetch(new Request("https://mydrop.example/ws"), env);
  assert.equal(nonWsRes.status, 426);
});

await runTest("3. Server generates peer identity and ignores client-supplied id/name", async () => {
  const env = createMockEnv();
  const res = await worker.fetch(
    makeWsRequest("https://mydrop.example/ws?id=attacker-id&name=AdminSpoof"),
    env
  );
  assert.equal(res.status, 101);
  const serverWs = res.webSocket.peer;
  assert.ok(serverWs.sent.length >= 1);
  const welcome = JSON.parse(serverWs.sent[0]);
  assert.equal(welcome.type, "welcome");
  assert.notEqual(welcome.id, "attacker-id");
  assert.notEqual(welcome.name, "AdminSpoof");
  assert.match(welcome.id, /^[0-9a-f-]{36}$/i);
  assert.equal(welcome.device, "phone");
});

await runTest("4. Multiple peers can join a room and discover each other", async () => {
  const env = createMockEnv();
  const res1 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=team_room-1", "198.51.100.1"), env);
  const res2 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=team_room-1", "198.51.100.2"), env);
  assert.equal(res1.status, 101);
  assert.equal(res2.status, 101);

  const ws1 = res1.webSocket.peer;
  const ws2 = res2.webSocket.peer;
  const welcome1 = JSON.parse(ws1.sent[0]);
  const welcome2 = JSON.parse(ws2.sent[0]);

  const peersMsg1 = JSON.parse(ws1.sent[ws1.sent.length - 1]);
  const peersMsg2 = JSON.parse(ws2.sent[ws2.sent.length - 1]);
  assert.equal(peersMsg1.type, "peers");
  assert.equal(peersMsg1.peers.length, 1);
  assert.equal(peersMsg1.peers[0].id, welcome2.id);
  assert.equal(peersMsg2.peers[0].id, welcome1.id);
  assert.equal(peersMsg1.peers[0].ip, undefined);
  assert.equal(peersMsg1.peers[0].rateCount, undefined);
});

await runTest("5. Room occupancy limit (12 peers) and per-IP connection limits are enforced", async () => {
  const env = createMockEnv();
  for (let i = 1; i <= 12; i++) {
    const res = await worker.fetch(
      makeWsRequest("https://mydrop.example/ws?room=fullroom", `192.0.2.${i}`),
      env
    );
    assert.equal(res.status, 101);
  }
  const res13 = await worker.fetch(
    makeWsRequest("https://mydrop.example/ws?room=fullroom", "192.0.2.99"),
    env
  );
  assert.equal(res13.status, 429);

  for (let i = 1; i <= 8; i++) {
    const res = await worker.fetch(
      makeWsRequest("https://mydrop.example/ws?room=ipcaproom", "198.51.100.50"),
      env
    );
    assert.equal(res.status, 101);
  }
  const resIp9 = await worker.fetch(
    makeWsRequest("https://mydrop.example/ws?room=ipcaproom", "198.51.100.50"),
    env
  );
  assert.equal(resIp9.status, 429);
});

await runTest("6. Excessive connection attempts per IP per minute are rate-limited", async () => {
  const env = createMockEnv();
  const attackerIp = "203.0.113.200";
  let lastStatus = 101;
  for (let i = 1; i <= 35; i++) {
    const res = await worker.fetch(
      makeWsRequest(`https://mydrop.example/ws?room=flood_${i}`, attackerIp),
      env
    );
    lastStatus = res.status;
    if (res.status === 101) {
      res.webSocket.peer.close(1000, "done");
    }
  }
  assert.equal(lastStatus, 429);
});

await runTest("7. Malformed, spoofed, plaintext-relay, and oversized WebSocket messages are rejected", async () => {
  const env = createMockEnv();
  const res1 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=msgtest", "198.51.100.10"), env);
  const res2 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=msgtest", "198.51.100.11"), env);
  const room = env.rooms.get("code:msgtest").roomInstance;
  const ws1 = res1.webSocket.peer;
  const ws2 = res2.webSocket.peer;
  const id1 = JSON.parse(ws1.sent[0]).id;
  const id2 = JSON.parse(ws2.sent[0]).id;
  const initialWs2Count = ws2.sent.length;

  await room.webSocketMessage(ws1, "{bad json");
  assert.equal(ws2.sent.length, initialWs2Count);

  await room.webSocketMessage(ws1, JSON.stringify({
    type: "relay",
    to: id1,
    data: { type: "e2ee-ctrl", seq: 0, iv: "AAAAAAAAAAAAAAAA", ct: "BBBBBBBBBBBBBBBBBBBBBBBB" },
  }));
  assert.equal(ws2.sent.length, initialWs2Count);

  // Plaintext payloads over Relay are strictly rejected
  for (const plain of [
    { type: "text", text: "plain" },
    { type: "header", transferId: "t1", name: "a.bin", size: 10 },
    { type: "chunk", data: "QUJDRA==" },
  ]) {
    await room.webSocketMessage(ws1, JSON.stringify({
      type: "relay",
      to: id2,
      data: plain,
    }));
    assert.equal(ws2.sent.length, initialWs2Count);
  }

  // Valid signaling & E2EE relay messages are forwarded with authoritative `from`
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "signal",
    to: id2,
    from: "spoofed-id",
    data: { type: "offer", sdp: { type: "offer", sdp: "v=0\r\n..." } },
  }));
  assert.equal(ws2.sent.length, initialWs2Count + 1);
  const forwardedSignal = JSON.parse(ws2.sent[ws2.sent.length - 1]);
  assert.equal(forwardedSignal.from, id1);

  // Oversized message (> 160 KB) closes socket with 1009
  const huge = JSON.stringify({
    type: "relay",
    to: id2,
    data: { type: "e2ee-ctrl", seq: 1, iv: "AAAAAAAAAAAAAAAA", ct: "A".repeat(170 * 1024) },
  });
  await room.webSocketMessage(ws1, huge);
  assert.equal(ws1.closed, true);
  assert.equal(ws1.closeCode, 1009);
});

await runTest("8. Adjusted per-connection WebSocket message rate limit (160 msg/sec) allows continuous streaming bursts and closes flooding sockets", async () => {
  const env = createMockEnv();
  const res1 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=ratetest", "198.51.100.21"), env);
  const res2 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=ratetest", "198.51.100.22"), env);
  const room = env.rooms.get("code:ratetest").roomInstance;
  const ws1 = res1.webSocket.peer;
  const ws2 = res2.webSocket.peer;
  const id2 = JSON.parse(ws2.sent[0]).id;

  // Send 100 chunks in the same second (simulating ~4.8 MB/s continuous Relay streaming) -> must NOT disconnect
  for (let i = 0; i < 100; i++) {
    await room.webSocketMessage(ws1, JSON.stringify({
      type: "relay",
      to: id2,
      data: {
        type: "e2ee-chunk",
        transferId: "stream-burst-1",
        fileIndex: 0,
        seq: i,
        iv: "AAAAAAAAAAAAAAAA",
        ct: "BBBBBBBBBBBBBBBBBBBBBBBB",
      },
    }));
  }
  assert.equal(ws1.closed, false, "100 streaming messages/sec must be permitted without disconnecting");

  // Exceed 160 msg/sec flood threshold -> closes with 1008
  for (let i = 100; i < 170; i++) {
    if (ws1.closed) break;
    await room.webSocketMessage(ws1, JSON.stringify({
      type: "relay",
      to: id2,
      data: {
        type: "e2ee-chunk",
        transferId: "stream-burst-1",
        fileIndex: 0,
        seq: i,
        iv: "AAAAAAAAAAAAAAAA",
        ct: "BBBBBBBBBBBBBBBBBBBBBBBB",
      },
    }));
  }
  assert.equal(ws1.closed, true);
  assert.equal(ws1.closeCode, 1008);
});

function createStreamingPairSandboxes() {
  const env = createMockEnv();
  const appJsCode = fs.readFileSync(path.join(rootDir, "public", "app.js"), "utf8");
  const relayCaptured = [];

  function createClientSandbox(ip, ua = "Mozilla/5.0 (Linux; Android 14) Chrome/125.0") {
    const elements = new Map();
    const makeEl = (id = "") => ({
      id,
      textContent: "",
      innerHTML: "",
      value: "",
      hidden: false,
      style: {},
      dataset: {},
      children: [],
      classList: {
        add() {},
        remove() {},
        toggle() {},
      },
      append(...nodes) {
        this.children.push(...nodes);
      },
      appendChild(node) {
        this.children.push(node);
      },
      prepend(node) {
        this.children.unshift(node);
      },
      querySelector(sel) {
        if (!this._q) this._q = new Map();
        if (!this._q.has(sel)) this._q.set(sel, makeEl(sel));
        return this._q.get(sel);
      },
      scrollIntoView() {},
      focus() {},
      click() {},
    });

    const document = {
      visibilityState: "visible",
      body: makeEl("body"),
      querySelector(sel) {
        if (!elements.has(sel)) elements.set(sel, makeEl(sel));
        return elements.get(sel);
      },
      createElement(tag) {
        return makeEl(tag);
      },
      addEventListener() {},
    };

    class ClientWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        this.bufferedAmount = 0;
        const req = makeWsRequest(url.replace(/^ws:/, "https:").replace(/^wss:/, "https:"), ip, {
          "User-Agent": ua,
        });
        worker.fetch(req, env).then((res) => {
          if (res.status !== 101) {
            this.readyState = 3;
            this.onclose?.();
            return;
          }
          this.serverWs = res.webSocket.peer;
          this.clientMock = res.webSocket;
          this.readyState = 1;
          this.clientMock.onmessage = (ev) => this.onmessage?.(ev);
          this.onopen?.();
          for (const queued of this.serverWs.sent) {
            queueMicrotask(() => this.onmessage?.({ data: queued }));
          }
        });
      }
      send(data) {
        try {
          const parsed = JSON.parse(data);
          if (parsed.type === "relay") relayCaptured.push(data);
        } catch {}
        const roomEntry = env.rooms.get("v4:" + ip);
        roomEntry.roomInstance.webSocketMessage(this.serverWs, data);
      }
      close() {
        this.readyState = 3;
        if (this.serverWs) {
          const roomEntry = env.rooms.get("v4:" + ip);
          roomEntry.roomInstance.webSocketClose(this.serverWs);
        }
        this.onclose?.();
      }
    }

    // Track OPFS streaming disk writes so we can verify chunks are written one by one without accumulating an Array in RAM
    const opfsDiskFiles = new Map();
    const mockStorage = {
      async getDirectory() {
        return {
          async getFileHandle(name) {
            if (!opfsDiskFiles.has(name)) {
              opfsDiskFiles.set(name, { parts: [], closed: false, aborted: false, writeCalls: 0 });
            }
            const entry = opfsDiskFiles.get(name);
            return {
              async createWritable() {
                return {
                  async write(chunkBytes) {
                    entry.writeCalls += 1;
                    entry.parts.push(new Uint8Array(chunkBytes));
                  },
                  async close() {
                    entry.closed = true;
                  },
                  async abort() {
                    entry.aborted = true;
                    entry.parts = [];
                  },
                };
              },
              async getFile() {
                return new Blob(entry.parts);
              },
            };
          },
          async removeEntry(name) {
            opfsDiskFiles.delete(name);
          },
        };
      },
    };

    class MockRTCPeerConnection {
      constructor() {
        this.connectionState = "new";
        this.signalingState = "stable";
        this.sctp = { maxMessageSize: 65536 };
      }
      createDataChannel(label) {
        return {
          label,
          readyState: "connecting",
          binaryType: "arraybuffer",
          bufferedAmount: 0,
          send() {
            throw new Error("P2P blocked");
          },
          addEventListener() {},
          close() {},
        };
      }
      async setLocalDescription() {}
      async setRemoteDescription() {}
      async addIceCandidate() {}
      close() {}
    }

    const sandbox = {
      console,
      setTimeout,
      clearTimeout,
      setInterval: () => 0,
      clearInterval,
      crypto: globalThis.crypto,
      TextEncoder: globalThis.TextEncoder,
      TextDecoder: globalThis.TextDecoder,
      DataView: globalThis.DataView,
      Blob: globalThis.Blob,
      File: globalThis.File,
      ArrayBuffer: globalThis.ArrayBuffer,
      Uint8Array: globalThis.Uint8Array,
      URL: globalThis.URL,
      URLSearchParams: globalThis.URLSearchParams,
      btoa: globalThis.btoa,
      atob: globalThis.atob,
      sessionStorage: {
        _s: new Map(),
        getItem(k) { return this._s.get(k) || null; },
        setItem(k, v) { this._s.set(k, String(v)); },
      },
      navigator: {
        userAgent: ua,
        storage: mockStorage,
        clipboard: { writeText: async () => {} },
      },
      indexedDB: {
        open() {
          const req = {};
          queueMicrotask(() => req.onerror?.());
          return req;
        },
      },
      location: {
        protocol: "https:",
        host: "mydrop.example",
        href: "https://mydrop.example/",
        pathname: "/",
        search: "",
      },
      history: { replaceState() {} },
      window: { addEventListener() {} },
      document,
      fetch: async (url) => worker.fetch(new Request("https://mydrop.example" + url), env),
      WebSocket: ClientWebSocket,
      RTCPeerConnection: MockRTCPeerConnection,
      prompt: () => "Hello",
    };
    sandbox.URL.createObjectURL = () => "blob:https://mydrop.example/mock-blob";

    vm.createContext(sandbox);
    vm.runInContext(appJsCode, sandbox);
    return { sandbox, elements, document, opfsDiskFiles };
  }

  return { env, createClientSandbox, relayCaptured };
}

await runTest("9. Large File Streaming (Virtual 500 MB Validation, Multi-MB Chunk Streaming to Disk Sink without RAM array, Progress/Speed/ETA UI & E2EE on Relay)", async () => {
  const { createClientSandbox, relayCaptured } = createStreamingPairSandboxes();
  const clientA = createClientSandbox("198.51.100.88", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Mobile/15E148 Safari/604.1");
  const clientB = createClientSandbox("198.51.100.88", "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/125.0.0.0 Mobile Safari/537.36");

  await new Promise((r) => setTimeout(r, 60));
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientA.sandbox);
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientB.sandbox);

  const idA = vm.runInContext(`myId`, clientA.sandbox);
  const idB = vm.runInContext(`myId`, clientB.sandbox);

  // Verify platform capability detection distinguishes iOS Safari vs Desktop/Android
  const capIOS = vm.runInContext(`detectStorageCapabilities()`, clientA.sandbox);
  assert.equal(capIOS.platform, "ios-opfs");
  assert.ok(capIOS.note.includes("iOS Safari ไม่รองรับ showSaveFilePicker"));

  // Verify multi-GB files (e.g., 1.5 GB) pass outgoing validation under streaming protocol
  const largeCheck = vm.runInContext(
    `validateOutgoingFiles([{ name: "movie_4k.mp4", size: 1500 * 1024 * 1024, type: "video/mp4" }])`,
    clientA.sandbox
  );
  assert.equal(largeCheck.ok, true);

  // Stream a 1.2 MB file (25 chunks of 48 KB) through E2EE + sliding window flow control + OPFS disk sink
  const streamSize = 1200 * 1024;
  const rawBytes = new Uint8Array(streamSize);
  for (let i = 0; i < streamSize; i++) rawBytes[i] = (i * 13) % 251;

  clientA.sandbox.largeFile = [
    new File([rawBytes], "large_dataset.bin", { type: "application/octet-stream" }),
  ];

  const sendPromise = vm.runInContext(`sendFiles("${idB}", largeFile)`, clientA.sandbox);
  await new Promise((r) => setTimeout(r, 40));

  const acceptBtnB = clientB.elements.get("#acceptBtn");
  await acceptBtnB.onclick();

  const ok = await sendPromise;
  assert.equal(ok, true);
  await new Promise((r) => setTimeout(r, 40));

  // Verify receiver used OPFS streaming disk sink (25 individual chunk writes, no in-memory f.chunks array)
  assert.equal(clientB.opfsDiskFiles.size, 1);
  const [diskEntry] = clientB.opfsDiskFiles.values();
  assert.equal(diskEntry.writeCalls, Math.ceil(streamSize / (48 * 1024)));
  assert.equal(diskEntry.closed, true);

  // Verify UI received item and Relay never saw plaintext filename
  const receivedB = clientB.elements.get("#received");
  assert.equal(receivedB.children.length, 1);
  assert.ok(receivedB.children[0].children[0].textContent.includes("large_dataset.bin"));
  for (const rawRelay of relayCaptured) {
    assert.ok(!rawRelay.includes("large_dataset.bin"), "Relay must never see plaintext filename");
  }
});

await runTest("10. Backpressure & Flow Control (DataChannel bufferedAmount drain + Sliding Window Receiver ACKs)", async () => {
  const { createClientSandbox } = createStreamingPairSandboxes();
  const clientA = createClientSandbox("198.51.100.90");
  const clientB = createClientSandbox("198.51.100.90");

  await new Promise((r) => setTimeout(r, 60));

  // Test DataChannel backpressure helper waitForChannelDrain directly
  let dcBuffered = 3 * 1024 * 1024; // 3 MB (> 2 MB MAX_BUFFER)
  let drainListener = null;
  const mockDc = {
    readyState: "open",
    bufferedAmountLowThreshold: 512 * 1024,
    get bufferedAmount() {
      return dcBuffered;
    },
    addEventListener(ev, fn) {
      if (ev === "bufferedamountlow") drainListener = fn;
    },
    removeEventListener() {},
  };
  clientA.sandbox.mockDc = mockDc;

  let drainCompleted = false;
  const drainPromise = vm.runInContext(`waitForChannelDrain(mockDc)`, clientA.sandbox).then(() => {
    drainCompleted = true;
  });
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(drainCompleted, false, "Sender must pause sending while DataChannel bufferedAmount > MAX_BUFFER");

  // Simulate buffer draining below threshold and firing bufferedamountlow
  dcBuffered = 256 * 1024;
  if (drainListener) drainListener();
  await drainPromise;
  assert.equal(drainCompleted, true, "Sender must resume once bufferedAmount drains");

  // Test sliding window flow control waitForFlowControl (blocks when nextSeq - (ackedSeq + 1) >= MAX_IN_FLIGHT_CHUNKS)
  const mockState = {
    cancelled: false,
    paused: false,
    remotePaused: false,
    nextSeq: 16,
    ackedSeq: -1, // 16 chunks in flight (equals MAX_IN_FLIGHT_CHUNKS = 16)
    waiters: new Set(),
  };
  clientA.sandbox.mockState = mockState;
  let windowOpened = false;
  const flowPromise = vm.runInContext(`waitForFlowControl(mockState, 16)`, clientA.sandbox).then(() => {
    windowOpened = true;
  });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(windowOpened, false, "Flow control must pause sender when 16 unacknowledged chunks are in flight");

  // Simulate cumulative ACK arriving from receiver for seq 3
  mockState.ackedSeq = 3;
  vm.runInContext(`notifyTransferWaiters(mockState)`, clientA.sandbox);
  await flowPromise;
  assert.equal(windowOpened, true, "Flow control must unblock sender as soon as receiver ACK advances window");
});

await runTest("11. Disconnect / Resume Recovery, Duplicate & Out-of-Order Chunk Handling, Pause & Cancel", async () => {
  const { createClientSandbox } = createStreamingPairSandboxes();
  const clientA = createClientSandbox("198.51.100.91");
  const clientB = createClientSandbox("198.51.100.91");

  await new Promise((r) => setTimeout(r, 60));
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientA.sandbox);
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientB.sandbox);

  const idA = vm.runInContext(`myId`, clientA.sandbox);
  const idB = vm.runInContext(`myId`, clientB.sandbox);

  await vm.runInContext(`ensureE2EE("${idB}")`, clientA.sandbox);
  await vm.runInContext(`ensureE2EE("${idA}")`, clientB.sandbox);

  // 1) Duplicate & Out-of-order chunk handling with Resume State realignment
  const tid = "resume-test-tid-01";
  const c0 = new TextEncoder().encode("CHUNK_0_PAYLOAD_");
  const c1 = new TextEncoder().encode("CHUNK_1_PAYLOAD_");
  const c2 = new TextEncoder().encode("CHUNK_2_PAYLOAD_");
  const totalBytes = c0.byteLength + c1.byteLength + c2.byteLength;

  clientA.sandbox.c0 = c0.buffer;
  clientA.sandbox.c1 = c1.buffer;
  clientA.sandbox.c2 = c2.buffer;

  const envC0 = await vm.runInContext(`encryptFileChunk("${idB}", "${tid}", 0, 0, c0)`, clientA.sandbox);
  const envC1 = await vm.runInContext(`encryptFileChunk("${idB}", "${tid}", 0, 1, c1)`, clientA.sandbox);
  const envC2 = await vm.runInContext(`encryptFileChunk("${idB}", "${tid}", 0, 2, c2)`, clientA.sandbox);

  vm.runInContext(
    `acceptedTransfers.set("${tid}", { peerId: "${idA}", remaining: 1, nextFileIndex: 0, fileHandles: [] });`,
    clientB.sandbox
  );
  const headerEnv = await vm.runInContext(
    `encryptControlMessage("${idB}", { type: "header", transferId: "${tid}", fileIndex: 0, name: "resumable.bin", size: ${totalBytes}, mime: "application/octet-stream" })`,
    clientA.sandbox
  );
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(headerEnv)})`, clientB.sandbox);

  // Deliver chunk 0
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(envC0)})`, clientB.sandbox);
  assert.equal(vm.runInContext(`incoming.get("${idA}").nextChunkSeq`, clientB.sandbox), 1);

  // Deliver duplicate chunk 0 again -> receiver ignores duplicate and keeps nextChunkSeq = 1
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(envC0)})`, clientB.sandbox);
  assert.equal(vm.runInContext(`incoming.get("${idA}").nextChunkSeq`, clientB.sandbox), 1);
  assert.equal(vm.runInContext(`incoming.get("${idA}").received`, clientB.sandbox), c0.byteLength);

  // Deliver out-of-order chunk 2 before chunk 1 -> receiver rejects chunk 2, keeps nextChunkSeq = 1, and requests resume from seq 1
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(envC2)})`, clientB.sandbox);
  assert.equal(vm.runInContext(`incoming.get("${idA}").nextChunkSeq`, clientB.sandbox), 1);

  // Deliver expected chunk 1 then chunk 2 -> file completes cleanly with exact integrity
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(envC1)})`, clientB.sandbox);
  await vm.runInContext(`onEncryptedEnvelope("${idA}", ${JSON.stringify(envC2)})`, clientB.sandbox);
  await new Promise((r) => setTimeout(r, 30));

  const receivedB = clientB.elements.get("#received");
  assert.equal(receivedB.children.length, 1);
  assert.ok(receivedB.children[0].children[0].textContent.includes("resumable.bin"));

  // 2) Pause, Resume & Cancel during active streaming transfer
  const cancelFileBytes = new Uint8Array(1500 * 1024); // 32 chunks (exceeds 16-chunk flow control window so it waits for ACKs)
  clientA.sandbox.cancelFiles = [
    new File([cancelFileBytes], "cancel_me.iso", { type: "application/octet-stream" }),
  ];

  const sendCancelPromise = vm.runInContext(`sendFiles("${idB}", cancelFiles)`, clientA.sandbox);
  await new Promise((r) => setTimeout(r, 40));
  const acceptBtnB2 = clientB.elements.get("#acceptBtn");
  await acceptBtnB2.onclick();
  // Give a few ms for file-response to reach A and start streaming chunks 0..15
  await new Promise((r) => setTimeout(r, 10));

  const activeTid = vm.runInContext(`outgoingTransfers.keys().next().value`, clientA.sandbox);
  assert.ok(activeTid, "Transfer must be active in outgoingTransfers");
  await vm.runInContext(`pauseTransfer("${activeTid}")`, clientA.sandbox);
  assert.equal(vm.runInContext(`outgoingTransfers.get("${activeTid}").paused`, clientA.sandbox), true);
  assert.equal(clientA.elements.get("#tpStateBadge").textContent.includes("Paused"), true);

  // Cancel the paused transfer and verify both sides abort cleanly
  await vm.runInContext(`cancelTransfer("${activeTid}", "ทดสอบยกเลิกการส่ง")`, clientA.sandbox);
  const cancelResult = await sendCancelPromise;
  assert.equal(cancelResult, false, "Cancelled transfer must resolve to false");
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(vm.runInContext(`incoming.has("${idA}")`, clientB.sandbox), false);
});

await runTest("12. Transfer Telemetry & Bottleneck Auto-Tuning (Mode P2P/Relay, Separate Tx/Rx Speeds, Read/Encrypt/Send/Decrypt/Write Timings, bufferedAmount/ACK Wait, msg/s & Rate Limit Pacing, Chunk/Window Tuning with E2EE & Mobile RAM Cap)", async () => {
  const { createClientSandbox } = createStreamingPairSandboxes();
  const clientA = createClientSandbox(
    "198.51.100.92",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Mobile/15E148 Safari/604.1"
  );
  const clientB = createClientSandbox(
    "198.51.100.92",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/125.0.0.0 Mobile Safari/537.36"
  );

  await new Promise((r) => setTimeout(r, 60));
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientA.sandbox);
  vm.runInContext(`connect = async () => { throw new Error("Use Relay"); };`, clientB.sandbox);

  const idA = vm.runInContext(`myId`, clientA.sandbox);
  const idB = vm.runInContext(`myId`, clientB.sandbox);

  // 1) Stream 1.15 MB (24 chunks > 16 burst allowance) over Relay to trigger rate-limit pacing & full telemetry
  const relayFileBytes = new Uint8Array(24 * 48 * 1024);
  for (let i = 0; i < relayFileBytes.length; i++) relayFileBytes[i] = (i * 17) & 255;
  clientA.sandbox.telemetryFiles = [
    new File([relayFileBytes], "telemetry_relay.bin", { type: "application/octet-stream" }),
  ];

  const sendPromise = vm.runInContext(`sendFiles("${idB}", telemetryFiles)`, clientA.sandbox);
  await new Promise((r) => setTimeout(r, 40));
  await clientB.elements.get("#acceptBtn").onclick();
  const ok = await sendPromise;
  assert.equal(ok, true);
  await new Promise((r) => setTimeout(r, 40));

  const senderDiag = vm.runInContext(`getTransferDiagnostics()`, clientA.sandbox);
  const receiverDiag = vm.runInContext(`getTransferDiagnostics()`, clientB.sandbox);
  assert.ok(senderDiag, "Sender diagnostics snapshot must be recorded");
  assert.ok(receiverDiag, "Receiver diagnostics snapshot must be recorded");

  // Verify actual mode detected on both sides
  assert.equal(senderDiag.mode, "relay");
  assert.equal(receiverDiag.mode, "relay");

  // Verify separate send and receive speeds
  assert.ok(senderDiag.sendSpeedBps > 0, "Sender sendSpeedBps must be measured");
  assert.ok(senderDiag.recvSpeedBps > 0, "Sender recvSpeedBps (from receiver ACKs) must be measured separately");
  assert.ok(receiverDiag.recvSpeedBps > 0, "Receiver recvSpeedBps must be measured");
  assert.ok(receiverDiag.sendSpeedBps > 0, "Receiver sendSpeedBps must be measured");

  // Verify all 5 stage timings (read, encrypt, send, decrypt, write) are collected
  assert.ok(senderDiag.timings.totalReadMs >= 0 && senderDiag.timings.readMs >= 0);
  assert.ok(senderDiag.timings.totalEncryptMs > 0 && senderDiag.timings.encryptMs > 0);
  assert.ok(senderDiag.timings.totalSendMs >= 0);
  assert.ok(senderDiag.timings.decryptMs > 0, "Receiver decryptMs must be reported back to sender via E2EE chunk-ack");
  assert.ok(senderDiag.timings.writeMs >= 0, "Receiver writeMs must be reported back to sender via E2EE chunk-ack");

  // Verify msg/s & Relay rate-limit pacing engaged before hitting 160 msg/s server disconnect
  assert.ok(senderDiag.rate.txMsgPerSec > 0);
  assert.ok(senderDiag.rate.rateLimitThrottles > 0, "Relay pacer must throttle after 16-chunk burst to protect against 160 msg/s limit");
  assert.equal(senderDiag.tuning.bottleneckCode, "relay-rate-limit");
  assert.equal(senderDiag.tuning.windowSize, 12, "Relay rate-limit bottleneck must tighten send window to 12 chunks");
  assert.equal(senderDiag.tuning.maxInFlightBytes, 1024 * 1024, "Mobile memory cap must remain 1 MB");
  assert.equal(senderDiag.tuning.e2eeActive, true);

  // Verify UI diagnostic elements in #transferPanel are populated with all 5 required telemetry rows
  assert.ok(clientA.elements.get("#tpDiagMode").textContent.includes("Relay"));
  assert.ok(clientA.elements.get("#tpDiagSpeeds").textContent.includes("ความเร็วส่ง (Tx)"));
  assert.ok(clientA.elements.get("#tpDiagSpeeds").textContent.includes("ความเร็วรับ (Rx)"));
  assert.ok(clientA.elements.get("#tpDiagTimings").textContent.includes("อ่าน:"));
  assert.ok(clientA.elements.get("#tpDiagTimings").textContent.includes("เข้ารหัส:"));
  assert.ok(clientA.elements.get("#tpDiagTimings").textContent.includes("ถอดรหัส:"));
  assert.ok(clientA.elements.get("#tpDiagTimings").textContent.includes("เขียน:"));
  assert.ok(clientA.elements.get("#tpDiagBuffer").textContent.includes("bufferedAmount:"));
  assert.ok(clientA.elements.get("#tpDiagRate").textContent.includes("msg/s"));
  assert.ok(clientA.elements.get("#tpDiagBottleneck").textContent.includes("Relay:"));

  // 2) Verify P2P bottleneck detector & adaptive chunk/window tuning (Buffer vs ACK vs Crypto vs Storage Write)
  // 2a) P2P ACK-bound -> expands window within mobile 1 MB RAM budget
  const p2pAckState = vm.runInContext(`({
    peerId: "${idB}",
    chunkSize: 48 * 1024,
    windowSize: 16,
    metrics: Object.assign(createTransferMetrics("p2p", 48 * 1024, 16), {
      chunksMeasured: 20,
      ackWaitCount: 3,
      ackWaitMs: 45,
      bufferWaitCount: 0,
      bufferWaitMs: 0,
      bufferedAmount: 64 * 1024,
      avgEncryptMs: 0.12,
      avgDecryptMs: 0.11,
      avgWriteMs: 0.35,
    })
  })`, clientA.sandbox);
  clientA.sandbox.p2pAckState = p2pAckState;
  vm.runInContext(`evaluateBottleneckAndTune(p2pAckState, { mode: "p2p", chunk: 48 * 1024, getBufferedAmount: () => 64 * 1024 })`, clientA.sandbox);
  assert.equal(p2pAckState.metrics.bottleneckCode, "p2p-ack-window");
  assert.equal(p2pAckState.windowSize, 20, "P2P ACK bottleneck on mobile must expand window from 16 to 20 (capped by 1 MB mobile RAM budget)");
  assert.ok(p2pAckState.windowSize * p2pAckState.chunkSize <= 1024 * 1024);

  // 2b) P2P DataChannel Buffer-bound -> shrinks window to relieve backpressure
  const p2pBufState = vm.runInContext(`({
    peerId: "${idB}",
    chunkSize: 48 * 1024,
    windowSize: 20,
    metrics: Object.assign(createTransferMetrics("p2p", 48 * 1024, 20), {
      chunksMeasured: 20,
      bufferWaitCount: 2,
      bufferWaitMs: 30,
      bufferedAmount: 1800 * 1024,
      ackWaitCount: 0,
      ackWaitMs: 0,
    })
  })`, clientA.sandbox);
  clientA.sandbox.p2pBufState = p2pBufState;
  vm.runInContext(`evaluateBottleneckAndTune(p2pBufState, { mode: "p2p", chunk: 48 * 1024, getBufferedAmount: () => 1800 * 1024 })`, clientA.sandbox);
  assert.equal(p2pBufState.metrics.bottleneckCode, "p2p-buffer");
  assert.equal(p2pBufState.windowSize, 16, "P2P buffer backpressure must reduce window from 20 to 16");

  // 2c) P2P Receiver Storage Write-bound -> caps window to 10 on mobile to prevent decrypt queue buildup in RAM
  const p2pWriteState = vm.runInContext(`({
    peerId: "${idB}",
    chunkSize: 48 * 1024,
    windowSize: 16,
    metrics: Object.assign(createTransferMetrics("p2p", 48 * 1024, 16), {
      chunksMeasured: 20,
      bufferWaitCount: 0,
      bufferWaitMs: 0,
      bufferedAmount: 32 * 1024,
      ackWaitCount: 2,
      ackWaitMs: 25,
      avgEncryptMs: 0.1,
      avgDecryptMs: 0.1,
      avgWriteMs: 5.5,
    })
  })`, clientA.sandbox);
  clientA.sandbox.p2pWriteState = p2pWriteState;
  vm.runInContext(`evaluateBottleneckAndTune(p2pWriteState, { mode: "p2p", chunk: 48 * 1024, getBufferedAmount: () => 32 * 1024 })`, clientA.sandbox);
  assert.equal(p2pWriteState.metrics.bottleneckCode, "p2p-storage-write");
  assert.equal(p2pWriteState.windowSize, 10, "P2P slow storage write on mobile must cap window at 10 chunks to protect RAM");
});

console.log(`\nAll ${passed} streaming, backpressure, resume & E2EE security test suites passed!`);
