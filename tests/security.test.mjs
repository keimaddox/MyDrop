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
  // Ensure internal fields like ip or rateCount are not leaked in peers list
  assert.equal(peersMsg1.peers[0].ip, undefined);
  assert.equal(peersMsg1.peers[0].rateCount, undefined);
});

await runTest("5. Room occupancy limit (12 peers) and per-IP connection limits are enforced", async () => {
  const env = createMockEnv();
  // Connect 12 peers from distinct IPs into the same room
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

  // Per-IP active connections limit (8 per IP in a room)
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

await runTest("7. Malformed, spoofed, and oversized WebSocket messages are rejected", async () => {
  const env = createMockEnv();
  const res1 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=msgtest", "198.51.100.10"), env);
  const res2 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=msgtest", "198.51.100.11"), env);
  const room = env.rooms.get("code:msgtest").roomInstance;
  const ws1 = res1.webSocket.peer;
  const ws2 = res2.webSocket.peer;
  const id1 = JSON.parse(ws1.sent[0]).id;
  const id2 = JSON.parse(ws2.sent[0]).id;
  const initialWs2Count = ws2.sent.length;

  // Malformed JSON
  await room.webSocketMessage(ws1, "{bad json");
  assert.equal(ws2.sent.length, initialWs2Count);

  // Self-send attempt
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "relay",
    to: id1,
    data: { type: "text", text: "self" },
  }));
  assert.equal(ws2.sent.length, initialWs2Count);

  // Invalid signal payload
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "signal",
    to: id2,
    data: { type: "offer", sdp: "not-an-object" },
  }));
  assert.equal(ws2.sent.length, initialWs2Count);

  // Invalid relay type
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "relay",
    to: id2,
    data: { type: "arbitrary-command", payload: "evil" },
  }));
  assert.equal(ws2.sent.length, initialWs2Count);

  // Invalid base64 chunk
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "relay",
    to: id2,
    data: { type: "chunk", data: "not_valid_base64$$$" },
  }));
  assert.equal(ws2.sent.length, initialWs2Count);

  // Valid signaling & relay messages are forwarded with authoritative `from`
  await room.webSocketMessage(ws1, JSON.stringify({
    type: "signal",
    to: id2,
    from: "spoofed-id",
    data: { type: "offer", sdp: { type: "offer", sdp: "v=0\r\n..." } },
  }));
  assert.equal(ws2.sent.length, initialWs2Count + 1);
  const forwardedSignal = JSON.parse(ws2.sent[ws2.sent.length - 1]);
  assert.equal(forwardedSignal.from, id1);

  // Oversized message (> 128 KB) closes socket with 1009
  const huge = JSON.stringify({
    type: "relay",
    to: id2,
    data: { type: "text", text: "A".repeat(140 * 1024) },
  });
  await room.webSocketMessage(ws1, huge);
  assert.equal(ws1.closed, true);
  assert.equal(ws1.closeCode, 1009);
});

await runTest("8. Per-connection WebSocket message rate limit (40 msg/sec) closes flooding socket", async () => {
  const env = createMockEnv();
  const res1 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=ratetest", "198.51.100.21"), env);
  const res2 = await worker.fetch(makeWsRequest("https://mydrop.example/ws?room=ratetest", "198.51.100.22"), env);
  const room = env.rooms.get("code:ratetest").roomInstance;
  const ws1 = res1.webSocket.peer;
  const ws2 = res2.webSocket.peer;
  const id2 = JSON.parse(ws2.sent[0]).id;

  for (let i = 0; i < 45; i++) {
    if (ws1.closed) break;
    await room.webSocketMessage(ws1, JSON.stringify({
      type: "relay",
      to: id2,
      data: { type: "text", text: `msg ${i}` },
    }));
  }
  assert.equal(ws1.closed, true);
  assert.equal(ws1.closeCode, 1008);
});

await runTest("9. End-to-End Application Protocol (Bidirectional File Transfer, Text Transfer, Relay Fallback, UI & Validation)", async () => {
  // Spin up two isolated client sandboxes connected to the same Room Durable Object
  const env = createMockEnv();
  const appJsCode = fs.readFileSync(path.join(rootDir, "public", "app.js"), "utf8");

  function createClientSandbox(ip, forceRelay = false) {
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

    let activeClientWs = null;
    class ClientWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        this.bufferedAmount = 0;
        activeClientWs = this;
        const req = makeWsRequest(url.replace(/^ws:/, "https:").replace(/^wss:/, "https:"), ip);
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
        const roomEntry = env.rooms.get(roomFromIpSafe(ip));
        roomEntry.roomInstance.webSocketMessage(this.serverWs, data);
      }
      close(code, reason) {
        this.readyState = 3;
        if (this.serverWs) {
          const roomEntry = env.rooms.get(roomFromIpSafe(ip));
          roomEntry.roomInstance.webSocketClose(this.serverWs);
        }
        this.onclose?.();
      }
    }

    function roomFromIpSafe(addr) {
      return "v4:" + addr;
    }

    class MockRTCPeerConnection {
      constructor() {
        this.connectionState = "new";
        this.signalingState = "stable";
        this.sctp = { maxMessageSize: 65536 };
      }
      createDataChannel(label) {
        const dc = {
          label,
          readyState: forceRelay ? "connecting" : "open",
          binaryType: "arraybuffer",
          bufferedAmount: 0,
          send(data) {
            if (forceRelay) throw new Error("P2P blocked");
            if (this._peerDc?.onmessage) {
              queueMicrotask(() => this._peerDc.onmessage({ data }));
            }
          },
          addEventListener(ev, fn) {
            if (ev === "open" && !forceRelay) queueMicrotask(fn);
          },
          close() {
            this.readyState = "closed";
          },
        };
        this._dc = dc;
        return dc;
      }
      async setLocalDescription() {}
      async setRemoteDescription() {}
      async addIceCandidate() {}
      close() {
        this.connectionState = "closed";
      }
    }

    const sandbox = {
      console,
      setTimeout,
      clearTimeout,
      setInterval: () => 0,
      clearInterval,
       crypto: globalThis.crypto,
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
      prompt: () => "Hello from prompt",
    };
    sandbox.URL.createObjectURL = () => "blob:https://mydrop.example/mock-blob";

    vm.createContext(sandbox);
    vm.runInContext(appJsCode, sandbox);
    return { sandbox, elements, document };
  }

  // Test Relay Fallback (forceRelay = true so connect() times out or we stub connect to reject immediately for fast test)
  const clientA = createClientSandbox("198.51.100.88", true);
  const clientB = createClientSandbox("198.51.100.88", true);

  // Wait for WS welcome and peer discovery
  await new Promise((r) => setTimeout(r, 40));

  // Speed up relay fallback in test by making connect() reject immediately when forceRelay is enabled
  vm.runInContext(`connect = async () => { throw new Error("Simulated NAT block -> use Relay"); };`, clientA.sandbox);
  vm.runInContext(`connect = async () => { throw new Error("Simulated NAT block -> use Relay"); };`, clientB.sandbox);

  const idA = vm.runInContext(`myId`, clientA.sandbox);
  const idB = vm.runInContext(`myId`, clientB.sandbox);
  assert.ok(idA && idB && idA !== idB);

  // 1) Text transfer A -> B over Relay
  const textOk = await vm.runInContext(`sendText("${idB}", "สวัสดี MyDrop ปลอดภัย!")`, clientA.sandbox);
  assert.equal(textOk, true);
  await new Promise((r) => setTimeout(r, 20));
  const receivedB = clientB.elements.get("#received");
  assert.equal(receivedB.children.length, 1);
  assert.ok(receivedB.children[0].children[0].textContent.includes("สวัสดี MyDrop ปลอดภัย!"));

  // 2) File transfer A -> B (multi-file) over Relay with recipient approval
  clientB.sandbox.testFilesToReceive = [];
  const file1Bytes = new Uint8Array(90 * 1024); // 90 KB (spans 2 chunks of 64KB)
  for (let i = 0; i < file1Bytes.length; i++) file1Bytes[i] = i % 251;
  const file2Bytes = new TextEncoder().encode("Second file content");

  clientA.sandbox.testFiles = [
    new File([file1Bytes], "../secret/video_clip.mp4", { type: "video/mp4" }),
    new File([file2Bytes], "notes.html", { type: "text/html" }),
  ];

  const sendPromiseAtoB = vm.runInContext(`sendFiles("${idB}", testFiles)`, clientA.sandbox);
  await new Promise((r) => setTimeout(r, 30));

  // Verify confirmModal opened on B and path traversal was sanitized
  const modalB = clientB.elements.get("#confirmModal");
  assert.equal(modalB.style.display, "flex");
  const acceptBtnB = clientB.elements.get("#acceptBtn");
  await acceptBtnB.onclick();

  const sendResAtoB = await sendPromiseAtoB;
  assert.equal(sendResAtoB, true);
  await new Promise((r) => setTimeout(r, 30));

  // Verify B received both files (1 text item + 2 file items = 3 items in #received)
  assert.equal(receivedB.children.length, 3);
  // Most recent prepended item is notes.html, second is video_clip.mp4
  assert.ok(receivedB.children[0].children[0].textContent.includes("notes.html"));
  assert.ok(receivedB.children[1].children[0].textContent.includes("video_clip.mp4"));
  assert.ok(!receivedB.children[1].children[0].textContent.includes(".."));

  // 3) Reverse direction File transfer B -> A
  clientB.sandbox.replyFiles = [
    new File([new TextEncoder().encode("Reply from Android to iPhone")], "reply.txt", { type: "text/plain" }),
  ];
  const sendPromiseBtoA = vm.runInContext(`sendFiles("${idA}", replyFiles)`, clientB.sandbox);
  await new Promise((r) => setTimeout(r, 30));
  const acceptBtnA = clientA.elements.get("#acceptBtn");
  await acceptBtnA.onclick();
  const sendResBtoA = await sendPromiseBtoA;
  assert.equal(sendResBtoA, true);
  await new Promise((r) => setTimeout(r, 20));

  const receivedA = clientA.elements.get("#received");
  assert.equal(receivedA.children.length, 1);
  assert.ok(receivedA.children[0].children[0].textContent.includes("reply.txt"));

  // 4) Oversized file rejection on sender
  clientA.sandbox.tooBig = [{ name: "huge.mov", size: 55 * 1024 * 1024, type: "video/quicktime" }];
  const bigRes = await vm.runInContext(`sendFiles("${idB}", tooBig)`, clientA.sandbox);
  assert.equal(bigRes, false);
});

console.log(`\nAll ${passed} integration & security test suites passed!`);
