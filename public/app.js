let rtcConfig = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
};
const iceReady = fetch("/ice")
  .then((r) => (r.ok ? r.json() : null))
  .then((d) => { if (d?.iceServers?.length) rtcConfig = { iceServers: d.iceServers }; })
  .catch(() => {});

const MAX_BUFFER = 8 * 1024 * 1024; // คิวค้างส่งได้ไม่เกิน 8MB
const MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_TRANSFER_SIZE = 100 * 1024 * 1024;
const MAX_FILES_PER_TRANSFER = 10;
const MAX_TEXT_LENGTH = 16 * 1024;
const ICONS = { phone: "📱", tablet: "📱", desktop: "💻" };

const $ = (s) => document.querySelector(s);
let ws;
let myId = sessionStorage.getItem("mydrop_id") || "";
let myName = sessionStorage.getItem("mydrop_name") || "";
let currentRoom = new URLSearchParams(location.search).get("room") || "";
let manualClose = false;
let reconnectTimer = null;
let lastWsActivity = 0;
const wsWaiters = new Set();
let peers = [];

const conns = new Map();            // peerId -> { pc, dc, polite, makingOffer, ignoreOffer, pending, chunk, open, resolveOpen, rejectOpen, timer }
const incoming = new Map();         // peerId -> { meta, chunks, received }
const pendingResponses = new Map(); // transferId -> { peerId, resolve, reject }
const acceptedTransfers = new Set();
const seenRequests = new Set();
const peerStatus = new Map();       // peerId -> string
const peerProgress = new Map();     // peerId -> { ratio, label }
const requestQueue = [];
let activeRequest = null;

function uuid() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) =>
    (+c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (+c / 4)))).toString(16)
  );
}

let targetPeer = null;
let stagedFiles = [];               // ไฟล์ที่เลือกไว้จาก Drop Zone รอจิ้มอุปกรณ์
let pendingShare = null;            // { files: File[], text: string }
let deferredInstallPrompt = null;

const DEVICE_LABELS = { phone: "Phone", tablet: "Tablet", desktop: "Laptop" };
const DEVICE_SVGS = {
  phone: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2.5" fill="rgba(15,23,42,0.45)"/><line x1="11" y1="18" x2="13" y2="18"/></svg>`,
  tablet: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2.5" fill="rgba(15,23,42,0.45)"/><line x1="11" y1="18" x2="13" y2="18"/></svg>`,
  desktop: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2" fill="rgba(15,23,42,0.45)"/><path d="M2 19h20"/></svg>`,
};
const CHAT_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`;
const SHARE_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`;

// ================= PWA & Share Target =================
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch((err) => console.error("SW error:", err));
}

window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  $("#installBtn").hidden = false;
});

$("#installBtn").onclick = async () => {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  await deferredInstallPrompt.userChoice;
  deferredInstallPrompt = null;
  $("#installBtn").hidden = true;
};

function takeSharedData() {
  return new Promise((resolve) => {
    const req = indexedDB.open("mydrop-share", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("pending")) db.createObjectStore("pending");
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("pending", "readwrite");
      const store = tx.objectStore("pending");
      const getReq = store.get("latest");
      getReq.onsuccess = () => {
        const val = getReq.result || null;
        if (val) store.delete("latest");
        resolve(val);
      };
      getReq.onerror = () => resolve(null);
      tx.oncomplete = () => db.close();
    };
    req.onerror = () => resolve(null);
  });
}

async function checkPendingShare() {
  const data = await takeSharedData();
  if (!data) return;
  const hasFiles = data.files && data.files.length > 0;
  const hasText = Boolean(data.text && data.text.trim());
  if (!hasFiles && !hasText) return;

  pendingShare = { files: data.files || [], text: data.text || "" };
  updateShareBanner();
  renderPeers();

  const url = new URL(location.href);
  if (url.searchParams.has("shared")) {
    url.searchParams.delete("shared");
    history.replaceState(null, "", url.pathname + (url.search || ""));
  }
}

function updateShareBanner() {
  const banner = $("#shareBanner");
  if (!pendingShare) {
    banner.style.display = "none";
    return;
  }
  const parts = [];
  if (pendingShare.files.length) parts.push(`${pendingShare.files.length} ไฟล์`);
  if (pendingShare.text) parts.push("ข้อความ/ลิงก์");
  $("#shareInfo").textContent = `พร้อมส่งจากการแชร์ (${parts.join(" + ")}) — กด "ส่งที่แชร์มา" บนอุปกรณ์ปลายทาง`;
  banner.style.display = "flex";
}

$("#clearShareBtn").onclick = () => {
  pendingShare = null;
  updateShareBanner();
  renderPeers();
};

// ================= Room Code UI =================
function updateRoomUI() {
  $("#roomInput").value = currentRoom;
  $("#leaveRoomBtn").hidden = !currentRoom;
  $("#roomStatus").textContent = currentRoom
    ? `ห้องกำหนดเอง: ${currentRoom}`
    : "โหมด: Wi-Fi / LAN เดียวกันอัตโนมัติ";
}

function switchRoom(newRoom) {
  currentRoom = newRoom.trim();
  const url = new URL(location.href);
  if (currentRoom) url.searchParams.set("room", currentRoom);
  else url.searchParams.delete("room");
  history.replaceState(null, "", url.pathname + (url.search || ""));
  updateRoomUI();

  for (const peerId of [...conns.keys()]) closeConn(peerId);
  peers = [];
  renderPeers();

  clearTimeout(reconnectTimer);
  if (ws && ws.readyState < 2) {
    manualClose = true;
    ws.close(1000, "switch room");
  }
  connectWS();
}

$("#roomForm").onsubmit = (e) => {
  e.preventDefault();
  switchRoom($("#roomInput").value);
  $("#roomPanel").hidden = true;
  $("#roomToggleBtn")?.classList.remove("active");
};

$("#leaveRoomBtn").onclick = () => {
  switchRoom("");
  $("#roomPanel").hidden = true;
  $("#roomToggleBtn")?.classList.remove("active");
};

$("#roomToggleBtn").onclick = () => {
  const panel = $("#roomPanel");
  panel.hidden = !panel.hidden;
  $("#roomToggleBtn").classList.toggle("active", !panel.hidden);
  if (!panel.hidden) $("#roomInput").focus();
};

$("#historyBtn").onclick = () => {
  $("#inbox")?.scrollIntoView({ behavior: "smooth" });
};

// ================= WebSocket (signaling) =================
function notifyWsWaiters() {
  lastWsActivity = Date.now();
  for (const fn of [...wsWaiters]) fn();
}

function connectWS() {
  clearTimeout(reconnectTimer);
  if (ws && ws.readyState < 2) {
    manualClose = true;
    try { ws.close(1000, "reconnect"); } catch {}
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const params = new URLSearchParams();
  if (currentRoom) params.set("room", currentRoom);
  const qs = params.toString();
  const socket = new WebSocket(`${proto}://${location.host}/ws${qs ? "?" + qs : ""}`);
  ws = socket;

  socket.onopen = () => {
    lastWsActivity = Date.now();
  };

  socket.onmessage = (e) => {
    if (ws !== socket) return;
    notifyWsWaiters();
    if (e.data === "pong") return;
    const msg = JSON.parse(e.data);
    if (msg.type === "welcome") {
      myId = msg.id;
      myName = msg.name;
      try {
        sessionStorage.setItem("mydrop_id", myId);
        sessionStorage.setItem("mydrop_name", myName);
      } catch {}
      $("#me").textContent = `คุณคือ ${msg.name}`;
    } else if (msg.type === "peers") {
      peers = msg.peers;
      renderPeers();
    } else if (msg.type === "signal") {
      onSignal(msg.from, msg.data);
    } else if (msg.type === "relay") {
      if (msg.data?.type === "chunk") {
        onData(msg.from, base64ToBuf(msg.data.data));
      } else {
        onData(msg.from, JSON.stringify(msg.data));
      }
    }
  };
  socket.onclose = () => {
    if (ws !== socket) return;
    if (manualClose) {
      manualClose = false;
      return;
    }
    $("#me").textContent = "หลุดการเชื่อมต่อ กำลังลองใหม่...";
    reconnectTimer = setTimeout(connectWS, 1000);
  };
}

function waitForWsActivity(timeoutMs) {
  return new Promise((resolve) => {
    let timer;
    const done = (ok) => {
      clearTimeout(timer);
      wsWaiters.delete(onMsg);
      resolve(ok);
    };
    const onMsg = () => done(true);
    wsWaiters.add(onMsg);
    timer = setTimeout(() => done(false), timeoutMs);
  });
}

async function ensureWS() {
  if (ws?.readyState === 1) {
    if (Date.now() - lastWsActivity < 2000) return;
    try {
      ws.send("ping");
      if (await waitForWsActivity(1500)) return;
    } catch {}
  }
  if (!ws || ws.readyState !== 0) {
    connectWS();
  }
  const ok = await waitForWsActivity(5000);
  if (!ok || ws?.readyState !== 1) throw new Error("ws closed");
}

setInterval(async () => {
  if (document.visibilityState === "hidden") return;
  if (ws?.readyState === 1) {
    try {
      ws.send("ping");
      const alive = await waitForWsActivity(3000);
      if (!alive && ws?.readyState === 1) connectWS();
    } catch {
      connectWS();
    }
  } else if (!ws || ws.readyState > 1) {
    connectWS();
  }
}, 15000);

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    ensureWS().catch(() => {});
  }
});
window.addEventListener("online", () => {
  ensureWS().catch(() => {});
});

function signal(to, data) {
  if (ws?.readyState === 1) {
    ws.send(JSON.stringify({ type: "signal", to, data }));
  }
}

function relaySend(to, data) {
  if (ws?.readyState !== 1) throw new Error("ws closed");
  ws.send(JSON.stringify({ type: "relay", to, data }));
}

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(bin);
}

function base64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ================= WebRTC (Perfect Negotiation กัน Glare) =================
function newConn(peerId) {
  const pc = new RTCPeerConnection(rtcConfig);
  let resolveOpen, rejectOpen;
  const open = new Promise((res, rej) => { resolveOpen = res; rejectOpen = rej; });
  open.catch(() => {}); // กัน Uncaught (in promise) กรณีฝั่งรับปิดก่อนมีคน await

  const c = {
    pc,
    dc: null,
    polite: myId < peerId,
    makingOffer: false,
    ignoreOffer: false,
    pending: [],
    chunk: 16384,
    open,
    resolveOpen,
    rejectOpen,
    timer: null,
  };

  c.timer = setTimeout(() => {
    if (c.dc?.readyState !== "open") closeConn(peerId);
  }, 8000);

  pc.onicecandidate = (e) => e.candidate && signal(peerId, { type: "ice", candidate: e.candidate });
  pc.onconnectionstatechange = () => {
    if (["failed", "closed", "disconnected"].includes(pc.connectionState)) closeConn(peerId);
  };
  pc.ondatachannel = (e) => {
    // กรณี rollback จาก glare แล้วรับ DataChannel จากฝั่ง impolite แทน
    if (c.dc && c.dc !== e.channel) {
      c.dc.onclose = null;
      c.dc.onmessage = null;
      try { c.dc.close(); } catch {}
    }
    setupChannel(c, peerId, e.channel);
  };

  conns.set(peerId, c);
  return c;
}

function setupChannel(c, peerId, dc) {
  dc.binaryType = "arraybuffer";
  dc.bufferedAmountLowThreshold = 1024 * 1024;
  c.dc = dc;

  const onOpen = () => {
    clearTimeout(c.timer);
    c.resolveOpen();
  };
  if (dc.readyState === "open") {
    onOpen();
  } else {
    dc.addEventListener("open", onOpen, { once: true });
  }
  dc.onmessage = (e) => onData(peerId, e.data);
  dc.onclose = () => {
    if (c.dc === dc) closeConn(peerId);
  };
}

function closeConn(peerId) {
  const c = conns.get(peerId);
  if (!c) return;
  clearTimeout(c.timer);
  conns.delete(peerId);
  c.rejectOpen(new Error("closed"));
  try { c.pc.close(); } catch {}
}

async function flushIce(c) {
  for (const cand of c.pending) {
    try { await c.pc.addIceCandidate(cand); } catch (err) {
      if (!c.ignoreOffer) throw err;
    }
  }
  c.pending = [];
}

// ฝั่งผู้ส่ง: สร้างการเชื่อมต่อ (หรือใช้ของเดิมที่เปิดอยู่ / กำลังเจรจาอยู่)
async function connect(peerId) {
  await iceReady;
  let c = conns.get(peerId);
  if (c?.dc?.readyState === "open" && c.pc.connectionState === "connected") return c;
  if (c && (!c.dc || ["failed", "closed", "disconnected"].includes(c.pc.connectionState))) {
    closeConn(peerId);
    c = null;
  }

  if (!c) {
    c = newConn(peerId);
    setupChannel(c, peerId, c.pc.createDataChannel("files", { ordered: true }));
    c.makingOffer = true;
    try {
      await c.pc.setLocalDescription();
      signal(peerId, { type: "offer", sdp: c.pc.localDescription });
    } finally {
      c.makingOffer = false;
    }
  }

  try {
    await Promise.race([
      c.open,
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 4000)),
    ]);
  } catch (err) {
    closeConn(peerId);
    throw err;
  }
  c.chunk = Math.min(64 * 1024, c.pc.sctp?.maxMessageSize || 16384);
  return c;
}

// ลองเชื่อม WebRTC P2P ก่อน ถ้าถูกบล็อก (เช่น mDNS/NAT) ให้สลับไปใช้ WebSocket Relay อัตโนมัติ
async function getTransport(peerId) {
  await ensureWS();
  try {
    const c = await connect(peerId);
    return {
      mode: "p2p",
      chunk: c.chunk,
      isOpen: () => c.dc?.readyState === "open",
      sendControl: (obj) => c.dc.send(JSON.stringify(obj)),
      async sendChunk(buf) {
        if (c.dc.bufferedAmount > MAX_BUFFER) {
          await new Promise((r) => c.dc.addEventListener("bufferedamountlow", r, { once: true }));
        }
        c.dc.send(buf);
      },
    };
  } catch {
    await ensureWS();
    setStatus(peerId, "ใช้โหมด Relay...");
    return {
      mode: "relay",
      chunk: 64 * 1024,
      isOpen: () => ws?.readyState === 1,
      sendControl: (obj) => relaySend(peerId, obj),
      async sendChunk(buf) {
        relaySend(peerId, { type: "chunk", data: bufToBase64(buf) });
        if (ws.bufferedAmount > 1024 * 1024) {
          await new Promise((r) => setTimeout(r, 20));
        }
      },
    };
  }
}

async function onSignal(from, data) {
  try {
    await iceReady;
    if (data.type === "offer") {
      let c = conns.get(from);
      if (c && c.dc?.readyState !== "open" && !c.makingOffer && c.pc.signalingState === "stable") {
        closeConn(from);
        c = null;
      }
      if (!c) c = newConn(from);
      const offerCollision = c.makingOffer || c.pc.signalingState !== "stable";
      c.ignoreOffer = !c.polite && offerCollision;
      if (c.ignoreOffer) return;

      if (c.pc.signalingState !== "stable") {
        // Polite peer ยอม rollback offer ของตัวเอง เพื่อรับ offer ของอีกฝั่ง
        if (c.dc && c.dc.readyState !== "open") {
          c.dc.onclose = null;
          try { c.dc.close(); } catch {}
          c.dc = null;
        }
        await c.pc.setLocalDescription({ type: "rollback" });
      }

      await c.pc.setRemoteDescription(data.sdp);
      await flushIce(c);
      await c.pc.setLocalDescription();
      signal(from, { type: "answer", sdp: c.pc.localDescription });
    } else if (data.type === "answer") {
      const c = conns.get(from);
      if (!c || c.pc.signalingState !== "have-local-offer") return;
      await c.pc.setRemoteDescription(data.sdp);
      await flushIce(c);
    } else if (data.type === "ice") {
      const c = conns.get(from);
      if (!c) return;
      if (c.pc.remoteDescription) {
        try { await c.pc.addIceCandidate(data.candidate); } catch (err) {
          if (!c.ignoreOffer) throw err;
        }
      } else {
        c.pending.push(data.candidate);
      }
    }
  } catch (err) {
    console.error("signal error", err);
  }
}

// ================= ส่งไฟล์ / ข้อความ =================
async function sendFiles(peerId, files) {
  if (!files.length) return false;
  let tx;
  try {
    setStatus(peerId, "กำลังเชื่อมต่อ...");
    tx = await getTransport(peerId);
  } catch {
    setStatus(peerId, "");
    toast("เชื่อมต่อไม่สำเร็จ");
    return false;
  }

  // ขออนุญาตผู้รับก่อนเริ่มส่งไฟล์
  const transferId = uuid();
  const responsePromise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingResponses.delete(transferId);
      reject(new Error("timeout"));
    }, 60000);
    pendingResponses.set(transferId, {
      peerId,
      resolve: (v) => { clearTimeout(timer); resolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    });
  });

  const reqMsg = {
    type: "file-request",
    transferId,
    files: files.map((f) => ({ name: f.name, size: f.size, mime: f.type })),
  };
  try {
    tx.sendControl(reqMsg);
    if (tx.mode === "p2p" && ws?.readyState === 1) {
      relaySend(peerId, reqMsg);
    }
  } catch {
    try {
      await ensureWS();
      relaySend(peerId, reqMsg);
    } catch {
      pendingResponses.delete(transferId);
      setStatus(peerId, "");
      toast("เชื่อมต่อไม่สำเร็จ");
      return false;
    }
  }
  setStatus(peerId, "รอผู้รับตอบรับ...");

  let accepted;
  try {
    accepted = await responsePromise;
  } catch {
    setStatus(peerId, "");
    toast("ไม่ได้รับการตอบรับจากผู้รับ");
    return false;
  }

  if (!accepted) {
    setStatus(peerId, "");
    toast("ผู้รับปฏิเสธไฟล์");
    return false;
  }

  for (const file of files) {
    if (!tx.isOpen()) {
      try {
        await ensureWS();
        tx = {
          mode: "relay",
          chunk: 64 * 1024,
          isOpen: () => ws?.readyState === 1,
          sendControl: (obj) => relaySend(peerId, obj),
          async sendChunk(buf) {
            relaySend(peerId, { type: "chunk", data: bufToBase64(buf) });
            if (ws.bufferedAmount > 1024 * 1024) {
              await new Promise((r) => setTimeout(r, 20));
            }
          },
        };
      } catch {
        setProgress(peerId, null);
        toast("การเชื่อมต่อหลุดระหว่างส่ง");
        return false;
      }
    }
    tx.sendControl({
      type: "header",
      transferId,
      name: file.name,
      size: file.size,
      mime: file.type,
    });
    let offset = 0;
    while (offset < file.size) {
      if (!tx.isOpen()) {
        setProgress(peerId, null);
        toast("การเชื่อมต่อหลุดระหว่างส่ง");
        return false;
      }
      const buf = await file.slice(offset, offset + tx.chunk).arrayBuffer();
      await tx.sendChunk(buf);
      offset += buf.byteLength;
      setProgress(peerId, offset / file.size, `ส่ง ${file.name}`);
    }
  }
  setProgress(peerId, null);
  toast(tx.mode === "relay" ? "ส่งเสร็จแล้ว (ผ่าน Relay)" : "ส่งเสร็จแล้ว");
  return true;
}

async function sendText(peerId, presetText = null) {
  const text = presetText ?? prompt("พิมพ์ข้อความ:");
  if (!text) return false;
  if (typeof text !== "string" || text.length > MAX_TEXT_LENGTH) {
    toast("ข้อความยาวเกินกำหนด (สูงสุด 16 KB)");
    return false;
  }
  try {
    const tx = await getTransport(peerId);
    tx.sendControl({ type: "text", text });
    toast("ส่งข้อความแล้ว");
    return true;
  } catch {
    toast("เชื่อมต่อไม่สำเร็จ");
    return false;
  }
}

async function sendPendingShare(peerId) {
  if (!pendingShare) return;
  const { files, text } = pendingShare;
  let ok = true;
  if (files.length) ok = await sendFiles(peerId, files);
  if (ok && text) ok = await sendText(peerId, text);
  if (ok) {
    pendingShare = null;
    updateShareBanner();
    renderPeers();
  }
}

// ================= รับข้อมูล & ยอมรับ/ปฏิเสธ =================
function onData(peerId, data) {
  if (typeof data === "string") {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    if (!msg || typeof msg.type !== "string") return;
    if (msg.type === "text") {
      if (typeof msg.text !== "string" || msg.text.length > MAX_TEXT_LENGTH) return;
      addReceivedText(peerName(peerId), msg.text);
    } else if (msg.type === "file-request") {
      if (typeof msg.transferId !== "string" || msg.transferId.length > 80 ||
          !Array.isArray(msg.files) || msg.files.length < 1 ||
          msg.files.length > MAX_FILES_PER_TRANSFER || seenRequests.has(msg.transferId)) return;
      const validFiles = msg.files.every((f) =>
        f && typeof f.name === "string" && f.name.length > 0 && f.name.length <= 255 &&
        Number.isSafeInteger(f.size) && f.size >= 0 && f.size <= MAX_FILE_SIZE
      );
      const total = msg.files.reduce((sum, f) => sum + (Number.isSafeInteger(f?.size) ? f.size : 0), 0);
      if (!validFiles || total > MAX_TRANSFER_SIZE) return;
      if (requestQueue.length >= 5) return;
      seenRequests.add(msg.transferId);
      if (seenRequests.size > 200) seenRequests.delete(seenRequests.values().next().value);
      requestQueue.push({ peerId, transferId: msg.transferId, files: msg.files });
      processRequestQueue();
    } else if (msg.type === "file-response") {
      if (typeof msg.transferId !== "string" || typeof msg.accepted !== "boolean") return;
      const pending = pendingResponses.get(msg.transferId);
      if (pending) {
        pendingResponses.delete(msg.transferId);
        pending.resolve(Boolean(msg.accepted));
      }
    } else if (msg.type === "header") {
      if (!acceptedTransfers.has(msg.transferId) || typeof msg.name !== "string" ||
          msg.name.length < 1 || msg.name.length > 255 ||
          !Number.isSafeInteger(msg.size) || msg.size < 0 || msg.size > MAX_FILE_SIZE ||
          incoming.has(peerId)) return;
      incoming.set(peerId, { meta: msg, chunks: [], received: 0 });
      if (msg.size === 0) finishFile(peerId);
    }
    return;
  }

  const f = incoming.get(peerId);
  if (!f || !(data instanceof ArrayBuffer) || data.byteLength === 0 ||
      f.received + data.byteLength > f.meta.size || f.received + data.byteLength > MAX_FILE_SIZE) {
    if (f) incoming.delete(peerId);
    return;
  }
  f.chunks.push(data);
  f.received += data.byteLength;
  setProgress(peerId, f.received / f.meta.size, `รับ ${f.meta.name}`);
  if (f.received === f.meta.size) finishFile(peerId);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function processRequestQueue() {
  if (activeRequest || requestQueue.length === 0) return;
  activeRequest = requestQueue.shift();

  const total = activeRequest.files.reduce((sum, f) => sum + (f.size || 0), 0);
  $("#modalTitle").textContent = `${peerName(activeRequest.peerId)} ต้องการส่งไฟล์`;
  $("#modalSub").textContent = `จำนวน ${activeRequest.files.length} ไฟล์ (รวม ${formatSize(total)})`;

  const list = $("#modalFiles");
  list.innerHTML = "";
  for (const f of activeRequest.files) {
    const li = document.createElement("li");
    const nameSpan = document.createElement("span");
    nameSpan.textContent = f.name;
    const sizeSpan = document.createElement("span");
    sizeSpan.textContent = formatSize(f.size || 0);
    sizeSpan.style.color = "#94a3b8";
    li.append(nameSpan, sizeSpan);
    list.appendChild(li);
  }
  $("#confirmModal").style.display = "flex";
}

async function respondToActiveRequest(accepted) {
  if (!activeRequest) return;
  const { peerId, transferId } = activeRequest;
  activeRequest = null;
  $("#confirmModal").style.display = "none";

  if (accepted) acceptedTransfers.add(transferId);
  const reply = { type: "file-response", transferId, accepted };
  const c = conns.get(peerId);
  let sentP2P = false;
  if (c?.dc?.readyState === "open") {
    try {
      c.dc.send(JSON.stringify(reply));
      sentP2P = true;
    } catch {}
  }
  try {
    await ensureWS();
    relaySend(peerId, reply);
  } catch {
    if (!sentP2P) toast("ส่งการตอบรับไม่สำเร็จ");
  }
  processRequestQueue();
}

$("#acceptBtn").onclick = () => respondToActiveRequest(true);
$("#rejectBtn").onclick = () => respondToActiveRequest(false);

function finishFile(peerId) {
  const f = incoming.get(peerId);
  incoming.delete(peerId);
  if (!f || f.received !== f.meta.size) return;
  acceptedTransfers.delete(f.meta.transferId);
  const safeMime = typeof f.meta.mime === "string" && /^[\w.+-]+\/[\w.+-]+$/.test(f.meta.mime)
    ? f.meta.mime : "application/octet-stream";
  const blob = new Blob(f.chunks, { type: safeMime });
  addReceivedFile(peerName(peerId), f.meta.name, blob);
  setProgress(peerId, null);
  toast(`ได้รับ ${f.meta.name}`);
}

// ================= UI =================
function peerName(id) {
  return peers.find((p) => p.id === id)?.name || "อุปกรณ์";
}

function updateDropZoneUI() {
  const zone = $("#dropZone");
  if (!zone) return;
  if (stagedFiles.length > 0) {
    const total = stagedFiles.reduce((sum, f) => sum + (f.size || 0), 0);
    zone.classList.add("has-staged");
    $("#dropZoneTitle").textContent = `เลือกไว้ ${stagedFiles.length} ไฟล์ (${formatSize(total)})`;
    $("#dropZoneSub").textContent = "แตะที่อุปกรณ์บนเรดาร์เพื่อเริ่มส่งทันที";
    $("#clearStagedBtn").hidden = false;
  } else {
    zone.classList.remove("has-staged");
    $("#dropZoneTitle").textContent = "Drag and Drop Zone";
    $("#dropZoneSub").textContent = "เลือกไฟล์ไว้ก่อนแล้วแตะอุปกรณ์บนเรดาร์ (หรือส่งทันทีถ้ามีเครื่องเดียว)";
    $("#clearStagedBtn").hidden = true;
  }
}

async function handleStagedFiles(files) {
  if (!files.length) return;
  if (peers.length === 1) {
    await sendFiles(peers[0].id, files);
    return;
  }
  stagedFiles = files;
  updateDropZoneUI();
  renderPeers();
  toast(peers.length ? "แตะอุปกรณ์บนเรดาร์เพื่อส่งไฟล์ที่เลือก" : "เลือกไฟล์แล้ว รออุปกรณ์อื่นเชื่อมต่อ");
}

function peerPosition(index, total) {
  const presets = [-142, -38, 142, 38];
  const angleDeg = total <= 4 ? presets[index] : -90 + (360 / total) * index;
  const rad = (angleDeg * Math.PI) / 180;
  const rx = 38;
  const ry = 36;
  return {
    left: `${50 + rx * Math.cos(rad)}%`,
    top: `${50 + ry * Math.sin(rad)}%`,
  };
}

function renderPeers() {
  const box = $("#peers");
  box.innerHTML = "";
  $("#empty").style.display = peers.length ? "none" : "block";

  peers.forEach((p, idx) => {
    const el = document.createElement("div");
    el.className = "peer" + (stagedFiles.length || pendingShare ? " staged-ready" : "");
    el.dataset.peer = p.id;
    const pos = peerPosition(idx, peers.length);
    el.style.left = pos.left;
    el.style.top = pos.top;

    const devSvg = DEVICE_SVGS[p.device] || DEVICE_SVGS.desktop;
    const devLabel = DEVICE_LABELS[p.device] || "Laptop";

    el.innerHTML = `
      <div class="peer-avatar-wrap">
        <div class="peer-ring" title="แตะเพื่อส่งไฟล์">
          <div class="peer-ring-inner">${devSvg}</div>
        </div>
        <button type="button" class="peer-action-btn msg" title="ส่งข้อความ">${CHAT_SVG}</button>
        ${pendingShare ? `<button type="button" class="peer-action-btn share-send" title="ส่งที่แชร์มา">${SHARE_SVG}</button>` : ""}
      </div>
      <div class="peer-type">${devLabel}</div>
      <div class="name"></div>
      <div class="progress"><div class="bar"></div></div>
      <div class="status"></div>`;

    el.querySelector(".name").textContent = `(${p.name})`;
    el.querySelector(".msg").onclick = (e) => {
      e.stopPropagation();
      sendText(p.id);
    };
    if (pendingShare) {
      el.querySelector(".share-send").onclick = (e) => {
        e.stopPropagation();
        sendPendingShare(p.id);
      };
    }

    el.onclick = async () => {
      if (stagedFiles.length > 0) {
        const toSend = stagedFiles;
        stagedFiles = [];
        updateDropZoneUI();
        renderPeers();
        await sendFiles(p.id, toSend);
      } else if (pendingShare) {
        await sendPendingShare(p.id);
      } else {
        targetPeer = p.id;
        $("#picker").click();
      }
    };

    const progState = peerProgress.get(p.id);
    if (progState) {
      const prog = el.querySelector(".progress");
      prog.style.display = "block";
      el.querySelector(".bar").style.width = `${Math.round(progState.ratio * 100)}%`;
    }
    const st = peerStatus.get(p.id);
    if (st) {
      el.querySelector(".status").textContent = st;
    }

    // ลากไฟล์มาวางบนไอคอนอุปกรณ์โดยตรง
    el.ondragover = (e) => { e.preventDefault(); e.stopPropagation(); el.classList.add("drag"); };
    el.ondragleave = () => el.classList.remove("drag");
    el.ondrop = (e) => {
      e.preventDefault();
      e.stopPropagation();
      el.classList.remove("drag");
      sendFiles(p.id, [...e.dataTransfer.files]);
    };
    box.appendChild(el);
  });
}

function setStatus(peerId, text) {
  if (text) peerStatus.set(peerId, text);
  else peerStatus.delete(peerId);
  const s = document.querySelector(`[data-peer="${peerId}"] .status`);
  if (s) s.textContent = text;
}

function setProgress(peerId, ratio, label = "") {
  if (ratio === null) {
    peerProgress.delete(peerId);
  } else {
    peerProgress.set(peerId, { ratio, label });
  }
  const card = document.querySelector(`[data-peer="${peerId}"]`);
  if (!card) {
    if (ratio === null) setStatus(peerId, "");
    else setStatus(peerId, `${label} ${Math.round(ratio * 100)}%`);
    return;
  }
  const prog = card.querySelector(".progress");
  if (ratio === null) {
    prog.style.display = "none";
    setStatus(peerId, "");
    return;
  }
  prog.style.display = "block";
  card.querySelector(".bar").style.width = `${Math.round(ratio * 100)}%`;
  setStatus(peerId, `${label} ${Math.round(ratio * 100)}%`);
}

function addReceivedFile(from, name, blob) {
  const item = document.createElement("div");
  item.className = "item";
  const info = document.createElement("div");
  info.textContent = `${name} (${formatSize(blob.size)}) จาก ${from}`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.textContent = "บันทึก";
  item.append(info, a);
  $("#received").prepend(item);
}

function addReceivedText(from, text) {
  const item = document.createElement("div");
  item.className = "item";
  const t = document.createElement("div");
  t.className = "text";
  t.textContent = `${from}: ${text}`;
  const btn = document.createElement("a");
  btn.href = "#";
  btn.textContent = "คัดลอก";
  btn.onclick = (e) => { e.preventDefault(); navigator.clipboard?.writeText(text); toast("คัดลอกแล้ว"); };
  item.append(t, btn);
  $("#received").prepend(item);
}

function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.style.display = "block";
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.style.display = "none"), 2500);
}

$("#picker").onchange = (e) => {
  const files = [...(e.target.files || [])];
  e.target.value = "";
  if (!files.length) return;
  if (targetPeer) {
    const peerId = targetPeer;
    targetPeer = null;
    sendFiles(peerId, files);
  } else {
    handleStagedFiles(files);
  }
};

$("#uploadBtn").onclick = () => {
  targetPeer = null;
  $("#picker").click();
};

$("#quickAddBtn").onclick = () => {
  targetPeer = null;
  $("#picker").click();
};

$("#clearStagedBtn").onclick = () => {
  stagedFiles = [];
  updateDropZoneUI();
  renderPeers();
};

$("#copyLinkBtn").onclick = () => {
  navigator.clipboard?.writeText(location.href);
  toast("คัดลอกลิงก์ห้องแล้ว");
};

const dropZone = $("#dropZone");
dropZone.ondragover = (e) => {
  e.preventDefault();
  dropZone.classList.add("drag");
};
dropZone.ondragleave = () => dropZone.classList.remove("drag");
dropZone.ondrop = (e) => {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.remove("drag");
  handleStagedFiles([...e.dataTransfer.files]);
};

document.body.ondragover = (e) => e.preventDefault();
document.body.ondrop = (e) => {
  e.preventDefault();
  if (e.dataTransfer?.files?.length) {
    handleStagedFiles([...e.dataTransfer.files]);
  }
};

updateRoomUI();
updateDropZoneUI();
checkPendingShare();
connectWS();
