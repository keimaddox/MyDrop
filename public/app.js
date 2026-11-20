// ================= Security Configuration & Configurable Limits =================
const SECURITY_LIMITS = {
  MAX_FILES_PER_TRANSFER: 10,
  MAX_FILE_SIZE: 50 * 1024 * 1024,        // 50 MB per file
  MAX_TOTAL_TRANSFER_SIZE: 100 * 1024 * 1024, // 100 MB total per transfer
  MAX_TEXT_BYTES: 16 * 1024,              // 16 KB per text message
  MAX_PENDING_REQUESTS: 5,                // Max 5 pending incoming file requests
  MAX_FILENAME_LENGTH: 255,               // Max 255 characters per filename
  MAX_CHUNK_SIZE: 64 * 1024,              // Max 64 KB plaintext chunk size
  REQUEST_TIMEOUT_MS: 60000,              // 60s timeout for recipient approval
  CHUNK_INACTIVITY_TIMEOUT_MS: 30000,     // 30s inactivity timeout during active file reception
  E2EE_HANDSHAKE_TIMEOUT_MS: 8000,        // 8s timeout for ECDH key exchange
  MAX_SEEN_REQUEST_IDS: 500,              // Bounded replay cache size
  MAX_RETAINED_BLOBS: 25,                 // Max retained Object URLs before auto-revoking oldest
  MAX_RECEIVED_ITEMS: 50,                 // Max retained DOM items in #received inbox
  MAX_CLIENT_CTRL_PER_10S: 60,            // Max incoming decrypted control/text messages per peer per 10s
  ROOM_CODE_MIN_LEN: 3,
  ROOM_CODE_MAX_LEN: 64,
  ...(typeof window !== "undefined" &&
  window.MYDROP_SECURITY_LIMITS &&
  typeof window.MYDROP_SECURITY_LIMITS === "object"
    ? window.MYDROP_SECURITY_LIMITS
    : {}),
};

function configureSecurityLimits(overrides = {}) {
  if (!overrides || typeof overrides !== "object") return { ...SECURITY_LIMITS };
  for (const [k, v] of Object.entries(overrides)) {
    if (Object.prototype.hasOwnProperty.call(SECURITY_LIMITS, k) && Number.isSafeInteger(v) && v > 0) {
      SECURITY_LIMITS[k] = v;
    }
  }
  return { ...SECURITY_LIMITS };
}

const ROOM_CODE_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MIME_REGEX = /^[a-zA-Z0-9!#$&-^_]{1,64}\/[a-zA-Z0-9!#$&-^_.+]{1,128}$/;

// Potentially dangerous file extensions & active MIME types requiring user warning and safe binary download
const DANGEROUS_EXTENSIONS = new Set([
  ".exe", ".bat", ".cmd", ".scr", ".ps1", ".psm1", ".js", ".mjs", ".cjs", ".jse",
  ".vbs", ".vbe", ".wsf", ".wsh", ".msi", ".msp", ".hta", ".html", ".htm", ".xhtml",
  ".svg", ".svgz", ".apk", ".app", ".dmg", ".pkg", ".sh", ".bash", ".com", ".pif",
  ".reg", ".jar", ".lnk", ".iso", ".img", ".dll", ".sys", ".cpl", ".scf", ".url",
]);

const ACTIVE_OR_DANGEROUS_MIMES = new Set([
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/javascript",
  "application/javascript",
  "application/x-javascript",
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/x-executable",
  "application/x-msi",
  "application/hta",
  "application/x-sh",
  "text/xml",
  "application/xml",
]);

const WINDOWS_RESERVED_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const BIDI_AND_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

let rtcConfig = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
};
const iceReady = fetch("/ice", { cache: "no-store" })
  .then((r) => (r.ok ? r.json() : null))
  .then((d) => { if (d?.iceServers?.length) rtcConfig = { iceServers: d.iceServers }; })
  .catch(() => {});

const MAX_BUFFER = 8 * 1024 * 1024; // คิวค้างส่งได้ไม่เกิน 8MB
const ICONS = { phone: "📱", tablet: "📱", desktop: "💻" };

const $ = (s) => document.querySelector(s);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

let ws;
let myId = "";
let myName = "";
let reconnectToken = sessionStorage.getItem("mydrop_reconnect_token") || "";
let currentRoom = "";
let manualClose = false;
let reconnectTimer = null;
let lastWsActivity = 0;
const wsWaiters = new Set();
let peers = [];

// Initialize currentRoom from URL safely
{
  const rawUrlRoom = new URLSearchParams(location.search).get("room") || "";
  if (rawUrlRoom && ROOM_CODE_REGEX.test(rawUrlRoom.trim())) {
    currentRoom = rawUrlRoom.trim();
  } else if (rawUrlRoom) {
    const cleanUrl = new URL(location.href);
    cleanUrl.searchParams.delete("room");
    history.replaceState(null, "", cleanUrl.pathname + (cleanUrl.search || ""));
  }
}

const conns = new Map();             // peerId -> { pc, dc, polite, makingOffer, ignoreOffer, pending, chunk, open, resolveOpen, rejectOpen, timer }
const e2eeSessions = new Map();      // peerId -> { state, keyPair, myPubB64, myNonceB64, peerPubB64, peerNonceB64, txKey, rxKey, txSalt, rxSalt, txControlSeq, rxControlSeq, txChunkSeq, rxChunkSeq, sas, confirmHashB64, readyPromise, resolveReady, rejectReady }
const incoming = new Map();          // peerId -> { transferId, fileIndex, meta, chunks, received, expectedChunkIndex, timer }
const pendingResponses = new Map();  // transferId -> { peerId, resolve, reject, timer }
const acceptedTransfers = new Map(); // transferId -> { peerId, files, nextFileIndex, totalBytes, receivedTotalBytes, createdAt, timer }
const seenRequests = new Set();      // Bounded set of transferIds
const peerStatus = new Map();        // peerId -> string
const peerProgress = new Map();      // peerId -> { ratio, label }
const peerElements = new Map();      // peerId -> HTMLElement
const peerClientRate = new Map();    // peerId -> { windowStart, count }
const requestQueue = [];             // Bounded queue of incoming file requests
const activeObjectUrls = [];         // Bounded list of created blob: URLs for cleanup
let activeRequest = null;

function uuid() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) =>
    (+c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (+c / 4)))).toString(16)
  );
}

// ================= Validation & Sanitization Helpers =================
function sanitizeFilename(rawName) {
  if (typeof rawName !== "string") return "file";
  // Strip directory paths and control/BiDi characters
  let clean = rawName
    .replace(/\\/g, "/")
    .split("/")
    .pop()
    .replace(BIDI_AND_CONTROL_CHARS, "")
    .replace(/[<>:"|?*]/g, "_")
    .trim();

  // Remove leading dots to prevent hidden dotfiles
  clean = clean.replace(/^\.+/, "").replace(/\.+$/, "");
  if (!clean || WINDOWS_RESERVED_NAMES.test(clean)) {
    clean = "file_" + (clean || "unnamed");
  }

  if (clean.length > SECURITY_LIMITS.MAX_FILENAME_LENGTH) {
    const dotIdx = clean.lastIndexOf(".");
    const ext = dotIdx > 0 && clean.length - dotIdx <= 16 ? clean.slice(dotIdx) : "";
    const baseLen = SECURITY_LIMITS.MAX_FILENAME_LENGTH - ext.length;
    clean = clean.slice(0, Math.max(1, baseLen)) + ext;
  }
  return clean;
}

function sanitizeMimeType(rawMime) {
  if (typeof rawMime !== "string" || !rawMime.trim()) return "application/octet-stream";
  const trimmed = rawMime.trim().toLowerCase().split(";")[0].trim();
  return MIME_REGEX.test(trimmed) ? trimmed : "application/octet-stream";
}

function isDangerousFile(filename, mimeType = "") {
  const safeName = String(filename || "").toLowerCase().trim();
  const safeMime = String(mimeType || "").toLowerCase().trim();

  if (ACTIVE_OR_DANGEROUS_MIMES.has(safeMime)) return true;

  // Check primary extension and trailing double extensions (e.g. "report.pdf.exe")
  const parts = safeName.split(".");
  if (parts.length > 1) {
    const lastExt = "." + parts[parts.length - 1];
    if (DANGEROUS_EXTENSIONS.has(lastExt)) return true;
    if (parts.length > 2) {
      const secondLastExt = "." + parts[parts.length - 2];
      if (DANGEROUS_EXTENSIONS.has(secondLastExt) && lastExt.length <= 5) {
        return true;
      }
    }
  }
  return false;
}

function getSafeDownloadMime(filename, rawMime) {
  const mime = sanitizeMimeType(rawMime);
  if (isDangerousFile(filename, mime)) {
    return "application/octet-stream";
  }
  return mime;
}

function validateOutgoingFiles(files) {
  if (!Array.isArray(files) || files.length === 0) {
    return { ok: false, error: "กรุณาเลือกไฟล์ก่อนส่ง" };
  }
  if (files.length > SECURITY_LIMITS.MAX_FILES_PER_TRANSFER) {
    return {
      ok: false,
      error: `ส่งได้สูงสุด ${SECURITY_LIMITS.MAX_FILES_PER_TRANSFER} ไฟล์ต่อครั้ง`,
    };
  }
  let totalBytes = 0;
  for (const f of files) {
    if (!(f instanceof Blob) || typeof f.size !== "number" || f.size < 0 || !Number.isSafeInteger(f.size)) {
      return { ok: false, error: "ข้อมูลไฟล์ไม่ถูกต้อง" };
    }
    if (f.size > SECURITY_LIMITS.MAX_FILE_SIZE) {
      return {
        ok: false,
        error: `ไฟล์ "${sanitizeFilename(f.name)}" มีขนาดเกิน ${formatSize(SECURITY_LIMITS.MAX_FILE_SIZE)}`,
      };
    }
    totalBytes += f.size;
    if (totalBytes > SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE) {
      return {
        ok: false,
        error: `ขนาดไฟล์รวมเกินขีดจำกัด (${formatSize(SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE)} ต่อครั้ง)`,
      };
    }
  }
  return { ok: true, totalBytes };
}

function validateIncomingFileRequest(msg) {
  if (!msg || typeof msg !== "object") return { ok: false, error: "Invalid request" };
  if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) {
    return { ok: false, error: "Invalid transferId" };
  }
  if (!Array.isArray(msg.files) || msg.files.length === 0 || msg.files.length > SECURITY_LIMITS.MAX_FILES_PER_TRANSFER) {
    return { ok: false, error: "Invalid file count" };
  }

  const sanitizedFiles = [];
  let totalBytes = 0;

  for (const rawFile of msg.files) {
    if (!rawFile || typeof rawFile !== "object") return { ok: false, error: "Malformed file entry" };
    if (typeof rawFile.name !== "string" || rawFile.name.trim().length === 0 || rawFile.name.length > 512) {
      return { ok: false, error: "Invalid filename" };
    }
    if (
      typeof rawFile.size !== "number" ||
      !Number.isSafeInteger(rawFile.size) ||
      rawFile.size < 0 ||
      rawFile.size > SECURITY_LIMITS.MAX_FILE_SIZE
    ) {
      return { ok: false, error: "Invalid file size" };
    }
    totalBytes += rawFile.size;
    if (totalBytes > SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE) {
      return { ok: false, error: "Total transfer size exceeded" };
    }
    const cleanName = sanitizeFilename(rawFile.name);
    const cleanMime = sanitizeMimeType(rawFile.mime || "");
    sanitizedFiles.push({
      name: cleanName,
      size: rawFile.size,
      mime: cleanMime,
      dangerous: isDangerousFile(cleanName, cleanMime),
    });
  }

  return { ok: true, transferId: msg.transferId, files: sanitizedFiles, totalBytes };
}

function rememberSeenRequest(transferId) {
  if (seenRequests.has(transferId)) return false;
  if (seenRequests.size >= SECURITY_LIMITS.MAX_SEEN_REQUEST_IDS) {
    const oldest = seenRequests.values().next().value;
    if (oldest) seenRequests.delete(oldest);
  }
  seenRequests.add(transferId);
  return true;
}

function generateSecureRoomCode() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    if (i > 0 && i % 4 === 0) out += "-";
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
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
  const trimmed = newRoom.trim();
  if (trimmed && !ROOM_CODE_REGEX.test(trimmed)) {
    toast("รหัสห้องต้องมีความยาว 3-64 ตัวอักษร (a-z, 0-9, - หรือ _)");
    return;
  }

  currentRoom = trimmed;
  // Clear reconnect token when switching rooms so a fresh room-scoped identity is issued
  reconnectToken = "";
  try { sessionStorage.removeItem("mydrop_reconnect_token"); } catch {}

  const url = new URL(location.href);
  if (currentRoom) url.searchParams.set("room", currentRoom);
  else url.searchParams.delete("room");
  history.replaceState(null, "", url.pathname + (url.search || ""));
  updateRoomUI();

  cleanupAllPeers("switch room");
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

const randomRoomBtn = $("#randomRoomBtn");
if (randomRoomBtn) {
  randomRoomBtn.onclick = () => {
    const secureCode = generateSecureRoomCode();
    $("#roomInput").value = secureCode;
    switchRoom(secureCode);
    $("#roomPanel").hidden = true;
    $("#roomToggleBtn")?.classList.remove("active");
    toast(`สร้างห้องปลอดภัย: ${secureCode}`);
  };
}

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

// ================= State & Memory Cleanup =================
function cleanupIncomingTransfer(peerId) {
  const f = incoming.get(peerId);
  if (!f) return;
  clearTimeout(f.timer);
  f.chunks = [];
  incoming.delete(peerId);
  setProgress(peerId, null);
}

function cleanupAcceptedTransfer(transferId) {
  const t = acceptedTransfers.get(transferId);
  if (!t) return;
  clearTimeout(t.timer);
  acceptedTransfers.delete(transferId);
}

function cleanupPeerState(peerId) {
  closeConn(peerId);

  const sess = e2eeSessions.get(peerId);
  e2eeInitPromises.delete(peerId);
  if (sess) {
    e2eeSessions.delete(peerId);
    try { sess.rejectReady?.(new Error("peer disconnected")); } catch {}
  }

  cleanupIncomingTransfer(peerId);

  for (const [transferId, pending] of pendingResponses) {
    if (pending.peerId === peerId) {
      clearTimeout(pending.timer);
      pendingResponses.delete(transferId);
      try { pending.reject(new Error("peer disconnected")); } catch {}
    }
  }

  for (const [transferId, accepted] of acceptedTransfers) {
    if (accepted.peerId === peerId) {
      cleanupAcceptedTransfer(transferId);
    }
  }

  for (let i = requestQueue.length - 1; i >= 0; i--) {
    if (requestQueue[i].peerId === peerId) {
      clearTimeout(requestQueue[i].expireTimer);
      requestQueue.splice(i, 1);
    }
  }

  if (activeRequest && activeRequest.peerId === peerId) {
    clearTimeout(activeRequest.expireTimer);
    activeRequest = null;
    $("#confirmModal").style.display = "none";
    processRequestQueue();
  }

  peerStatus.delete(peerId);
  peerProgress.delete(peerId);
  peerClientRate.delete(peerId);
}

function cleanupAllPeers(reason = "reset") {
  const allPeerIds = new Set([
    ...conns.keys(),
    ...e2eeSessions.keys(),
    ...incoming.keys(),
    ...peers.map((p) => p.id),
  ]);
  for (const pid of allPeerIds) {
    cleanupPeerState(pid);
  }
}

window.addEventListener("pagehide", () => {
  while (activeObjectUrls.length > 0) {
    const entry = activeObjectUrls.shift();
    try { URL.revokeObjectURL(entry.url); } catch {}
  }
});

// ================= WebSocket (signaling & encrypted relay) =================
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
  // Never send client-controlled id or name; only send server-issued secret reconnectToken if available
  if (reconnectToken) params.set("token", reconnectToken);
  const qs = params.toString();
  const socket = new WebSocket(`${proto}://${location.host}/ws${qs ? "?" + qs : ""}`);
  ws = socket;

  socket.onopen = () => {
    lastWsActivity = Date.now();
  };

  socket.onmessage = (e) => {
    if (ws !== socket) return;
    notifyWsWaiters();
    if (typeof e.data !== "string" || e.data === "pong") return;

    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (!msg || typeof msg !== "object") return;

    if (msg.type === "welcome") {
      if (typeof msg.id === "string" && UUID_REGEX.test(msg.id)) {
        const idChanged = myId && myId !== msg.id;
        myId = msg.id;
        myName = String(msg.name || "อุปกรณ์").slice(0, 64);
        if (typeof msg.reconnectToken === "string") {
          reconnectToken = msg.reconnectToken;
          try { sessionStorage.setItem("mydrop_reconnect_token", reconnectToken); } catch {}
        }
        if (idChanged) {
          // Our identity rotated; reset any stale E2EE sessions bound to the old ID
          for (const pid of [...e2eeSessions.keys()]) {
            const s = e2eeSessions.get(pid);
            e2eeSessions.delete(pid);
            try { s?.rejectReady?.(new Error("identity rotated")); } catch {}
          }
        }
        $("#me").textContent = `คุณคือ ${myName}`;
      }
    } else if (msg.type === "peers") {
      if (!Array.isArray(msg.peers)) return;
      const validPeers = msg.peers
        .filter((p) => p && typeof p.id === "string" && UUID_REGEX.test(p.id) && p.id !== myId)
        .map((p) => ({
          id: p.id,
          name: String(p.name || "อุปกรณ์").slice(0, 64),
          device: ["phone", "tablet", "desktop"].includes(p.device) ? p.device : "desktop",
        }));

      const activeIds = new Set(validPeers.map((p) => p.id));
      for (const oldPeer of peers) {
        if (!activeIds.has(oldPeer.id)) {
          cleanupPeerState(oldPeer.id);
        }
      }
      peers = validPeers;
      renderPeers();
    } else if (msg.type === "signal") {
      if (typeof msg.from === "string" && UUID_REGEX.test(msg.from) && isKnownPeer(msg.from)) {
        onSignal(msg.from, msg.data);
      }
    } else if (msg.type === "relay") {
      if (typeof msg.from === "string" && UUID_REGEX.test(msg.from) && isKnownPeer(msg.from)) {
        onRelayMessage(msg.from, msg.data);
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
    reconnectTimer = setTimeout(connectWS, 1200);
  };
}

function isKnownPeer(peerId) {
  return peers.some((p) => p.id === peerId);
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
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
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

function isArrayBufferLike(val) {
  return val instanceof ArrayBuffer || Object.prototype.toString.call(val) === "[object ArrayBuffer]";
}

// ================= End-to-End Encryption (ECDH P-256 + HKDF-SHA256 + AES-256-GCM) =================
/*
 * E2EE Protocol Architecture:
 * 1. Ephemeral Key Generation: Each peer generates a fresh P-256 ECDH key pair and a 16-byte CSPRNG nonce.
 * 2. Handshake: Peers exchange `e2ee-init` and `e2ee-ack` containing uncompressed raw public keys (65 bytes) and nonces.
 * 3. Canonical Transcript Binding:
 *    Peers are sorted lexicographically by server-assigned UUID (`lowId < highId`).
 *    Transcript = "MyDrop-E2EE-v1|<lowId>|<highId>|<pubLow>|<pubHigh>|<nonceLow>|<nonceHigh>"
 *    Salt = SHA-256(Transcript)
 * 4. HKDF-SHA256 Key Derivation:
 *    - Low->High AES-256-GCM key + 4-byte IV prefix
 *    - High->Low AES-256-GCM key + 4-byte IV prefix
 *    - 6-digit SAS (Short Authentication String) verification code for out-of-band MITM protection
 *    - Key confirmation MAC token (`e2ee-confirm`)
 * 5. Unique Nonce Guarantee:
 *    Each direction uses its own AES-256-GCM key and constructs a 12-byte IV:
 *    [4-byte directional salt || 1-byte channel ID (0x01=control, 0x02=chunk, 0x03=confirm) || 7-byte monotonic big-endian counter]
 *    A counter never wraps or repeats, guaranteeing zero AES-GCM nonce reuse.
 */

function buildDeterministicIv(salt4Bytes, channelByte, seqNumber) {
  if (!Number.isSafeInteger(seqNumber) || seqNumber <= 0) {
    throw new Error("Invalid sequence number for IV");
  }
  const iv = new Uint8Array(12);
  iv.set(salt4Bytes.subarray(0, 4), 0);
  iv[4] = channelByte & 0xff;
  // Write 56-bit big-endian monotonic counter into bytes 5..11
  let rem = BigInt(seqNumber);
  for (let i = 11; i >= 5; i--) {
    iv[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return iv;
}

const e2eeInitPromises = new Map(); // peerId -> Promise<sess>

async function createOrGetLocalE2EEState(peerId) {
  let sess = e2eeSessions.get(peerId);
  if (sess && sess.keyPair) return sess;
  if (e2eeInitPromises.has(peerId)) return e2eeInitPromises.get(peerId);

  const initPromise = (async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
    const rawPub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const nonceBytes = new Uint8Array(16);
    crypto.getRandomValues(nonceBytes);

    let resolveReady, rejectReady;
    const readyPromise = new Promise((res, rej) => {
      resolveReady = res;
      rejectReady = rej;
    });
    readyPromise.catch(() => {});

    const newSess = {
      peerId,
      state: "init",
      keyPair,
      myPubB64: bufToBase64(rawPub),
      myNonceB64: bufToBase64(nonceBytes),
      peerPubB64: null,
      peerNonceB64: null,
      txKey: null,
      rxKey: null,
      txSalt: null,
      rxSalt: null,
      txControlSeq: 0,
      rxControlSeq: 0,
      txChunkSeq: 0,
      rxChunkSeq: 0,
      seenRxNonces: new Set(),
      sas: "",
      readyPromise,
      resolveReady,
      rejectReady,
    };
    e2eeSessions.set(peerId, newSess);
    e2eeInitPromises.delete(peerId);
    return newSess;
  })();

  e2eeInitPromises.set(peerId, initPromise);
  return initPromise;
}

async function deriveSessionKeys(sess, peerId, peerPubB64, peerNonceB64) {
  if (sess.txKey && sess.rxKey && sess.peerPubB64 === peerPubB64 && sess.peerNonceB64 === peerNonceB64) {
    return;
  }

  if (typeof peerPubB64 !== "string" || typeof peerNonceB64 !== "string") {
    throw new Error("Invalid E2EE public key or nonce type");
  }
  const peerPubBuf = base64ToBuf(peerPubB64);
  const peerPubBytes = new Uint8Array(peerPubBuf);
  // Strictly verify uncompressed P-256 public key format (65 bytes starting with 0x04)
  if (peerPubBytes.byteLength !== 65 || peerPubBytes[0] !== 0x04) {
    throw new Error("Invalid P-256 uncompressed public key format");
  }
  const peerNonceBuf = base64ToBuf(peerNonceB64);
  if (peerNonceBuf.byteLength !== 16) {
    throw new Error("Invalid E2EE nonce length");
  }

  const peerPubKey = await crypto.subtle.importKey(
    "raw",
    peerPubBuf,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPubKey },
    sess.keyPair.privateKey,
    256
  );

  const hkdfBaseKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey", "deriveBits"]
  );

  const isLow = myId < peerId;
  const lowId = isLow ? myId : peerId;
  const highId = isLow ? peerId : myId;
  const pubLow = isLow ? sess.myPubB64 : peerPubB64;
  const pubHigh = isLow ? peerPubB64 : sess.myPubB64;
  const nonceLow = isLow ? sess.myNonceB64 : peerNonceB64;
  const nonceHigh = isLow ? peerNonceB64 : sess.myNonceB64;

  const transcriptStr = `MyDrop-E2EE-v1|${lowId}|${highId}|${pubLow}|${pubHigh}|${nonceLow}|${nonceHigh}`;
  const transcriptBytes = textEncoder.encode(transcriptStr);
  const transcriptHash = await crypto.subtle.digest("SHA-256", transcriptBytes);

  const lowToHighKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: transcriptHash,
      info: textEncoder.encode(`MyDrop-Key|${lowId}->${highId}`),
    },
    hkdfBaseKey,
    { name: "AES-GCM", length: 256 },
    false,
    isLow ? ["encrypt"] : ["decrypt"]
  );

  const highToLowKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: transcriptHash,
      info: textEncoder.encode(`MyDrop-Key|${highId}->${lowId}`),
    },
    hkdfBaseKey,
    { name: "AES-GCM", length: 256 },
    false,
    isLow ? ["decrypt"] : ["encrypt"]
  );

  // Derive 8 bytes for directional IV salts (4B low->high, 4B high->low) + 4 bytes for 6-digit SAS code
  const extraBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: transcriptHash,
      info: textEncoder.encode("MyDrop-IV-And-SAS-v1"),
    },
    hkdfBaseKey,
    96
  );
  const extraBytes = new Uint8Array(extraBits);
  const lowSalt = extraBytes.slice(0, 4);
  const highSalt = extraBytes.slice(4, 8);
  const sasVal =
    ((extraBytes[8] << 24) >>> 0) +
    ((extraBytes[9] << 16) >>> 0) +
    ((extraBytes[10] << 8) >>> 0) +
    (extraBytes[11] >>> 0);
  const sasNum = String(sasVal % 1000000).padStart(6, "0");

  sess.peerPubB64 = peerPubB64;
  sess.peerNonceB64 = peerNonceB64;
  sess.txKey = isLow ? lowToHighKey : highToLowKey;
  sess.rxKey = isLow ? highToLowKey : lowToHighKey;
  sess.txSalt = isLow ? lowSalt : highSalt;
  sess.rxSalt = isLow ? highSalt : lowSalt;
  sess.txControlSeq = 0;
  sess.rxControlSeq = 0;
  sess.txChunkSeq = 0;
  sess.rxChunkSeq = 0;
  sess.seenRxNonces.clear();
  sess.sas = `${sasNum.slice(0, 3)}-${sasNum.slice(3)}`;
  sess.transcriptHashB64 = bufToBase64(transcriptHash);
  sess.state = "established";
  sess.resolveReady(sess);
}

function sendHandshakePacket(peerId, pkt) {
  const c = conns.get(peerId);
  if (c?.dc?.readyState === "open") {
    try {
      c.dc.send(JSON.stringify(pkt));
      return;
    } catch {}
  }
  if (ws?.readyState === 1) {
    relaySend(peerId, pkt);
  }
}

function hasActivePeerTransaction(peerId) {
  if (incoming.has(peerId)) return true;
  for (const p of pendingResponses.values()) {
    if (p.peerId === peerId) return true;
  }
  for (const a of acceptedTransfers.values()) {
    if (a.peerId === peerId) return true;
  }
  return false;
}

async function handleE2EEHandshake(peerId, data) {
  try {
    const sess = await createOrGetLocalE2EEState(peerId);
    if (data.type === "e2ee-init") {
      // Prevent mid-transfer session reset DoS when a transfer or approval with this peer is already active
      if (sess.state === "established" && sess.peerNonceB64 && sess.peerNonceB64 !== data.nonce) {
        if (hasActivePeerTransaction(peerId)) {
          return;
        }
        e2eeSessions.delete(peerId);
        return handleE2EEHandshake(peerId, data);
      }
      await deriveSessionKeys(sess, peerId, data.pub, data.nonce);
      sendHandshakePacket(peerId, {
        type: "e2ee-ack",
        pub: sess.myPubB64,
        nonce: sess.myNonceB64,
        peerNonce: data.nonce,
      });
    } else if (data.type === "e2ee-ack") {
      if (data.peerNonce !== sess.myNonceB64) return;
      await deriveSessionKeys(sess, peerId, data.pub, data.nonce);
      // Send authenticated key confirmation
      const iv = buildDeterministicIv(sess.txSalt, 0x03, 1);
      const aad = textEncoder.encode(`MyDrop-Confirm-v1|${myId}|${peerId}`);
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad },
        sess.txKey,
        textEncoder.encode(sess.transcriptHashB64)
      );
      sendHandshakePacket(peerId, {
        type: "e2ee-confirm",
        iv: bufToBase64(iv),
        ct: bufToBase64(ct),
      });
    } else if (data.type === "e2ee-confirm") {
      if (sess.state !== "established" || !sess.rxKey) return;
      if (typeof data.iv !== "string" || typeof data.ct !== "string") {
        throw new Error("Malformed e2ee-confirm packet");
      }
      if (sess.seenRxNonces.has(data.iv)) {
        return;
      }
      const iv = new Uint8Array(base64ToBuf(data.iv));
      const expectedConfirmIv = buildDeterministicIv(sess.rxSalt, 0x03, 1);
      if (
        iv.byteLength !== 12 ||
        iv[4] !== 0x03 ||
        ! iv.every((b, idx) => b === expectedConfirmIv[idx])
      ) {
        throw new Error("Invalid e2ee-confirm IV structure");
      }
      const aad = textEncoder.encode(`MyDrop-Confirm-v1|${peerId}|${myId}`);
      const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad },
        sess.rxKey,
        base64ToBuf(data.ct)
      );
      const confirmedHash = textDecoder.decode(plainBuf);
      if (confirmedHash !== sess.transcriptHashB64) {
        throw new Error("E2EE key confirmation mismatch");
      }
      sess.seenRxNonces.add(data.iv);
      sess.peerConfirmed = true;
    }
  } catch (err) {
    console.error("E2EE handshake error:", err);
    const s = e2eeSessions.get(peerId);
    e2eeSessions.delete(peerId);
    try { s?.rejectReady?.(err); } catch {}
  }
}

async function ensureE2EESession(peerId) {
  let sess = await createOrGetLocalE2EEState(peerId);
  if (sess.state === "established" && sess.txKey && sess.rxKey) {
    return sess;
  }

  sendHandshakePacket(peerId, {
    type: "e2ee-init",
    pub: sess.myPubB64,
    nonce: sess.myNonceB64,
  });

  try {
    await Promise.race([
      sess.readyPromise,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("E2EE handshake timeout")), SECURITY_LIMITS.E2EE_HANDSHAKE_TIMEOUT_MS)
      ),
    ]);
    return sess;
  } catch (err) {
    e2eeSessions.delete(peerId);
    throw err;
  }
}

async function encryptControlMessage(peerId, payloadObj) {
  const sess = await ensureE2EESession(peerId);
  sess.txControlSeq += 1;
  const seq = sess.txControlSeq;
  const iv = buildDeterministicIv(sess.txSalt, 0x01, seq);
  const aad = textEncoder.encode(`MyDrop-Ctrl-v1|${myId}|${peerId}|${seq}`);
  const plainBytes = textEncoder.encode(JSON.stringify(payloadObj));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    sess.txKey,
    plainBytes
  );
  return {
    type: "enc-control",
    seq,
    iv: bufToBase64(iv),
    ct: bufToBase64(ctBuf),
  };
}

async function decryptControlMessage(peerId, packet) {
  const sess = e2eeSessions.get(peerId);
  if (!sess || sess.state !== "established" || !sess.rxKey) {
    // Peer may have retained an old session across a fast token reconnect; trigger re-key handshake
    createOrGetLocalE2EEState(peerId)
      .then((newSess) =>
        sendHandshakePacket(peerId, {
          type: "e2ee-init",
          pub: newSess.myPubB64,
          nonce: newSess.myNonceB64,
        })
      )
      .catch(() => {});
    throw new Error("No established E2EE session for control message");
  }
  if (!Number.isSafeInteger(packet.seq) || packet.seq <= sess.rxControlSeq) {
    throw new Error("Replayed or out-of-order control message rejected");
  }
  if (typeof packet.iv !== "string" || typeof packet.ct !== "string") {
    throw new Error("Malformed encrypted control packet");
  }
  if (sess.seenRxNonces.has(packet.iv)) {
    throw new Error("Duplicate nonce rejected");
  }

  const iv = new Uint8Array(base64ToBuf(packet.iv));
  if (iv.byteLength !== 12 || iv[4] !== 0x01) {
    throw new Error("Invalid control IV structure");
  }
  const aad = textEncoder.encode(`MyDrop-Ctrl-v1|${peerId}|${myId}|${packet.seq}`);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    sess.rxKey,
    base64ToBuf(packet.ct)
  );

  sess.rxControlSeq = packet.seq;
  sess.seenRxNonces.add(packet.iv);
  return JSON.parse(textDecoder.decode(plainBuf));
}

async function encryptFileChunk(peerId, transferId, fileIndex, chunkIndex, isLast, plainArrayBuffer) {
  const sess = await ensureE2EESession(peerId);
  sess.txChunkSeq += 1;
  const seq = sess.txChunkSeq;
  const iv = buildDeterministicIv(sess.txSalt, 0x02, seq);
  const aadStr = `MyDrop-Chunk-v1|${myId}|${peerId}|${transferId}|${fileIndex}|${chunkIndex}|${isLast ? 1 : 0}`;
  const aad = textEncoder.encode(aadStr);
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    sess.txKey,
    plainArrayBuffer
  );
  return {
    type: "enc-chunk",
    transferId,
    fileIndex,
    chunkIndex,
    last: Boolean(isLast),
    iv,
    ctBuf,
  };
}

// Pack encrypted chunk into a compact binary frame for WebRTC DataChannel
// Layout: [0xE2 (1B) | flags (1B) | fileIndex (2B) | chunkIndex (4B) | iv (12B) | transferId ASCII (36B) | ciphertext+tag] = 56B header
function packEncryptedChunkBinary(enc) {
  const ctBytes = new Uint8Array(enc.ctBuf);
  const frame = new Uint8Array(56 + ctBytes.byteLength);
  const view = new DataView(frame.buffer);
  frame[0] = 0xe2;
  frame[1] = enc.last ? 1 : 0;
  view.setUint16(2, enc.fileIndex, false);
  view.setUint32(4, enc.chunkIndex, false);
  frame.set(enc.iv, 8);
  const idBytes = textEncoder.encode(enc.transferId);
  frame.set(idBytes.subarray(0, 36), 20);
  frame.set(ctBytes, 56);
  return frame.buffer;
}

function unpackEncryptedChunkBinary(buf) {
  if (!isArrayBufferLike(buf) || buf.byteLength < 56 + 16) {
    throw new Error("Encrypted binary frame too short");
  }
  const bytes = new Uint8Array(buf);
  if (bytes[0] !== 0xe2) {
    throw new Error("Invalid binary frame header magic");
  }
  const view = new DataView(buf);
  const last = (bytes[1] & 1) === 1;
  const fileIndex = view.getUint16(2, false);
  const chunkIndex = view.getUint32(4, false);
  const iv = bytes.slice(8, 20);
  const transferId = textDecoder.decode(bytes.subarray(20, 56));
  const ctBuf = buf.slice(56);
  return {
    type: "enc-chunk",
    transferId,
    fileIndex,
    chunkIndex,
    last,
    iv,
    ctBuf,
  };
}

async function decryptFileChunk(peerId, packet) {
  const sess = e2eeSessions.get(peerId);
  if (!sess || sess.state !== "established" || !sess.rxKey) {
    throw new Error("No established E2EE session for chunk");
  }

  const ivBytes = packet.iv instanceof Uint8Array ? packet.iv : new Uint8Array(base64ToBuf(packet.iv));
  if (ivBytes.byteLength !== 12 || ivBytes[4] !== 0x02) {
    throw new Error("Invalid chunk IV structure");
  }

  // Extract 56-bit monotonic sequence number from IV bytes 5..11
  let seqBig = 0n;
  for (let i = 5; i < 12; i++) {
    seqBig = (seqBig << 8n) | BigInt(ivBytes[i]);
  }
  const seq = Number(seqBig);
  if (!Number.isSafeInteger(seq) || seq <= sess.rxChunkSeq) {
    throw new Error("Replayed or out-of-order chunk IV rejected");
  }

  const ivKey = bufToBase64(ivBytes);
  if (sess.seenRxNonces.has(ivKey)) {
    throw new Error("Duplicate chunk nonce rejected");
  }

  const ctBuf = isArrayBufferLike(packet.ctBuf) ? packet.ctBuf : base64ToBuf(packet.ct);
  const aadStr = `MyDrop-Chunk-v1|${peerId}|${myId}|${packet.transferId}|${packet.fileIndex}|${packet.chunkIndex}|${packet.last ? 1 : 0}`;
  const aad = textEncoder.encode(aadStr);

  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes, additionalData: aad },
    sess.rxKey,
    ctBuf
  );

  sess.rxChunkSeq = seq;
  sess.seenRxNonces.add(ivKey);
  if (sess.seenRxNonces.size > 4096) {
    const oldest = sess.seenRxNonces.values().next().value;
    if (oldest) sess.seenRxNonces.delete(oldest);
  }
  return plainBuf;
}

// ================= WebRTC (Perfect Negotiation กัน Glare) =================
function newConn(peerId) {
  const pc = new RTCPeerConnection(rtcConfig);
  let resolveOpen, rejectOpen;
  const open = new Promise((res, rej) => { resolveOpen = res; rejectOpen = rej; });
  open.catch(() => {});

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
  dc.onmessage = (e) => {
    onP2PMessage(peerId, e.data);
  };
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
  // Reserve 128 bytes for AES-GCM tag and binary framing header
  const sctpMax = c.pc.sctp?.maxMessageSize || 16384;
  c.chunk = Math.min(SECURITY_LIMITS.MAX_CHUNK_SIZE, Math.max(4096, sctpMax - 128));
  return c;
}

function createRelayTransport(peerId) {
  return {
    mode: "relay",
    chunk: SECURITY_LIMITS.MAX_CHUNK_SIZE,
    isOpen: () => ws?.readyState === 1,
    async sendEncryptedControl(obj) {
      const encPkt = await encryptControlMessage(peerId, obj);
      relaySend(peerId, encPkt);
    },
    async sendEncryptedChunk(transferId, fileIndex, chunkIndex, isLast, plainBuf) {
      const enc = await encryptFileChunk(peerId, transferId, fileIndex, chunkIndex, isLast, plainBuf);
      relaySend(peerId, {
        type: "enc-chunk",
        transferId: enc.transferId,
        fileIndex: enc.fileIndex,
        chunkIndex: enc.chunkIndex,
        last: enc.last,
        iv: bufToBase64(enc.iv),
        ct: bufToBase64(enc.ctBuf),
      });
      if (ws.bufferedAmount > 1024 * 1024) {
        await new Promise((r) => setTimeout(r, 25));
      }
    },
  };
}

// ลองเชื่อม WebRTC P2P ก่อน ถ้าถูกบล็อกให้สลับไปใช้ WebSocket Relay โดยทั้งสองโหมดเข้ารหัส E2EE (AES-256-GCM)
async function getTransport(peerId) {
  await ensureWS();
  try {
    const c = await connect(peerId);
    setStatus(peerId, "กำลังตรวจสอบกุญแจเข้ารหัส...");
    await ensureE2EESession(peerId);
    return {
      mode: "p2p",
      chunk: c.chunk,
      isOpen: () => c.dc?.readyState === "open",
      async sendEncryptedControl(obj) {
        const encPkt = await encryptControlMessage(peerId, obj);
        c.dc.send(JSON.stringify(encPkt));
      },
      async sendEncryptedChunk(transferId, fileIndex, chunkIndex, isLast, plainBuf) {
        const enc = await encryptFileChunk(peerId, transferId, fileIndex, chunkIndex, isLast, plainBuf);
        const binaryFrame = packEncryptedChunkBinary(enc);
        if (c.dc.bufferedAmount > MAX_BUFFER) {
          await new Promise((r) => c.dc.addEventListener("bufferedamountlow", r, { once: true }));
        }
        c.dc.send(binaryFrame);
      },
    };
  } catch {
    await ensureWS();
    setStatus(peerId, "กำลังสร้างช่องทาง Relay ที่เข้ารหัส...");
    await ensureE2EESession(peerId);
    setStatus(peerId, "โหมด Relay (เข้ารหัส E2EE)");
    return createRelayTransport(peerId);
  }
}

async function onSignal(from, data) {
  if (!data || typeof data !== "object") return;
  if (data.type === "e2ee-init" || data.type === "e2ee-ack" || data.type === "e2ee-confirm") {
    await handleE2EEHandshake(from, data);
    return;
  }

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
        if (c.pending.length < 64) {
          c.pending.push(data.candidate);
        }
      }
    }
  } catch (err) {
    console.error("signal error", err);
  }
}

// ================= ส่งไฟล์ / ข้อความ (E2EE) =================
async function sendFiles(peerId, files) {
  if (!files || !files.length) return false;
  if (!isKnownPeer(peerId)) {
    toast("ไม่พบอุปกรณ์ปลายทางในห้องนี้");
    return false;
  }

  const validation = validateOutgoingFiles(files);
  if (!validation.ok) {
    toast(validation.error);
    return false;
  }

  let tx;
  try {
    setStatus(peerId, "กำลังเชื่อมต่ออย่างปลอดภัย...");
    tx = await getTransport(peerId);
  } catch {
    setStatus(peerId, "");
    toast("สร้างการเชื่อมต่อที่ปลอดภัยไม่สำเร็จ");
    return false;
  }

  const transferId = uuid();
  const responsePromise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingResponses.delete(transferId);
      reject(new Error("timeout"));
    }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);
    pendingResponses.set(transferId, {
      peerId,
      timer,
      resolve: (v) => { clearTimeout(timer); resolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    });
  });

  const sanitizedManifest = files.map((f) => ({
    name: sanitizeFilename(f.name),
    size: f.size,
    mime: sanitizeMimeType(f.type),
  }));

  const reqMsg = {
    type: "file-request",
    transferId,
    files: sanitizedManifest,
  };

  try {
    await tx.sendEncryptedControl(reqMsg);
  } catch {
    try {
      await ensureWS();
      tx = createRelayTransport(peerId);
      await tx.sendEncryptedControl(reqMsg);
    } catch {
      const p = pendingResponses.get(transferId);
      if (p) clearTimeout(p.timer);
      pendingResponses.delete(transferId);
      setStatus(peerId, "");
      toast("เชื่อมต่อไม่สำเร็จ");
      return false;
    }
  }

  const sas = e2eeSessions.get(peerId)?.sas;
  setStatus(peerId, sas ? `รอผู้รับตอบรับ (รหัส: ${sas})` : "รอผู้รับตอบรับ...");

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

  for (let fileIndex = 0; fileIndex < files.length; fileIndex++) {
    const file = files[fileIndex];
    const meta = sanitizedManifest[fileIndex];

    if (!tx.isOpen()) {
      try {
        await ensureWS();
        tx = createRelayTransport(peerId);
      } catch {
        setProgress(peerId, null);
        toast("การเชื่อมต่อหลุดระหว่างส่ง");
        return false;
      }
    }

    const totalChunks = meta.size === 0 ? 0 : Math.ceil(meta.size / tx.chunk);
    try {
      await tx.sendEncryptedControl({
        type: "header",
        transferId,
        fileIndex,
        name: meta.name,
        size: meta.size,
        mime: meta.mime,
        totalChunks,
      });
    } catch {
      setProgress(peerId, null);
      toast("ส่งข้อมูลหัวไฟล์ไม่สำเร็จ");
      return false;
    }

    let offset = 0;
    let chunkIndex = 0;
    while (offset < file.size) {
      if (!tx.isOpen()) {
        setProgress(peerId, null);
        toast("การเชื่อมต่อหลุดระหว่างส่ง");
        return false;
      }
      const nextOffset = Math.min(file.size, offset + tx.chunk);
      const isLast = nextOffset >= file.size;
      const buf = await file.slice(offset, nextOffset).arrayBuffer();
      try {
        await tx.sendEncryptedChunk(transferId, fileIndex, chunkIndex, isLast, buf);
      } catch {
        setProgress(peerId, null);
        toast("การเข้ารหัสหรือส่งไฟล์ล้มเหลว");
        return false;
      }
      offset += buf.byteLength;
      chunkIndex += 1;
      setProgress(peerId, offset / file.size, `เข้ารหัสและส่ง ${meta.name}`);
    }
  }

  setProgress(peerId, null);
  toast(tx.mode === "relay" ? "ส่งเสร็จแล้ว (เข้ารหัส E2EE ผ่าน Relay)" : "ส่งเสร็จแล้ว (เข้ารหัส E2EE P2P)");
  return true;
}

async function sendText(peerId, presetText = null) {
  if (!isKnownPeer(peerId)) {
    toast("ไม่พบอุปกรณ์ปลายทางในห้องนี้");
    return false;
  }
  const text = presetText ?? prompt("พิมพ์ข้อความ:");
  if (!text) return false;

  const byteLen = textEncoder.encode(text).byteLength;
  if (byteLen > SECURITY_LIMITS.MAX_TEXT_BYTES) {
    toast(`ข้อความยาวเกินไป (สูงสุด ${formatSize(SECURITY_LIMITS.MAX_TEXT_BYTES)})`);
    return false;
  }

  try {
    const tx = await getTransport(peerId);
    await tx.sendEncryptedControl({ type: "text", text });
    setStatus(peerId, "");
    toast("ส่งข้อความที่เข้ารหัสแล้ว");
    return true;
  } catch {
    setStatus(peerId, "");
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

// ================= รับข้อมูลที่เข้ารหัส & ตรวจสอบความถูกต้อง =================
async function onP2PMessage(peerId, rawData) {
  try {
    if (typeof rawData === "string") {
      if (rawData.length > 131072) return;
      const pkt = JSON.parse(rawData);
      if (!pkt || typeof pkt !== "object") return;
      if (pkt.type === "e2ee-init" || pkt.type === "e2ee-ack" || pkt.type === "e2ee-confirm") {
        await handleE2EEHandshake(peerId, pkt);
      } else if (pkt.type === "enc-control") {
        const decryptedMsg = await decryptControlMessage(peerId, pkt);
        onDecryptedControl(peerId, decryptedMsg);
      } else if (pkt.type === "enc-chunk") {
        await onEncryptedChunk(peerId, pkt);
      }
      return;
    }

    if (isArrayBufferLike(rawData)) {
      if (rawData.byteLength > SECURITY_LIMITS.MAX_CHUNK_SIZE + 256) {
        abortPeerTransfer(peerId, "ขนาด Chunk เกินขีดจำกัดที่อนุญาต");
        return;
      }
      const pkt = unpackEncryptedChunkBinary(rawData);
      await onEncryptedChunk(peerId, pkt);
    }
  } catch (err) {
    console.error("P2P message error:", err);
    abortPeerTransfer(peerId, "การตรวจสอบความปลอดภัยของข้อมูลล้มเหลว");
  }
}

async function onRelayMessage(peerId, data) {
  if (!data || typeof data !== "object") return;
  try {
    if (data.type === "e2ee-init" || data.type === "e2ee-ack" || data.type === "e2ee-confirm") {
      await handleE2EEHandshake(peerId, data);
    } else if (data.type === "enc-control") {
      const decryptedMsg = await decryptControlMessage(peerId, data);
      onDecryptedControl(peerId, decryptedMsg);
    } else if (data.type === "enc-chunk") {
      await onEncryptedChunk(peerId, data);
    }
  } catch (err) {
    console.error("Relay message error:", err);
    abortPeerTransfer(peerId, "การตรวจสอบความปลอดภัยของข้อมูลล้มเหลว");
  }
}

function abortPeerTransfer(peerId, userReason) {
  const f = incoming.get(peerId);
  if (f) {
    cleanupAcceptedTransfer(f.transferId);
    cleanupIncomingTransfer(peerId);
    if (userReason) toast(userReason);
  }
}

function resetIncomingWatchdog(peerId, f) {
  clearTimeout(f.timer);
  f.timer = setTimeout(() => {
    abortPeerTransfer(peerId, `การรับไฟล์ ${f.meta.name} หมดเวลาเชื่อมต่อ`);
  }, SECURITY_LIMITS.CHUNK_INACTIVITY_TIMEOUT_MS);
}

function checkPeerControlRate(peerId) {
  const now = Date.now();
  let state = peerClientRate.get(peerId);
  if (!state || now - state.windowStart >= 10000) {
    state = { windowStart: now, count: 0 };
    peerClientRate.set(peerId, state);
  }
  state.count += 1;
  return state.count <= SECURITY_LIMITS.MAX_CLIENT_CTRL_PER_10S;
}

function refreshAcceptedTransferTimer(approved) {
  if (!approved) return;
  clearTimeout(approved.timer);
  approved.timer = setTimeout(() => {
    for (const [tid, entry] of acceptedTransfers) {
      if (entry === approved) {
        cleanupAcceptedTransfer(tid);
        break;
      }
    }
  }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);
}

function onDecryptedControl(peerId, msg) {
  if (!msg || typeof msg !== "object") return;
  if (!checkPeerControlRate(peerId)) return;

  if (msg.type === "text") {
    if (typeof msg.text !== "string" || !msg.text.trim()) return;
    if (textEncoder.encode(msg.text).byteLength > SECURITY_LIMITS.MAX_TEXT_BYTES) return;
    addReceivedText(peerName(peerId), msg.text);
    return;
  }

  if (msg.type === "file-request") {
    const check = validateIncomingFileRequest(msg);
    if (!check.ok) return;
    if (!rememberSeenRequest(check.transferId)) return;

    // Enforce maximum 5 pending incoming file requests per device
    const pendingCount = requestQueue.length + (activeRequest ? 1 : 0);
    if (pendingCount >= SECURITY_LIMITS.MAX_PENDING_REQUESTS) {
      // Auto-reject when queue is full to prevent memory/UI exhaustion
      sendEncryptedFileResponse(peerId, check.transferId, false).catch(() => {});
      return;
    }

    const reqEntry = {
      peerId,
      transferId: check.transferId,
      files: check.files,
      totalBytes: check.totalBytes,
      createdAt: Date.now(),
      expireTimer: null,
    };

    reqEntry.expireTimer = setTimeout(() => {
      const idx = requestQueue.indexOf(reqEntry);
      if (idx !== -1) {
        requestQueue.splice(idx, 1);
      } else if (activeRequest === reqEntry) {
        activeRequest = null;
        $("#confirmModal").style.display = "none";
        processRequestQueue();
      }
    }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);

    requestQueue.push(reqEntry);
    processRequestQueue();
    return;
  }

  if (msg.type === "file-response") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const pending = pendingResponses.get(msg.transferId);
    // Verify response actually came from the expected target peer
    if (pending && pending.peerId === peerId) {
      pendingResponses.delete(msg.transferId);
      pending.resolve(Boolean(msg.accepted));
    }
    return;
  }

  if (msg.type === "header") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const approved = acceptedTransfers.get(msg.transferId);
    if (!approved || approved.peerId !== peerId) return;

    // Prevent starting a new file while another file from this peer is still incomplete
    if (incoming.has(peerId)) {
      abortPeerTransfer(peerId, "ลำดับการส่งไฟล์ไม่ถูกต้อง");
      return;
    }

    const expectedFileIndex = approved.nextFileIndex;
    if (msg.fileIndex !== expectedFileIndex || expectedFileIndex >= approved.files.length) {
      cleanupAcceptedTransfer(msg.transferId);
      return;
    }

    const approvedFile = approved.files[expectedFileIndex];
    const cleanHeaderName = sanitizeFilename(msg.name);

    // Strictly verify that header metadata matches what the user approved in the modal
    if (
      cleanHeaderName !== approvedFile.name ||
      msg.size !== approvedFile.size ||
      !Number.isSafeInteger(msg.size) ||
      msg.size < 0 ||
      msg.size > SECURITY_LIMITS.MAX_FILE_SIZE
    ) {
      cleanupAcceptedTransfer(msg.transferId);
      toast("ปฏิเสธไฟล์: ข้อมูลไฟล์ไม่ตรงกับที่ขออนุญาตไว้");
      return;
    }

    approved.nextFileIndex += 1;
    clearTimeout(approved.timer);
    approved.timer = setTimeout(() => {
      cleanupAcceptedTransfer(msg.transferId);
    }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);

    const fState = {
      transferId: msg.transferId,
      fileIndex: expectedFileIndex,
      meta: approvedFile,
      chunks: [],
      received: 0,
      expectedChunkIndex: 0,
      timer: null,
    };
    incoming.set(peerId, fState);

    if (approvedFile.size === 0) {
      finishFile(peerId);
    } else {
      resetIncomingWatchdog(peerId, fState);
    }
  }
}

async function onEncryptedChunk(peerId, packet) {
  const f = incoming.get(peerId);
  if (!f) return;

  if (
    packet.transferId !== f.transferId ||
    packet.fileIndex !== f.fileIndex ||
    packet.chunkIndex !== f.expectedChunkIndex
  ) {
    abortPeerTransfer(peerId, "ตรวจพบลำดับข้อมูลไฟล์ผิดปกติหรือซ้ำซ้อน");
    return;
  }

  const approved = acceptedTransfers.get(f.transferId);
  if (!approved || approved.peerId !== peerId) {
    abortPeerTransfer(peerId, "ไม่พบสิทธิ์การส่งไฟล์นี้");
    return;
  }

  // Decrypt and verify AES-256-GCM authentication tag & AAD
  const plainBuf = await decryptFileChunk(peerId, packet);

  if (plainBuf.byteLength === 0 || plainBuf.byteLength > SECURITY_LIMITS.MAX_CHUNK_SIZE) {
    abortPeerTransfer(peerId, "ขนาดข้อมูลย่อย (Chunk) ไม่ถูกต้อง");
    return;
  }

  if (
    f.received + plainBuf.byteLength > f.meta.size ||
    approved.receivedTotalBytes + plainBuf.byteLength > approved.totalBytes
  ) {
    abortPeerTransfer(peerId, "ผู้ส่งส่งข้อมูลเกินขนาดไฟล์ที่ระบุไว้");
    return;
  }

  f.chunks.push(plainBuf);
  f.received += plainBuf.byteLength;
  f.expectedChunkIndex += 1;
  approved.receivedTotalBytes += plainBuf.byteLength;
  refreshAcceptedTransferTimer(approved);

  if (packet.last && f.received !== f.meta.size) {
    abortPeerTransfer(peerId, "ข้อมูลไฟล์ไม่ครบตามขนาดที่ระบุ");
    return;
  }
  if (!packet.last && f.received >= f.meta.size) {
    abortPeerTransfer(peerId, "โครงสร้างข้อมูลไฟล์ไม่ถูกต้อง");
    return;
  }

  setProgress(peerId, f.received / f.meta.size, `รับและถอดรหัส ${f.meta.name}`);

  if (packet.last && f.received === f.meta.size) {
    finishFile(peerId);
  } else {
    resetIncomingWatchdog(peerId, f);
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function processRequestQueue() {
  if (activeRequest || requestQueue.length === 0) return;
  activeRequest = requestQueue.shift();

  const total = activeRequest.totalBytes;
  $("#modalTitle").textContent = `${peerName(activeRequest.peerId)} ต้องการส่งไฟล์`;
  $("#modalSub").textContent = `จำนวน ${activeRequest.files.length} ไฟล์ (รวม ${formatSize(total)})`;

  const secBadge = $("#modalSecurityInfo");
  if (secBadge) {
    const sas = e2eeSessions.get(activeRequest.peerId)?.sas;
    secBadge.textContent = sas
      ? `🔒 เข้ารหัส End-to-End (AES-256-GCM) • รหัสยืนยัน: ${sas}`
      : "🔒 เข้ารหัส End-to-End (AES-256-GCM)";
  }

  const hasDangerous = activeRequest.files.some((f) => f.dangerous);
  const warningEl = $("#modalWarning");
  if (warningEl) {
    if (hasDangerous) {
      warningEl.hidden = false;
      warningEl.textContent =
        "⚠️ คำเตือนความปลอดภัย: มีไฟล์ที่อาจเป็นอันตราย (เช่น โปรแกรม, สคริปต์ หรือไฟล์ HTML/SVG) โปรดตรวจสอบว่าคุณรู้จักผู้ส่งก่อนกดยอมรับ";
    } else {
      warningEl.hidden = true;
      warningEl.textContent = "";
    }
  }

  const list = $("#modalFiles");
  list.textContent = "";
  for (const f of activeRequest.files) {
    const li = document.createElement("li");
    const nameSpan = document.createElement("span");
    nameSpan.textContent = f.dangerous ? `⚠️ ${f.name}` : f.name;
    if (f.dangerous) nameSpan.style.color = "#fca5a5";

    const sizeSpan = document.createElement("span");
    sizeSpan.textContent = formatSize(f.size || 0);
    sizeSpan.style.color = "#94a3b8";
    li.append(nameSpan, sizeSpan);
    list.appendChild(li);
  }
  $("#confirmModal").style.display = "flex";
}

async function sendEncryptedFileResponse(peerId, transferId, accepted) {
  const reply = { type: "file-response", transferId, accepted: Boolean(accepted) };
  const encPkt = await encryptControlMessage(peerId, reply);
  const c = conns.get(peerId);
  let sentP2P = false;
  if (c?.dc?.readyState === "open") {
    try {
      c.dc.send(JSON.stringify(encPkt));
      sentP2P = true;
    } catch {}
  }
  if (!sentP2P) {
    await ensureWS();
    relaySend(peerId, encPkt);
  }
}

async function respondToActiveRequest(accepted) {
  if (!activeRequest) return;
  const req = activeRequest;
  clearTimeout(req.expireTimer);
  activeRequest = null;
  $("#confirmModal").style.display = "none";

  const { peerId, transferId, files, totalBytes } = req;

  if (accepted) {
    const timer = setTimeout(() => {
      cleanupAcceptedTransfer(transferId);
    }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);

    acceptedTransfers.set(transferId, {
      peerId,
      files,
      nextFileIndex: 0,
      totalBytes,
      receivedTotalBytes: 0,
      createdAt: Date.now(),
      timer,
    });
  }

  try {
    await sendEncryptedFileResponse(peerId, transferId, accepted);
  } catch {
    if (accepted) cleanupAcceptedTransfer(transferId);
    toast("ส่งการตอบรับไม่สำเร็จ");
  }
  processRequestQueue();
}

$("#acceptBtn").onclick = () => respondToActiveRequest(true);
$("#rejectBtn").onclick = () => respondToActiveRequest(false);

function finishFile(peerId) {
  const f = incoming.get(peerId);
  if (!f) return;
  clearTimeout(f.timer);
  incoming.delete(peerId);

  const approved = acceptedTransfers.get(f.transferId);
  if (approved) {
    if (approved.nextFileIndex >= approved.files.length) {
      cleanupAcceptedTransfer(f.transferId);
    } else {
      refreshAcceptedTransferTimer(approved);
    }
  }

  const safeMime = getSafeDownloadMime(f.meta.name, f.meta.mime);
  const blob = new Blob(f.chunks, { type: safeMime });
  f.chunks = [];

  addReceivedFile(peerName(peerId), f.meta.name, blob, f.meta.dangerous);
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
  const check = validateOutgoingFiles(files);
  if (!check.ok) {
    toast(check.error);
    return;
  }
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
  box.textContent = "";
  peerElements.clear();
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
      <div class="peer-type"></div>
      <div class="name"></div>
      <div class="progress"><div class="bar"></div></div>
      <div class="status"></div>`;

    el.querySelector(".peer-type").textContent = devLabel;
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

    el.ondragover = (e) => { e.preventDefault(); e.stopPropagation(); el.classList.add("drag"); };
    el.ondragleave = () => el.classList.remove("drag");
    el.ondrop = (e) => {
      e.preventDefault();
      e.stopPropagation();
      el.classList.remove("drag");
      sendFiles(p.id, [...e.dataTransfer.files]);
    };

    peerElements.set(p.id, el);
    box.appendChild(el);
  });
}

function setStatus(peerId, text) {
  if (text) peerStatus.set(peerId, text);
  else peerStatus.delete(peerId);
  const card = peerElements.get(peerId);
  const s = card?.querySelector(".status");
  if (s) s.textContent = text;
}

function setProgress(peerId, ratio, label = "") {
  if (ratio === null) {
    peerProgress.delete(peerId);
  } else {
    peerProgress.set(peerId, { ratio, label });
  }
  const card = peerElements.get(peerId);
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

function registerObjectUrl(url, itemElement) {
  activeObjectUrls.push({ url, itemElement });
  while (activeObjectUrls.length > SECURITY_LIMITS.MAX_RETAINED_BLOBS) {
    const oldest = activeObjectUrls.shift();
    if (oldest) {
      try { URL.revokeObjectURL(oldest.url); } catch {}
      oldest.itemElement?.remove();
    }
  }
}

function revokeAndRemoveItem(url, itemElement) {
  try { URL.revokeObjectURL(url); } catch {}
  const idx = activeObjectUrls.findIndex((e) => e.url === url);
  if (idx !== -1) activeObjectUrls.splice(idx, 1);
  itemElement.remove();
}

function enforceReceivedInboxCap() {
  const box = $("#received");
  if (!box || !Array.isArray(box.children)) {
    // Handle both real DOM NodeList/HTMLCollection and mock test arrays
    while (box?.children && box.children.length > SECURITY_LIMITS.MAX_RECEIVED_ITEMS) {
      const last = box.children[box.children.length - 1];
      if (!last) break;
      if (Array.isArray(box.children)) box.children.pop();
      else last.remove?.();
    }
    return;
  }
  while (box.children.length > SECURITY_LIMITS.MAX_RECEIVED_ITEMS) {
    const oldestEl = box.children.pop();
    oldestEl?.remove?.();
  }
}

function addReceivedFile(from, name, blob, isDangerous = false) {
  const safeName = sanitizeFilename(name);
  const dangerous = isDangerous || isDangerousFile(safeName, blob.type);

  const item = document.createElement("div");
  item.className = "item";

  const infoWrap = document.createElement("div");
  const info = document.createElement("div");
  info.textContent = `${safeName} (${formatSize(blob.size)}) จาก ${from}`;
  infoWrap.appendChild(info);

  if (dangerous) {
    const badge = document.createElement("div");
    badge.className = "danger-badge";
    badge.textContent = "⚠️ ไฟล์ประเภทนี้อาจเป็นอันตราย โปรดระวังก่อนเปิดใช้งาน";
    infoWrap.appendChild(badge);
  }

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const objUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objUrl;
  a.download = safeName;
  a.rel = "noopener noreferrer";
  a.textContent = "บันทึก";
  if (dangerous) {
    a.onclick = (e) => {
      const ok = confirm(
        `คำเตือน: "${safeName}" เป็นประเภทไฟล์ที่อาจทำงานได้หรือเป็นอันตรายต่อเครื่องของคุณ คุณแน่ใจหรือไม่ว่าต้องการบันทึกไฟล์นี้?`
      );
      if (!ok) e.preventDefault();
    };
  }

  const dismissBtn = document.createElement("button");
  dismissBtn.type = "button";
  dismissBtn.className = "item-dismiss";
  dismissBtn.title = "ลบและคืนหน่วยความจำ";
  dismissBtn.textContent = "✕";
  dismissBtn.onclick = () => revokeAndRemoveItem(objUrl, item);

  actions.append(a, dismissBtn);
  item.append(infoWrap, actions);
  registerObjectUrl(objUrl, item);
  $("#received").prepend(item);
  enforceReceivedInboxCap();
}

function addReceivedText(from, text) {
  const item = document.createElement("div");
  item.className = "item";
  const t = document.createElement("div");
  t.className = "text";
  t.textContent = `${from}: ${text}`;

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const btn = document.createElement("a");
  btn.href = "#";
  btn.textContent = "คัดลอก";
  btn.onclick = (e) => {
    e.preventDefault();
    navigator.clipboard?.writeText(text);
    toast("คัดลอกแล้ว");
  };

  const dismissBtn = document.createElement("button");
  dismissBtn.type = "button";
  dismissBtn.className = "item-dismiss";
  dismissBtn.title = "ลบข้อความ";
  dismissBtn.textContent = "✕";
  dismissBtn.onclick = () => item.remove();

  actions.append(btn, dismissBtn);
  item.append(t, actions);
  $("#received").prepend(item);
  enforceReceivedInboxCap();
}

function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.style.display = "block";
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.style.display = "none"), 3000);
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

// Expose security primitives for automated testing & audit verification
window.MyDropSecurity = {
  SECURITY_LIMITS,
  configureSecurityLimits,
  sanitizeFilename,
  sanitizeMimeType,
  isDangerousFile,
  getSafeDownloadMime,
  validateOutgoingFiles,
  validateIncomingFileRequest,
  buildDeterministicIv,
  packEncryptedChunkBinary,
  unpackEncryptedChunkBinary,
  generateSecureRoomCode,
};

updateRoomUI();
updateDropZoneUI();
checkPendingShare();
connectWS();
