// ================= Security Configuration & Configurable Limits =================
const SECURITY_LIMITS = {
  MAX_FILES_PER_TRANSFER: 10,
  MAX_FILE_SIZE: 5 * 1024 * 1024 * 1024,        // 5 GB per file (P2P target)
  MAX_TOTAL_TRANSFER_SIZE: 10 * 1024 * 1024 * 1024, // 10 GB total per transfer (P2P)
  MAX_RELAY_FILE_SIZE: 500 * 1024 * 1024,       // 500 MB max per file over DO WebSocket Relay fallback
  MAX_RELAY_TOTAL_SIZE: 500 * 1024 * 1024,      // 500 MB max total over DO WebSocket Relay fallback
  INITIAL_CHUNK_SIZE: 1 * 1024 * 1024,          // 1 MB initial logical chunk size (adapts 1-4 MB)
  MIN_CHUNK_SIZE: 256 * 1024,                   // 256 KB minimum adaptive P2P chunk size
  MAX_CHUNK_SIZE: 4 * 1024 * 1024,              // 4 MB maximum logical chunk size
  RELAY_CHUNK_SIZE: 64 * 1024,                  // 64 KB plaintext chunk over WebSocket Relay (< 128 KB DO frame limit)
  SCTP_SAFE_FRAME_SIZE: 64 * 1024,              // 64 KB SCTP sub-frame payload for cross-browser iOS/Android DataChannels
  MAX_IN_FLIGHT_BYTES: 16 * 1024 * 1024,        // 16 MB max unacknowledged in-flight bytes on sender (receiver backpressure)
  STORAGE_COMPACT_THRESHOLD: 8 * 1024 * 1024,   // 8 MB compaction threshold when OPFS is unavailable
  INTEGRITY_BLOCK_SIZE: 1 * 1024 * 1024,        // 1 MB block size for hardware-accelerated streaming SHA-256
  MAX_OUT_OF_ORDER_CHUNKS: 8,                   // Max buffered out-of-order chunks during missing chunk retransmission
  MAX_TEXT_BYTES: 16 * 1024,                    // 16 KB per text message
  MAX_PENDING_REQUESTS: 5,                      // Max 5 pending incoming file requests
  MAX_FILENAME_LENGTH: 255,                     // Max 255 characters per filename
  REQUEST_TIMEOUT_MS: 60000,                    // 60s timeout for recipient approval
  CHUNK_INACTIVITY_TIMEOUT_MS: 45000,           // 45s inactivity timeout during active file reception
  RESUME_TIMEOUT_MS: 30000,                     // 30s window to reconnect and resume an interrupted transfer
  PAUSE_TIMEOUT_MS: 300000,                     // 5 min timeout while transfer is explicitly paused
  E2EE_HANDSHAKE_TIMEOUT_MS: 8000,              // 8s timeout for ECDH key exchange
  MAX_SEEN_REQUEST_IDS: 500,                    // Bounded replay cache size
  MAX_RETAINED_BLOBS: 25,                       // Max retained Object URLs before auto-revoking oldest
  MAX_RECEIVED_ITEMS: 50,                       // Max retained DOM items in #received inbox
  MAX_CLIENT_CTRL_PER_10S: 250,                 // Max incoming decrypted control/ack messages per peer per 10s
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

function validateOutgoingFiles(files, transportMode = "p2p") {
  if (!Array.isArray(files) || files.length === 0) {
    return { ok: false, error: "กรุณาเลือกไฟล์ก่อนส่ง" };
  }
  if (files.length > SECURITY_LIMITS.MAX_FILES_PER_TRANSFER) {
    return {
      ok: false,
      error: `ส่งได้สูงสุด ${SECURITY_LIMITS.MAX_FILES_PER_TRANSFER} ไฟล์ต่อครั้ง`,
    };
  }
  const isRelay = transportMode === "relay";
  const maxFileLimit = isRelay
    ? Math.min(SECURITY_LIMITS.MAX_FILE_SIZE, SECURITY_LIMITS.MAX_RELAY_FILE_SIZE)
    : SECURITY_LIMITS.MAX_FILE_SIZE;
  const maxTotalLimit = isRelay
    ? Math.min(SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE, SECURITY_LIMITS.MAX_RELAY_TOTAL_SIZE)
    : SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE;

  let totalBytes = 0;
  for (const f of files) {
    if (!(f instanceof Blob) || typeof f.size !== "number" || f.size < 0 || !Number.isSafeInteger(f.size)) {
      return { ok: false, error: "ข้อมูลไฟล์ไม่ถูกต้อง" };
    }
    if (f.size > maxFileLimit) {
      return {
        ok: false,
        error: isRelay
          ? `โหมด Relay รองรับไฟล์ขนาดสูงสุด ${formatSize(maxFileLimit)} ต่อไฟล์ (ไฟล์ "${sanitizeFilename(f.name)}" มีขนาด ${formatSize(f.size)} กรุณาเชื่อมต่อผ่าน WebRTC P2P หรือ TURN)`
          : `ไฟล์ "${sanitizeFilename(f.name)}" มีขนาดเกิน ${formatSize(maxFileLimit)}`,
      };
    }
    totalBytes += f.size;
    if (totalBytes > maxTotalLimit) {
      return {
        ok: false,
        error: isRelay
          ? `โหมด Relay รองรับขนาดไฟล์รวมสูงสุด ${formatSize(maxTotalLimit)} ต่อครั้ง`
          : `ขนาดไฟล์รวมเกินขีดจำกัด (${formatSize(maxTotalLimit)} ต่อครั้ง)`,
      };
    }
  }
  return { ok: true, totalBytes };
}

function validateIncomingFileRequest(msg, transportMode = "p2p") {
  if (!msg || typeof msg !== "object") return { ok: false, error: "Invalid request" };
  if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) {
    return { ok: false, error: "Invalid transferId" };
  }
  if (!Array.isArray(msg.files) || msg.files.length === 0 || msg.files.length > SECURITY_LIMITS.MAX_FILES_PER_TRANSFER) {
    return { ok: false, error: "Invalid file count" };
  }

  const isRelay = transportMode === "relay" || msg.transportMode === "relay";
  const maxFileLimit = isRelay
    ? Math.min(SECURITY_LIMITS.MAX_FILE_SIZE, SECURITY_LIMITS.MAX_RELAY_FILE_SIZE)
    : SECURITY_LIMITS.MAX_FILE_SIZE;
  const maxTotalLimit = isRelay
    ? Math.min(SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE, SECURITY_LIMITS.MAX_RELAY_TOTAL_SIZE)
    : SECURITY_LIMITS.MAX_TOTAL_TRANSFER_SIZE;

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
      rawFile.size > maxFileLimit
    ) {
      return { ok: false, error: isRelay ? "File size exceeds Relay limit" : "Invalid file size" };
    }
    totalBytes += rawFile.size;
    if (totalBytes > maxTotalLimit) {
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
const activeOutgoingTransfers = new Map(); // transferId -> outgoing transfer controller state
const sctpFragAssemblers = new Map();      // peerId -> { fileIndex, chunkIndex, totalFrags, nextFrag, chunks, totalBytes, timer }
const peerRxQueues = new Map();            // peerId -> Promise chain serializing async WebCrypto & OPFS storage operations
let activeWakeLock = null;

function enqueuePeerRx(peerId, taskFn) {
  const prev = peerRxQueues.get(peerId) || Promise.resolve();
  const next = prev.then(taskFn, taskFn);
  peerRxQueues.set(peerId, next);
  next.finally(() => {
    if (peerRxQueues.get(peerId) === next) {
      peerRxQueues.delete(peerId);
    }
  });
  return next;
}

async function acquireWakeLock() {
  try {
    if (typeof navigator !== "undefined" && navigator.wakeLock && typeof navigator.wakeLock.request === "function") {
      if (!activeWakeLock) {
        activeWakeLock = await navigator.wakeLock.request("screen");
        activeWakeLock?.addEventListener?.("release", () => {
          activeWakeLock = null;
        });
      }
    }
  } catch {
    // WakeLock may fail on battery saver or unsupported browser; fail safely
  }
}

async function releaseWakeLockIfIdle() {
  if (incoming.size > 0 || activeOutgoingTransfers.size > 0) return;
  if (activeWakeLock) {
    try {
      await activeWakeLock.release();
    } catch {}
    activeWakeLock = null;
  }
}

function detectPlatformCapabilities() {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  const isIOS = /iPhone|iPad|iPod/i.test(ua);
  const isAndroid = /Android/i.test(ua);
  const isSafari = /Safari/i.test(ua) && !/Chrome|Chromium|CriOS|FxiOS|EdgiOS/i.test(ua);
  const hasOPFS = Boolean(
    typeof navigator !== "undefined" &&
      navigator.storage &&
      typeof navigator.storage.getDirectory === "function"
  );
  const hasIndexedDB = typeof indexedDB !== "undefined";
  return { isIOS, isAndroid, isSafari, isMobile: isIOS || isAndroid, hasOPFS, hasIndexedDB };
}

async function checkStorageQuota(requiredBytes) {
  if (!Number.isSafeInteger(requiredBytes) || requiredBytes <= 0) {
    return { ok: true, availableBytes: null };
  }
  try {
    if (typeof navigator !== "undefined" && navigator.storage && typeof navigator.storage.estimate === "function") {
      const est = await navigator.storage.estimate();
      if (est && typeof est.quota === "number" && est.quota > 0) {
        const usage = typeof est.usage === "number" ? est.usage : 0;
        const availableBytes = Math.max(0, est.quota - usage);
        // Require at least 5% or 16 MB safety headroom
        const safetyMargin = Math.min(64 * 1024 * 1024, Math.max(4 * 1024 * 1024, Math.floor(requiredBytes * 0.05)));
        if (availableBytes < requiredBytes + safetyMargin) {
          return {
            ok: false,
            availableBytes,
            quota: est.quota,
            error: `พื้นที่จัดเก็บข้อมูลของเบราว์เซอร์ไม่เพียงพอ (ต้องการ ${formatSize(requiredBytes)} แต่เหลือพื้นที่ว่าง ${formatSize(availableBytes)})`,
          };
        }
        return { ok: true, availableBytes, quota: est.quota };
      }
    }
  } catch {
    // Proceed if storage.estimate() is restricted
  }
  return { ok: true, availableBytes: null };
}

// ================= Streaming Cryptographic Integrity Hasher (SHA-256) =================
/*
 * Computes a deterministic SHA-256 integrity digest without loading the entire file into RAM:
 * - Feeds incoming bytes sequentially into fixed INTEGRITY_BLOCK_SIZE (default 1 MB) blocks.
 * - Uses hardware-accelerated WebCrypto `crypto.subtle.digest("SHA-256", block)` on each block.
 * - For files <= 1 MB (single block), returns the direct standard SHA-256 hex digest of the file bytes.
 * - For files > 1 MB (multi-block up to 5 GB+), hashes the concatenated 32-byte block digests + 8-byte total size
 *   with `crypto.subtle.digest("SHA-256", ...)`.
 * - Because block boundaries are fixed at 1 MB file offsets, the resulting SHA-256 digest is 100% independent
 *   of transport chunk sizes (whether 64 KB Relay, 1 MB, 2 MB, or 4 MB adaptive P2P chunks).
 */
class IntegrityHasher {
  constructor(blockSize = SECURITY_LIMITS.INTEGRITY_BLOCK_SIZE) {
    this.blockSize = Math.max(64 * 1024, blockSize || 1024 * 1024);
    this.buffer = new Uint8Array(this.blockSize);
    this.bufLen = 0;
    this.totalBytes = 0;
    this.blockDigests = [];
    this.finalHex = null;
  }

  async update(chunkLike) {
    if (this.finalHex) throw new Error("Hasher already finalized");
    const bytes =
      chunkLike instanceof Uint8Array
        ? chunkLike
        : isArrayBufferLike(chunkLike)
        ? new Uint8Array(chunkLike)
        : new Uint8Array(chunkLike.buffer || chunkLike);
    let offset = 0;
    this.totalBytes += bytes.byteLength;

    while (offset < bytes.byteLength) {
      const space = this.blockSize - this.bufLen;
      const take = Math.min(space, bytes.byteLength - offset);
      if (this.bufLen === 0 && take === this.blockSize) {
        const slice = bytes.subarray(offset, offset + this.blockSize);
        const digest = await crypto.subtle.digest("SHA-256", slice);
        this.blockDigests.push(new Uint8Array(digest));
      } else {
        this.buffer.set(bytes.subarray(offset, offset + take), this.bufLen);
        this.bufLen += take;
        if (this.bufLen === this.blockSize) {
          const digest = await crypto.subtle.digest("SHA-256", this.buffer);
          this.blockDigests.push(new Uint8Array(digest));
          this.bufLen = 0;
        }
      }
      offset += take;
    }
  }

  async finalize() {
    if (this.finalHex) return this.finalHex;
    if (this.totalBytes === 0) {
      const emptyDigest = await crypto.subtle.digest("SHA-256", new Uint8Array(0));
      this.finalHex = bytesToHex(new Uint8Array(emptyDigest));
      this.buffer = null;
      return this.finalHex;
    }
    if (this.bufLen > 0) {
      const tail = this.buffer.subarray(0, this.bufLen);
      const digest = await crypto.subtle.digest("SHA-256", tail);
      this.blockDigests.push(new Uint8Array(digest));
      this.bufLen = 0;
    }
    this.buffer = null;

    if (this.blockDigests.length === 1) {
      this.finalHex = bytesToHex(this.blockDigests[0]);
      this.blockDigests = [];
      return this.finalHex;
    }

    const summary = new Uint8Array(this.blockDigests.length * 32 + 8);
    for (let i = 0; i < this.blockDigests.length; i++) {
      summary.set(this.blockDigests[i], i * 32);
    }
    const view = new DataView(summary.buffer);
    view.setBigUint64(this.blockDigests.length * 32, BigInt(this.totalBytes), false);
    const rootDigest = await crypto.subtle.digest("SHA-256", summary);
    this.blockDigests = [];
    this.finalHex = bytesToHex(new Uint8Array(rootDigest));
    return this.finalHex;
  }
}

function bytesToHex(uint8) {
  let out = "";
  for (let i = 0; i < uint8.byteLength; i++) {
    out += uint8[i].toString(16).padStart(2, "0");
  }
  return out;
}

async function computeBlobSha256(blob, blockSize = SECURITY_LIMITS.INTEGRITY_BLOCK_SIZE) {
  if (!(blob instanceof Blob)) throw new Error("Expected Blob or File");
  const hasher = new IntegrityHasher(blockSize);
  const step = hasher.blockSize;
  let offset = 0;
  while (offset < blob.size) {
    const next = Math.min(blob.size, offset + step);
    const buf = await blob.slice(offset, next).arrayBuffer();
    await hasher.update(buf);
    offset = next;
  }
  return hasher.finalize();
}

// ================= 3-Tier Receiver Storage Engine (OPFS -> Segmented Blob Compaction) =================
/*
 * Prevents accumulating thousands of raw ArrayBuffers in JS heap RAM during large 1-5 GB transfers:
 * - Tier 1 (OPFS): Streams chunks directly to disk in the Origin Private File System (`navigator.storage.getDirectory()`)
 *   and returns a disk-backed `File` (`Blob`) at completion with near-zero RAM footprint.
 * - Tier 2 (Segmented Blob Compaction): Periodically compacts incoming chunks every `STORAGE_COMPACT_THRESHOLD` (8 MB)
 *   into immutable `Blob` segments and immediately releases the raw `ArrayBuffer` references so the browser can
 *   page Blob data and GC raw buffers without ever concatenating large ArrayBuffers.
 */
async function createReceiverFileStorage(transferId, fileIndex, meta) {
  const opfsFileName = `mydrop-rx-${transferId}-${fileIndex}.part`;
  let opfsRoot = null;
  let opfsHandle = null;
  let opfsWritable = null;

  if (
    typeof navigator !== "undefined" &&
    navigator.storage &&
    typeof navigator.storage.getDirectory === "function"
  ) {
    try {
      opfsRoot = await navigator.storage.getDirectory();
      opfsHandle = await opfsRoot.getFileHandle(opfsFileName, { create: true });
      if (typeof opfsHandle.createWritable === "function") {
        opfsWritable = await opfsHandle.createWritable({ keepExistingData: false });
      }
    } catch {
      opfsRoot = null;
      opfsHandle = null;
      opfsWritable = null;
    }
  }

  if (opfsWritable && opfsHandle) {
    let closed = false;
    return {
      mode: "opfs",
      compactedSegments: 0,
      pendingBufferCount: 0,
      async writeChunk(plainBuf) {
        if (closed) throw new Error("OPFS writer already closed");
        await opfsWritable.write(plainBuf);
      },
      async finalize(safeMime) {
        if (closed) throw new Error("OPFS writer already finalized");
        closed = true;
        await opfsWritable.close();
        const diskFile = await opfsHandle.getFile();
        const finalBlob =
          diskFile.type === safeMime ? diskFile : diskFile.slice(0, diskFile.size, safeMime);
        finalBlob._opfsCleanup = async () => {
          try {
            await opfsRoot.removeEntry(opfsFileName);
          } catch {}
        };
        return finalBlob;
      },
      async abort() {
        if (closed) return;
        closed = true;
        try {
          if (typeof opfsWritable.abort === "function") await opfsWritable.abort();
          else await opfsWritable.close();
        } catch {}
        try {
          await opfsRoot?.removeEntry(opfsFileName);
        } catch {}
      },
    };
  }

  // Fallback Tier: Bounded Segmented Blob Compaction (zero ArrayBuffer concatenation, periodic compaction)
  let pendingBuffers = [];
  let pendingBytes = 0;
  let blobSegments = [];
  let closed = false;

  const compactPending = () => {
    if (pendingBuffers.length === 0) return;
    const seg = new Blob(pendingBuffers);
    blobSegments.push(seg);
    pendingBuffers = [];
    pendingBytes = 0;
  };

  return {
    mode: "segmented-blob",
    get compactedSegments() {
      return blobSegments.length;
    },
    get pendingBufferCount() {
      return pendingBuffers.length;
    },
    async writeChunk(plainBuf) {
      if (closed) throw new Error("Segmented storage already closed");
      pendingBuffers.push(plainBuf);
      pendingBytes += plainBuf.byteLength;
      if (pendingBytes >= SECURITY_LIMITS.STORAGE_COMPACT_THRESHOLD) {
        compactPending();
      }
    },
    async finalize(safeMime) {
      if (closed) throw new Error("Segmented storage already finalized");
      closed = true;
      compactPending();
      const finalBlob = new Blob(blobSegments, { type: safeMime });
      blobSegments = [];
      pendingBuffers = [];
      pendingBytes = 0;
      return finalBlob;
    },
    async abort() {
      closed = true;
      pendingBuffers = [];
      pendingBytes = 0;
      blobSegments = [];
    },
  };
}

// ================= Adaptive Chunk Size Controller (1 MB - 4 MB) =================
class AdaptiveChunkSizer {
  constructor(mode = "p2p") {
    this.mode = mode;
    if (mode === "relay") {
      this.currentSize = Math.min(SECURITY_LIMITS.RELAY_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
    } else {
      const init = Math.min(SECURITY_LIMITS.INITIAL_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
      const min = Math.min(SECURITY_LIMITS.MIN_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
      this.currentSize = Math.max(min, init);
    }
    this.history = [];
  }

  nextChunkSize() {
    if (this.mode === "relay") {
      return Math.min(SECURITY_LIMITS.RELAY_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
    }
    const min = Math.min(SECURITY_LIMITS.MIN_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
    return Math.max(min, Math.min(this.currentSize, SECURITY_LIMITS.MAX_CHUNK_SIZE));
  }

  recordSample(bytesSent, elapsedMs, hadBackpressureStall = false) {
    if (this.mode === "relay") return this.currentSize;
    const min = Math.min(SECURITY_LIMITS.MIN_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
    const max = SECURITY_LIMITS.MAX_CHUNK_SIZE;

    if (hadBackpressureStall || elapsedMs > 1200) {
      this.currentSize = Math.max(min, Math.floor(this.currentSize / 2));
      return this.currentSize;
    }

    // High throughput (< 250ms per chunk without stall): step up towards 4 MB
    if (elapsedMs < 250 && this.currentSize < max) {
      this.currentSize = Math.min(max, this.currentSize * 2);
    }
    return this.currentSize;
  }

  onCongestion() {
    if (this.mode === "relay") return this.currentSize;
    const min = Math.min(SECURITY_LIMITS.MIN_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
    this.currentSize = Math.max(min, Math.floor(this.currentSize / 2));
    return this.currentSize;
  }
}

function cleanupSctpAssembler(peerId) {
  const a = sctpFragAssemblers.get(peerId);
  if (!a) return;
  clearTimeout(a.timer);
  a.chunks = [];
  sctpFragAssemblers.delete(peerId);
}

function cleanupIncomingTransfer(peerId) {
  const f = incoming.get(peerId);
  if (!f) return;
  clearTimeout(f.timer);
  f.chunks = [];
  f.outOfOrderChunks?.clear?.();
  if (f.storage) {
    f.storage.abort().catch(() => {});
    f.storage = null;
  }
  incoming.delete(peerId);
  cleanupSctpAssembler(peerId);
  setProgress(peerId, null);
  hideTransferPanelIfIdle(f.transferId);
  releaseWakeLockIfIdle();
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

  for (const [tid, out] of activeOutgoingTransfers) {
    if (out.peerId === peerId) {
      out.cancelled = true;
      out.cancelReason = "peer disconnected";
      out.wakeWaiters?.();
      activeOutgoingTransfers.delete(tid);
      hideTransferPanelIfIdle(tid);
    }
  }

  cleanupSctpAssembler(peerId);
  peerStatus.delete(peerId);
  peerProgress.delete(peerId);
  peerClientRate.delete(peerId);
  releaseWakeLockIfIdle();
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
    try { entry.cleanup?.(); } catch {}
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
  if (document.visibilityState === "hidden") {
    // Extend watchdog timers while backgrounded on mobile (iOS Safari / Android Chrome)
    for (const [peerId, f] of incoming) {
      clearTimeout(f.timer);
      f.timer = setTimeout(() => {
        abortPeerTransfer(peerId, `การรับไฟล์ ${f.meta.name} หมดเวลาเนื่องจากแอปถูกพักอยู่เบื้องหลัง`);
      }, SECURITY_LIMITS.PAUSE_TIMEOUT_MS);
    }
    if (incoming.size > 0 || activeOutgoingTransfers.size > 0) {
      const warn = $("#transferWarningBanner");
      if (warn) {
        warn.hidden = false;
        warn.textContent =
          "⚠️ แอปถูกสลับไปอยู่เบื้องหลัง: กรุณากลับมาที่หน้าจอนี้เพื่อป้องกัน iOS/Android ตัดการเชื่อมต่อไฟล์ขนาดใหญ่";
      }
    }
  } else if (document.visibilityState === "visible") {
    if (incoming.size > 0 || activeOutgoingTransfers.size > 0) {
      acquireWakeLock();
    }
    for (const [peerId, f] of incoming) {
      if (!f.paused) resetIncomingWatchdog(peerId, f);
    }
    ensureWS()
      .then(() => {
        for (const out of activeOutgoingTransfers.values()) {
          out.wakeWaiters?.();
        }
      })
      .catch(() => {});
  }
});
window.addEventListener("online", () => {
  ensureWS()
    .then(() => {
      for (const out of activeOutgoingTransfers.values()) {
        out.wakeWaiters?.();
      }
    })
    .catch(() => {});
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

// Split an encrypted 0xE2 binary chunk frame (1-4 MB) into SCTP-safe 0xE3 sub-frames when WebRTC maxMessageSize is smaller
// Layout: [0xE3 (1B) | flags (1B: bit0=lastFrag) | fileIndex (2B) | chunkIndex (4B) | fragIndex (2B) | totalFrags (2B) | totalFrameLen (4B) | payload] = 16B header
function splitBinaryFrameForSctp(binaryFrame, fileIndex, chunkIndex, maxSctpFrame) {
  const safeLimit = Math.max(4096, maxSctpFrame || SECURITY_LIMITS.SCTP_SAFE_FRAME_SIZE);
  if (binaryFrame.byteLength <= safeLimit) {
    return [binaryFrame];
  }
  const src = new Uint8Array(binaryFrame);
  const payloadCap = Math.max(1024, safeLimit - 16);
  const totalFrags = Math.ceil(src.byteLength / payloadCap);
  const frames = [];

  for (let fragIndex = 0; fragIndex < totalFrags; fragIndex++) {
    const start = fragIndex * payloadCap;
    const end = Math.min(src.byteLength, start + payloadCap);
    const slice = src.subarray(start, end);
    const isLastFrag = fragIndex === totalFrags - 1;

    const pkt = new Uint8Array(16 + slice.byteLength);
    const view = new DataView(pkt.buffer);
    pkt[0] = 0xe3;
    pkt[1] = isLastFrag ? 1 : 0;
    view.setUint16(2, fileIndex, false);
    view.setUint32(4, chunkIndex, false);
    view.setUint16(8, fragIndex, false);
    view.setUint16(10, totalFrags, false);
    view.setUint32(12, src.byteLength, false);
    pkt.set(slice, 16);
    frames.push(pkt.buffer);
  }
  return frames;
}

function reassembleSctpFragment(peerId, rawBuf) {
  if (!isArrayBufferLike(rawBuf) || rawBuf.byteLength < 17) {
    throw new Error("SCTP fragment frame too short");
  }
  const bytes = new Uint8Array(rawBuf);
  if (bytes[0] !== 0xe3) {
    throw new Error("Invalid SCTP fragment magic");
  }
  const view = new DataView(rawBuf);
  const isLastFrag = (bytes[1] & 1) === 1;
  const fileIndex = view.getUint16(2, false);
  const chunkIndex = view.getUint32(4, false);
  const fragIndex = view.getUint16(8, false);
  const totalFrags = view.getUint16(10, false);
  const totalFrameLen = view.getUint32(12, false);
  const payload = bytes.subarray(16);

  const maxAllowedFrame = SECURITY_LIMITS.MAX_CHUNK_SIZE + 512;
  if (
    totalFrags < 2 ||
    totalFrags > 2048 ||
    fragIndex >= totalFrags ||
    totalFrameLen < 72 ||
    totalFrameLen > maxAllowedFrame
  ) {
    cleanupSctpAssembler(peerId);
    throw new Error("Invalid SCTP fragment bounds");
  }

  let asm = sctpFragAssemblers.get(peerId);
  if (fragIndex === 0) {
    cleanupSctpAssembler(peerId);
    asm = {
      fileIndex,
      chunkIndex,
      totalFrags,
      totalFrameLen,
      nextFrag: 0,
      offset: 0,
      buffer: new Uint8Array(totalFrameLen),
      timer: setTimeout(() => cleanupSctpAssembler(peerId), SECURITY_LIMITS.CHUNK_INACTIVITY_TIMEOUT_MS),
    };
    sctpFragAssemblers.set(peerId, asm);
  } else if (
    !asm ||
    asm.fileIndex !== fileIndex ||
    asm.chunkIndex !== chunkIndex ||
    asm.totalFrags !== totalFrags ||
    asm.totalFrameLen !== totalFrameLen ||
    asm.nextFrag !== fragIndex
  ) {
    cleanupSctpAssembler(peerId);
    throw new Error("Out-of-sequence SCTP fragment");
  }

  if (asm.offset + payload.byteLength > asm.totalFrameLen) {
    cleanupSctpAssembler(peerId);
    throw new Error("SCTP fragment overflow");
  }

  asm.buffer.set(payload, asm.offset);
  asm.offset += payload.byteLength;
  asm.nextFrag += 1;

  if (isLastFrag) {
    if (asm.nextFrag !== asm.totalFrags || asm.offset !== asm.totalFrameLen) {
      cleanupSctpAssembler(peerId);
      throw new Error("Incomplete SCTP fragmented frame");
    }
    const completeBuf = asm.buffer.buffer;
    clearTimeout(asm.timer);
    sctpFragAssemblers.delete(peerId);
    return completeBuf;
  }
  return null;
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
  // Negotiate safe SCTP frame size (for 0xE3 sub-frame splitting) while supporting 1-4 MB logical chunks
  const rawSctpMax = c.pc.sctp?.maxMessageSize;
  const sctpMax =
    typeof rawSctpMax === "number" && rawSctpMax > 0
      ? Math.min(256 * 1024, rawSctpMax)
      : SECURITY_LIMITS.SCTP_SAFE_FRAME_SIZE;
  c.maxSctpFrame = Math.max(16384, sctpMax - 128);
  c.chunk = Math.min(
    SECURITY_LIMITS.MAX_CHUNK_SIZE,
    Math.max(SECURITY_LIMITS.MIN_CHUNK_SIZE, SECURITY_LIMITS.INITIAL_CHUNK_SIZE)
  );
  return c;
}

async function waitForDataChannelDrain(dc, maxBuffer = MAX_BUFFER) {
  if (!dc || dc.readyState !== "open" || !(dc.bufferedAmount > maxBuffer)) {
    return 0;
  }
  const t0 = Date.now();
  await new Promise((resolve, reject) => {
    let settled = false;
    let pollTimer = null;
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearInterval(pollTimer);
      try {
        dc.removeEventListener?.("bufferedamountlow", onLow);
        dc.removeEventListener?.("close", onClose);
      } catch {}
      if (err) reject(err);
      else resolve();
    };
    const onLow = () => finish();
    const onClose = () => finish(new Error("DataChannel closed during backpressure wait"));
    dc.addEventListener?.("bufferedamountlow", onLow, { once: true });
    dc.addEventListener?.("close", onClose, { once: true });
    pollTimer = setInterval(() => {
      if (dc.readyState !== "open") {
        finish(new Error("DataChannel closed"));
      } else if (!(dc.bufferedAmount > (dc.bufferedAmountLowThreshold || maxBuffer / 2))) {
        finish();
      }
    }, 40);
  });
  return Date.now() - t0;
}

function createRelayTransport(peerId) {
  const relayChunk = Math.min(SECURITY_LIMITS.RELAY_CHUNK_SIZE, SECURITY_LIMITS.MAX_CHUNK_SIZE);
  return {
    mode: "relay",
    chunk: relayChunk,
    maxSctpFrame: relayChunk,
    isOpen: () => ws?.readyState === 1,
    async sendEncryptedControl(obj) {
      const encPkt = await encryptControlMessage(peerId, obj);
      relaySend(peerId, encPkt);
    },
    async sendEncryptedChunk(transferId, fileIndex, chunkIndex, isLast, plainBuf) {
      const enc = await encryptFileChunk(peerId, transferId, fileIndex, chunkIndex, isLast, plainBuf);
      let stalledMs = 0;
      while (ws?.readyState === 1 && ws.bufferedAmount > 1024 * 1024) {
        const t0 = Date.now();
        await new Promise((r) => setTimeout(r, 25));
        stalledMs += Date.now() - t0;
      }
      relaySend(peerId, {
        type: "enc-chunk",
        transferId: enc.transferId,
        fileIndex: enc.fileIndex,
        chunkIndex: enc.chunkIndex,
        last: enc.last,
        iv: bufToBase64(enc.iv),
        ct: bufToBase64(enc.ctBuf),
      });
      return { stalledMs };
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
      maxSctpFrame: c.maxSctpFrame || SECURITY_LIMITS.SCTP_SAFE_FRAME_SIZE,
      isOpen: () => c.dc?.readyState === "open",
      async sendEncryptedControl(obj) {
        const encPkt = await encryptControlMessage(peerId, obj);
        c.dc.send(JSON.stringify(encPkt));
      },
      async sendEncryptedChunk(transferId, fileIndex, chunkIndex, isLast, plainBuf) {
        const enc = await encryptFileChunk(peerId, transferId, fileIndex, chunkIndex, isLast, plainBuf);
        const binaryFrame = packEncryptedChunkBinary(enc);
        const subFrames = splitBinaryFrameForSctp(
          binaryFrame,
          fileIndex,
          chunkIndex,
          c.maxSctpFrame || SECURITY_LIMITS.SCTP_SAFE_FRAME_SIZE
        );
        let stalledMs = 0;
        for (const frame of subFrames) {
          if (c.dc?.readyState !== "open") throw new Error("DataChannel closed");
          stalledMs += await waitForDataChannelDrain(c.dc, MAX_BUFFER);
          c.dc.send(frame);
        }
        return { stalledMs, subFrames: subFrames.length };
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

// ================= Active Transfer UI Panel & Controls =================
let currentUiTransfer = null; // { transferId, peerId, direction, mode, totalBytes, files: [{ name, size, bytes, status }], startTime, lastSampleTime, lastSampleBytes, speedBps, paused }

function formatSpeed(bps) {
  if (!Number.isFinite(bps) || bps <= 0) return "--";
  if (bps < 1024) return `${Math.round(bps)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / (1024 * 1024)).toFixed(2)} MB/s`;
}

function formatDuration(sec) {
  if (!Number.isFinite(sec) || sec < 0 || sec > 86400 * 7) return "--";
  const s = Math.ceil(sec);
  if (s < 60) return `${s} วินาที`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  if (m < 60) return `${m} นาที ${remS} วินาที`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return `${h} ชม. ${remM} นาที`;
}

function initTransferPanel(transferId, peerId, direction, mode, files, totalBytes) {
  const now = Date.now();
  currentUiTransfer = {
    transferId,
    peerId,
    direction, // "send" | "receive"
    mode: mode || "p2p",
    totalBytes,
    transferredBytes: 0,
    files: files.map((f) => ({
      name: f.name,
      size: f.size,
      bytes: 0,
      status: direction === "send" ? "รอส่ง" : "รอรับ",
    })),
    startTime: now,
    lastSampleTime: now,
    lastSampleBytes: 0,
    speedBps: 0,
    paused: false,
  };

  const panel = $("#transferPanel");
  if (!panel) return;
  panel.hidden = false;

  const titleEl = $("#transferTitle");
  if (titleEl) {
    titleEl.textContent =
      direction === "send"
        ? `กำลังส่งไฟล์ไปยัง ${peerName(peerId)}`
        : `กำลังรับไฟล์จาก ${peerName(peerId)}`;
  }

  const badgeEl = $("#transferModeBadge");
  if (badgeEl) {
    badgeEl.textContent =
      mode === "relay" ? "Relay Fallback • E2EE (สูงสุด 500 MB)" : "WebRTC P2P Direct • E2EE (สูงสุด 5 GB)";
  }

  const pauseBtn = $("#pauseTransferBtn");
  const resumeBtn = $("#resumeTransferBtn");
  if (pauseBtn) pauseBtn.hidden = false;
  if (resumeBtn) resumeBtn.hidden = true;

  const cap = detectPlatformCapabilities();
  const warnEl = $("#transferWarningBanner");
  if (warnEl) {
    if (totalBytes >= 50 * 1024 * 1024 || cap.isMobile) {
      warnEl.hidden = false;
      warnEl.textContent = cap.isIOS
        ? "⚠️ iPhone / iOS Safari: กรุณาเปิดหน้าจอค้างไว้และอย่าสลับแอปขณะโอนย้ายวิดีโอขนาดใหญ่ ระบบกำลังสตรีมข้อมูลแบบประหยัดหน่วยความจำ"
        : "⚠️ คำแนะนำสำหรับไฟล์ขนาดใหญ่: กรุณาเปิดหน้าจอค้างไว้และอย่าสลับแอปหรือล็อกหน้าจอขณะรับ-ส่งไฟล์ เพื่อป้องกันเบราว์เซอร์ตัดการเชื่อมต่อ";
    } else {
      warnEl.hidden = true;
    }
  }

  renderTransferPanelFiles();
  updateTransferPanelStats(0);
}

function renderTransferPanelFiles() {
  const list = $("#transferFileList");
  if (!list || !currentUiTransfer) return;
  list.textContent = "";
  currentUiTransfer.files.forEach((f, idx) => {
    const li = document.createElement("li");
    li.className = "transfer-file-item";
    li.dataset.fileIndex = String(idx);
    const pct = f.size > 0 ? Math.min(100, Math.round((f.bytes / f.size) * 100)) : 100;
    li.innerHTML = `
      <div class="transfer-file-top">
        <span class="transfer-file-name"></span>
        <span class="transfer-file-status"></span>
      </div>
      <div class="transfer-file-bar-track">
        <div class="transfer-file-bar" style="width:${pct}%"></div>
      </div>`;
    li.querySelector(".transfer-file-name").textContent = `${f.name} (${formatSize(f.size)})`;
    li.querySelector(".transfer-file-status").textContent = `${f.status} • ${pct}%`;
    list.appendChild(li);
  });
}

function updateTransferPanelFile(transferId, fileIndex, fileBytes, statusText) {
  if (!currentUiTransfer || currentUiTransfer.transferId !== transferId) return;
  const f = currentUiTransfer.files[fileIndex];
  if (!f) return;
  if (typeof fileBytes === "number") f.bytes = Math.min(f.size, Math.max(0, fileBytes));
  if (statusText) f.status = statusText;

  let sum = 0;
  for (const item of currentUiTransfer.files) sum += item.bytes;
  updateTransferPanelStats(sum);
  renderTransferPanelFiles();
}

function updateTransferPanelStats(overallBytes) {
  if (!currentUiTransfer) return;
  const now = Date.now();
  currentUiTransfer.transferredBytes = Math.min(currentUiTransfer.totalBytes, Math.max(0, overallBytes));

  const dtSec = (now - currentUiTransfer.lastSampleTime) / 1000;
  if (dtSec >= 0.25) {
    const dBytes = Math.max(0, currentUiTransfer.transferredBytes - currentUiTransfer.lastSampleBytes);
    const instSpeed = dBytes / dtSec;
    currentUiTransfer.speedBps =
      currentUiTransfer.speedBps > 0 ? currentUiTransfer.speedBps * 0.65 + instSpeed * 0.35 : instSpeed;
    currentUiTransfer.lastSampleTime = now;
    currentUiTransfer.lastSampleBytes = currentUiTransfer.transferredBytes;
  } else if (currentUiTransfer.speedBps === 0 && now > currentUiTransfer.startTime) {
    const totalElapsed = (now - currentUiTransfer.startTime) / 1000;
    if (totalElapsed > 0.05) {
      currentUiTransfer.speedBps = currentUiTransfer.transferredBytes / totalElapsed;
    }
  }

  const pct =
    currentUiTransfer.totalBytes > 0
      ? Math.min(100, Math.round((currentUiTransfer.transferredBytes / currentUiTransfer.totalBytes) * 100))
      : 100;
  const remBytes = Math.max(0, currentUiTransfer.totalBytes - currentUiTransfer.transferredBytes);
  const etaSec = currentUiTransfer.speedBps > 0 ? remBytes / currentUiTransfer.speedBps : NaN;

  const bytesEl = $("#transferOverallBytes");
  const pctEl = $("#transferOverallPct");
  const barEl = $("#transferOverallBar");
  const speedEl = $("#transferSpeed");
  const etaEl = $("#transferEta");

  if (bytesEl) {
    bytesEl.textContent = `${formatSize(currentUiTransfer.transferredBytes)} / ${formatSize(currentUiTransfer.totalBytes)}`;
  }
  if (pctEl) pctEl.textContent = `${pct}%`;
  if (barEl) barEl.style.width = `${pct}%`;
  if (speedEl) {
    speedEl.textContent = currentUiTransfer.paused
      ? "ความเร็ว: พักการส่งชั่วคราว"
      : `ความเร็ว: ${formatSpeed(currentUiTransfer.speedBps)}`;
  }
  if (etaEl) {
    etaEl.textContent = currentUiTransfer.paused
      ? "เวลาที่เหลือ: --"
      : `เวลาที่เหลือ: ${remBytes === 0 ? "0 วินาที" : formatDuration(etaSec)}`;
  }
}

function hideTransferPanelIfIdle(transferId = null) {
  if (transferId && currentUiTransfer && currentUiTransfer.transferId !== transferId) return;
  if (activeOutgoingTransfers.size === 0 && incoming.size === 0) {
    currentUiTransfer = null;
    const panel = $("#transferPanel");
    if (panel) panel.hidden = true;
  }
}

async function sendControlBestEffort(peerId, payload) {
  try {
    const encPkt = await encryptControlMessage(peerId, payload);
    const c = conns.get(peerId);
    if (c?.dc?.readyState === "open") {
      try {
        c.dc.send(JSON.stringify(encPkt));
        return true;
      } catch {}
    }
    if (ws?.readyState === 1) {
      relaySend(peerId, encPkt);
      return true;
    }
  } catch {}
  return false;
}

function pauseActiveTransfer(transferId = currentUiTransfer?.transferId) {
  if (!transferId) return false;
  const out = activeOutgoingTransfers.get(transferId);
  if (out && !out.paused) {
    out.paused = true;
    if (currentUiTransfer?.transferId === transferId) {
      currentUiTransfer.paused = true;
      if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = true;
      if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = false;
      updateTransferPanelStats(currentUiTransfer.transferredBytes);
    }
    sendControlBestEffort(out.peerId, { type: "transfer-pause", transferId, reason: "user" });
    setStatus(out.peerId, "พักการส่งชั่วคราว");
    return true;
  }
  for (const [peerId, f] of incoming) {
    if (f.transferId === transferId && !f.paused) {
      f.paused = true;
      clearTimeout(f.timer);
      f.timer = setTimeout(() => {
        abortPeerTransfer(peerId, `การรับไฟล์ ${f.meta.name} หมดเวลาขณะพักการส่ง`);
      }, SECURITY_LIMITS.PAUSE_TIMEOUT_MS);
      if (currentUiTransfer?.transferId === transferId) {
        currentUiTransfer.paused = true;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = true;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = false;
        updateTransferPanelStats(currentUiTransfer.transferredBytes);
      }
      sendControlBestEffort(peerId, { type: "transfer-pause", transferId, reason: "user" });
      setStatus(peerId, "พักการรับชั่วคราว");
      return true;
    }
  }
  return false;
}

function resumeActiveTransfer(transferId = currentUiTransfer?.transferId) {
  if (!transferId) return false;
  const out = activeOutgoingTransfers.get(transferId);
  if (out && out.paused) {
    out.paused = false;
    if (currentUiTransfer?.transferId === transferId) {
      currentUiTransfer.paused = false;
      if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = false;
      if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = true;
    }
    sendControlBestEffort(out.peerId, { type: "transfer-resume", transferId });
    out.wakeWaiters?.();
    return true;
  }
  for (const [peerId, f] of incoming) {
    if (f.transferId === transferId && f.paused) {
      f.paused = false;
      resetIncomingWatchdog(peerId, f);
      if (currentUiTransfer?.transferId === transferId) {
        currentUiTransfer.paused = false;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = false;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = true;
      }
      sendControlBestEffort(peerId, {
        type: "transfer-resume",
        transferId,
        fileIndex: f.fileIndex,
        nextChunkIndex: f.expectedChunkIndex,
        receivedBytes: f.received,
      });
      return true;
    }
  }
  return false;
}

function cancelActiveTransfer(transferId = currentUiTransfer?.transferId, notifyPeer = true) {
  if (!transferId) return false;
  const out = activeOutgoingTransfers.get(transferId);
  if (out) {
    out.cancelled = true;
    out.cancelReason = "cancelled by user";
    if (notifyPeer) {
      sendControlBestEffort(out.peerId, { type: "transfer-cancel", transferId, reason: "user" });
    }
    out.wakeWaiters?.();
    activeOutgoingTransfers.delete(transferId);
    setProgress(out.peerId, null);
    hideTransferPanelIfIdle(transferId);
    releaseWakeLockIfIdle();
    toast("ยกเลิกการส่งไฟล์แล้ว");
    return true;
  }
  for (const [peerId, f] of incoming) {
    if (f.transferId === transferId) {
      if (notifyPeer) {
        sendControlBestEffort(peerId, { type: "transfer-cancel", transferId, reason: "user" });
      }
      abortPeerTransfer(peerId, "ยกเลิกการรับไฟล์แล้ว");
      return true;
    }
  }
  const accepted = acceptedTransfers.get(transferId);
  if (accepted) {
    if (notifyPeer) {
      sendControlBestEffort(accepted.peerId, { type: "transfer-cancel", transferId, reason: "user" });
    }
    cleanupAcceptedTransfer(transferId);
    hideTransferPanelIfIdle(transferId);
    return true;
  }
  return false;
}

if ($("#pauseTransferBtn")) {
  $("#pauseTransferBtn").onclick = () => pauseActiveTransfer();
}
if ($("#resumeTransferBtn")) {
  $("#resumeTransferBtn").onclick = () => resumeActiveTransfer();
}
if ($("#cancelTransferBtn")) {
  $("#cancelTransferBtn").onclick = () => cancelActiveTransfer();
}

// ================= ส่งไฟล์ / ข้อความ (E2EE + Streaming + Backpressure + Resume + SHA-256) =================
async function sendFiles(peerId, files) {
  if (!files || !files.length) return false;
  if (!isKnownPeer(peerId)) {
    toast("ไม่พบอุปกรณ์ปลายทางในห้องนี้");
    return false;
  }

  const initialValidation = validateOutgoingFiles(files, "p2p");
  if (!initialValidation.ok) {
    toast(initialValidation.error);
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

  // Re-validate against actual established transport mode (Relay fallback has a strict 500 MB limit due to Cloudflare DO constraints)
  const modeValidation = validateOutgoingFiles(files, tx.mode);
  if (!modeValidation.ok) {
    setStatus(peerId, "");
    toast(modeValidation.error);
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
    transportMode: tx.mode,
    files: sanitizedManifest,
  };

  try {
    await tx.sendEncryptedControl(reqMsg);
  } catch {
    try {
      await ensureWS();
      tx = createRelayTransport(peerId);
      const relayVal = validateOutgoingFiles(files, "relay");
      if (!relayVal.ok) {
        const p = pendingResponses.get(transferId);
        if (p) clearTimeout(p.timer);
        pendingResponses.delete(transferId);
        setStatus(peerId, "");
        toast(relayVal.error);
        return false;
      }
      reqMsg.transportMode = "relay";
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

  let resp;
  try {
    resp = await responsePromise;
  } catch {
    setStatus(peerId, "");
    toast("ไม่ได้รับการตอบรับจากผู้รับ");
    return false;
  }

  const accepted = typeof resp === "object" && resp !== null ? Boolean(resp.accepted) : Boolean(resp);
  const rejectReason = typeof resp === "object" && resp !== null ? resp.reason : "";
  if (!accepted) {
    setStatus(peerId, "");
    if (rejectReason === "insufficient-storage") {
      toast("ผู้รับมีพื้นที่จัดเก็บข้อมูลไม่เพียงพอสำหรับไฟล์ขนาดใหญ่นี้");
    } else {
      toast("ผู้รับปฏิเสธไฟล์");
    }
    return false;
  }

  await acquireWakeLock();
  initTransferPanel(transferId, peerId, "send", tx.mode, sanitizedManifest, modeValidation.totalBytes);

  const waiters = new Set();
  const outState = {
    transferId,
    peerId,
    mode: tx.mode,
    files,
    manifest: sanitizedManifest,
    currentFileIndex: 0,
    ackedChunkIndex: -1,
    ackedBytes: 0,
    retransmitQueue: [],
    resumeTarget: null,
    fileVerifyResult: null,
    paused: false,
    cancelled: false,
    cancelReason: "",
    wakeWaiters() {
      for (const fn of [...waiters]) fn();
    },
    waitForEvent(timeoutMs = 5000) {
      return new Promise((resolve) => {
        let timer;
        const done = () => {
          clearTimeout(timer);
          waiters.delete(done);
          resolve();
        };
        waiters.add(done);
        timer = setTimeout(done, timeoutMs);
      });
    },
  };
  activeOutgoingTransfers.set(transferId, outState);

  const attemptReconnectAndResume = async (fileIndex) => {
    if (outState.cancelled) return false;
    setStatus(peerId, "การเชื่อมต่อสะดุด กำลังเชื่อมต่อใหม่เพื่อส่งต่อ...");
    const deadline = Date.now() + SECURITY_LIMITS.RESUME_TIMEOUT_MS;

    while (Date.now() < deadline && !outState.cancelled) {
      try {
        await ensureWS();
        tx = await getTransport(peerId);
        if (tx.mode === "relay") {
          const relayCheck = validateOutgoingFiles([files[fileIndex]], "relay");
          if (!relayCheck.ok) {
            toast(relayCheck.error);
            return false;
          }
        }
        outState.resumeTarget = null;
        await tx.sendEncryptedControl({
          type: "resume-request",
          transferId,
          fileIndex,
        });
        const waitEnd = Date.now() + 4000;
        while (Date.now() < waitEnd && !outState.resumeTarget && !outState.cancelled) {
          await outState.waitForEvent(500);
        }
        if (outState.resumeTarget && outState.resumeTarget.fileIndex === fileIndex) {
          if (!outState.resumeTarget.canResume) return false;
          return true;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  };

  try {
    for (let fileIndex = 0; fileIndex < files.length; fileIndex++) {
      if (outState.cancelled) throw new Error(outState.cancelReason || "cancelled");
      const file = files[fileIndex];
      const meta = sanitizedManifest[fileIndex];

      outState.currentFileIndex = fileIndex;
      outState.ackedChunkIndex = -1;
      outState.ackedBytes = 0;
      outState.retransmitQueue = [];
      outState.resumeTarget = null;
      outState.fileVerifyResult = null;

      if (!tx.isOpen()) {
        const ok = await attemptReconnectAndResume(fileIndex);
        if (!ok && !tx.isOpen()) throw new Error("connection lost");
      }

      const sizer = new AdaptiveChunkSizer(tx.mode);
      const initialChunkSize = sizer.nextChunkSize();
      const estimatedChunks = meta.size === 0 ? 0 : Math.ceil(meta.size / initialChunkSize);

      try {
        await tx.sendEncryptedControl({
          type: "header",
          transferId,
          fileIndex,
          name: meta.name,
          size: meta.size,
          mime: meta.mime,
          totalChunks: estimatedChunks,
          chunkSize: initialChunkSize,
          resumable: true,
          requiresCommit: true,
          transportMode: tx.mode,
        });
      } catch {
        setProgress(peerId, null);
        toast("ส่งข้อมูลหัวไฟล์ไม่สำเร็จ");
        return false;
      }

      updateTransferPanelFile(transferId, fileIndex, 0, "กำลังส่ง");
      const fileHasher = new IntegrityHasher();
      const chunkMap = new Map(); // chunkIndex -> { offset, size, isLast }
      let offset = 0;
      let hashedOffset = 0;
      let chunkIndex = 0;

      const sendSingleChunkByInfo = async (cIdx, cInfo) => {
        const buf = await file.slice(cInfo.offset, cInfo.offset + cInfo.size).arrayBuffer();
        if (buf.byteLength !== cInfo.size) {
          throw new Error("File read size mismatch (file modified or truncated during transfer)");
        }
        // Feed only newly visited sequential bytes into the file integrity hasher
        if (cInfo.offset + buf.byteLength > hashedOffset) {
          const sliceStart = Math.max(0, hashedOffset - cInfo.offset);
          const unhashedSlice = sliceStart === 0 ? buf : buf.slice(sliceStart);
          await fileHasher.update(unhashedSlice);
          hashedOffset = cInfo.offset + buf.byteLength;
        }
        const t0 = Date.now();
        const sendRes = await tx.sendEncryptedChunk(transferId, fileIndex, cIdx, cInfo.isLast, buf);
        const elapsedMs = Date.now() - t0;
        sizer.recordSample(buf.byteLength, elapsedMs, (sendRes?.stalledMs || 0) > 80);
      };

      while (offset < file.size || outState.retransmitQueue.length > 0) {
        if (outState.cancelled) throw new Error(outState.cancelReason || "cancelled");

        // 1. Wait while paused
        while (outState.paused && !outState.cancelled) {
          await outState.waitForEvent(500);
        }
        if (outState.cancelled) throw new Error(outState.cancelReason || "cancelled");

        // 2. Apply resume rewind if receiver requested a specific offset/chunkIndex
        if (outState.resumeTarget && outState.resumeTarget.fileIndex === fileIndex) {
          const target = outState.resumeTarget;
          outState.resumeTarget = null;
          if (
            Number.isSafeInteger(target.receivedBytes) &&
            target.receivedBytes >= 0 &&
            target.receivedBytes <= hashedOffset &&
            Number.isSafeInteger(target.nextChunkIndex) &&
            target.nextChunkIndex >= 0
          ) {
            offset = target.receivedBytes;
            chunkIndex = target.nextChunkIndex;
            outState.ackedBytes = Math.max(outState.ackedBytes, target.receivedBytes);
            outState.retransmitQueue = [];
          }
        }

        // 3. Process missing chunk retransmission requests (chunk-nak)
        if (outState.retransmitQueue.length > 0) {
          const missingIdx = outState.retransmitQueue.shift();
          const cInfo = chunkMap.get(missingIdx);
          if (cInfo) {
            try {
              sizer.onCongestion();
              await sendSingleChunkByInfo(missingIdx, cInfo);
            } catch {
              const resumed = await attemptReconnectAndResume(fileIndex);
              if (!resumed) throw new Error("connection lost during retransmission");
            }
            continue;
          }
        }

        if (offset >= file.size) break;

        // 4. Receiver-driven sliding window backpressure (limit unacknowledged bytes in flight)
        const maxInFlight = SECURITY_LIMITS.MAX_IN_FLIGHT_BYTES;
        const backpressureWaitStart = Date.now();
        while (
          offset - outState.ackedBytes >= maxInFlight &&
          outState.retransmitQueue.length === 0 &&
          !outState.resumeTarget &&
          !outState.cancelled
        ) {
          if (!tx.isOpen() || Date.now() - backpressureWaitStart > SECURITY_LIMITS.CHUNK_INACTIVITY_TIMEOUT_MS) {
            const resumed = await attemptReconnectAndResume(fileIndex);
            if (!resumed) throw new Error("receiver ack timeout");
            break;
          }
          await outState.waitForEvent(200);
        }
        if (outState.cancelled) throw new Error(outState.cancelReason || "cancelled");
        if (outState.retransmitQueue.length > 0 || outState.resumeTarget) continue;

        if (!tx.isOpen()) {
          const resumed = await attemptReconnectAndResume(fileIndex);
          if (!resumed) throw new Error("connection lost");
          continue;
        }

        // 5. Read and send next progressive chunk using adaptive chunk size (1-4 MB on P2P, 64 KB on Relay)
        const existingInfo = chunkMap.get(chunkIndex);
        let cInfo;
        if (existingInfo && existingInfo.offset === offset) {
          cInfo = existingInfo;
        } else {
          const stepSize = sizer.nextChunkSize();
          const nextOffset = Math.min(file.size, offset + stepSize);
          cInfo = {
            offset,
            size: nextOffset - offset,
            isLast: nextOffset >= file.size,
          };
          chunkMap.set(chunkIndex, cInfo);
        }

        try {
          await sendSingleChunkByInfo(chunkIndex, cInfo);
        } catch {
          const resumed = await attemptReconnectAndResume(fileIndex);
          if (!resumed) throw new Error("chunk send failed");
          continue;
        }

        offset += cInfo.size;
        chunkIndex += 1;

        // Prune old acknowledged entries from chunkMap to keep sender memory O(window_size)
        if (chunkMap.size > 64 && outState.ackedChunkIndex > 0) {
          for (const k of chunkMap.keys()) {
            if (k < outState.ackedChunkIndex - 8) chunkMap.delete(k);
          }
        }

        const ratio = file.size > 0 ? offset / file.size : 1;
        setProgress(peerId, ratio, `เข้ารหัสและส่ง ${meta.name}`);
        updateTransferPanelFile(transferId, fileIndex, offset, "กำลังส่ง");
      }

      // 6. Finalize file SHA-256 cryptographic digest and wait for receiver integrity verification
      updateTransferPanelFile(transferId, fileIndex, file.size, "กำลังตรวจสอบ SHA-256...");
      setStatus(peerId, `กำลังตรวจสอบความถูกต้อง (SHA-256) ของ ${meta.name}...`);
      const sha256 = await fileHasher.finalize();

      const sendCommit = async () => {
        await tx.sendEncryptedControl({
          type: "file-complete",
          transferId,
          fileIndex,
          size: meta.size,
          totalChunks: chunkIndex,
          sha256,
        });
      };

      try {
        await sendCommit();
      } catch {
        const resumed = await attemptReconnectAndResume(fileIndex);
        if (!resumed) throw new Error("failed to send file-complete");
        await sendCommit();
      }

      const verifyDeadline = Date.now() + SECURITY_LIMITS.REQUEST_TIMEOUT_MS;
      while (!outState.fileVerifyResult && Date.now() < verifyDeadline && !outState.cancelled) {
        if (outState.retransmitQueue.length > 0) {
          const missingIdx = outState.retransmitQueue.shift();
          const cInfo = chunkMap.get(missingIdx);
          if (cInfo) {
            await sendSingleChunkByInfo(missingIdx, cInfo);
            await sendCommit();
          }
        }
        await outState.waitForEvent(250);
      }

      if (outState.cancelled) throw new Error(outState.cancelReason || "cancelled");
      if (!outState.fileVerifyResult || !outState.fileVerifyResult.ok) {
        const errMsg = outState.fileVerifyResult?.error || "การตรวจสอบความสมบูรณ์ของไฟล์ (SHA-256) ล้มเหลว";
        updateTransferPanelFile(transferId, fileIndex, file.size, "✕ ตรวจสอบไม่ผ่าน");
        toast(errMsg);
        return false;
      }

      chunkMap.clear();
      updateTransferPanelFile(transferId, fileIndex, file.size, "✓ สำเร็จ (SHA-256)");
    }

    setProgress(peerId, null);
    toast(
      tx.mode === "relay"
        ? "ส่งและตรวจสอบ SHA-256 สำเร็จ (เข้ารหัส E2EE ผ่าน Relay)"
        : "ส่งและตรวจสอบ SHA-256 สำเร็จ (เข้ารหัส E2EE P2P)"
    );
    return true;
  } catch (err) {
    setProgress(peerId, null);
    if (!outState.cancelled) {
      toast("การส่งไฟล์ล้มเหลวหรือการเชื่อมต่อถูกตัด");
    }
    return false;
  } finally {
    activeOutgoingTransfers.delete(transferId);
    hideTransferPanelIfIdle(transferId);
    releaseWakeLockIfIdle();
  }
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
function onP2PMessage(peerId, rawData) {
  return enqueuePeerRx(peerId, async () => {
    try {
      if (typeof rawData === "string") {
        if (rawData.length > 131072) return;
        const pkt = JSON.parse(rawData);
        if (!pkt || typeof pkt !== "object") return;
        if (pkt.type === "e2ee-init" || pkt.type === "e2ee-ack" || pkt.type === "e2ee-confirm") {
          await handleE2EEHandshake(peerId, pkt);
        } else if (pkt.type === "enc-control") {
          const decryptedMsg = await decryptControlMessage(peerId, pkt);
          await onDecryptedControl(peerId, decryptedMsg);
        } else if (pkt.type === "enc-chunk") {
          await onEncryptedChunk(peerId, pkt);
        }
        return;
      }

      if (isArrayBufferLike(rawData)) {
        if (rawData.byteLength > SECURITY_LIMITS.MAX_CHUNK_SIZE + 512) {
          abortPeerTransfer(peerId, "ขนาด Chunk เกินขีดจำกัดที่อนุญาต");
          return;
        }
        const headerByte = new Uint8Array(rawData, 0, 1)[0];
        if (headerByte === 0xe3) {
          const reassembled = reassembleSctpFragment(peerId, rawData);
          if (!reassembled) return;
          const pkt = unpackEncryptedChunkBinary(reassembled);
          await onEncryptedChunk(peerId, pkt);
          return;
        }
        const pkt = unpackEncryptedChunkBinary(rawData);
        await onEncryptedChunk(peerId, pkt);
      }
    } catch (err) {
      console.error("P2P message error:", err);
      abortPeerTransfer(peerId, "การตรวจสอบความปลอดภัยของข้อมูลล้มเหลว");
    }
  });
}

function onRelayMessage(peerId, data) {
  if (!data || typeof data !== "object") return Promise.resolve();
  return enqueuePeerRx(peerId, async () => {
    try {
      if (data.type === "e2ee-init" || data.type === "e2ee-ack" || data.type === "e2ee-confirm") {
        await handleE2EEHandshake(peerId, data);
      } else if (data.type === "enc-control") {
        const decryptedMsg = await decryptControlMessage(peerId, data);
        await onDecryptedControl(peerId, decryptedMsg);
      } else if (data.type === "enc-chunk") {
        await onEncryptedChunk(peerId, data);
      }
    } catch (err) {
      console.error("Relay message error:", err);
      abortPeerTransfer(peerId, "การตรวจสอบความปลอดภัยของข้อมูลล้มเหลว");
    }
  });
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
  const timeoutMs = f.paused ? SECURITY_LIMITS.PAUSE_TIMEOUT_MS : SECURITY_LIMITS.CHUNK_INACTIVITY_TIMEOUT_MS;
  f.timer = setTimeout(() => {
    abortPeerTransfer(peerId, `การรับไฟล์ ${f.meta.name} หมดเวลาเชื่อมต่อ`);
  }, timeoutMs);
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

const FLOW_CONTROL_TYPES = new Set([
  "chunk-ack",
  "chunk-nak",
  "file-complete",
  "file-verified",
  "resume-request",
  "resume-response",
  "transfer-pause",
  "transfer-resume",
  "transfer-cancel",
]);

async function onDecryptedControl(peerId, msg) {
  if (!msg || typeof msg !== "object") return;
  if (!FLOW_CONTROL_TYPES.has(msg.type) && !checkPeerControlRate(peerId)) return;

  if (msg.type === "text") {
    if (typeof msg.text !== "string" || !msg.text.trim()) return;
    if (textEncoder.encode(msg.text).byteLength > SECURITY_LIMITS.MAX_TEXT_BYTES) return;
    addReceivedText(peerName(peerId), msg.text);
    return;
  }

  if (msg.type === "file-request") {
    const check = validateIncomingFileRequest(msg, msg.transportMode || "p2p");
    if (!check.ok) return;
    if (!rememberSeenRequest(check.transferId)) return;

    // Enforce maximum 5 pending incoming file requests per device
    const pendingCount = requestQueue.length + (activeRequest ? 1 : 0);
    if (pendingCount >= SECURITY_LIMITS.MAX_PENDING_REQUESTS) {
      // Auto-reject when queue is full to prevent memory/UI exhaustion
      sendEncryptedFileResponse(peerId, check.transferId, false).catch(() => {});
      return;
    }

    // Check browser storage quota before prompting user for large transfers
    const quotaCheck = await checkStorageQuota(check.totalBytes);
    if (!quotaCheck.ok) {
      toast(quotaCheck.error);
      sendEncryptedFileResponse(peerId, check.transferId, false, "insufficient-storage").catch(() => {});
      return;
    }

    const reqEntry = {
      peerId,
      transferId: check.transferId,
      transportMode: msg.transportMode === "relay" ? "relay" : "p2p",
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
      pending.resolve(
        msg.reason
          ? { accepted: Boolean(msg.accepted), reason: String(msg.reason) }
          : Boolean(msg.accepted)
      );
    }
    return;
  }

  if (msg.type === "chunk-ack") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId || msg.fileIndex !== out.currentFileIndex) return;
    if (Number.isSafeInteger(msg.chunkIndex) && msg.chunkIndex > out.ackedChunkIndex) {
      out.ackedChunkIndex = msg.chunkIndex;
    }
    if (Number.isSafeInteger(msg.receivedBytes) && msg.receivedBytes > out.ackedBytes) {
      out.ackedBytes = msg.receivedBytes;
    }
    out.wakeWaiters?.();
    return;
  }

  if (msg.type === "chunk-nak") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId || msg.fileIndex !== out.currentFileIndex) return;
    if (
      Number.isSafeInteger(msg.missingChunkIndex) &&
      msg.missingChunkIndex >= 0 &&
      !out.retransmitQueue.includes(msg.missingChunkIndex)
    ) {
      out.retransmitQueue.push(msg.missingChunkIndex);
      out.wakeWaiters?.();
    }
    return;
  }

  if (msg.type === "resume-request") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const f = incoming.get(peerId);
    const approved = acceptedTransfers.get(msg.transferId);
    if (!approved || approved.peerId !== peerId) {
      sendControlBestEffort(peerId, {
        type: "resume-response",
        transferId: msg.transferId,
        fileIndex: msg.fileIndex,
        canResume: false,
      });
      return;
    }
    if (f && f.transferId === msg.transferId && f.fileIndex === msg.fileIndex) {
      resetIncomingWatchdog(peerId, f);
      sendControlBestEffort(peerId, {
        type: "resume-response",
        transferId: msg.transferId,
        fileIndex: f.fileIndex,
        canResume: true,
        nextChunkIndex: f.expectedChunkIndex,
        receivedBytes: f.received,
      });
    } else {
      sendControlBestEffort(peerId, {
        type: "resume-response",
        transferId: msg.transferId,
        fileIndex: msg.fileIndex,
        canResume: true,
        nextChunkIndex: 0,
        receivedBytes: 0,
      });
    }
    return;
  }

  if (msg.type === "resume-response") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId) return;
    out.resumeTarget = {
      fileIndex: msg.fileIndex,
      canResume: Boolean(msg.canResume),
      nextChunkIndex: Number.isSafeInteger(msg.nextChunkIndex) ? msg.nextChunkIndex : 0,
      receivedBytes: Number.isSafeInteger(msg.receivedBytes) ? msg.receivedBytes : 0,
    };
    out.wakeWaiters?.();
    return;
  }

  if (msg.type === "transfer-pause") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (out && out.peerId === peerId) {
      out.paused = true;
      if (currentUiTransfer?.transferId === msg.transferId) {
        currentUiTransfer.paused = true;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = true;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = false;
        updateTransferPanelStats(currentUiTransfer.transferredBytes);
      }
      setStatus(peerId, "อีกฝ่ายพักการรับ-ส่งไฟล์ชั่วคราว");
      return;
    }
    const f = incoming.get(peerId);
    if (f && f.transferId === msg.transferId) {
      f.paused = true;
      resetIncomingWatchdog(peerId, f);
      if (currentUiTransfer?.transferId === msg.transferId) {
        currentUiTransfer.paused = true;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = true;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = false;
        updateTransferPanelStats(currentUiTransfer.transferredBytes);
      }
      setStatus(peerId, "ผู้ส่งพักการส่งไฟล์ชั่วคราว");
    }
    return;
  }

  if (msg.type === "transfer-resume") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (out && out.peerId === peerId) {
      out.paused = false;
      if (
        Number.isSafeInteger(msg.fileIndex) &&
        msg.fileIndex === out.currentFileIndex &&
        Number.isSafeInteger(msg.nextChunkIndex) &&
        Number.isSafeInteger(msg.receivedBytes)
      ) {
        out.resumeTarget = {
          fileIndex: msg.fileIndex,
          canResume: true,
          nextChunkIndex: msg.nextChunkIndex,
          receivedBytes: msg.receivedBytes,
        };
      }
      if (currentUiTransfer?.transferId === msg.transferId) {
        currentUiTransfer.paused = false;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = false;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = true;
      }
      out.wakeWaiters?.();
      return;
    }
    const f = incoming.get(peerId);
    if (f && f.transferId === msg.transferId) {
      f.paused = false;
      resetIncomingWatchdog(peerId, f);
      if (currentUiTransfer?.transferId === msg.transferId) {
        currentUiTransfer.paused = false;
        if ($("#pauseTransferBtn")) $("#pauseTransferBtn").hidden = false;
        if ($("#resumeTransferBtn")) $("#resumeTransferBtn").hidden = true;
      }
    }
    return;
  }

  if (msg.type === "transfer-cancel") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    cancelActiveTransfer(msg.transferId, false);
    toast("อีกฝ่ายยกเลิกการรับ-ส่งไฟล์");
    return;
  }

  if (msg.type === "file-complete") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const f = incoming.get(peerId);
    if (!f || f.transferId !== msg.transferId || f.fileIndex !== msg.fileIndex) return;
    if (typeof msg.sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(msg.sha256)) {
      abortPeerTransfer(peerId, "ข้อมูลตรวจสอบความสมบูรณ์ของไฟล์ (SHA-256) ไม่ถูกต้อง");
      return;
    }
    f.commitMsg = {
      sha256: msg.sha256.toLowerCase(),
      size: msg.size,
      totalChunks: msg.totalChunks,
    };
    if (f.allBytesReceived) {
      await verifyAndCommitIncomingFile(peerId, f);
    } else if (Number.isSafeInteger(msg.totalChunks) && f.expectedChunkIndex < msg.totalChunks) {
      // Request missing chunk if sender thought it was done
      sendControlBestEffort(peerId, {
        type: "chunk-nak",
        transferId: f.transferId,
        fileIndex: f.fileIndex,
        missingChunkIndex: f.expectedChunkIndex,
        receivedBytes: f.received,
      });
    }
    return;
  }

  if (msg.type === "file-verified") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const out = activeOutgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId || msg.fileIndex !== out.currentFileIndex) return;
    out.fileVerifyResult = {
      ok: Boolean(msg.ok),
      sha256: msg.sha256 || "",
      error: msg.error || "",
    };
    out.wakeWaiters?.();
    return;
  }

  if (msg.type === "header") {
    if (typeof msg.transferId !== "string" || !UUID_REGEX.test(msg.transferId)) return;
    const approved = acceptedTransfers.get(msg.transferId);
    if (!approved || approved.peerId !== peerId) return;

    // If same file header is re-sent during reconnect/resume, ignore duplicate header safely
    const existingIncoming = incoming.get(peerId);
    if (
      existingIncoming &&
      existingIncoming.transferId === msg.transferId &&
      existingIncoming.fileIndex === msg.fileIndex &&
      existingIncoming.resumable
    ) {
      resetIncomingWatchdog(peerId, existingIncoming);
      return;
    }

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
    const isRelayMode = msg.transportMode === "relay" || approved.transportMode === "relay";
    const maxAllowedSize = isRelayMode
      ? Math.min(SECURITY_LIMITS.MAX_FILE_SIZE, SECURITY_LIMITS.MAX_RELAY_FILE_SIZE)
      : SECURITY_LIMITS.MAX_FILE_SIZE;

    // Strictly verify that header metadata matches what the user approved in the modal
    if (
      cleanHeaderName !== approvedFile.name ||
      msg.size !== approvedFile.size ||
      !Number.isSafeInteger(msg.size) ||
      msg.size < 0 ||
      msg.size > maxAllowedSize
    ) {
      cleanupAcceptedTransfer(msg.transferId);
      toast("ปฏิเสธไฟล์: ข้อมูลไฟล์ไม่ตรงกับที่ขออนุญาตไว้หรือเกินขีดจำกัด");
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
      storage: null,
      hasher: new IntegrityHasher(),
      resumable: Boolean(msg.resumable),
      requiresCommit: Boolean(msg.requiresCommit),
      allBytesReceived: approvedFile.size === 0,
      commitMsg: null,
      outOfOrderChunks: new Map(),
      duplicateCount: 0,
      paused: false,
      received: 0,
      expectedChunkIndex: 0,
      timer: null,
    };
    incoming.set(peerId, fState);
    fState.storage = await createReceiverFileStorage(msg.transferId, expectedFileIndex, approvedFile);
    updateTransferPanelFile(msg.transferId, expectedFileIndex, 0, "กำลังรับ");

    if (approvedFile.size === 0) {
      if (!fState.requiresCommit) {
        await finishFile(peerId);
      } else {
        resetIncomingWatchdog(peerId, fState);
      }
    } else {
      resetIncomingWatchdog(peerId, fState);
    }
  }
}

async function verifyAndCommitIncomingFile(peerId, f) {
  if (!f || f.verifying || !f.allBytesReceived || !f.commitMsg) return;
  f.verifying = true;
  try {
    updateTransferPanelFile(f.transferId, f.fileIndex, f.received, "กำลังตรวจสอบ SHA-256...");
    const actualSha256 = await f.hasher.finalize();
    if (
      f.received !== f.meta.size ||
      f.commitMsg.size !== f.meta.size ||
      actualSha256.toLowerCase() !== f.commitMsg.sha256.toLowerCase()
    ) {
      await sendControlBestEffort(peerId, {
        type: "file-verified",
        transferId: f.transferId,
        fileIndex: f.fileIndex,
        ok: false,
        error: "SHA-256 integrity verification failed",
      });
      abortPeerTransfer(peerId, `ตรวจพบไฟล์ ${f.meta.name} เสียหายหรือไม่สมบูรณ์ (SHA-256 ไม่ตรงกัน)`);
      return;
    }

    await finishFile(peerId, actualSha256);
    await sendControlBestEffort(peerId, {
      type: "file-verified",
      transferId: f.transferId,
      fileIndex: f.fileIndex,
      ok: true,
      sha256: actualSha256,
    });
  } catch (err) {
    console.error("Verify and commit error:", err);
    abortPeerTransfer(peerId, "การตรวจสอบความสมบูรณ์ของไฟล์ล้มเหลว");
  }
}

async function onEncryptedChunk(peerId, packet) {
  const f = incoming.get(peerId);
  if (!f) return;

  if (packet.transferId !== f.transferId || packet.fileIndex !== f.fileIndex) {
    abortPeerTransfer(peerId, "ตรวจพบลำดับข้อมูลไฟล์ผิดปกติหรือซ้ำซ้อน");
    return;
  }

  const approved = acceptedTransfers.get(f.transferId);
  if (!approved || approved.peerId !== peerId) {
    abortPeerTransfer(peerId, "ไม่พบสิทธิ์การส่งไฟล์นี้");
    return;
  }

  // Legacy non-resumable headers enforce strict immediate sequential chunkIndex check before decryption
  if (!f.resumable && packet.chunkIndex !== f.expectedChunkIndex) {
    abortPeerTransfer(peerId, "ตรวจพบลำดับข้อมูลไฟล์ผิดปกติหรือซ้ำซ้อน");
    return;
  }

  // Decrypt and verify AES-256-GCM authentication tag & AAD
  const plainBuf = await decryptFileChunk(peerId, packet);

  if (plainBuf.byteLength === 0 || plainBuf.byteLength > SECURITY_LIMITS.MAX_CHUNK_SIZE) {
    abortPeerTransfer(peerId, "ขนาดข้อมูลย่อย (Chunk) ไม่ถูกต้อง");
    return;
  }

  // 1. Duplicate chunk detection (legitimate sender retransmission of an already-written chunkIndex)
  if (f.resumable && packet.chunkIndex < f.expectedChunkIndex) {
    f.duplicateCount += 1;
    sendControlBestEffort(peerId, {
      type: "chunk-ack",
      transferId: f.transferId,
      fileIndex: f.fileIndex,
      chunkIndex: f.expectedChunkIndex - 1,
      receivedBytes: f.received,
    });
    resetIncomingWatchdog(peerId, f);
    return;
  }

  // 2. Missing chunk detection & out-of-order buffering (requests retransmission via chunk-nak)
  if (f.resumable && packet.chunkIndex > f.expectedChunkIndex) {
    const gap = packet.chunkIndex - f.expectedChunkIndex;
    if (gap > SECURITY_LIMITS.MAX_OUT_OF_ORDER_CHUNKS) {
      abortPeerTransfer(peerId, "ตรวจพบข้อมูลสูญหายเกินขีดจำกัดระหว่างส่ง");
      return;
    }
    if (!f.outOfOrderChunks.has(packet.chunkIndex)) {
      f.outOfOrderChunks.set(packet.chunkIndex, { packet, plainBuf });
    }
    sendControlBestEffort(peerId, {
      type: "chunk-nak",
      transferId: f.transferId,
      fileIndex: f.fileIndex,
      missingChunkIndex: f.expectedChunkIndex,
      receivedBytes: f.received,
    });
    resetIncomingWatchdog(peerId, f);
    return;
  }

  // 3. Process current in-order chunk and any consecutive buffered out-of-order chunks
  const queueToProcess = [{ packet, plainBuf }];
  while (f.outOfOrderChunks.has(f.expectedChunkIndex + queueToProcess.length)) {
    const nextIdx = f.expectedChunkIndex + queueToProcess.length;
    queueToProcess.push(f.outOfOrderChunks.get(nextIdx));
    f.outOfOrderChunks.delete(nextIdx);
  }

  for (const item of queueToProcess) {
    const curPkt = item.packet;
    const curBuf = item.plainBuf;

    if (
      f.received + curBuf.byteLength > f.meta.size ||
      approved.receivedTotalBytes + curBuf.byteLength > approved.totalBytes
    ) {
      abortPeerTransfer(peerId, "ผู้ส่งส่งข้อมูลเกินขนาดไฟล์ที่ระบุไว้");
      return;
    }

    await f.hasher.update(curBuf);
    if (f.storage) {
      await f.storage.writeChunk(curBuf);
    } else {
      f.chunks.push(curBuf);
    }

    f.received += curBuf.byteLength;
    f.expectedChunkIndex += 1;
    approved.receivedTotalBytes += curBuf.byteLength;
    refreshAcceptedTransferTimer(approved);

    if (curPkt.last && f.received !== f.meta.size) {
      abortPeerTransfer(peerId, "ข้อมูลไฟล์ไม่ครบตามขนาดที่ระบุ");
      return;
    }
    if (!curPkt.last && f.received >= f.meta.size) {
      abortPeerTransfer(peerId, "โครงสร้างข้อมูลไฟล์ไม่ถูกต้อง");
      return;
    }

    if (f.resumable) {
      // Send chunk-ack at least every 1 MB or on the final chunk to avoid flooding control channel on 64KB Relay chunks
      const ackStep = Math.max(256 * 1024, Math.floor(SECURITY_LIMITS.MAX_IN_FLIGHT_BYTES / 8));
      if (curPkt.last || curPkt.chunkIndex === 0 || f.received - (f.lastAckedBytes || 0) >= ackStep) {
        f.lastAckedBytes = f.received;
        sendControlBestEffort(peerId, {
          type: "chunk-ack",
          transferId: f.transferId,
          fileIndex: f.fileIndex,
          chunkIndex: curPkt.chunkIndex,
          receivedBytes: f.received,
        });
      }
    }

    setProgress(peerId, f.received / f.meta.size, `รับและถอดรหัส ${f.meta.name}`);
    updateTransferPanelFile(f.transferId, f.fileIndex, f.received, "กำลังรับ");

    if (curPkt.last && f.received === f.meta.size) {
      f.allBytesReceived = true;
      if (f.requiresCommit) {
        if (f.commitMsg) {
          await verifyAndCommitIncomingFile(peerId, f);
        } else {
          resetIncomingWatchdog(peerId, f);
        }
      } else {
        await finishFile(peerId);
      }
      return;
    }
  }

  resetIncomingWatchdog(peerId, f);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
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

async function sendEncryptedFileResponse(peerId, transferId, accepted, reason = "") {
  const reply = {
    type: "file-response",
    transferId,
    accepted: Boolean(accepted),
    ...(reason ? { reason: String(reason) } : {}),
  };
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

  const { peerId, transferId, transportMode, files, totalBytes } = req;

  if (accepted) {
    const quotaCheck = await checkStorageQuota(totalBytes);
    if (!quotaCheck.ok) {
      toast(quotaCheck.error);
      try {
        await sendEncryptedFileResponse(peerId, transferId, false, "insufficient-storage");
      } catch {}
      processRequestQueue();
      return;
    }

    await acquireWakeLock();
    initTransferPanel(transferId, peerId, "receive", transportMode || "p2p", files, totalBytes);

    const timer = setTimeout(() => {
      cleanupAcceptedTransfer(transferId);
    }, SECURITY_LIMITS.REQUEST_TIMEOUT_MS);

    acceptedTransfers.set(transferId, {
      peerId,
      transportMode: transportMode || "p2p",
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

async function finishFile(peerId, verifiedSha256 = null) {
  const f = incoming.get(peerId);
  if (!f) return;
  clearTimeout(f.timer);
  incoming.delete(peerId);

  const approved = acceptedTransfers.get(f.transferId);
  let allFilesComplete = true;
  if (approved) {
    if (approved.nextFileIndex >= approved.files.length) {
      cleanupAcceptedTransfer(f.transferId);
    } else {
      allFilesComplete = false;
      refreshAcceptedTransferTimer(approved);
    }
  }

  const safeMime = getSafeDownloadMime(f.meta.name, f.meta.mime);
  let blob;
  if (f.storage) {
    blob = await f.storage.finalize(safeMime);
    f.storage = null;
  } else {
    blob = new Blob(f.chunks, { type: safeMime });
  }
  f.chunks = [];
  f.outOfOrderChunks?.clear?.();

  const finalHash = verifiedSha256 || (await f.hasher.finalize());
  blob.sha256 = finalHash;

  updateTransferPanelFile(f.transferId, f.fileIndex, f.meta.size, "✓ สำเร็จ (SHA-256)");
  addReceivedFile(peerName(peerId), f.meta.name, blob, f.meta.dangerous, finalHash);
  setProgress(peerId, null);
  if (allFilesComplete) {
    hideTransferPanelIfIdle(f.transferId);
    releaseWakeLockIfIdle();
  }
  toast(`ได้รับ ${f.meta.name} (ตรวจสอบความสมบูรณ์แล้ว)`);
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

function registerObjectUrl(url, itemElement, cleanup = null) {
  activeObjectUrls.push({ url, itemElement, cleanup });
  while (activeObjectUrls.length > SECURITY_LIMITS.MAX_RETAINED_BLOBS) {
    const oldest = activeObjectUrls.shift();
    if (oldest) {
      try { URL.revokeObjectURL(oldest.url); } catch {}
      try { oldest.cleanup?.(); } catch {}
      oldest.itemElement?.remove();
    }
  }
}

function revokeAndRemoveItem(url, itemElement) {
  try { URL.revokeObjectURL(url); } catch {}
  const idx = activeObjectUrls.findIndex((e) => e.url === url);
  if (idx !== -1) {
    const [removed] = activeObjectUrls.splice(idx, 1);
    try { removed?.cleanup?.(); } catch {}
  }
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

function addReceivedFile(from, name, blob, isDangerous = false, sha256 = "") {
  const safeName = sanitizeFilename(name);
  const dangerous = isDangerous || isDangerousFile(safeName, blob.type);

  const item = document.createElement("div");
  item.className = "item";
  item.dataset.filename = safeName;
  item.dataset.filesize = String(blob.size);
  if (sha256 || blob.sha256) {
    item.dataset.sha256 = sha256 || blob.sha256;
  }
  item._blob = blob;

  const infoWrap = document.createElement("div");
  const info = document.createElement("div");
  const shortHash = (sha256 || blob.sha256 || "").slice(0, 12);
  info.textContent = shortHash
    ? `${safeName} (${formatSize(blob.size)}) จาก ${from} • SHA-256: ${shortHash}…`
    : `${safeName} (${formatSize(blob.size)}) จาก ${from}`;
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
  registerObjectUrl(objUrl, item, blob._opfsCleanup || null);
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
  splitBinaryFrameForSctp,
  reassembleSctpFragment,
  IntegrityHasher,
  computeBlobSha256,
  AdaptiveChunkSizer,
  createReceiverFileStorage,
  checkStorageQuota,
  detectPlatformCapabilities,
  formatSize,
  pauseActiveTransfer,
  resumeActiveTransfer,
  cancelActiveTransfer,
  generateSecureRoomCode,
};

updateRoomUI();
updateDropZoneUI();
checkPendingShare();
connectWS();
