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

const MAX_BUFFER = 2 * 1024 * 1024; // WebRTC bufferedAmount high watermark (2MB)
const MAX_WS_BUFFER = 1024 * 1024;  // WebSocket bufferedAmount high watermark (1MB)
const MAX_IN_FLIGHT_CHUNKS = 16;    // Sliding window flow control (max unacknowledged chunks)
const ACK_BATCH_INTERVAL = 4;       // Receiver sends cumulative ACK every 4 chunks (or on final chunk)
const MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024; // 4 GB streaming file support
const MAX_TRANSFER_SIZE = 8 * 1024 * 1024 * 1024; // 8 GB total transfer support
const MAX_IN_MEMORY_FALLBACK_BYTES = 128 * 1024 * 1024; // 128 MB safe ceiling if neither FS Access nor IndexedDB is available
const MAX_FILES_PER_TRANSFER = 10;
const MAX_TEXT_LENGTH = 16 * 1024;
const MAX_PENDING_REQUESTS = 5;
const INCOMING_TIMEOUT_MS = 45000;
const ROOM_CODE_RE = /^[a-zA-Z0-9_-]{3,48}$/;
const BIDI_AND_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
const WINDOWS_RESERVED_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const DANGEROUS_MIMES = new Set([
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/javascript",
  "application/javascript",
  "application/x-javascript",
  "text/xml",
  "application/xml",
]);
const ICONS = { phone: "📱", tablet: "📱", desktop: "💻" };

const $ = (s) => document.querySelector(s);
let ws;
let myId = sessionStorage.getItem("mydrop_id") || "";
let myName = sessionStorage.getItem("mydrop_name") || "";
let currentRoom = "";
{
  const rawRoom = (new URLSearchParams(location.search).get("room") || "").trim();
  if (rawRoom && ROOM_CODE_RE.test(rawRoom)) {
    currentRoom = rawRoom;
  } else if (rawRoom) {
    const cleanUrl = new URL(location.href);
    cleanUrl.searchParams.delete("room");
    history.replaceState(null, "", cleanUrl.pathname + (cleanUrl.search || ""));
  }
}
let manualClose = false;
let reconnectTimer = null;
let lastWsActivity = 0;
const wsWaiters = new Set();
let peers = [];

const conns = new Map();             // peerId -> { pc, dc, polite, makingOffer, ignoreOffer, pending, chunk, open, resolveOpen, rejectOpen, timer }
const incoming = new Map();          // peerId -> { meta, fileIndex, nextChunkSeq, received, sink, paused, cancelled, timer, startTime, lastAckSeq }
const outgoingTransfers = new Map(); // transferId -> { peerId, files, fileIndex, nextSeq, ackedSeq, offset, paused, RemotePaused, cancelled, waiters, startTime, totalBytes, sentBytes }
const pendingResponses = new Map();  // transferId -> { peerId, resolve, reject }
const acceptedTransfers = new Map(); // transferId -> { peerId, remaining, nextFileIndex, files }
const seenRequests = new Set();
const peerStatus = new Map();        // peerId -> string
const peerProgress = new Map();      // peerId -> { ratio, label }
const requestQueue = [];
let activeRequest = null;
let activeUiTransfer = null;         // { transferId, peerId, direction: 'send'|'recv' }

// ================= E2EE State & Web Crypto Primitives =================
// E2EE is integrated directly with the chunk streaming protocol so Relay never sees plaintext.
const e2eeSessions = new Map();

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

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a instanceof Uint8Array ? a : new Uint8Array(a), offset);
    offset += a.byteLength;
  }
  return out;
}

function buildDeterministicIv(prefix4Bytes, channelTypeByte, fileIndex, seq) {
  const iv = new Uint8Array(12);
  iv.set(prefix4Bytes.subarray(0, 4), 0);
  const view = new DataView(iv.buffer);
  const high = ((channelTypeByte & 0xff) << 24) | (fileIndex & 0x00ffffff);
  view.setUint32(4, high >>> 0, false);
  view.setUint32(8, seq >>> 0, false);
  return iv;
}

function buildControlAad(senderId, recipientId, seq) {
  const roomTag = currentRoom ? `code:${currentRoom.toLowerCase()}` : "ip-room";
  return new TextEncoder().encode(`mydrop-stream-e2ee-v1|ctrl|${roomTag}|${senderId}|${recipientId}|${seq}`);
}

function buildChunkAad(transferId, fileIndex, seq, senderId, recipientId) {
  const roomTag = currentRoom ? `code:${currentRoom.toLowerCase()}` : "ip-room";
  return new TextEncoder().encode(
    `mydrop-stream-e2ee-v1|chunk|${roomTag}|${transferId}|${fileIndex}|${seq}|${senderId}|${recipientId}`
  );
}

async function getOrCreateE2EESession(peerId) {
  let sess = e2eeSessions.get(peerId);
  if (sess) return sess;

  let resolveReady;
  const readyPromise = new Promise((r) => { resolveReady = r; });
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));

  sess = {
    peerId,
    localKeyPair: keyPair,
    localPubRaw: pubRaw,
    localPubRawB64: bufToBase64(pubRaw),
    localNonce: nonceBytes,
    localNonceB64: bufToBase64(nonceBytes),
    remotePubRawB64: null,
    remoteNonceB64: null,
    sendKey: null,
    recvKey: null,
    sendPrefix: null,
    recvPrefix: null,
    nextOutCtrlSeq: 0,
    nextInCtrlSeq: 0,
    readyPromise,
    resolveReady,
  };
  e2eeSessions.set(peerId, sess);
  return sess;
}

async function derivePeerKeys(sess, remotePubRawB64, remoteNonceB64) {
  const remotePubBytes = new Uint8Array(base64ToBuf(remotePubRawB64));
  const remoteNonceBytes = new Uint8Array(base64ToBuf(remoteNonceB64));
  const remotePubKey = await crypto.subtle.importKey(
    "raw",
    remotePubBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePubKey },
    sess.localKeyPair.privateKey,
    256
  );

  const hkdfBaseKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveBits"]);

  const iAmLower = myId < sess.peerId;
  const lowId = iAmLower ? myId : sess.peerId;
  const highId = iAmLower ? sess.peerId : myId;
  const lowPub = iAmLower ? sess.localPubRaw : remotePubBytes;
  const highPub = iAmLower ? remotePubBytes : sess.localPubRaw;
  const lowNonce = iAmLower ? sess.localNonce : remoteNonceBytes;
  const highNonce = iAmLower ? remoteNonceBytes : sess.localNonce;
  const roomTag = currentRoom ? `code:${currentRoom.toLowerCase()}` : "ip-room";

  const transcript = concatBytes(
    new TextEncoder().encode(`mydrop-stream-e2ee-v1|${roomTag}|${lowId}|${highId}|`),
    lowPub,
    highPub,
    lowNonce,
    highNonce
  );
  const saltHash = new Uint8Array(await crypto.subtle.digest("SHA-256", transcript));

  const deriveDirKeyAndPrefix = async (fromId, toId) => {
    const info = new TextEncoder().encode(`mydrop-dir-key|${fromId}->${toId}`);
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: saltHash, info },
        hkdfBaseKey,
        288
      )
    );
    const rawAes = bits.subarray(0, 32);
    const ivPrefix = bits.subarray(32, 36);
    const aesKey = await crypto.subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return { aesKey, ivPrefix };
  };

  const sendMat = await deriveDirKeyAndPrefix(myId, sess.peerId);
  const recvMat = await deriveDirKeyAndPrefix(sess.peerId, myId);

  sess.remotePubRawB64 = remotePubRawB64;
  sess.remoteNonceB64 = remoteNonceB64;
  sess.sendKey = sendMat.aesKey;
  sess.sendPrefix = sendMat.ivPrefix;
  sess.recvKey = recvMat.aesKey;
  sess.recvPrefix = recvMat.ivPrefix;
  sess.nextOutCtrlSeq = 0;
  sess.nextInCtrlSeq = 0;
  sess.resolveReady(sess);
}

async function ensureE2EE(peerId) {
  await ensureWS();
  const sess = await getOrCreateE2EESession(peerId);
  if (sess.sendKey && sess.recvKey) return sess;

  signal(peerId, {
    type: "e2ee-key",
    pub: sess.localPubRawB64,
    nonce: sess.localNonceB64,
  });

  await Promise.race([
    sess.readyPromise,
    new Promise((_, rej) => setTimeout(() => rej(new Error("E2EE key exchange timeout")), 5000)),
  ]);
  return sess;
}

async function encryptControlMessage(peerId, plainObj) {
  const sess = await ensureE2EE(peerId);
  const seq = sess.nextOutCtrlSeq++;
  const iv = buildDeterministicIv(sess.sendPrefix, 1, 0, seq);
  const aad = buildControlAad(myId, peerId, seq);
  const pt = new TextEncoder().encode(JSON.stringify(plainObj));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    sess.sendKey,
    pt
  );
  return {
    type: "e2ee-ctrl",
    seq,
    iv: bufToBase64(iv),
    ct: bufToBase64(ctBuf),
  };
}

async function decryptControlMessage(peerId, envMsg) {
  const sess = e2eeSessions.get(peerId);
  if (!sess || !sess.recvKey) return null;
  if (!Number.isSafeInteger(envMsg.seq) || envMsg.seq !== sess.nextInCtrlSeq) {
    return null;
  }
  const expectedIv = buildDeterministicIv(sess.recvPrefix, 1, 0, envMsg.seq);
  if (envMsg.iv !== bufToBase64(expectedIv)) return null;

  const aad = buildControlAad(peerId, myId, envMsg.seq);
  let ctBuf;
  try {
    ctBuf = base64ToBuf(envMsg.ct);
  } catch {
    return null;
  }
  try {
    const ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: expectedIv, additionalData: aad, tagLength: 128 },
      sess.recvKey,
      ctBuf
    );
    sess.nextInCtrlSeq += 1;
    return JSON.parse(new TextDecoder().decode(ptBuf));
  } catch {
    return null;
  }
}

async function encryptFileChunk(peerId, transferId, fileIndex, seq, plainBuf) {
  const sess = await ensureE2EE(peerId);
  const iv = buildDeterministicIv(sess.sendPrefix, 2, fileIndex, seq);
  const aad = buildChunkAad(transferId, fileIndex, seq, myId, peerId);
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    sess.sendKey,
    plainBuf
  );
  return {
    type: "e2ee-chunk",
    transferId,
    fileIndex,
    seq,
    iv: bufToBase64(iv),
    ct: bufToBase64(ctBuf),
  };
}

async function decryptFileChunk(peerId, envMsg) {
  const sess = e2eeSessions.get(peerId);
  const f = incoming.get(peerId);
  if (!sess || !sess.recvKey || !f) return { ok: false, reason: "no_session" };
  if (envMsg.transferId !== f.meta.transferId || envMsg.fileIndex !== f.fileIndex) {
    return { ok: false, reason: "wrong_transfer" };
  }
  if (!Number.isSafeInteger(envMsg.seq)) {
    return { ok: false, reason: "invalid_seq" };
  }
  if (envMsg.seq < f.nextChunkSeq) {
    // Duplicate chunk (e.g., sender retransmitted after reconnect) -> ignore safely and re-ACK
    return { ok: false, reason: "duplicate_chunk", expectedSeq: f.nextChunkSeq };
  }
  if (envMsg.seq > f.nextChunkSeq) {
    // Out-of-order chunk -> reject and signal expected nextChunkSeq
    return { ok: false, reason: "out_of_order", expectedSeq: f.nextChunkSeq };
  }
  const expectedIv = buildDeterministicIv(sess.recvPrefix, 2, f.fileIndex, envMsg.seq);
  if (envMsg.iv !== bufToBase64(expectedIv)) {
    return { ok: false, reason: "iv_mismatch" };
  }

  const aad = buildChunkAad(f.meta.transferId, f.fileIndex, envMsg.seq, peerId, myId);
  let ctBuf;
  try {
    ctBuf = base64ToBuf(envMsg.ct);
  } catch {
    return { ok: false, reason: "bad_base64" };
  }
  try {
    const ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: expectedIv, additionalData: aad, tagLength: 128 },
      sess.recvKey,
      ctBuf
    );
    f.nextChunkSeq += 1;
    return { ok: true, ptBuf };
  } catch {
    return { ok: false, reason: "auth_tag_failed" };
  }
}

// ================= Platform Detection & Non-RAM Streaming Sinks =================
function detectStorageCapabilities() {
  const ua = typeof navigator !== "undefined" ? navigator.userAgent || "" : "";
  const isIOS = /iPhone|iPad|iPod/i.test(ua);
  const isAndroid = /Android/i.test(ua);
  const hasShowSaveFilePicker = typeof window !== "undefined" && typeof window.showSaveFilePicker === "function";
  const hasOPFS =
    typeof navigator !== "undefined" &&
    typeof navigator.storage?.getDirectory === "function";

  let idbAvailable = false;
  try {
    idbAvailable = typeof indexedDB !== "undefined" && indexedDB !== null;
  } catch {}

  if (hasShowSaveFilePicker && !isIOS) {
    return {
      platform: isAndroid ? "android-fsa" : "desktop-fsa",
      strategy: "fs-access",
      note: "บันทึกแบบสตรีมลงดิสก์โดยตรงผ่าน File System Access API (ไม่สะสมไฟล์ใน RAM)",
    };
  }
  if (hasOPFS) {
    return {
      platform: isIOS ? "ios-opfs" : isAndroid ? "android-opfs" : "opfs",
      strategy: "opfs",
      note: isIOS
        ? "iOS Safari ไม่รองรับ showSaveFilePicker — ใช้ Origin Private File System (OPFS) สตรีมลงดิสก์ชั่วคราวแล้วส่งออกโดยไม่เก็บก้อนเดียวใน RAM"
        : "ใช้ Origin Private File System (OPFS) สตรีมลงดิสก์โดยไม่สะสมใน RAM",
    };
  }
  if (idbAvailable) {
    return {
      platform: isIOS ? "ios-idb" : isAndroid ? "android-idb" : "idb-stream",
      strategy: "idb-chunk-store",
      note: isIOS
        ? "iOS Safari ไม่รองรับ File System Access API — สตรีม chunks ลง IndexedDB ทีละส่วนเพื่อไม่ให้สะสมใน Array บน RAM (ข้อจำกัด iOS: ขั้นตอนส่งออกไฟล์ใหญ่มากอาจถูกจำกัดด้วยโควตา Safari Blob)"
        : isAndroid
        ? "Android Browser นี้ไม่รองรับ showSaveFilePicker — สตรีม chunks ลง IndexedDB ทีละส่วนแทนการสะสมใน RAM"
        : "เบราว์เซอร์ไม่รองรับ File System Access API — ใช้ IndexedDB Chunk Store แทนการสะสมใน RAM",
    };
  }
  return {
    platform: isIOS ? "ios-fallback" : isAndroid ? "android-fallback" : "memory-fallback",
    strategy: "memory-capped",
    note: `คำเตือน: เบราว์เซอร์ไม่รองรับทั้ง File System Access API, OPFS และ IndexedDB — จำกัดขนาดรับไฟล์ไม่เกิน ${formatSize(MAX_IN_MEMORY_FALLBACK_BYTES)} เพื่อป้องกันแอปล่มจาก RAM เต็ม`,
  };
}

function openChunkDb() {
  return new Promise((resolve, reject) => {
    try {
      const req = indexedDB.open("mydrop-chunk-stream", 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains("chunks")) {
          db.createObjectStore("chunks");
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error("idb failed"));
    } catch (e) {
      reject(e);
    }
  });
}

async function createStreamingFileSink(meta, preboundFileHandle = null) {
  const cap = detectStorageCapabilities();
  const keyPrefix = `${meta.transferId}:${meta.fileIndex}:`;

  // 1) File System Access API (Desktop Chrome/Edge or Android with FSA handle)
  if (preboundFileHandle && typeof preboundFileHandle.createWritable === "function") {
    const writable = await preboundFileHandle.createWritable();
    let written = 0;
    return {
      strategy: "fs-access",
      note: cap.note,
      async writeChunk(seq, buf) {
        await writable.write(new Uint8Array(buf));
        written += buf.byteLength;
      },
      async finalize(safeMime) {
        await writable.close();
        if (typeof preboundFileHandle.getFile === "function") {
          return await preboundFileHandle.getFile();
        }
        return new Blob([], { type: safeMime });
      },
      async abort() {
        try { await writable.abort(); } catch {}
      },
    };
  }

  // 2) Origin Private File System (OPFS)
  if (cap.strategy === "opfs") {
    try {
      const root = await navigator.storage.getDirectory();
      const tempName = `mydrop_${meta.transferId}_${meta.fileIndex}.part`;
      const fileHandle = await root.getFileHandle(tempName, { create: true });
      if (typeof fileHandle.createWritable === "function") {
        const writable = await fileHandle.createWritable();
        return {
          strategy: "opfs",
          note: cap.note,
          async writeChunk(seq, buf) {
            await writable.write(new Uint8Array(buf));
          },
          async finalize() {
            await writable.close();
            const diskFile = await fileHandle.getFile();
            return diskFile;
          },
          async abort() {
            try { await writable.abort(); } catch {}
            try { await root.removeEntry(tempName); } catch {}
          },
        };
      }
    } catch {
      // Fallback to IndexedDB chunk store or capped spool
    }
  }

  // 3) IndexedDB Chunk Store (writes each chunk by key directly into IDB without holding an in-RAM chunk array)
  if (cap.strategy === "idb-chunk-store" || cap.strategy === "opfs" || cap.strategy === "fs-access") {
    try {
      const db = await openChunkDb();
      let chunkCount = 0;
      const putChunk = (seq, buf) =>
        new Promise((resolve, reject) => {
          const tx = db.transaction("chunks", "readwrite");
          tx.objectStore("chunks").put(new Blob([buf]), `${keyPrefix}${seq}`);
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
      const getChunk = (seq) =>
        new Promise((resolve, reject) => {
          const tx = db.transaction("chunks", "readonly");
          const req = tx.objectStore("chunks").get(`${keyPrefix}${seq}`);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
      const deleteChunks = (count) =>
        new Promise((resolve) => {
          const tx = db.transaction("chunks", "readwrite");
          const store = tx.objectStore("chunks");
          for (let i = 0; i < count; i++) store.delete(`${keyPrefix}${i}`);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        });

      return {
        strategy: "idb-chunk-store",
        note: cap.note,
        async writeChunk(seq, buf) {
          await putChunk(seq, buf);
          chunkCount = Math.max(chunkCount, seq + 1);
        },
        async finalize(safeMime) {
          const partBlobs = [];
          for (let i = 0; i < chunkCount; i++) {
            const b = await getChunk(i);
            if (!b) throw new Error("missing chunk in IndexedDB");
            partBlobs.push(b);
          }
          await deleteChunks(chunkCount);
          db.close();
          return new Blob(partBlobs, { type: safeMime });
        },
        async abort() {
          await deleteChunks(chunkCount);
          db.close();
        },
      };
    } catch {
      // Fall through to Blob-backed incremental spool
    }
  }

  // 4) Fallback Capped Spool (when IDB/OPFS/FSA are unavailable in restricted/private mode or VM tests)
  if (meta.size > MAX_IN_MEMORY_FALLBACK_BYTES) {
    throw new Error(
      `เบราว์เซอร์นี้ไม่รองรับการเขียนสตรีมลงดิสก์ (FSA/OPFS/IndexedDB) จึงจำกัดขนาดไฟล์ไว้ที่ ${formatSize(MAX_IN_MEMORY_FALLBACK_BYTES)} เพื่อป้องกันหน่วยความจำเต็ม`
    );
  }
  let rollingBlob = new Blob([]);
  let chunkWritesCount = 0;
  return {
    strategy: "blob-spool-fallback",
    note: cap.note,
    async writeChunk(seq, buf) {
      // Combine incrementally into a single Blob reference rather than keeping an unbounded Array of ArrayBuffers
      rollingBlob = new Blob([rollingBlob, buf]);
      chunkWritesCount += 1;
    },
    async finalize(safeMime) {
      const finalBlob = new Blob([rollingBlob], { type: safeMime });
      rollingBlob = new Blob([]);
      return finalBlob;
    },
    async abort() {
      rollingBlob = new Blob([]);
    },
    getChunkWritesCount: () => chunkWritesCount,
  };
}

function sanitizeFilename(rawName) {
  if (typeof rawName !== "string") return "file";
  let clean = rawName
    .replace(/\\/g, "/")
    .split("/")
    .pop()
    .replace(BIDI_AND_CONTROL_CHARS, "")
    .replace(/[<>:"|?*]/g, "_")
    .trim();
  clean = clean.replace(/^\.+/, "").replace(/\.+$/, "");
  if (!clean || WINDOWS_RESERVED_NAMES.test(clean)) {
    clean = "file_" + (clean || "unnamed");
  }
  if (clean.length > 255) {
    const dotIdx = clean.lastIndexOf(".");
    const ext = dotIdx > 0 && clean.length - dotIdx <= 16 ? clean.slice(dotIdx) : "";
    clean = clean.slice(0, Math.max(1, 255 - ext.length)) + ext;
  }
  return clean;
}

function validateOutgoingFiles(files) {
  if (!Array.isArray(files) || files.length === 0) return { ok: false, error: "กรุณาเลือกไฟล์ก่อนส่ง" };
  if (files.length > MAX_FILES_PER_TRANSFER) {
    return { ok: false, error: `ส่งได้สูงสุด ${MAX_FILES_PER_TRANSFER} ไฟล์ต่อครั้ง` };
  }
  let total = 0;
  for (const f of files) {
    if (!f || typeof f.size !== "number" || !Number.isSafeInteger(f.size) || f.size < 0) {
      return { ok: false, error: "ข้อมูลไฟล์ไม่ถูกต้อง" };
    }
    if (f.size > MAX_FILE_SIZE) {
      return { ok: false, error: `ไฟล์ "${sanitizeFilename(f.name)}" มีขนาดเกิน ${formatSize(MAX_FILE_SIZE)}` };
    }
    total += f.size;
    if (total > MAX_TRANSFER_SIZE) {
      return { ok: false, error: `ขนาดไฟล์รวมเกิน ${formatSize(MAX_TRANSFER_SIZE)} ต่อครั้ง` };
    }
  }
  return { ok: true, total };
}

async function clearIncomingState(peerId, notifyText = "") {
  const f = incoming.get(peerId);
  if (!f) return;
  clearTimeout(f.timer);
  incoming.delete(peerId);
  if (f.sink) {
    try { await f.sink.abort(); } catch {}
  }
  setProgress(peerId, null);
  if (activeUiTransfer?.peerId === peerId && activeUiTransfer?.direction === "recv") {
    if (notifyText) showTransferError(notifyText);
    else hideTransferPanel();
  }
  if (notifyText) toast(notifyText);
}

function refreshIncomingTimer(peerId, f) {
  clearTimeout(f.timer);
  f.timer = setTimeout(() => {
    if (f.paused) return; // Do not expire while explicitly paused
    acceptedTransfers.delete(f.meta?.transferId);
    clearIncomingState(peerId, `การรับไฟล์ ${f.meta?.name || ""} หมดเวลา`);
  }, INCOMING_TIMEOUT_MS);
}

function uuid() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) =>
    (+c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (+c / 4)))).toString(16)
  );
}

let targetPeer = null;
let stagedFiles = [];
let pendingShare = null;
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
  navigator.serviceWorker.register("/sw.js").catch(() => {});
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

// ================= Transfer Progress UI, Speed, ETA, Pause/Resume/Cancel =================
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "ETA: --";
  if (seconds < 1) return "ETA: < 1s";
  const s = Math.round(seconds);
  if (s < 60) return `ETA: ${s}s`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  return `ETA: ${m}m ${remS}s`;
}

function updateTransferPanel({
  transferId,
  peerId,
  direction,
  title,
  stateLabel,
  transferredBytes,
  totalBytes,
  startTime,
  paused = false,
  storageNote = "",
  errorText = "",
}) {
  activeUiTransfer = { transferId, peerId, direction };
  const panel = $("#transferPanel");
  if (!panel) return;
  panel.hidden = false;

  const ratio = totalBytes > 0 ? Math.min(1, transferredBytes / totalBytes) : 1;
  const pct = Math.round(ratio * 100);
  const elapsedSec = Math.max(0.001, (Date.now() - (startTime || Date.now())) / 1000);
  const bytesPerSec = transferredBytes / elapsedSec;
  const remainingBytes = Math.max(0, totalBytes - transferredBytes);
  const etaSec = bytesPerSec > 0 ? remainingBytes / bytesPerSec : Infinity;

  $("#tpTitle").textContent = title || (direction === "send" ? "กำลังส่งไฟล์..." : "กำลังรับไฟล์...");
  $("#tpStateBadge").textContent = stateLabel || (paused ? "หยุดชั่วคราว" : "กำลังสตรีม (E2EE)");
  $("#tpBar").style.width = `${pct}%`;
  $("#tpSizeInfo").textContent = `${formatSize(transferredBytes)} / ${formatSize(totalBytes)} (${pct}%)`;
  $("#tpSpeedInfo").textContent = paused ? "0 B/s (Paused)" : `${formatSize(bytesPerSec)}/s`;
  $("#tpEtaInfo").textContent = paused ? "ETA: หยุดชั่วคราว" : formatEta(etaSec);

  const noteEl = $("#tpStorageNote");
  if (noteEl) noteEl.textContent = storageNote || detectStorageCapabilities().note;

  const errEl = $("#tpError");
  if (errEl) {
    errEl.hidden = !errorText;
    errEl.textContent = errorText || "";
  }

  const pauseBtn = $("#tpPauseBtn");
  const resumeBtn = $("#tpResumeBtn");
  if (pauseBtn && resumeBtn) {
    pauseBtn.hidden = paused;
    resumeBtn.hidden = !paused;
  }
}

function showTransferError(errorText) {
  const panel = $("#transferPanel");
  if (!panel) return;
  panel.hidden = false;
  $("#tpStateBadge").textContent = "ข้อผิดพลาด";
  const errEl = $("#tpError");
  if (errEl) {
    errEl.hidden = false;
    errEl.textContent = errorText;
  }
}

function hideTransferPanel() {
  activeUiTransfer = null;
  const panel = $("#transferPanel");
  if (panel) panel.hidden = true;
}

function notifyTransferWaiters(state) {
  if (!state?.waiters) return;
  for (const fn of [...state.waiters]) fn();
}

async function pauseTransfer(transferId = activeUiTransfer?.transferId) {
  if (!transferId) return false;
  const out = outgoingTransfers.get(transferId);
  if (out) {
    out.paused = true;
    notifyTransferWaiters(out);
    try {
      const envMsg = await encryptControlMessage(out.peerId, { type: "transfer-control", transferId, action: "pause" });
      sendEnvelopeBestEffort(out.peerId, envMsg);
    } catch {}
    updateTransferPanel({
      transferId,
      peerId: out.peerId,
      direction: "send",
      title: `หยุดส่งชั่วคราว (${peerName(out.peerId)})`,
      stateLabel: "หยุดชั่วคราว (Paused)",
      transferredBytes: out.sentBytes,
      totalBytes: out.totalBytes,
      startTime: out.startTime,
      paused: true,
    });
    return true;
  }
  for (const [peerId, inc] of incoming.entries()) {
    if (inc.meta?.transferId === transferId) {
      inc.paused = true;
      clearTimeout(inc.timer);
      try {
        const envMsg = await encryptControlMessage(peerId, { type: "transfer-control", transferId, action: "pause" });
        sendEnvelopeBestEffort(peerId, envMsg);
      } catch {}
      updateTransferPanel({
        transferId,
        peerId,
        direction: "recv",
        title: `หยุดรับชั่วคราว: ${inc.meta.name}`,
        stateLabel: "หยุดชั่วคราว (Paused)",
        transferredBytes: inc.received,
        totalBytes: inc.meta.size,
        startTime: inc.startTime,
        paused: true,
        storageNote: inc.sink?.note,
      });
      return true;
    }
  }
  return false;
}

async function resumeTransfer(transferId = activeUiTransfer?.transferId) {
  if (!transferId) return false;
  const out = outgoingTransfers.get(transferId);
  if (out) {
    out.paused = false;
    out.remotePaused = false;
    notifyTransferWaiters(out);
    try {
      const envMsg = await encryptControlMessage(out.peerId, { type: "transfer-control", transferId, action: "resume" });
      sendEnvelopeBestEffort(out.peerId, envMsg);
    } catch {}
    updateTransferPanel({
      transferId,
      peerId: out.peerId,
      direction: "send",
      title: `กำลังส่งให้ ${peerName(out.peerId)}`,
      stateLabel: "กำลังสตรีม (E2EE)",
      transferredBytes: out.sentBytes,
      totalBytes: out.totalBytes,
      startTime: out.startTime,
      paused: false,
    });
    return true;
  }
  for (const [peerId, inc] of incoming.entries()) {
    if (inc.meta?.transferId === transferId) {
      inc.paused = false;
      refreshIncomingTimer(peerId, inc);
      try {
        const envMsg = await encryptControlMessage(peerId, {
          type: "transfer-control",
          transferId,
          action: "resume",
          fileIndex: inc.fileIndex,
          nextSeq: inc.nextChunkSeq,
        });
        sendEnvelopeBestEffort(peerId, envMsg);
      } catch {}
      updateTransferPanel({
        transferId,
        peerId,
        direction: "recv",
        title: `กำลังรับ: ${inc.meta.name}`,
        stateLabel: "กำลังสตรีม (E2EE)",
        transferredBytes: inc.received,
        totalBytes: inc.meta.size,
        startTime: inc.startTime,
        paused: false,
        storageNote: inc.sink?.note,
      });
      return true;
    }
  }
  return false;
}

async function cancelTransfer(transferId = activeUiTransfer?.transferId, reason = "ผู้ใช้ยกเลิกการส่งไฟล์") {
  if (!transferId) return false;
  const out = outgoingTransfers.get(transferId);
  if (out) {
    out.cancelled = true;
    out.cancelReason = reason;
    notifyTransferWaiters(out);
    try {
      const envMsg = await encryptControlMessage(out.peerId, {
        type: "transfer-control",
        transferId,
        action: "cancel",
        reason,
      });
      sendEnvelopeBestEffort(out.peerId, envMsg);
    } catch {}
    showTransferError(reason);
    setProgress(out.peerId, null);
    return true;
  }
  for (const [peerId, inc] of incoming.entries()) {
    if (inc.meta?.transferId === transferId) {
      inc.cancelled = true;
      acceptedTransfers.delete(transferId);
      try {
        const envMsg = await encryptControlMessage(peerId, {
          type: "transfer-control",
          transferId,
          action: "cancel",
          reason,
        });
        sendEnvelopeBestEffort(peerId, envMsg);
      } catch {}
      await clearIncomingState(peerId, reason);
      return true;
    }
  }
  return false;
}

if ($("#tpPauseBtn")) $("#tpPauseBtn").onclick = () => pauseTransfer();
if ($("#tpResumeBtn")) $("#tpResumeBtn").onclick = () => resumeTransfer();
if ($("#tpCancelBtn")) $("#tpCancelBtn").onclick = () => cancelTransfer();

function sendEnvelopeBestEffort(peerId, envMsg) {
  const c = conns.get(peerId);
  if (c?.dc?.readyState === "open") {
    try {
      c.dc.send(JSON.stringify(envMsg));
      return true;
    } catch {}
  }
  if (ws?.readyState === 1) {
    try {
      relaySend(peerId, envMsg);
      return true;
    } catch {}
  }
  return false;
}

// ================= Room Code UI =================
function updateRoomUI() {
  $("#roomInput").value = currentRoom;
  $("#leaveRoomBtn").hidden = !currentRoom;
  $("#roomStatus").textContent = currentRoom
    ? `ห้องกำหนดเอง: ${currentRoom}`
    : "โหมด: Wi-Fi / LAN เดียวกันอัตโนมัติ";
}

function switchRoom(newRoom) {
  const trimmed = (newRoom || "").trim();
  if (trimmed && !ROOM_CODE_RE.test(trimmed)) {
    toast("รหัสห้องต้องมีความยาว 3-48 ตัวอักษร (a-z, 0-9, -, _)");
    return;
  }
  currentRoom = trimmed;
  const url = new URL(location.href);
  if (currentRoom) url.searchParams.set("room", currentRoom);
  else url.searchParams.delete("room");
  history.replaceState(null, "", url.pathname + (url.search || ""));
  updateRoomUI();

  for (const peerId of [...conns.keys()]) closeConn(peerId);
  for (const peerId of [...incoming.keys()]) clearIncomingState(peerId);
  e2eeSessions.clear();
  acceptedTransfers.clear();
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
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (!msg || typeof msg.type !== "string") return;
    if (msg.type === "welcome") {
      myId = msg.id;
      myName = msg.name;
      try {
        sessionStorage.setItem("mydrop_id", myId);
        sessionStorage.setItem("mydrop_name", myName);
      } catch {}
      $("#me").textContent = `คุณคือ ${msg.name}`;
    } else if (msg.type === "peers") {
      peers = Array.isArray(msg.peers) ? msg.peers : [];
      renderPeers();
      for (const p of peers) {
        ensureE2EE(p.id).catch(() => {});
      }
    } else if (msg.type === "signal") {
      onSignal(msg.from, msg.data);
    } else if (msg.type === "relay") {
      onEncryptedEnvelope(msg.from, msg.data);
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
    chunk: 32768,
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
  dc.bufferedAmountLowThreshold = 512 * 1024;
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
    if (typeof e.data === "string") {
      try {
        onEncryptedEnvelope(peerId, JSON.parse(e.data));
      } catch {}
    }
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
  c.chunk = Math.min(48 * 1024, c.pc.sctp?.maxMessageSize ? Math.floor(c.pc.sctp.maxMessageSize * 0.65) : 32768);
  return c;
}

// Drain WebRTC DataChannel or WebSocket buffer with explicit backpressure
async function waitForChannelDrain(dc) {
  if (dc.bufferedAmount <= MAX_BUFFER) return;
  await new Promise((resolve) => {
    let resolved = false;
    const done = () => {
      if (resolved) return;
      resolved = true;
      clearInterval(poll);
      try { dc.removeEventListener?.("bufferedamountlow", done); } catch {}
      resolve();
    };
    try { dc.addEventListener("bufferedamountlow", done, { once: true }); } catch {}
    const poll = setInterval(() => {
      if (dc.readyState !== "open" || dc.bufferedAmount <= (dc.bufferedAmountLowThreshold || 512 * 1024)) {
        done();
      }
    }, 15);
  });
}

async function waitForWsDrain(socket) {
  while (socket?.readyState === 1 && socket.bufferedAmount > MAX_WS_BUFFER) {
    await new Promise((r) => setTimeout(r, 15));
  }
}

async function getTransport(peerId) {
  await ensureWS();
  await ensureE2EE(peerId);
  try {
    const c = await connect(peerId);
    return {
      mode: "p2p",
      chunk: c.chunk,
      isOpen: () => c.dc?.readyState === "open",
      getBufferedAmount: () => c.dc?.bufferedAmount || 0,
      async sendControl(plainObj) {
        const envMsg = await encryptControlMessage(peerId, plainObj);
        c.dc.send(JSON.stringify(envMsg));
      },
      async sendChunk(transferId, fileIndex, seq, plainBuf) {
        await waitForChannelDrain(c.dc);
        const envMsg = await encryptFileChunk(peerId, transferId, fileIndex, seq, plainBuf);
        c.dc.send(JSON.stringify(envMsg));
      },
    };
  } catch {
    await ensureWS();
    await ensureE2EE(peerId);
    setStatus(peerId, "ใช้โหมด Relay (E2EE)...");
    return {
      mode: "relay",
      chunk: 48 * 1024,
      isOpen: () => ws?.readyState === 1,
      getBufferedAmount: () => ws?.bufferedAmount || 0,
      async sendControl(plainObj) {
        const envMsg = await encryptControlMessage(peerId, plainObj);
        relaySend(peerId, envMsg);
      },
      async sendChunk(transferId, fileIndex, seq, plainBuf) {
        await waitForWsDrain(ws);
        const envMsg = await encryptFileChunk(peerId, transferId, fileIndex, seq, plainBuf);
        relaySend(peerId, envMsg);
      },
    };
  }
}

async function onSignal(from, data) {
  try {
    if (!data || typeof data.type !== "string") return;

    if (data.type === "e2ee-key" || data.type === "e2ee-ack") {
      if (typeof data.pub !== "string" || typeof data.nonce !== "string") return;
      const sess = await getOrCreateE2EESession(from);
      const changed = sess.remotePubRawB64 !== data.pub || sess.remoteNonceB64 !== data.nonce;
      if (changed || !sess.sendKey) {
        await derivePeerKeys(sess, data.pub, data.nonce);
      }
      if (data.type === "e2ee-key") {
        signal(from, {
          type: "e2ee-ack",
          pub: sess.localPubRawB64,
          nonce: sess.localNonceB64,
        });
      }
      return;
    }

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
        c.pending.push(data.candidate);
      }
    }
  } catch {}
}

// ================= Streaming File Transfer with Flow Control, Backpressure, Pause/Cancel/Resume =================
async function waitForFlowControl(state, maxInFlight = MAX_IN_FLIGHT_CHUNKS) {
  while (!state.cancelled) {
    if (state.paused || state.remotePaused) {
      await new Promise((resolve) => {
        const w = () => {
          state.waiters.delete(w);
          resolve();
        };
        state.waiters.add(w);
      });
      continue;
    }
    const inFlight = state.nextSeq - (state.ackedSeq + 1);
    if (inFlight < maxInFlight) return;
    await new Promise((resolve) => {
      let timer;
      const w = () => {
        clearTimeout(timer);
        state.waiters.delete(w);
        resolve();
      };
      state.waiters.add(w);
      timer = setTimeout(w, 250);
    });
  }
}

async function sendFiles(peerId, files) {
  if (!files.length) return false;
  const check = validateOutgoingFiles(files);
  if (!check.ok) {
    toast(check.error);
    return false;
  }
  let tx;
  try {
    setStatus(peerId, "กำลังเชื่อมต่อ...");
    tx = await getTransport(peerId);
  } catch {
    setStatus(peerId, "");
    toast("เชื่อมต่อไม่สำเร็จ");
    return false;
  }

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
    files: files.map((f) => ({ name: sanitizeFilename(f.name), size: f.size, mime: f.type })),
  };
  try {
    await tx.sendControl(reqMsg);
  } catch {
    try {
      await ensureWS();
      const envMsg = await encryptControlMessage(peerId, reqMsg);
      relaySend(peerId, envMsg);
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

  const totalBytes = files.reduce((sum, f) => sum + f.size, 0);
  const state = {
    transferId,
    peerId,
    files,
    fileIndex: 0,
    nextSeq: 0,
    ackedSeq: -1,
    offset: 0,
    chunkSize: tx.chunk,
    paused: false,
    remotePaused: false,
    cancelled: false,
    cancelReason: "",
    fileDoneAcked: false,
    resumeRequestedSeq: null,
    waiters: new Set(),
    startTime: Date.now(),
    totalBytes,
    sentBytes: 0,
  };
  outgoingTransfers.set(transferId, state);

  try {
    for (let fileIndex = 0; fileIndex < files.length; fileIndex++) {
      const file = files[fileIndex];
      const safeName = sanitizeFilename(file.name);
      state.fileIndex = fileIndex;
      state.nextSeq = 0;
      state.ackedSeq = -1;
      state.offset = 0;
      state.fileDoneAcked = false;
      state.chunkSize = tx.chunk;
      const totalChunks = Math.ceil(file.size / state.chunkSize);

      if (!tx.isOpen()) {
        tx = await recoverTransportAndHandshake(peerId, state);
        if (!tx) return false;
      }

      await tx.sendControl({
        type: "header",
        transferId,
        fileIndex,
        name: safeName,
        size: file.size,
        mime: file.type,
        chunkSize: state.chunkSize,
        totalChunks,
      });

      updateTransferPanel({
        transferId,
        peerId,
        direction: "send",
        title: `กำลังส่ง ${safeName} ให้ ${peerName(peerId)}`,
        stateLabel: tx.mode === "relay" ? "กำลังสตรีม (Relay E2EE)" : "กำลังสตรีม (P2P E2EE)",
        transferredBytes: state.sentBytes,
        totalBytes: state.totalBytes,
        startTime: state.startTime,
        paused: false,
      });

      while (state.offset < file.size) {
        if (state.cancelled) {
          throw new Error(state.cancelReason || "การส่งถูกยกเลิก");
        }
        await waitForFlowControl(state);
        if (state.cancelled) {
          throw new Error(state.cancelReason || "การส่งถูกยกเลิก");
        }

        // Check if receiver requested resume from a specific chunk sequence after reconnect
        if (state.resumeRequestedSeq !== null) {
          const resumeSeq = state.resumeRequestedSeq;
          state.resumeRequestedSeq = null;
          state.nextSeq = resumeSeq;
          state.ackedSeq = resumeSeq - 1;
          state.offset = resumeSeq * state.chunkSize;
        }

        if (!tx.isOpen()) {
          tx = await recoverTransportAndHandshake(peerId, state);
          if (!tx) throw new Error("การเชื่อมต่อหลุดและกู้คืนไม่สำเร็จ");
          continue;
        }

        const seq = state.nextSeq;
        const sliceStart = seq * state.chunkSize;
        const sliceEnd = Math.min(file.size, sliceStart + state.chunkSize);
        const buf = await file.slice(sliceStart, sliceEnd).arrayBuffer();

        try {
          await tx.sendChunk(transferId, fileIndex, seq, buf);
        } catch {
          tx = await recoverTransportAndHandshake(peerId, state);
          if (!tx) throw new Error("การเชื่อมต่อหลุดระหว่างส่ง chunk");
          continue;
        }

        state.nextSeq += 1;
        state.offset = sliceEnd;
        const priorFilesBytes = files.slice(0, fileIndex).reduce((s, f) => s + f.size, 0);
        state.sentBytes = priorFilesBytes + state.offset;

        setProgress(peerId, state.offset / file.size, `ส่ง ${safeName}`);
        updateTransferPanel({
          transferId,
          peerId,
          direction: "send",
          title: `กำลังส่ง ${safeName} ให้ ${peerName(peerId)}`,
          stateLabel: tx.mode === "relay" ? "กำลังสตรีม (Relay E2EE)" : "กำลังสตรีม (P2P E2EE)",
          transferredBytes: state.sentBytes,
          totalBytes: state.totalBytes,
          startTime: state.startTime,
          paused: state.paused || state.remotePaused,
        });
      }

      // Wait for receiver's final ACK confirming all chunks for this file were verified & written
      if (totalChunks > 0) {
        const finalSeq = totalChunks - 1;
        const waitStart = Date.now();
        while (!state.cancelled && state.ackedSeq < finalSeq && Date.now() - waitStart < 15000) {
          if (state.resumeRequestedSeq !== null) break;
          await new Promise((resolve) => {
            const timer = setTimeout(resolve, 100);
            const w = () => {
              clearTimeout(timer);
              state.waiters.delete(w);
              resolve();
            };
            state.waiters.add(w);
          });
        }
      }
    }

    outgoingTransfers.delete(transferId);
    setProgress(peerId, null);
    hideTransferPanel();
    toast(tx.mode === "relay" ? "ส่งเสร็จแล้ว (สตรีม E2EE ผ่าน Relay)" : "ส่งเสร็จแล้ว (สตรีม E2EE)");
    return true;
  } catch (err) {
    outgoingTransfers.delete(transferId);
    setProgress(peerId, null);
    showTransferError(err?.message || "การส่งไฟล์ล้มเหลว");
    toast(err?.message || "การส่งไฟล์ล้มเหลว");
    return false;
  }
}

async function recoverTransportAndHandshake(peerId, state) {
  setStatus(peerId, "การเชื่อมต่อสะดุด กำลังต่อใหม่และ Resume...");
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await ensureWS();
      await ensureE2EE(peerId);
      const tx = {
        mode: "relay",
        chunk: state.chunkSize,
        isOpen: () => ws?.readyState === 1,
        async sendControl(plainObj) {
          const envMsg = await encryptControlMessage(peerId, plainObj);
          relaySend(peerId, envMsg);
        },
        async sendChunk(tId, fIdx, seq, plainBuf) {
          await waitForWsDrain(ws);
          const envMsg = await encryptFileChunk(peerId, tId, fIdx, seq, plainBuf);
          relaySend(peerId, envMsg);
        },
      };
      // Query receiver for the next expected chunk sequence so no chunks are lost or duplicated
      await tx.sendControl({
        type: "resume-query",
        transferId: state.transferId,
        fileIndex: state.fileIndex,
      });
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 250);
        const w = () => {
          clearTimeout(timer);
          state.waiters.delete(w);
          resolve();
        };
        state.waiters.add(w);
      });
      return tx;
    } catch {
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  return null;
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
    await tx.sendControl({ type: "text", text });
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

// ================= รับข้อมูล & ยอมรับ/ปฏิเสธ (Streaming Sink + Flow Control ACKs) =================
const peerDecryptQueues = new Map();

function onEncryptedEnvelope(peerId, envMsg) {
  const prev = peerDecryptQueues.get(peerId) || Promise.resolve();
  const next = prev
    .then(() => processEncryptedEnvelope(peerId, envMsg))
    .catch(() => {});
  peerDecryptQueues.set(peerId, next);
  return next;
}

async function processEncryptedEnvelope(peerId, envMsg) {
  if (!envMsg || typeof envMsg !== "object" || typeof envMsg.type !== "string") return;

  if (envMsg.type === "e2ee-ctrl") {
    const msg = await decryptControlMessage(peerId, envMsg);
    if (!msg || typeof msg.type !== "string") return;
    await handleDecryptedControl(peerId, msg);
    return;
  }

  if (envMsg.type === "e2ee-chunk") {
    const f = incoming.get(peerId);
    if (!f || f.cancelled) return;
    const dec = await decryptFileChunk(peerId, envMsg);
    if (!dec.ok) {
      if (dec.reason === "duplicate_chunk") {
        // Re-send cumulative ACK so sender advances its sliding window
        await sendChunkAck(peerId, f, f.nextChunkSeq - 1);
        return;
      }
      if (dec.reason === "out_of_order") {
        // Inform sender of exact expected sequence number for resume/realignment
        try {
          const resumeMsg = await encryptControlMessage(peerId, {
            type: "resume-state",
            transferId: f.meta.transferId,
            fileIndex: f.fileIndex,
            nextSeq: f.nextChunkSeq,
            receivedBytes: f.received,
          });
          sendEnvelopeBestEffort(peerId, resumeMsg);
        } catch {}
        return;
      }
      await clearIncomingState(peerId, "ตรวจพบ chunk ที่ถูกแก้ไขหรือไม่ถูกต้อง ยกเลิกการรับไฟล์");
      return;
    }

    const ptBuf = dec.ptBuf;
    if (ptBuf.byteLength === 0 || f.received + ptBuf.byteLength > f.meta.size || f.received + ptBuf.byteLength > MAX_FILE_SIZE) {
      await clearIncomingState(peerId, "ขนาดข้อมูลเกินที่กำหนดใน header");
      return;
    }

    try {
      await f.sink.writeChunk(envMsg.seq, ptBuf);
    } catch (err) {
      await clearIncomingState(peerId, err?.message || "เขียนไฟล์ลงพื้นที่จัดเก็บไม่สำเร็จ");
      return;
    }

    f.received += ptBuf.byteLength;
    refreshIncomingTimer(peerId, f);
    setProgress(peerId, f.received / f.meta.size, `รับ ${f.meta.name}`);

    updateTransferPanel({
      transferId: f.meta.transferId,
      peerId,
      direction: "recv",
      title: `กำลังรับ ${f.meta.name} จาก ${peerName(peerId)}`,
      stateLabel: f.paused ? "หยุดชั่วคราว" : "กำลังสตรีมลงพื้นที่จัดเก็บ (E2EE)",
      transferredBytes: f.received,
      totalBytes: f.meta.size,
      startTime: f.startTime,
      paused: f.paused,
      storageNote: f.sink?.note,
    });

    const isLastChunk = f.received === f.meta.size;
    if (isLastChunk || (envMsg.seq - f.lastAckSeq) >= ACK_BATCH_INTERVAL) {
      f.lastAckSeq = envMsg.seq;
      await sendChunkAck(peerId, f, envMsg.seq, isLastChunk);
    }

    if (isLastChunk) {
      await finishFile(peerId);
    }
  }
}

async function sendChunkAck(peerId, f, ackSeq, done = false) {
  try {
    const ackEnv = await encryptControlMessage(peerId, {
      type: "chunk-ack",
      transferId: f.meta.transferId,
      fileIndex: f.fileIndex,
      ackSeq,
      receivedBytes: f.received,
      paused: f.paused,
      done,
    });
    sendEnvelopeBestEffort(peerId, ackEnv);
  } catch {}
}

async function handleDecryptedControl(peerId, msg) {
  if (msg.type === "text") {
    if (typeof msg.text !== "string" || msg.text.length === 0 || msg.text.length > MAX_TEXT_LENGTH) return;
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
    if (requestQueue.length >= MAX_PENDING_REQUESTS) return;
    seenRequests.add(msg.transferId);
    if (seenRequests.size > 200) seenRequests.delete(seenRequests.values().next().value);
    const sanitizedFiles = msg.files.map((f) => ({
      name: sanitizeFilename(f.name),
      size: f.size,
      mime: typeof f.mime === "string" ? f.mime.slice(0, 255) : "",
    }));
    requestQueue.push({ peerId, transferId: msg.transferId, files: sanitizedFiles });
    processRequestQueue();
  } else if (msg.type === "file-response") {
    if (typeof msg.transferId !== "string" || typeof msg.accepted !== "boolean") return;
    const pending = pendingResponses.get(msg.transferId);
    if (pending && pending.peerId === peerId) {
      pendingResponses.delete(msg.transferId);
      pending.resolve(Boolean(msg.accepted));
    }
  } else if (msg.type === "header") {
    const accepted = acceptedTransfers.get(msg.transferId);
    const expectedFileIndex = accepted ? accepted.nextFileIndex : -1;
    const msgFileIndex = Number.isSafeInteger(msg.fileIndex) ? msg.fileIndex : 0;
    if (!accepted || accepted.peerId !== peerId || accepted.remaining <= 0 ||
        msgFileIndex !== expectedFileIndex ||
        typeof msg.name !== "string" || msg.name.length < 1 || msg.name.length > 255 ||
        !Number.isSafeInteger(msg.size) || msg.size < 0 || msg.size > MAX_FILE_SIZE ||
        incoming.has(peerId)) return;

    const safeMeta = {
      ...msg,
      name: sanitizeFilename(msg.name),
    };
    const preboundHandle = accepted.fileHandles?.[msgFileIndex] || null;
    let sink;
    try {
      sink = await createStreamingFileSink(
        { transferId: msg.transferId, fileIndex: msgFileIndex, name: safeMeta.name, size: safeMeta.size },
        preboundHandle
      );
    } catch (err) {
      showTransferError(err?.message || "ไม่สามารถเตรียมพื้นที่จัดเก็บไฟล์ได้");
      toast(err?.message || "ไม่สามารถเตรียมพื้นที่จัดเก็บไฟล์ได้");
      return;
    }

    const entry = {
      meta: safeMeta,
      fileIndex: msgFileIndex,
      nextChunkSeq: 0,
      lastAckSeq: -1,
      received: 0,
      sink,
      paused: false,
      cancelled: false,
      startTime: Date.now(),
      timer: null,
    };
    incoming.set(peerId, entry);
    if (safeMeta.size === 0) {
      await finishFile(peerId);
    } else {
      refreshIncomingTimer(peerId, entry);
    }
  } else if (msg.type === "chunk-ack") {
    const out = outgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId || msg.fileIndex !== out.fileIndex) return;
    if (Number.isSafeInteger(msg.ackSeq) && msg.ackSeq > out.ackedSeq) {
      out.ackedSeq = msg.ackSeq;
    }
    if (typeof msg.paused === "boolean") {
      out.remotePaused = msg.paused;
    }
    if (msg.done) {
      out.fileDoneAcked = true;
    }
    notifyTransferWaiters(out);
  } else if (msg.type === "resume-query") {
    const f = incoming.get(peerId);
    if (!f || f.meta?.transferId !== msg.transferId || f.fileIndex !== msg.fileIndex) return;
    try {
      const replyEnv = await encryptControlMessage(peerId, {
        type: "resume-state",
        transferId: f.meta.transferId,
        fileIndex: f.fileIndex,
        nextSeq: f.nextChunkSeq,
        receivedBytes: f.received,
      });
      sendEnvelopeBestEffort(peerId, replyEnv);
    } catch {}
  } else if (msg.type === "resume-state") {
    const out = outgoingTransfers.get(msg.transferId);
    if (!out || out.peerId !== peerId || msg.fileIndex !== out.fileIndex) return;
    if (Number.isSafeInteger(msg.nextSeq) && msg.nextSeq >= 0) {
      out.resumeRequestedSeq = msg.nextSeq;
      out.ackedSeq = msg.nextSeq - 1;
      notifyTransferWaiters(out);
    }
  } else if (msg.type === "transfer-control") {
    const { transferId, action, reason } = msg;
    const out = outgoingTransfers.get(transferId);
    if (out && out.peerId === peerId) {
      if (action === "pause") {
        out.remotePaused = true;
        notifyTransferWaiters(out);
        updateTransferPanel({
          transferId,
          peerId,
          direction: "send",
          title: `ผู้รับหยุดพักการรับชั่วคราว`,
          stateLabel: "ผู้รับกด Pause",
          transferredBytes: out.sentBytes,
          totalBytes: out.totalBytes,
          startTime: out.startTime,
          paused: true,
        });
      } else if (action === "resume") {
        out.remotePaused = false;
        if (Number.isSafeInteger(msg.nextSeq) && msg.nextSeq >= 0) {
          out.resumeRequestedSeq = msg.nextSeq;
        }
        notifyTransferWaiters(out);
      } else if (action === "cancel") {
        out.cancelled = true;
        out.cancelReason = reason || "ผู้รับยกเลิกการรับไฟล์";
        notifyTransferWaiters(out);
      }
      return;
    }

    const inc = incoming.get(peerId);
    if (inc && inc.meta?.transferId === transferId) {
      if (action === "pause") {
        inc.paused = true;
        clearTimeout(inc.timer);
      } else if (action === "resume") {
        inc.paused = false;
        refreshIncomingTimer(peerId, inc);
      } else if (action === "cancel") {
        inc.cancelled = true;
        acceptedTransfers.delete(transferId);
        await clearIncomingState(peerId, reason || "ผู้ส่งยกเลิกการส่งไฟล์");
      }
    }
  }
}

function processRequestQueue() {
  if (activeRequest || requestQueue.length === 0) return;
  activeRequest = requestQueue.shift();

  const total = activeRequest.files.reduce((sum, f) => sum + (f.size || 0), 0);
  const cap = detectStorageCapabilities();
  $("#modalTitle").textContent = `${peerName(activeRequest.peerId)} ต้องการส่งไฟล์`;
  $("#modalSub").textContent = `จำนวน ${activeRequest.files.length} ไฟล์ (รวม ${formatSize(total)}) — ${cap.note}`;

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
  const { peerId, transferId, files } = activeRequest;
  activeRequest = null;
  $("#confirmModal").style.display = "none";

  const fileHandles = [];
  if (accepted) {
    // If File System Access API is supported and user is on a single-file transfer, offer direct disk save handle during user gesture
    const cap = detectStorageCapabilities();
    if (cap.strategy === "fs-access" && files.length === 1 && typeof window?.showSaveFilePicker === "function") {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: files[0].name });
        if (handle) fileHandles[0] = handle;
      } catch {
        // User dismissed native picker or test environment; fallback to OPFS / IndexedDB stream sink automatically
      }
    }
    acceptedTransfers.set(transferId, {
      peerId,
      remaining: Math.max(1, files.length),
      nextFileIndex: 0,
      fileHandles,
    });
  }

  const reply = { type: "file-response", transferId, accepted };
  let sent = false;
  try {
    const envMsg = await encryptControlMessage(peerId, reply);
    sent = sendEnvelopeBestEffort(peerId, envMsg);
    if (!sent) {
      await ensureWS();
      relaySend(peerId, envMsg);
      sent = true;
    }
  } catch {
    if (!sent) toast("ส่งการตอบรับไม่สำเร็จ");
  }
  processRequestQueue();
}

$("#acceptBtn").onclick = () => respondToActiveRequest(true);
$("#rejectBtn").onclick = () => respondToActiveRequest(false);

async function finishFile(peerId) {
  const f = incoming.get(peerId);
  if (f) clearTimeout(f.timer);
  incoming.delete(peerId);
  if (!f || f.received !== f.meta.size) return;

  const accepted = acceptedTransfers.get(f.meta.transferId);
  if (accepted) {
    accepted.remaining -= 1;
    accepted.nextFileIndex += 1;
    if (accepted.remaining <= 0) {
      acceptedTransfers.delete(f.meta.transferId);
      hideTransferPanel();
    }
  } else {
    hideTransferPanel();
  }

  const rawMime = typeof f.meta.mime === "string" ? f.meta.mime.trim().toLowerCase() : "";
  const safeMime =
    /^[\w.+-]+\/[\w.+-]+$/.test(rawMime) && !DANGEROUS_MIMES.has(rawMime)
      ? rawMime
      : "application/octet-stream";
  const safeName = sanitizeFilename(f.meta.name);

  let blob;
  try {
    blob = await f.sink.finalize(safeMime);
  } catch (err) {
    showTransferError(err?.message || "ประกอบไฟล์จากพื้นที่จัดเก็บไม่สำเร็จ");
    toast(err?.message || "ประกอบไฟล์ไม่สำเร็จ");
    return;
  }

  addReceivedFile(peerName(peerId), safeName, blob, f.sink.strategy);
  setProgress(peerId, null);
  toast(`ได้รับ ${safeName}`);
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

function addReceivedFile(from, name, blob, strategy = "") {
  const item = document.createElement("div");
  item.className = "item";
  const info = document.createElement("div");
  const modeTag = strategy === "fs-access" ? " [ลงดิสก์แล้ว]" : "";
  info.textContent = `${name} (${formatSize(blob.size)}) จาก ${from}${modeTag}`;
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
