const CACHE_NAME = "mydrop-v6";
const ASSETS = [
  "/",
  "/index.html",
  "/app.js",
  "/manifest.webmanifest",
  "/icon-192.png",
  "/icon-512.png"
];

const SHARE_LIMITS = {
  MAX_FILES: 10,
  MAX_FILE_SIZE: 5 * 1024 * 1024 * 1024, // 5 GB per file
  MAX_TOTAL_SIZE: 10 * 1024 * 1024 * 1024, // 10 GB total
  MAX_TEXT_CHARS: 16384,
  MAX_FILENAME_LENGTH: 255,
};

const BIDI_AND_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
const WINDOWS_RESERVED_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

function sanitizeSharedFilename(rawName) {
  if (typeof rawName !== "string") return "shared_file";
  let clean = rawName
    .replace(/\\/g, "/")
    .split("/")
    .pop()
    .replace(BIDI_AND_CONTROL_CHARS, "")
    .replace(/[<>:"|?*]/g, "_")
    .trim()
    .replace(/^\.+/, "")
    .replace(/\.+$/, "");
  if (!clean || WINDOWS_RESERVED_NAMES.test(clean)) {
    clean = "file_" + (clean || "unnamed");
  }
  return clean.slice(0, SHARE_LIMITS.MAX_FILENAME_LENGTH);
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

function saveSharedData(payload) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("mydrop-share", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("pending")) {
        db.createObjectStore("pending");
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("pending", "readwrite");
      tx.objectStore("pending").put(payload, "latest");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
    req.onerror = () => reject(req.error);
  });
}

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // รับข้อมูลจาก Web Share Target (POST /share-target) พร้อมตรวจสอบ Origin/Sec-Fetch-Site และขีดจำกัดความปลอดภัย
  if (url.pathname === "/share-target" && event.request.method === "POST") {
    const reqOrigin = event.request.headers.get("Origin");
    const secFetchSite = event.request.headers.get("Sec-Fetch-Site");
    if (
      (reqOrigin && reqOrigin !== "null" && reqOrigin !== self.location.origin) ||
      (secFetchSite && secFetchSite === "cross-site")
    ) {
      event.respondWith(new Response("Forbidden cross-site share target request", { status: 403 }));
      return;
    }

    event.respondWith((async () => {
      try {
        const formData = await event.request.formData();
        const rawFiles = formData.getAll("files").filter((f) => f instanceof File && f.size >= 0 && f.name);
        const files = [];
        let totalBytes = 0;

        for (const f of rawFiles) {
          if (files.length >= SHARE_LIMITS.MAX_FILES) break;
          if (f.size > SHARE_LIMITS.MAX_FILE_SIZE) continue;
          if (totalBytes + f.size > SHARE_LIMITS.MAX_TOTAL_SIZE) break;
          const safeName = sanitizeSharedFilename(f.name);
          const safeFile = safeName === f.name ? f : new File([f], safeName, { type: f.type, lastModified: f.lastModified });
          files.push(safeFile);
          totalBytes += safeFile.size;
        }

        const title = String(formData.get("title") || "").slice(0, 2048);
        const text = String(formData.get("text") || "").slice(0, SHARE_LIMITS.MAX_TEXT_CHARS);
        const sharedUrl = String(formData.get("url") || "").slice(0, 2048);
        const combinedText = [title, text, sharedUrl].filter(Boolean).join("\n").slice(0, SHARE_LIMITS.MAX_TEXT_CHARS);

        if (files.length > 0 || combinedText) {
          await saveSharedData({
            files,
            text: combinedText,
            createdAt: Date.now()
          });
        }
      } catch (err) {
        console.error("Share target error:", err);
      }
      return Response.redirect("/?shared=1", 303);
    })());
    return;
  }

  // ไม่แคช WebSocket, ข้อมูล TURN/ICE (/ice) หรือ request ข้ามโดเมน
  if (url.pathname === "/ws" || url.pathname === "/ice" || url.origin !== self.location.origin) {
    return;
  }

  // Network-first สำหรับไฟล์ static ของแอป โดยใช้คีย์แบบตัด query string (?room=...) เพื่อไม่ให้รหัสห้องถูกเก็บลง Cache Storage บนดิสก์
  if (event.request.method === "GET" && ASSETS.includes(url.pathname)) {
    const cacheKeyUrl = new URL(url.pathname, self.location.origin).toString();
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          if (res.ok && res.type === "basic") {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(cacheKeyUrl, copy));
          }
          return res;
        })
        .catch(() => caches.match(cacheKeyUrl))
    );
  }
});
