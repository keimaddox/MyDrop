const CACHE_NAME = "mydrop-v4";
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
  MAX_FILE_SIZE: 50 * 1024 * 1024,
  MAX_TOTAL_SIZE: 100 * 1024 * 1024,
  MAX_TEXT_CHARS: 16384,
};

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

  // รับข้อมูลจาก Web Share Target (POST /share-target) พร้อมตรวจสอบขีดจำกัดความปลอดภัย
  if (url.pathname === "/share-target" && event.request.method === "POST") {
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
          files.push(f);
          totalBytes += f.size;
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

  // Network-first สำหรับไฟล์ static ของแอป เพื่อให้ได้อัปเดตล่าสุดเสมอ และ fallback เป็น cache เมื่อออฟไลน์
  if (event.request.method === "GET" && ASSETS.includes(url.pathname)) {
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          if (res.ok && res.type === "basic") {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return res;
        })
        .catch(() => caches.match(event.request))
    );
  }
});
