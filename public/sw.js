const CACHE_NAME = "mydrop-v4";
const ASSETS = [
  "/",
  "/index.html",
  "/app.js",
  "/manifest.webmanifest",
  "/icon-192.png",
  "/icon-512.png"
];

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

  // รับข้อมูลจาก Web Share Target (POST /share-target)
  if (url.pathname === "/share-target" && event.request.method === "POST") {
    event.respondWith((async () => {
      try {
        const formData = await event.request.formData();
        const files = formData.getAll("files").filter((f) => f instanceof File && f.size >= 0 && f.name);
        const title = formData.get("title") || "";
        const text = formData.get("text") || "";
        const sharedUrl = formData.get("url") || "";
        const combinedText = [title, text, sharedUrl].filter(Boolean).join("\n");

        await saveSharedData({
          files,
          text: combinedText,
          createdAt: Date.now()
        });
      } catch (err) {
        console.error("Share target error:", err);
      }
      return Response.redirect("/?shared=1", 303);
    })());
    return;
  }

  // ไม่แคช WebSocket หรือ request ข้ามโดเมน
  if (url.pathname === "/ws" || url.origin !== self.location.origin) {
    return;
  }

  // Network-first สำหรับไฟล์แอป เพื่อให้ได้อัปเดตล่าสุดเสมอ และ fallback เป็น cache เมื่อออฟไลน์
  if (event.request.method === "GET") {
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return res;
        })
        .catch(() => caches.match(event.request))
    );
  }
});
