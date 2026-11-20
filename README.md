# MyDrop

เว็บแอปส่งไฟล์และข้อความแบบ **Peer-to-Peer (P2P)** ระหว่างอุปกรณ์ในวง Wi-Fi / LAN เดียวกัน หรือข้ามเครือข่ายผ่านรหัสห้อง (คล้าย AirDrop) พัฒนาและโฮสต์บน **Cloudflare Workers + Durable Objects**

## ฟีเจอร์หลัก

- **ค้นหาอุปกรณ์อัตโนมัติในวงเดียวกัน:** จัดห้องให้อัตโนมัติตาม Public IP (รองรับทั้ง IPv4 และ IPv6 `/64` prefix)
- **ส่งข้ามเครือข่ายด้วยรหัสห้อง:** กำหนดชื่อห้องเองผ่าน UI หรือ URL (`?room=ชื่อห้อง`) เพื่อเชื่อมต่ออุปกรณ์คนละเครือข่าย
- **ส่งไฟล์และข้อความผ่าน WebRTC (P2P):** ไฟล์ถูกส่งตรงระหว่างอุปกรณ์ผ่าน WebRTC DataChannel พร้อมหน้าต่างยืนยันก่อนรับไฟล์ รองรับการลากวาง (Drag & Drop) และแสดงแถบความคืบหน้า
- **รองรับ PWA & Web Share Target:** ติดตั้งเป็นแอปบนมือถือ/คอมพิวเตอร์ได้ และรับไฟล์/ข้อความจากเมนู Share ของระบบได้โดยตรง
- **ประหยัดโควตา Cloudflare:** ใช้ Durable Objects WebSocket Hibernation API พร้อมตอบ `ping`/`pong` อัตโนมัติ
- **รองรับ Cloudflare TURN (ตัวเลือกเสริม):** เชื่อมต่อผ่าน TURN Server อัตโนมัติเมื่อตั้งค่า Secret สำหรับกรณีที่อุปกรณ์อยู่หลัง NAT/Firewall เข้มงวด

## โครงสร้างโปรเจกต์

```text
MyDrop/
├── wrangler.jsonc              # การตั้งค่า Cloudflare Worker, Assets และ Durable Objects
├── src/
│   └── index.js                # Worker หลัก (/ws, /ice, /share-target) และ Durable Object (Room)
└── public/
    ├── index.html              # หน้าเว็บหลัก (UI เรดาร์ค้นหาอุปกรณ์)
    ├── app.js                  # ลอจิก WebSocket, WebRTC P2P, การรับ-ส่งไฟล์ และ PWA
    ├── sw.js                   # Service Worker สำหรับ PWA และ Share Target
    ├── manifest.webmanifest    # ไฟล์ตั้งค่า PWA
    ├── icon-192.png            # ไอคอนแอป 192x192
    └── icon-512.png            # ไอคอนแอป 512x512
```

## การใช้งานและ Deploy

### รันทดสอบในเครื่อง (Local Development)

```bash
npx wrangler dev
```

### Deploy ขึ้น Cloudflare Workers

```bash
npx wrangler deploy
```

### (ตัวเลือกเสริม) เปิดใช้งาน Cloudflare TURN

หากต้องการให้ส่งไฟล์ข้ามเครือข่ายที่ติด Firewall/NAT ได้เสถียรขึ้น สามารถตั้งค่า Secret ของ Cloudflare TURN เพิ่มได้:

```bash
npx wrangler secret put TURN_TOKEN_ID
npx wrangler secret put TURN_API_TOKEN
```
