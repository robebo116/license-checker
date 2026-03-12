export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json() as any;
    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ===== CACHE ===== */
    const cache = caches.default;
    const cacheReq = new Request(cacheKey(key, hwid));
    const cached = await cache.match(cacheReq);
    if (cached) return cached;

    /* ===== DB ===== */
    const record = await env.DB
      .prepare("SELECT * FROM license_keys WHERE key = ?")
      .bind(key)
      .first();

    if (!record) return json({ error: "Invalid key" }, 403);
    if (record.hwid && record.hwid !== hwid) {
      return json({ error: "Key đã được dùng cho thiết bị khác" }, 403);
    }

    let activatedAt = record.activated_at;
    let finalHwid = record.hwid;

    if (!record.hwid) {
      activatedAt = new Date().toISOString();
      await env.DB
        .prepare("UPDATE license_keys SET hwid = ?, activated_at = ? WHERE key = ?")
        .bind(hwid, activatedAt, key)
        .run();
      finalHwid = hwid;
    }

    const expireAtTs = Date.parse(activatedAt) + (Number(record.expire_days) * 86400000);
    const nowTs = Date.now();

    if (nowTs > expireAtTs) return json({ error: "Key đã hết hạn" }, 403);

    /* ===== PAYLOAD & SIGNING (Đồng bộ với Python) ===== */
    const finalExpireTs = Math.floor(expireAtTs);
    
    const payload = {
      key: key,
      hwid: finalHwid,
      expire_at_ts: finalExpireTs
    };
    
    const message = JSON.stringify(payload);
    
    const signature = await signPayload(message, env.PRIVATE_KEY);
    
    const responseData = { ...payload, signature };
    const responseString = JSON.stringify(responseData);

    /* =====  TTL ===== */
    let ttlSeconds = Math.max(0, Math.floor((expireAtTs - nowTs) / 1000));
    ttlSeconds = Math.min(ttlSeconds, 31536000);

    const finalResponse = new Response(responseString, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${ttlSeconds}`
      }
    });

    ctx.waitUntil(cache.put(cacheReq, finalResponse.clone()));
    return finalResponse;
  }
};

/* ===== SIGNING UTILS ===== */
let cachedPrivateKey: CryptoKey | null = null;

async function signPayload(message: string, privateKeyPem: string) {
  if (!cachedPrivateKey) {
    cachedPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(privateKeyPem),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    cachedPrivateKey!,
    new TextEncoder().encode(message)
  );

  return bufferToBase64(signature);
}

// ... các hàm utils (pemToArrayBuffer, bufferToBase64, cacheKey, json) giữ nguyên ...
/* ===== UTILS ===== */

function json(data: any, status = 200): Response {

  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function cacheKey(key: string, hwid: string): string {

  return `https://cache/license1/${key}/${hwid}`;
}

function nowIsoString(): string {

  return new Date().toISOString();
}

function bufferToBase64(buffer: ArrayBuffer) {

  const bytes = new Uint8Array(buffer);

  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}

function pemToArrayBuffer(pem) {

  const clean = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\r/g, "")
    .replace(/\n/g, "")
    .trim();

  const binary = atob(clean);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}
