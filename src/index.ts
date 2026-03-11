export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {

    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json();

    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ================= CACHE CHECK ================= */

    const cache = caches.default;
    const cacheReq = new Request(cacheKey(key, hwid));
    const cached = await cache.match(cacheReq);

    if (cached) {
      return cached;
    }

    /* ================= DB CHECK ================= */

    const record = await env.DB
      .prepare("SELECT * FROM license_keys WHERE key = ?")
      .bind(key)
      .first();

    if (!record) {
      return json({ error: "Invalid key" }, 403);
    }

    if (record.hwid && record.hwid !== hwid) {
      return json({ error: "Key already used on another device" }, 403);
    }

    let activatedAt = record.activated_at;
    let finalHwid = record.hwid;

    if (!record.hwid) {

      const nowIso = nowIsoString();

      await env.DB
        .prepare(
          "UPDATE license_keys SET hwid = ?, activated_at = ? WHERE key = ?"
        )
        .bind(hwid, nowIso, key)
        .run();

      activatedAt = nowIso;
      finalHwid = hwid;
    }

    const activatedTs = Date.parse(activatedAt);
    const expireAtTs = activatedTs + record.expire_days * 86400000;

    const nowTs = Date.now();

    if (nowTs > expireAtTs) {
      return json({ error: "Key expired" }, 403);
    }

    /* ================= PAYLOAD ================= */
    
    const payload = {
      key,
      hwid: finalHwid,
      expire_at_ts: expireAtTs
    };
    
    const signature = await signPayload(payload, env.PRIVATE_KEY);
    
    const responseBody = json({
      ...payload,
      signature
    });

    /* ================= CACHE TTL ================= */

    let ttlSeconds = Math.floor((expireAtTs - nowTs) / 1000);
    ttlSeconds = Math.min(ttlSeconds, 31536000);

    const cachedResponse = new Response(responseBody.body, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${ttlSeconds}, immutable`
      }
    });

    ctx.waitUntil(
      cache.put(cacheReq, cachedResponse.clone())
    );

    return cachedResponse;
  }
};

function json(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function cacheKey(key: string, hwid: string): string {
  return `https://cache/license3/${key}/${hwid}`;
}

function nowIsoString(): string {
  return new Date().toISOString();
}
let cachedPrivateKey: CryptoKey | null = null;
async function signPayload(payload: any, privateKeyPem: string) {

  const data =
    payload.key +
    payload.hwid +
    payload.expire_at_ts;

  const encoder = new TextEncoder();

  if (!cachedPrivateKey) {
    cachedPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(privateKeyPem),
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      false,
      ["sign"]
    );
  }

  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    cachedPrivateKey,
    encoder.encode(data)
  );

  return bufferToBase64(signature);
}

function bufferToBase64(buffer: ArrayBuffer) {

  const bytes = new Uint8Array(buffer);

  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}

function pemToArrayBuffer(pem: string) {

  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\n/g, "")
    .trim();

  const binary = atob(b64);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}
