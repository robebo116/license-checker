let cachedCryptoKey: CryptoKey | null = null;

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {

    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json();

    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ===== CACHE ===== */

    const cache = caches.default;
    const cacheReq = new Request(cacheKey(key, hwid));

    const cached = await cache.match(cacheReq);

    if (cached) {
      return cached;
    }

    /* ===== DB ===== */

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

    const expireAtTs =
      activatedTs + Number(record.expire_days) * 86400000;

    const nowTs = Date.now();

    if (nowTs > expireAtTs) {
      return json({ error: "Key expired" }, 403);
    }

    /* ===== PAYLOAD ===== */

    const payload = {
      key,
      hwid: finalHwid,
      expire_at_ts: expireAtTs
    };

    const signature = await signPayload(payload, env.SECRET_KEY);


    console.log("payload:", payload);
    console.log("secret:", env.SECRET_KEY);

    const responseBody = json({
      ...payload,
      signature
    });

    /* ===== CACHE TTL ===== */

    let ttlSeconds = Math.floor((expireAtTs - nowTs) / 1000);

    ttlSeconds = Math.min(ttlSeconds, 31536000);

    const cachedResponse = new Response(responseBody.body, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${ttlSeconds}, immutable`
      }
    });

    ctx.waitUntil(cache.put(cacheReq, cachedResponse.clone()));

    return cachedResponse;
  }
};

/* ===== SIGN ===== */

async function signPayload(payload: any, secret: string) {

  const data =
    payload.key +
    payload.hwid +
    payload.expire_at_ts;

  if (!cachedCryptoKey) {

    cachedCryptoKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }

  const signature = await crypto.subtle.sign(
    "HMAC",
    cachedCryptoKey,
    new TextEncoder().encode(data)
  );

  return bufferToBase64(signature);
}

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

  return `https://cache/license/${key}/${hwid}`;
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
