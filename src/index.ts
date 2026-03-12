export default {
  async fetch(request, env, ctx) {

    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json();

    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ================= CACHE ================= */

    const cache = caches.default;
    const cacheReq = new Request(cacheKey(key, hwid));

    const cached = await cache.match(cacheReq);

    if (cached) {
      return cached;
    }

    /* ================= DB ================= */

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

    /* ================= ACTIVATE ================= */

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

    /* ================= EXPIRE ================= */

    const activatedTs = Date.parse(activatedAt);

    const expireAtTs =
      activatedTs + Number(record.expire_days) * 86400000;

    const nowTs = Date.now();

    if (nowTs > expireAtTs) {
      return json({ error: "Key expired" }, 403);
    }

    const expireAtIso = formatIso(expireAtTs);

    /* ================= PAYLOAD ================= */

    const payload = {
      key,
      hwid: finalHwid,
      activated_at: activatedAt,
      expire_at: expireAtIso,
      expire_at_ts: expireAtTs,
      issued_at: nowTs
    };

    /* ================= SIGN STRING ================= */

    const raw =
      `${payload.key}|${payload.hwid}|` +
      `${payload.expire_at_ts}|${payload.issued_at}`;

    const signature = await sign(raw, env.PRIVATE_KEY);

    const responseBody = JSON.stringify({
      ...payload,
      signature
    });

    /* ================= CACHE TTL ================= */

    let ttlSeconds = Math.floor((expireAtTs - nowTs) / 1000);

    ttlSeconds = Math.min(ttlSeconds, 31536000);

    const response = new Response(responseBody, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${ttlSeconds}`
      }
    });

    ctx.waitUntil(
      cache.put(cacheReq, response.clone())
    );

    return response;
  }
};






/* ================= SIGNING ================= */

let cachedPrivateKey = null;

async function sign(data, privateKeyPem) {

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
    new TextEncoder().encode(data)
  );

  return bufferToBase64(signature);
}





/* ================= UTILS ================= */

function json(data, status = 200) {

  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}


function cacheKey(key, hwid) {

  return `https://cache/license/${key}/${hwid}`;
}


function nowIsoString() {

  return new Date().toISOString();
}


function formatIso(ts) {

  return new Date(ts).toISOString();
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


function bufferToBase64(buffer) {

  const bytes = new Uint8Array(buffer);

  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}
