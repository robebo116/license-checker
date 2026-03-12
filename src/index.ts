export default {
  async fetch(request, env) {

    if (request.method !== "POST") {
      return json({ error: "Only POST allowed" }, 405);
    }

    const { key, hwid } = await request.json();

    if (!key || !hwid) {
      return json({ error: "Missing key or hwid" }, 400);
    }

    /* ===== DB CHECK ===== */

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

    /* ===== FIRST ACTIVATE ===== */

    if (!record.hwid) {

      const nowIso = new Date().toISOString();

      await env.DB
        .prepare(
          "UPDATE license_keys SET hwid = ?, activated_at = ? WHERE key = ?"
        )
        .bind(hwid, nowIso, key)
        .run();

      activatedAt = nowIso;
      finalHwid = hwid;
    }

    /* ===== EXPIRE ===== */

    const activatedTs = Date.parse(activatedAt);

    const expireAtTs =
      activatedTs + Number(record.expire_days) * 86400000;

    const nowTs = Date.now();

    if (nowTs > expireAtTs) {
      return json({ error: "Key expired" }, 403);
    }

    /* ===== PAYLOAD ===== */

    const payload = {
      key: key,
      hwid: finalHwid,
      expire_at_ts: expireAtTs,
      issued_at: nowTs
    };

    /* ===== SIGN ===== */

    const raw =
      `${payload.key}|${payload.hwid}|` +
      `${payload.expire_at_ts}|${payload.issued_at}`;

    const signature = await signHmac(raw, env.SECRET_KEY);

    const response = {
      ...payload,
      signature
    };

    return new Response(JSON.stringify(response), {
      headers: {
        "Content-Type": "application/json"
      }
    });
  }
};


/* ===== HMAC SIGN ===== */

async function signHmac(data, secret) {

  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(data)
  );

  return bufferToBase64(sig);
}


/* ===== UTILS ===== */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function bufferToBase64(buffer) {

  const bytes = new Uint8Array(buffer);

  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}
