export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // endpoint lấy thời gian server
    if (url.pathname === "/time") {
      return new Response(
        JSON.stringify({ now: Date.now() }),
        { headers: { "content-type": "application/json" } }
      );
    }
    try {

      if (request.method !== "POST") {
        return json({ error: "Only POST allowed" }, 405);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const { key, hwid, timestamp } = body || {};

      if (!key || !hwid || !timestamp) {
        return json({ error: "Missing key, hwid or timestamp" }, 400);
      }

      const now = Date.now();
  
      if (Math.abs(now - timestamp) > 60000) { // 5 phút
        return json({ error: "Timestamp invalid" }, 403);
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
        issued_at: nowTs,
        password: env.APP_PASS
      };

      /* ===== SIGN DATA ===== */

      /* ===== SIGN DATA ===== */
      
      const raw =
      `${payload.key}|${payload.hwid}|${payload.expire_at_ts}|${payload.issued_at}|${timestamp}|${payload.password}`;
      
      const signature = await signRSA(raw, env.PRIVATE_KEY);
      
      const response = {
        ...payload,
        timestamp,
        signature
      };

      return json(response);

    } catch (e) {

      return json({
        error: "worker_exception",
        message: e.toString()
      }, 500);

    }
  }
};


/* ===== RSA SIGN ===== */

async function signRSA(data, privateKeyPem) {

  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKeyPem),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    enc.encode(data)
  );

  return bufferToBase64(sig);
}


/* ===== PEM → ARRAYBUFFER ===== */

function pemToArrayBuffer(pem) {

  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binary = atob(b64);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}


/* ===== JSON RESPONSE ===== */

function json(data, status = 200) {

  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "Content-Type": "application/json"
    }
  });

}


/* ===== BASE64 ===== */

function bufferToBase64(buffer) {

  const bytes = new Uint8Array(buffer);

  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}
