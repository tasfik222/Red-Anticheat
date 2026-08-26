// ============================================================
//  RED EYE ANTICHEAT - CLOUDFLARE WORKER (D1 version)
//  API endpoints:
//  POST /api/register  - EXE থেকে key register করা
//  POST /api/event     - Detection event পাঠানো
//  GET  /api/events    - Website থেকে events নেওয়া
//  POST /api/heartbeat - EXE থেকে heartbeat
//
//  NOTE: KV এর বদলে D1 (SQL) ব্যবহার করা হচ্ছে — D1-এ Cloudflare Free
//  plan-এ কোনো daily write limit নেই (KV-তে ছিল মাত্র 1,000/day)।
// ============================================================

const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
};

const SESSION_TTL_MS = 86400 * 1000; // 24 ঘণ্টা পর session expired ধরা হবে
const MAX_EVENTS = 200;

// Key format: RED-XXXX-XXXX
function generateKey() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const part  = (n) => Array.from({length: n}, () =>
        chars[Math.floor(Math.random() * chars.length)]).join("");
    return `RED-${part(4)}-${part(4)}`;
}

function jsonResp(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json", ...CORS },
    });
}

export default {
    async fetch(request, env) {
        const url    = new URL(request.url);
        const path   = url.pathname;
        const method = request.method;

        // CORS preflight
        if (method === "OPTIONS")
            return new Response(null, { headers: CORS });

        try {
            // ── POST /api/register ──
            if (path === "/api/register" && method === "POST") {
                const body = await request.json().catch(() => ({}));
                const key  = generateKey();
                const now  = Date.now();

                await env.REDEYE_DB.prepare(
                    `INSERT INTO sessions (key, hwid, pc_name, username, created, last_seen, active)
                     VALUES (?, ?, ?, ?, ?, ?, 1)`
                ).bind(
                    key,
                    body.hwid     || "Unknown",
                    body.pc_name  || "Unknown",
                    body.username || "Unknown",
                    now,
                    now
                ).run();

                return jsonResp({ success: true, key });
            }

            // ── POST /api/event ──
            if (path === "/api/event" && method === "POST") {
                const apiKey = request.headers.get("X-API-Key") || "";
                const body   = await request.json().catch(() => ({}));

                if (!apiKey) return jsonResp({ error: "No API key" }, 401);

                const session = await env.REDEYE_DB.prepare(
                    `SELECT key FROM sessions WHERE key = ?`
                ).bind(apiKey).first();

                if (!session) return jsonResp({ error: "Invalid key" }, 404);

                const now = Date.now();

                await env.REDEYE_DB.prepare(
                    `INSERT INTO events (session_key, type, title, description, severity, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?)`
                ).bind(
                    apiKey,
                    body.type        || "UNKNOWN",
                    body.title       || "Detection",
                    body.description || "",
                    body.severity    || "HIGH",
                    now
                ).run();

                // পুরনো events ছেঁটে ফেলা (max 200 per session রাখা)
                await env.REDEYE_DB.prepare(
                    `DELETE FROM events WHERE session_key = ? AND id NOT IN (
                        SELECT id FROM events WHERE session_key = ? ORDER BY id DESC LIMIT ?
                    )`
                ).bind(apiKey, apiKey, MAX_EVENTS).run();

                await env.REDEYE_DB.prepare(
                    `UPDATE sessions SET last_seen = ?, active = 1 WHERE key = ?`
                ).bind(now, apiKey).run();

                return jsonResp({ success: true });
            }

            // ── POST /api/heartbeat ──
            if (path === "/api/heartbeat" && method === "POST") {
                const apiKey = request.headers.get("X-API-Key") || "";
                if (!apiKey) return jsonResp({ error: "No key" }, 401);

                const session = await env.REDEYE_DB.prepare(
                    `SELECT key FROM sessions WHERE key = ?`
                ).bind(apiKey).first();

                if (!session) return jsonResp({ error: "Invalid key" }, 404);

                await env.REDEYE_DB.prepare(
                    `UPDATE sessions SET last_seen = ?, active = 1 WHERE key = ?`
                ).bind(Date.now(), apiKey).run();

                return jsonResp({ success: true });
            }

            // ── GET /api/events?key=RED-XXXX-XXXX ──
            if (path === "/api/events" && method === "GET") {
                const key = url.searchParams.get("key") || "";
                if (!key) return jsonResp({ error: "No key" }, 400);

                const session = await env.REDEYE_DB.prepare(
                    `SELECT * FROM sessions WHERE key = ?`
                ).bind(key).first();

                if (!session) return jsonResp({ error: "Invalid or expired key" }, 404);

                // 24 ঘণ্টার বেশি পুরনো session-কে expired ধরা (KV-এর expirationTtl এর মতোই)
                if (Date.now() - session.created > SESSION_TTL_MS) {
                    await env.REDEYE_DB.prepare(`DELETE FROM sessions WHERE key = ?`).bind(key).run();
                    await env.REDEYE_DB.prepare(`DELETE FROM events WHERE session_key = ?`).bind(key).run();
                    return jsonResp({ error: "Invalid or expired key" }, 404);
                }

                const { results: events } = await env.REDEYE_DB.prepare(
                    `SELECT id, type, title, description, severity, timestamp
                     FROM events WHERE session_key = ? ORDER BY id ASC LIMIT ?`
                ).bind(key, MAX_EVENTS).all();

                const online = (Date.now() - session.last_seen) < 60000;

                return jsonResp({
                    success:   true,
                    key:       session.key,
                    hwid:      session.hwid,
                    pc_name:   session.pc_name,
                    username:  session.username,
                    created:   session.created,
                    last_seen: session.last_seen,
                    online,
                    events,
                });
            }

            return jsonResp({ error: "Not found" }, 404);

        } catch (err) {
            return jsonResp({ error: "Internal error", detail: String(err) }, 500);
        }
    }
};
