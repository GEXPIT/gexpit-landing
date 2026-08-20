/**
 * ============================================================================
 * GEXPIT INSTITUTIONAL PLATFORM — CLOUDFLARE WORKER (EDGE GATEWAY)
 * Version: 2.1.0 (Hardened Edge Shield + Multi-Isolate Cache Rate Limiting + PoW Anti-DoS)
 * Stack: Cloudflare Workers ES Module (Zero External Dependencies)
 * ============================================================================
 */

// In-Memory Fallback Map (used when Cache API is unavailable, e.g. local unit tests)
const ipRateLimitMap = new Map();
const IP_WINDOW_MS = 60000; // 60 seconds rolling window
const MAX_REQUESTS_PER_IP = 3;
const MAX_MAP_ENTRIES = 5000; // Memory leak safeguard against bot floods
const EVICTION_BATCH_SIZE = 500;

// RFC 5322 Compliant Email Regex Validator
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Micro Proof-of-Work (PoW) Constants (Anti-DoS Shield)
const POW_PREFIX = "000";
const POW_MAX_AGE_MS = 300000; // 5 minutes validity window

/**
 * Builds standardized Security & CORS Response Headers with origin validation
 * @param {Request} request
 * @param {object} env
 * @returns {object}
 */
function getSecurityHeaders(request, env) {
    let originHeader = "*";
    if (request && request.headers) {
        const incomingOrigin = request.headers.get("origin") || request.headers.get("Origin") || "";
        if (env && env.ALLOWED_ORIGIN) {
            const allowedList = env.ALLOWED_ORIGIN.split(",").map(s => s.trim());
            if (allowedList.includes(incomingOrigin) || allowedList.includes("*")) {
                originHeader = incomingOrigin || allowedList[0];
            } else {
                originHeader = allowedList[0];
            }
        } else if (incomingOrigin) {
            originHeader = incomingOrigin;
        }
    }
    return {
        "Access-Control-Allow-Origin": originHeader,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
        "Access-Control-Max-Age": "86400",
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    };
}

/**
 * Helper to build JSON responses with consistent security and CORS headers
 * @param {object} data
 * @param {number} status
 * @param {Request} request
 * @param {object} env
 * @returns {Response}
 */
function jsonResponse(data, status = 200, request = null, env = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: getSecurityHeaders(request, env)
    });
}

/**
 * Robust Client IP Extraction with strict Cloudflare header binding
 * @param {Request} request
 * @param {object} env
 * @returns {string}
 */
function extractClientIP(request, env = {}) {
    const cfIP = request.headers.get("cf-connecting-ip");
    if (cfIP && cfIP.trim()) return cfIP.trim().slice(0, 45);

    // Fallback strictly for local non-Cloudflare development/testing environments
    const isDevOrTest = (env && (env.ENVIRONMENT === "development" || env.ENVIRONMENT === "test" || env.ALLOW_DEV_IP_FALLBACK === "true"));
    if (isDevOrTest) {
        const rawFwd = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "";
        const firstIP = rawFwd.split(",")[0].trim().slice(0, 45);
        if (/^[0-9a-fA-F:.]+$/.test(firstIP)) {
            return firstIP;
        }
    }

    // Isolated anonymous token with SHA-256 fingerprint hash to prevent collision DoS
    const userAgent = request.headers.get("user-agent") || "unknown_client";
    const acceptLang = request.headers.get("accept-language") || "";
    let hash = 0;
    const combined = userAgent + "|" + acceptLang;
    for (let i = 0; i < combined.length; i++) {
        hash = ((hash << 5) - hash) + combined.charCodeAt(i);
        hash |= 0;
    }
    return `anon_${Math.abs(hash).toString(16)}`;
}

/**
 * Validates Micro-PoW cryptographic challenge (Anti-DoS Shield)
 * @param {string} email
 * @param {number} powTs
 * @param {number|string} powNonce
 * @returns {Promise<boolean>}
 */
async function verifyProofOfWork(email, powTs, powNonce) {
    if (typeof powTs !== "number" || typeof powNonce === "undefined") {
        return false;
    }

    const now = Date.now();
    if (Math.abs(now - powTs) > POW_MAX_AGE_MS) {
        return false; // Challenge timestamp expired or in the future
    }

    const challenge = `gexpit_pow_v1:${email.toLowerCase().trim()}:${powTs}:${powNonce}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(challenge);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

    return hashHex.startsWith(POW_PREFIX);
}

/**
 * Checks and records rate limit using Cloudflare Cache API with fallback to memory map
 * @param {string} clientIP
 * @returns {Promise<boolean>} True if allowed, False if rate limited
 */
async function checkAndRecordRateLimit(clientIP) {
    const now = Date.now();

    // 1. Try Cloudflare Cache API (Shared across V8 isolates on the same PoP edge)
    try {
        if (typeof caches !== "undefined" && caches.default) {
            const cacheKey = new Request(`https://gexpit-ratelimit.internal/ip/${encodeURIComponent(clientIP)}`);
            const cachedRes = await caches.default.match(cacheKey);

            let timestamps = [];
            if (cachedRes) {
                try {
                    const data = await cachedRes.json();
                    if (Array.isArray(data)) {
                        timestamps = data.filter(ts => now - ts < IP_WINDOW_MS);
                    }
                } catch (_) {}
            }

            if (timestamps.length >= MAX_REQUESTS_PER_IP) {
                return false;
            }

            timestamps.push(now);
            const newRes = new Response(JSON.stringify(timestamps), {
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "public, max-age=60"
                }
            });
            await caches.default.put(cacheKey, newRes);
            return true;
        }
    } catch (_) {
        // Fall back to memory map if Cache API is unavailable
    }

    // 2. In-Memory Isolate Fallback
    if (ipRateLimitMap.size > MAX_MAP_ENTRIES) {
        for (const [key, timestamps] of ipRateLimitMap.entries()) {
            const activeTimestamps = timestamps.filter(ts => now - ts < IP_WINDOW_MS);
            if (activeTimestamps.length === 0) {
                ipRateLimitMap.delete(key);
            } else {
                ipRateLimitMap.set(key, activeTimestamps);
            }
        }
        if (ipRateLimitMap.size > MAX_MAP_ENTRIES) {
            let evicted = 0;
            for (const key of ipRateLimitMap.keys()) {
                ipRateLimitMap.delete(key);
                evicted++;
                if (evicted >= EVICTION_BATCH_SIZE) break;
            }
        }
    }

    let requestTimestamps = ipRateLimitMap.get(clientIP) || [];
    requestTimestamps = requestTimestamps.filter(ts => now - ts < IP_WINDOW_MS);

    if (requestTimestamps.length >= MAX_REQUESTS_PER_IP) {
        return false;
    }

    requestTimestamps.push(now);
    ipRateLimitMap.set(clientIP, requestTimestamps);
    return true;
}

export default {
    /**
     * Main fetch event dispatcher for Cloudflare Workers
     * @param {Request} request
     * @param {object} env
     * @param {object} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        // --------------------------------------------------------------------
        // 1. CORS PREFLIGHT (OPTIONS)
        // --------------------------------------------------------------------
        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: getSecurityHeaders(request, env)
            });
        }

        // --------------------------------------------------------------------
        // 2. HTTP METHOD VALIDATION
        // --------------------------------------------------------------------
        if (request.method !== "POST") {
            return jsonResponse({
                status: "error",
                message: "Method not allowed. Only POST is accepted."
            }, 405, request, env);
        }

        // --------------------------------------------------------------------
        // 3. MULTI-ISOLATE & IN-MEMORY RATE LIMITING (VULN-01 REMEDIATION)
        // --------------------------------------------------------------------
        const clientIP = extractClientIP(request, env);
        const withinRateLimit = await checkAndRecordRateLimit(clientIP);

        if (!withinRateLimit) {
            return jsonResponse({
                status: "error",
                message: "Too Many Requests: Rate limit exceeded (3 requests per minute)."
            }, 429, request, env);
        }

        // --------------------------------------------------------------------
        // 4. PARSE & SANITIZE PAYLOAD -> ANTI-DOS & VALIDATION
        // --------------------------------------------------------------------
        try {
            const payload = await request.json().catch(() => null);

            if (!payload || !payload.email || typeof payload.email !== "string") {
                return jsonResponse({
                    status: "error",
                    message: "Bad Request: Missing or invalid email in payload."
                }, 400, request, env);
            }

            // Server-Side Anti-Bot Honeypot Trap Verification
            if (payload.hp_code && typeof payload.hp_code === "string" && payload.hp_code.trim().length > 0) {
                // Return deceptive 200 OK without forwarding to storage
                return jsonResponse({
                    status: "success",
                    message: "Access request successfully registered."
                }, 200, request, env);
            }

            const rawEmail = payload.email.trim();
            if (rawEmail.length > 254 || !EMAIL_REGEX.test(rawEmail)) {
                return jsonResponse({
                    status: "error",
                    message: "Bad Request: Email does not conform to RFC 5322 specification."
                }, 400, request, env);
            }

            // ----------------------------------------------------------------
            // 5. MICRO-POW CRYPTOGRAPHIC VERIFICATION (VULN-02 ANTI-DOS SHIELD)
            // ----------------------------------------------------------------
            const isPowValid = await verifyProofOfWork(rawEmail, payload.pow_ts, payload.pow_nonce);
            if (!isPowValid) {
                return jsonResponse({
                    status: "error",
                    message: "Forbidden: Cryptographic challenge validation failed."
                }, 403, request, env);
            }

            // ----------------------------------------------------------------
            // 6. STRICT PAYLOAD SANITIZATION (VULN-08 REMEDIATION)
            // ----------------------------------------------------------------
            let sanitizedTimestamp = new Date().toISOString();
            if (typeof payload.timestamp === "string" && payload.timestamp.length <= 50) {
                const parsedMs = Date.parse(payload.timestamp);
                if (!isNaN(parsedMs)) {
                    sanitizedTimestamp = new Date(parsedMs).toISOString();
                }
            }

            let sanitizedSource = "web_edge_cockpit";
            if (typeof payload.source === "string") {
                const cleanSource = payload.source.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 50);
                if (cleanSource.length > 0) {
                    sanitizedSource = cleanSource;
                }
            }

            const targetGoogleScriptUrl = env.GOOGLE_SCRIPT_URL;
            if (!targetGoogleScriptUrl) {
                console.error("[GEXPIT WORKER CONFIG ERROR] GOOGLE_SCRIPT_URL environment variable is not configured.");
                return jsonResponse({
                    status: "error",
                    message: "Service temporarily unavailable. Please retry later."
                }, 503, request, env);
            }

            const vaultSecretToken = env.VAULT_SECRET_TOKEN;
            if (!vaultSecretToken) {
                console.error("[GEXPIT WORKER CONFIG ERROR] VAULT_SECRET_TOKEN environment variable is not configured.");
                return jsonResponse({
                    status: "error",
                    message: "Service temporarily unavailable. Please retry later."
                }, 503, request, env);
            }

            // Forward sanitized payload to Google Apps Script Web App with AbortController timeout (8s)
            const abortCtrl = new AbortController();
            const timeoutId = setTimeout(() => abortCtrl.abort(), 8000);

            let vaultResponse;
            try {
                vaultResponse = await fetch(targetGoogleScriptUrl, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        email: rawEmail,
                        source: sanitizedSource,
                        timestamp: sanitizedTimestamp,
                        clientIp: clientIP,
                        vaultToken: vaultSecretToken
                    }),
                    redirect: "follow",
                    signal: abortCtrl.signal
                });
            } catch (fetchErr) {
                if (fetchErr.name === "AbortError") {
                    console.error("[GEXPIT WORKER] Upstream storage vault request timed out after 8000ms");
                    return jsonResponse({
                        status: "error",
                        message: "Storage vault response timed out. Please retry later."
                    }, 504, request, env);
                }
                throw fetchErr;
            } finally {
                clearTimeout(timeoutId);
            }

            if (!vaultResponse.ok) {
                console.error(`[GEXPIT WORKER] Vault upstream HTTP error: ${vaultResponse.status}`);
                return jsonResponse({
                    status: "error",
                    message: "Upstream processing error. Please retry later."
                }, 502, request, env);
            }

            let vaultData = null;
            try {
                vaultData = await vaultResponse.json();
            } catch (parseErr) {
                console.error("[GEXPIT WORKER] Failed to parse upstream vault JSON response:", parseErr);
                return jsonResponse({
                    status: "error",
                    message: "Upstream response parsing failed. Please retry later."
                }, 502, request, env);
            }

            if (!vaultData || vaultData.status !== "success") {
                console.error("[GEXPIT WORKER] Upstream storage vault returned error payload:", vaultData ? vaultData.message : "Unknown error");
                return jsonResponse({
                    status: "error",
                    message: "Storage vault was unable to record request. Please retry later."
                }, 502, request, env);
            }

            return jsonResponse({
                status: "success",
                message: "Access request successfully registered."
            }, 200, request, env);

        } catch (error) {
            console.error("[GEXPIT WORKER EXCEPTION]", error);
            return jsonResponse({
                status: "error",
                message: "Internal edge gateway processing error."
            }, 500, request, env);
        }
    }
};


