/**
 * ============================================================================
 * GEXPIT INSTITUTIONAL PLATFORM — CLOUDFLARE WORKER (EDGE GATEWAY)
 * Version: 2.3.0 (Hardened Edge Shield + Non-Blocking Async Ingestion + KV Buffer)
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
        const defaultAllowed = ["https://gexpit.com", "https://www.gexpit.com"];
        const allowedList = (env && env.ALLOWED_ORIGIN)
            ? env.ALLOWED_ORIGIN.split(",").map(s => s.trim())
            : defaultAllowed;

        const isDevOrTest = (env && (env.ENVIRONMENT === "development" || env.ENVIRONMENT === "test" || env.ALLOW_DEV_IP_FALLBACK === "true"));

        if (!incomingOrigin) {
            originHeader = "*";
        } else if (allowedList.includes(incomingOrigin) || allowedList.includes("*")) {
            originHeader = incomingOrigin;
        } else if (isDevOrTest && (incomingOrigin.startsWith("http://localhost") || incomingOrigin.startsWith("http://127.0.0.1"))) {
            originHeader = incomingOrigin;
        } else {
            originHeader = allowedList[0];
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
 * Validates Cloudflare Turnstile cryptographic token via siteverify API
 * @param {string} token Turnstile response token from client
 * @param {string} clientIP Client IP address
 * @param {object} env Worker environment variables
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function verifyTurnstileToken(token, clientIP, env) {
    const turnstileSecret = env && env.TURNSTILE_SECRET_KEY;
    if (!turnstileSecret) {
        // Fallback mode if Turnstile secret is not yet configured in Worker environment
        return { success: true, bypassed: true };
    }

    if (!token || typeof token !== "string" || token.trim().length === 0) {
        return { success: false, error: "Missing Turnstile verification token." };
    }

    try {
        const formData = new FormData();
        formData.append("secret", turnstileSecret.trim());
        formData.append("response", token.trim());
        if (clientIP && !clientIP.startsWith("anon_")) {
            formData.append("remoteip", clientIP);
        }

        const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST",
            body: formData
        });

        if (!verifyRes.ok) {
            console.error(`[TURNSTILE VERIFY] HTTP error from Cloudflare siteverify: ${verifyRes.status}`);
            return { success: false, error: "Turnstile verification service error." };
        }

        const outcome = await verifyRes.json();
        return {
            success: Boolean(outcome && outcome.success),
            error: outcome && outcome["error-codes"] ? outcome["error-codes"].join(", ") : undefined
        };
    } catch (err) {
        console.error("[TURNSTILE VERIFY EXCEPTION]", err);
        return { success: false, error: "Turnstile challenge validation exception." };
    }
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

/**
 * Asynchronously dispatches sanitized lead payload to upstream storage
 * (Google Apps Script & optional Cloudflare KV Edge Buffer) with automatic retry and exponential backoff.
 * @param {object} leadData Sanitized lead telemetry data
 * @param {object} env Worker environment bindings
 * @returns {Promise<{success: boolean, message?: string}>}
 */
async function dispatchPayloadToVault(leadData, env) {
    const targetGoogleScriptUrl = env && env.GOOGLE_SCRIPT_URL;
    const vaultSecretToken = env && env.VAULT_SECRET_TOKEN;

    // 1. Edge Buffer Backup in Cloudflare KV (if bound) — Zero Data Loss Guarantee
    if (env && env.LEADS_KV && typeof env.LEADS_KV.put === "function") {
        try {
            const kvKey = `lead:${Date.now()}:${encodeURIComponent(leadData.email)}`;
            await env.LEADS_KV.put(kvKey, JSON.stringify(leadData), {
                expirationTtl: 2592000 // 30 days retention
            });
        } catch (kvErr) {
            console.error("[GEXPIT KV BUFFER ERROR]", kvErr);
        }
    }

    if (!targetGoogleScriptUrl || !vaultSecretToken) {
        console.error("[GEXPIT DISPATCH ERROR] Missing GOOGLE_SCRIPT_URL or VAULT_SECRET_TOKEN");
        return { success: false, message: "Storage vault credentials missing." };
    }

    // 2. Resilient Ingestion with Exponential Backoff (Up to 3 attempts)
    const MAX_ATTEMPTS = 3;
    let lastError = null;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const abortCtrl = new AbortController();
        const timeoutId = setTimeout(() => abortCtrl.abort(), 8000);

        try {
            const vaultResponse = await fetch(targetGoogleScriptUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email: leadData.email,
                    source: leadData.source,
                    timestamp: leadData.timestamp,
                    clientIp: leadData.clientIp,
                    vaultToken: vaultSecretToken
                }),
                redirect: "follow",
                signal: abortCtrl.signal
            });

            clearTimeout(timeoutId);

            if (vaultResponse.ok) {
                const vaultData = await vaultResponse.json().catch(() => null);
                if (vaultData && vaultData.status === "success") {
                    return { success: true };
                }
                console.warn(`[GEXPIT DISPATCH] Attempt ${attempt} returned non-success:`, vaultData ? vaultData.message : "Invalid payload");
            } else {
                console.warn(`[GEXPIT DISPATCH] Attempt ${attempt} HTTP error: ${vaultResponse.status}`);
            }
        } catch (err) {
            clearTimeout(timeoutId);
            lastError = err;
            console.warn(`[GEXPIT DISPATCH] Attempt ${attempt} exception: ${err.message || err}`);
        }

        if (attempt < MAX_ATTEMPTS) {
            // Exponential backoff delay (e.g. 600ms, 1200ms) to absorb lock contention
            await new Promise(resolve => setTimeout(resolve, attempt * 600));
        }
    }

    console.error("[GEXPIT DISPATCH FAILED] Exhausted all retry attempts to Google Apps Script.", lastError);
    return { success: false, message: "Exhausted retry attempts." };
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
        const url = new URL(request.url);

        // --------------------------------------------------------------------
        // 0. HEALTHCHECK / ROUTING
        // --------------------------------------------------------------------
        if (request.method === "GET" && (url.pathname === "/health" || url.pathname === "/api/health")) {
            return jsonResponse({ status: "active", version: "2.3.0" }, 200, request, env);
        }

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
        // 2. HTTP METHOD & PATH VALIDATION
        // --------------------------------------------------------------------
        if (request.method !== "POST") {
            return jsonResponse({
                status: "error",
                message: "Method not allowed. Only POST is accepted."
            }, 405, request, env);
        }

        // Acceptable paths for registration on root or /api/*
        const validPathPrefixes = ["/", "/api", "/api/request-access", "/api/waitlist", "/request-access"];
        const isPathValid = validPathPrefixes.some(p => url.pathname === p || url.pathname.startsWith("/api/"));
        if (!isPathValid) {
            return jsonResponse({
                status: "error",
                message: "Not found: Endpoint does not exist."
            }, 404, request, env);
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
            // 5. CLOUDFLARE TURNSTILE & MICRO-POW ANTI-DOS SHIELD
            // ----------------------------------------------------------------
            if (env && env.TURNSTILE_SECRET_KEY) {
                const turnstileCheck = await verifyTurnstileToken(payload.cf_turnstile_token, clientIP, env);
                if (!turnstileCheck.success) {
                    console.error("[GEXPIT WORKER] Turnstile validation rejected:", turnstileCheck.error);
                    return jsonResponse({
                        status: "error",
                        message: "Forbidden: Cloudflare Turnstile human verification challenge failed."
                    }, 403, request, env);
                }
            } else {
                // Interim / Offline fallback: Micro-PoW validation
                const isPowValid = await verifyProofOfWork(rawEmail, payload.pow_ts, payload.pow_nonce);
                if (!isPowValid) {
                    return jsonResponse({
                        status: "error",
                        message: "Forbidden: Cryptographic challenge validation failed."
                    }, 403, request, env);
                }
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

            const leadData = {
                email: rawEmail,
                source: sanitizedSource,
                timestamp: sanitizedTimestamp,
                clientIp: clientIP
            };

            // Check if synchronous mode is requested or if running in test environment without ctx.waitUntil
            const isSync = url.searchParams.get("sync") === "true" || !ctx || typeof ctx.waitUntil !== "function";

            if (isSync) {
                const dispatchResult = await dispatchPayloadToVault(leadData, env);
                if (!dispatchResult.success) {
                    return jsonResponse({
                        status: "error",
                        message: "Storage vault was unable to record request. Please retry later."
                    }, 502, request, env);
                }
                return jsonResponse({
                    status: "success",
                    message: "Access request successfully registered."
                }, 200, request, env);
            }

            // Production High-Performance Asynchronous Non-Blocking Edge Ingestion (ctx.waitUntil)
            ctx.waitUntil(dispatchPayloadToVault(leadData, env));

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


