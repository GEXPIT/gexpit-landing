# GEXPIT — AI SYSTEM DIRECTIVES & ARCHITECTURAL BLUEPRINT

> **MANDATORY INSTRUCTION FOR LLM AGENTS**: Read this file entirely before inspecting, modifying, or generating code in this repository. This document serves as the absolute Source of Truth for the GEXPIT institutional web platform. Maintain strict compliance with all structural, design, and security invariants.

---

### 1. PROJECT OVERVIEW & ARCHITECTURE
- **Core Utility**: Institutional web platform delivering zero lag 0DTE options flow, proprietary real time gamma exposure (GEX, VEX, DEX), and deterministic market maker hedging analytics.
- **Frontend Stack**: Pure Vanilla HTML5, Vanilla CSS3, and Vanilla JavaScript (ES6+ in Strict Mode).
- **Zero Framework Invariant**: Absolute prohibition of heavy frontend frameworks or utility engines (no React, Vue, Angular, jQuery, TailwindCSS, Bootstrap, or external runtime CDNs).
- **Runtime Performance**: Sub millisecond DOM operations, deterministic paint cycles, zero layout thrashing, and zero external blocking dependencies.
- **Decoupled Backend Architecture**:
  - **Edge Gateway**: Cloudflare Worker (`backend/worker.js`) handling CORS preflight, secret token authorization, IP throttling, and upstream payload masking.
  - **Storage Vault**: Google Apps Script (`backend/apps_script.gs`) managing atomic row insertion into Google Sheets via `LockService`.

---

### 2. DIRECTORY TOPOLOGY & ASSET GOVERNANCE
- **Root Repository Tree**:
  - `index.html`: Semantic HTML5 document containing all 8 macro-sections (`header`, `#hero`, `#specs`, `#features`, `#showcase`, `#comparison`, `#pricing`, `#faq`, `footer`). The header additionally contains `#nav-toggle` (hamburger button) and a `.nav-menu-cta` duplicate of the Request Access link inside `#nav-menu`, both only visible below the 1180px navigation breakpoint (see Section 3). `.brand-logo` wraps an `<img class="brand-logo-img">` (the official processed logo, not text) — do not revert to a text/gradient wordmark.
  - `style.css`: Unified hardware-accelerated CSS3 stylesheet containing design tokens, reset, glassmorphism components, and responsive breakpoints.
  - `script.js`: Encapsulated client-side core logic (`Strict Mode`), RFC 5322 validation, honeypot filter, localStorage throttling, and async fetch dispatcher.
  - `backend/worker.js`: Cloudflare Workers ES Module for edge proxying and CORS enforcement.
  - `backend/apps_script.gs`: Google Apps Script web application for telemetry ingestion.
  - `dev_log.md`: Development log documenting project evolution across all phases.
  - `AI_INSTRUCTIONS.md`: This master directive document.
- **Asset Directories & Strict Media Formats**:
  - `assets/img/`: Primarily `.webp` image assets with lossless alpha transparency where required (e.g. `gexpit-logo-header.webp`, the header brand mark). Three narrow, documented exceptions to the "no jpg/uncompressed png" rule exist for platform-format requirements, not convenience: `favicon-16.png` / `favicon-32.png` / `favicon-48.png` / `favicon.ico` (PNG/ICO required by browser favicon conventions — transparent, all under 1.5KB), `apple-touch-icon.png` (PNG required by iOS; deliberately opaque with `--bg-main` composited in, since iOS renders transparent icon regions as white), and `gexpit-og-image.jpg` (JPG required by Open Graph/Twitter Card social preview conventions, ~36KB). Do not add further `.jpg`/`.png` assets outside these platform-mandated cases without updating this list.
  - `assets/video/`: Strictly `.webm` and `.mp4` formats, completely stripped of audio tracks (`audio: none`), configured with `autoplay loop muted playsinline preload="metadata"`.
  - `assets/icons/`: Inline SVG vectors or lightweight scalable icons.

---

### 3. UI/UX & DESIGN SYSTEM (CSS TOKENS)
- **Theme Palette**: Institutional Dark Mode Spectrum:
  - `--bg-main`: `#080b10` (Deep black background)
  - `--bg-surface`: `#121620` (Surface elevation)
  - `--bg-card`: `rgba(18, 22, 32, 0.65)` (Translucent glass substrate)
- **Quantitative Signal Accents**:
  - `--accent-spot`: `#ffd700` (Spot index / key level highlight)
  - `--accent-zerogamma`: `#00d4ff` (Zero gamma boundary & primary glow)
  - `--accent-call`: `#00ff88` (Call volume / positive delta / live pulse)
  - `--accent-put`: `#ff4d4d` (Put volume / negative delta / error state)
- **Glassmorphism Infrastructure**:
  - `--border-glass`: `rgba(255, 255, 255, 0.08)`
  - `--border-glow`: `rgba(0, 212, 255, 0.2)`
  - `--blur-glass`: `blur(12px)` (`blur(8px)` override below the 768px breakpoint — backdrop-filter cost scales with radius and weaker mobile GPUs pay it on every scroll/composite)
  - `--shadow-glass`: `0 8px 32px 0 rgba(0, 0, 0, 0.6)`
  - `--shadow-cockpit-glow`: `0 0 50px rgba(0, 212, 255, 0.05)`
  - `--border-glass-inner`: `rgba(255, 255, 255, 0.14)` — inner rim highlight (multi level border depth)
  - `--border-glass-outer`: `rgba(0, 212, 255, 0.16)` — outer luminous edge (multi level border depth)
  - `--sheen-glass`: diagonal refraction gradient, applied as `background-image` on `.glass-container` / `.glass-card`
  - `--shadow-glass-depth`: composite `box-shadow` (outer drop shadow + inset inner rim + inset hairline + outer luminous ring), used on `.glass-container`
- **Dual Typography Hierarchy**:
  - Primary Body & Headlines: `'Space Grotesk', sans-serif`
  - Technical Data, Badges, Tables & Code: `'JetBrains Mono', monospace`
  - Gradient headings (`.hero-title`, `.section-title`, `.cta-title`) use a 3 stop `linear-gradient` text fill plus dual `filter: drop-shadow()` (light rim above, dark contact shadow below) for an engraved metal/glass finish. `filter` is compositor only, zero reflow.
- **Zero Reflow Motion**:
  - Hardware acceleration enforced via `transform`, `opacity`, `box-shadow`, `filter: drop-shadow()`, and `will-change` (the last used sparingly — see Performance note below).
  - No transitions or animations triggering costly layout reflows (`width`, `height`, `top`, `margin`).
  - `background-position` animation is banned outright, not just reflow-safe: it repaints every frame and forces `backdrop-filter` on any overlapping glass element to re-blur every frame too. This caused a real CPU/GPU spike on first load in production; do not reintroduce it (`hero-aurora-drift` and `data-sweep` were removed for this exact reason — see `dev_log.md` Fase 10).
  - `will-change` is applied only to elements that animate continuously by design (status dots, the Founder card's opacity-pulsing glow layer) — never as a blanket default on shared classes like `.btn` or `.glass-card`, which would permanently GPU-promote every button/card on the page even at rest.
  - Infinite hover-triggered animations (`btn-glow-pulse-cyan` on `.btn-header`/`.btn-primary`) are scoped inside `@media (hover: hover) and (pointer: fine)` — on touch devices `:hover` persists after a tap with no mouse to "leave", so an unscoped infinite animation would appear to glitch/stick until the next tap elsewhere.
  - `founder-ambient-glow` animates `opacity` on a separate pre-blurred pseudo layer, not `box-shadow` directly, so the blur is computed once rather than every frame; disabled entirely below 768px.
  - All remaining infinite/looping animations are additionally disabled under `@media (prefers-reduced-motion: reduce)`; content remains fully visible with zero dependency on motion to convey information.

---

### 3B. CROSS-DEVICE COMPATIBILITY (PC / TABLET / PHONE, iOS & ANDROID)
- **Navigation breakpoint is NOT 768px**: `#nav-toggle` (hamburger) activates and `#nav-menu` becomes a dropdown drawer at `max-width: 1180px`, not the layout breakpoint used elsewhere. Measured via headless browser: the full desktop nav (logo + status badge + 6 links + Request Access button) needs ~1150px of minimum content width and overflows the viewport between roughly 769px and 1150px (tablet landscape, small laptop windows) if left at the narrower breakpoint. Do not consolidate this back into the 768px query without re-measuring.
- **`.nav-actions .btn-header`** (header's Request Access button) is hidden below 1180px; **`.nav-menu-cta`** inside the drawer is its mobile/tablet replacement. Both must stay in sync (same href, same copy) if either is edited.
- **CSS specificity trap (already hit once, do not reintroduce)**: `.nav-menu-cta`'s hide/show rules MUST stay written as `.nav-menu .nav-menu-cta` (specificity 0,2,0), never bare `.nav-menu-cta` (0,1,0). The base `.btn { display: inline-flex; }` rule is also 0,1,0 and declared later in the file, so a bare-class hide rule loses the cascade tie by source order and the drawer's duplicate CTA becomes permanently visible next to the header's — this exact regression shipped once and was fixed in Fase 12. If adding other visibility overrides on shared `.btn`-family elements, always out-specify `.btn`, don't rely on declaration order.
- **`index.html` `<head>` carries favicon (`favicon-16/32/48.png`, `favicon.ico`, `apple-touch-icon.png`) and Open Graph / Twitter Card meta (`og:title`, `og:description`, `og:image` → `gexpit-og-image.jpg`, `twitter:card`, `twitter:image`)** — keep these in sync if the brand copy or logo asset changes.
- **iOS Safari specifics**: `min-height: 100dvh` (with `100vh` fallback) on `body`/`.hero-section` to avoid the address-bar-resize jump; form inputs kept at `font-size: 1rem` (16px) minimum to prevent Safari's auto-zoom-on-focus; `-webkit-text-size-adjust: 100%` prevents font auto-inflation on rotation; `env(safe-area-inset-*)` padding on `.header`, `.hero-section`, `.footer-container`, `.section-container` clears the notch/Dynamic Island/home-indicator (requires `viewport-fit=cover` in the viewport meta tag — do not remove it).
- **Android Chrome**: `<meta name="theme-color" content="#080b10">` tints the address bar to match the brand; no Android-specific layout issues found, same dvh/safe-area handling applies for symmetry (harmless no-op on devices without cutouts).
- **Verification method**: cross-device layout claims in this project should be checked with a headless Chromium pass across representative viewports (360, 375, 393, 412, 768, 1024, 1280, 1440, 1920px) checking for elements whose `getBoundingClientRect()` exceeds the viewport bounds — `document.scrollWidth` alone is NOT sufficient, since `position: fixed` elements (the header) can overflow the visible viewport without affecting document scroll width.

---

### 4. COPYWRITING & NAMING CONVENTIONS
- **Language**: Exclusively formal, technical, and institutional English across all UI elements, headings, subtitles, placeholders, and error messages.
- **Brand Consistency**: Strictly **"GEXPIT"** (single uppercase word, never hyphenated, never spaced).
- **No Hyphens in Titles Invariant**: Hyphens (`-`) are strictly forbidden in all `<h1>`, `<h2>`, `<h3>`, metric tickers, and status badges (e.g., use `"ZERO LAG REPLAY ENGINE"`, `"0DTE LIVE ENGINE ACTIVE"`, `"REAL TIME ORDER FLOW"` instead of hyphenated variants).
- **Tone of Voice**: Cold, quantitative, probabilistic, and algorithmic. Zero retail marketing hype, gambling jargon, or emotional copy.

---

### 5. SECURITY PROTOCOLS & DATA PIPELINE
- **Client-Side Validation & Resilience**:
  - Input email sanitization conforming strictly to RFC 5322 regex specifications prior to network dispatch.
  - Semantic `<noscript>` banner alerting users if JavaScript execution is disabled or restricted.
- **Anti-Bot Honeypot Shield**:
  - Invisible trap container (`.hp-trap`) styled exclusively with:
    `position: absolute; opacity: 0; pointer-events: none; height: 0; width: 0; z-index: -1; overflow: hidden; margin: 0; padding: 0;`
  - Form input includes `autocomplete="new-password"` and `aria-hidden="true"` to prevent password managers and browser autofill from populating the honeypot.
  - Never apply `display: none` to honeypot fields.
  - If honeypot is populated, simulate an 800ms artificial network delay, display "ACCESS REQUESTED" on UI, and abort network fetch silently.
- **Client-Side Throttling**:
  - Rolling window limiter in `localStorage` (`MAX_REQUESTS = 2`, `COOLDOWN_MS = 60000`).
- **Edge Gateway Security (Cloudflare Worker)**:
  - Strict Anti-IP Spoofing: IP extraction binds exclusively to the edge-certified `cf-connecting-ip` header (untrusted proxy headers rejected in production).
  - Cloudflare Worker enforces strict CORS preflight (`OPTIONS -> 204`).
  - Method locking (POST only, reject other methods with HTTP 405).
  - Server-side and client-side anti-bot honeypot trap verification (silent discard with deceptive 200 OK).
  - In-memory isolate IP rate limiting (maximum 3 requests per minute per IP, protected by `MAX_MAP_ENTRIES` memory safeguard).
  - Upstream timeout shield: 8-second `AbortController` preventing Worker isolate hangs during upstream congestions.
  - Upstream vault URL (`GOOGLE_SCRIPT_URL`) and private `VAULT_SECRET_TOKEN` strictly secured in worker environment variables (zero fallback credentials).
  - Security headers enforced: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
- **Storage Vault Shielding (Google Apps Script)**:
  - Fast-fail validation: JSON parsing, RFC syntax check, `VAULT_SECRET_TOKEN` authentication, and sanitization execute *outside the script lock* (< 5ms).
  - Lock duration minimization: Scoped locking using `lock.tryLock(2500)` strictly surrounding the atomic sheet append operation (`appendRow`), released immediately in `finally`.
  - Anti-Email Enumeration: Uniform JSON response payload for both new entries and duplicate requests (`"status": "success", "message": "Access request successfully registered."`).
  - Minimization of `doGet`: Neutral status `{ "status": "active" }` without service detail or architecture disclosure.
  - Formula/CSV injection neutralization via `sanitizeCellValue()` escaping formula trigger characters.

---

### 6. AI DEVELOPMENT DIRECTIVES (SELF-INSTRUCTIONS)
- **Pre-Execution Context Loading**: Review this file prior to implementing any modifications, refactoring existing components, or generating new assets in this directory.
- **Token Economy**: Provide terse, dense, production-grade solutions without conversational preamble or repetitive commentary.
- **Security Invariants**: Never compromise the honeypot mechanism, expose backend endpoints in client code, or inject external runtime dependencies.
- **State Synchronization**: When altering or adding components, routes, styles, or logic, update `AI_INSTRUCTIONS.md` and append an entry to `dev_log.md` immediately.

---

### 7. BACKEND ACTIVATION & END-TO-END EMAIL TEST PROTOCOL
- **Current status**: `backend/worker.js` and `backend/apps_script.gs` are hardened against broken authentication, IP spoofing, lock exhaustion DoS, multi-isolate rate limit bypass, timing attacks, $O(N)$ lock contention, and email enumeration. Client-side code is free of fake public tokens, protected by a Web Crypto SHA-256 Micro Proof-of-Work engine, and includes scroll-resilient UX. Static deployment is secured via `_headers` with strict anti-clickjacking directives.
- **Components & Pipeline**:
  1. `backend/worker.js`: Cloudflare Worker ES Module implementing CORS preflight (`OPTIONS` -> 204), method locking (POST only -> 405), anti-IP spoofing (`cf-connecting-ip`), server-side honeypot verification, multi-isolate Cache API rate limiting (max 3 req/min per IP -> 429), Micro-PoW validation (SHA-256 prefix `000` -> 403 on invalid challenge), RFC email validation, security headers, upstream timeout shield (8s `AbortController`), and upstream payload forwarding with `VAULT_SECRET_TOKEN` to `env.GOOGLE_SCRIPT_URL` with `redirect: "follow"`.
  2. `backend/apps_script.gs`: Google Apps Script Web App managing private `VAULT_SECRET_TOKEN` validation with timing-safe comparison, fast-fail outside lock, formula/CSV injection sanitization, scoped atomic row insertion into Google Sheets via `lock.tryLock(2500)`, native $O(1)$ deduplication via `createTextFinder()`, uniform anti-enumeration responses, and minimal `doGet`.
  3. `_headers`: Static HTTP security headers configuration file for Cloudflare Pages/Netlify (`X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`).
  4. `backend/wrangler.toml`: Standard configuration file for Cloudflare Workers deployment.
  5. `backend/test_suite.js`: Automated test harness verifying Google Apps Script ingestion, Worker security shields, Micro-PoW solver/validator, Cache API integration, and client-side throttle/honeypot invariants (15/15 PASS, 100%).
- **Deployment & Production Notes**:
  - Worker secrets (`GOOGLE_SCRIPT_URL`, `VAULT_SECRET_TOKEN`) are set in the Worker environment via `wrangler secret put` or Cloudflare Dashboard Variables, never exposed in client bundles.
  - Script Properties in Google Apps Script must have `VAULT_SECRET_TOKEN` configured to match the Cloudflare Worker secret.

