/**
 * ============================================================================
 * GEXPIT INSTITUTIONAL PLATFORM — CLIENT-SIDE CORE LOGIC & DATA PIPELINE
 * Version: 1.0.0 (Phase 5 Master Blueprint)
 * Stack: Pure Vanilla JavaScript (ES6+, Strict Mode, Zero External Dependencies)
 * ============================================================================
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    // ------------------------------------------------------------------------
    // 1. QUANTITATIVE CONFIGURATION & EDGE GATEWAY ENDPOINTS
    // ------------------------------------------------------------------------
    const WORKER_ENDPOINT = window.GEXPIT_API_ENDPOINT || "/api/waitlist";
    const MAX_REQUESTS = 2;
    const COOLDOWN_MS = 60000; // 60 seconds rolling window
    const STORAGE_KEY = "gexpit_telemetry_ts";

    // Form DOM References
    const heroForm = document.getElementById("hero-form");
    const bottomForm = document.getElementById("bottom-form");

    // ------------------------------------------------------------------------
    // 2. VALIDATION & SECURITY SUBSYSTEMS
    // ------------------------------------------------------------------------

    /**
     * Syntactic email validation conforming to RFC 5322 specifications.
     * Prevents invalid or malformed payloads before dispatching network requests.
     * @param {string} email
     * @returns {boolean}
     */
    function isValidEmail(email) {
        if (!email || typeof email !== "string") return false;
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
        return emailRegex.test(email.trim());
    }

    /**
     * Client-side rolling window throttling via localStorage telemetry.
     * Restricts submissions to a maximum of 2 requests per 60-second window.
     * @returns {boolean} True if within rate limit, false if exceeded.
     */
    function checkRateLimit() {
        try {
            const now = Date.now();
            const rawStorage = localStorage.getItem(STORAGE_KEY);
            let timestamps = [];

            if (rawStorage) {
                const parsed = JSON.parse(rawStorage);
                if (Array.isArray(parsed)) {
                    // Prune timestamps older than the cooldown duration
                    timestamps = parsed.filter(ts => typeof ts === "number" && now - ts < COOLDOWN_MS);
                }
            }

            if (timestamps.length >= MAX_REQUESTS) {
                return false;
            }

            timestamps.push(now);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(timestamps));
            return true;
        } catch (storageError) {
            // Graceful fallback if localStorage is restricted or disabled
            console.warn("[GEXPIT SECURITY] Local telemetry unavailable. Proceeding with in-memory execution.");
            return true;
        }
    }

    /**
     * Inspects invisible honeypot trap field.
     * Automated bots parse and populate all form fields indiscriminately.
     * @param {HTMLFormElement} formElement
     * @returns {boolean} True if honeypot was touched by automated actor.
     */
    function isBot(formElement) {
        const trapInput = formElement.querySelector(".hp-trap input");
        if (!trapInput) return false;
        return trapInput.value.trim().length > 0;
    }

    /**
     * Computes client-side Micro Proof-of-Work (PoW) challenge using Web Crypto API.
     * Neutralizes automated spam and bot flooding (< 5ms computation time).
     * @param {string} email
     * @param {number} powTs
     * @returns {Promise<number>}
     */
    async function solveProofOfWork(email, powTs) {
        const cleanEmail = email.toLowerCase().trim();
        const encoder = new TextEncoder();
        let nonce = 0;

        if (window.crypto && window.crypto.subtle) {
            while (nonce < 100000) {
                const challenge = `gexpit_pow_v1:${cleanEmail}:${powTs}:${nonce}`;
                const data = encoder.encode(challenge);
                const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
                const hashArray = new Uint8Array(hashBuffer);
                // 3 leading hex zeros check: byte 0 is 0x00 and high nibble of byte 1 is 0 (< 16)
                if (hashArray[0] === 0 && hashArray[1] < 16) {
                    return nonce;
                }
                nonce++;
            }
        }
        return nonce;
    }

    // ------------------------------------------------------------------------
    // 3. ASYNC FORM SUBMISSION & UI MUTATION PIPELINE
    // ------------------------------------------------------------------------

    /**
     * Unified async form submission handler for institutional access requests.
     * @param {Event} event
     */
    async function handleFormSubmit(event) {
        event.preventDefault();

        const form = event.currentTarget;
        const submitBtn = form.querySelector('button[type="submit"]');
        const emailInput = form.querySelector('input[type="email"]');

        if (!submitBtn || !emailInput) return;

        const userEmail = emailInput.value.trim();
        const originalBtnHTML = submitBtn.innerHTML;

        // Reset any previous visual error styles
        emailInput.style.borderColor = "";

        // UI Mutation: State -> Processing
        submitBtn.disabled = true;
        submitBtn.innerHTML = "<span>PROCESSING...</span>";

        // Step 1: Syntactic Validation (Fast non-blocking feedback BUG-02)
        if (!isValidEmail(userEmail)) {
            emailInput.style.borderColor = "var(--accent-put)";
            submitBtn.innerHTML = "<span>INVALID EMAIL</span>";
            submitBtn.style.borderColor = "var(--accent-put)";
            submitBtn.style.color = "var(--accent-put)";

            setTimeout(() => {
                emailInput.style.borderColor = "";
                submitBtn.innerHTML = originalBtnHTML;
                submitBtn.style.borderColor = "";
                submitBtn.style.color = "";
                submitBtn.disabled = false;
                emailInput.focus();
            }, 1000);
            return;
        }

        // Step 2: Rate Limit Verification
        if (!checkRateLimit()) {
            submitBtn.innerHTML = "<span>RATE LIMITED (60s)</span>";
            submitBtn.style.borderColor = "var(--accent-spot)";
            submitBtn.style.color = "var(--accent-spot)";

            setTimeout(() => {
                submitBtn.innerHTML = originalBtnHTML;
                submitBtn.style.borderColor = "";
                submitBtn.style.color = "";
                submitBtn.disabled = false;
            }, 3000);
            return;
        }

        // Step 3: Honeypot Anti-Bot Silent Discard
        if (isBot(form)) {
            // Emulate artificial network round-trip to deceive automated scraping tools
            setTimeout(() => {
                submitBtn.innerHTML = "<span>ACCESS REQUESTED</span>";
                submitBtn.style.borderColor = "var(--accent-call)";
                submitBtn.style.color = "var(--accent-call)";
                submitBtn.style.boxShadow = "0 0 20px rgba(0, 255, 136, 0.25)";
                submitBtn.disabled = true;
                emailInput.disabled = true;
                emailInput.style.borderColor = "rgba(0, 255, 136, 0.3)";
            }, 800);
            return;
        }

        // Step 4: Dispatch Async Fetch Request to Edge Gateway with Micro-PoW
        try {
            const trapInput = form.querySelector(".hp-trap input");
            const trapValue = trapInput ? trapInput.value.trim() : "";
            const powTs = Date.now();
            const powNonce = await solveProofOfWork(userEmail, powTs);

            const response = await fetch(WORKER_ENDPOINT, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    email: userEmail,
                    timestamp: new Date().toISOString(),
                    source: form.id || "unknown_cockpit",
                    hp_code: trapValue,
                    pow_ts: powTs,
                    pow_nonce: powNonce
                })
            });

            if (response.ok) {
                // UI Mutation: State -> Success
                submitBtn.innerHTML = "<span>ACCESS REQUESTED</span>";
                submitBtn.style.borderColor = "var(--accent-call)";
                submitBtn.style.color = "var(--accent-call)";
                submitBtn.style.boxShadow = "0 0 20px rgba(0, 255, 136, 0.25)";
                submitBtn.disabled = true;

                emailInput.disabled = true;
                emailInput.style.borderColor = "rgba(0, 255, 136, 0.3)";
            } else {
                throw new Error(`[GEXPIT GATEWAY] Server responded with status: ${response.status}`);
            }
        } catch (networkError) {
            console.error("[GEXPIT GATEWAY ERROR]", networkError);

            // UI Mutation: State -> Error & Retry
            submitBtn.innerHTML = "<span>ERROR - RETRY</span>";
            submitBtn.style.borderColor = "var(--accent-put)";
            submitBtn.style.color = "var(--accent-put)";

            setTimeout(() => {
                submitBtn.innerHTML = originalBtnHTML;
                submitBtn.style.borderColor = "";
                submitBtn.style.color = "";
                submitBtn.disabled = false;
            }, 3000);
        }
    }

    // ------------------------------------------------------------------------
    // 4. ATTACH LISTENERS & INITIALIZE DISPATCHERS
    // ------------------------------------------------------------------------
    if (heroForm) {
        heroForm.addEventListener("submit", handleFormSubmit);
    }

    if (bottomForm) {
        bottomForm.addEventListener("submit", handleFormSubmit);
    }

    // ------------------------------------------------------------------------
    // 5. SCROLL REVEAL ENGINE (Specs Ticker)
    // ------------------------------------------------------------------------
    const prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (!prefersReducedMotion && "IntersectionObserver" in window) {
        const revealTargets = document.querySelectorAll(".spec-block");

        if (revealTargets.length) {
            const revealObserver = new IntersectionObserver(
                (entries, observer) => {
                    entries.forEach((entry) => {
                        if (entry.isIntersecting) {
                            entry.target.classList.add("in-view");
                            observer.unobserve(entry.target);
                        }
                    });
                },
                { threshold: 0.2, rootMargin: "0px 0px -40px 0px" }
            );

            revealTargets.forEach((target) => revealObserver.observe(target));
        }
    } else {
        document.querySelectorAll(".spec-block").forEach((el) => el.classList.add("in-view"));
    }

    // ------------------------------------------------------------------------
    // 6. MAGNETIC CTA MICRO-INTERACTION (Scroll-Resilient BUG-03)
    // ------------------------------------------------------------------------
    if (!prefersReducedMotion && window.matchMedia && window.matchMedia("(pointer: fine)").matches) {
        const MAGNETIC_RANGE_PX = 7;
        const magneticTargets = document.querySelectorAll(".btn-primary, .btn-header");

        magneticTargets.forEach((btn) => {
            let cachedRect = null;
            let pendingFrame = null;

            const invalidateRect = () => { cachedRect = null; };
            window.addEventListener("scroll", invalidateRect, { passive: true });

            btn.addEventListener("mouseenter", () => {
                cachedRect = btn.getBoundingClientRect();
            });

            btn.addEventListener("mousemove", (event) => {
                if (!cachedRect) {
                    cachedRect = btn.getBoundingClientRect();
                }
                if (pendingFrame) return;

                pendingFrame = requestAnimationFrame(() => {
                    pendingFrame = null;
                    if (!cachedRect) return;
                    const relX = event.clientX - cachedRect.left - cachedRect.width / 2;
                    const relY = event.clientY - cachedRect.top - cachedRect.height / 2;
                    const offsetX = Math.max(-MAGNETIC_RANGE_PX, Math.min(MAGNETIC_RANGE_PX, relX * 0.25));
                    const offsetY = Math.max(-MAGNETIC_RANGE_PX, Math.min(MAGNETIC_RANGE_PX, relY * 0.25));

                    btn.style.transform = `translate(${offsetX}px, ${offsetY - 1}px) scale(1.02)`;
                });
            });

            btn.addEventListener("mouseleave", () => {
                cachedRect = null;
                if (pendingFrame) {
                    cancelAnimationFrame(pendingFrame);
                    pendingFrame = null;
                }
                btn.style.transform = "";
            });
        });
    }

    // ------------------------------------------------------------------------
    // 7. OFFSCREEN VIDEO PAUSE (Showcase Terminal)
    // ------------------------------------------------------------------------
    // Marketing rationale for keeping it at all: the looping replay demo is
    // the single best proof of "zero lag" the page has. Marketing rationale
    // for THIS block: a decoding, looping video costs real CPU/GPU for as
    // long as it is running, even scrolled far out of view. Pausing it when
    // it leaves the viewport (and resuming on return) keeps that cost paid
    // only while a visitor is actually looking at it.
    if ("IntersectionObserver" in window) {
        const showcaseVideo = document.querySelector(".terminal-video");

        if (showcaseVideo) {
            const videoObserver = new IntersectionObserver(
                (entries) => {
                    entries.forEach((entry) => {
                        if (entry.isIntersecting) {
                            showcaseVideo.play().catch(() => {
                                /* Autoplay can be blocked by the browser; non-fatal. */
                            });
                        } else {
                            showcaseVideo.pause();
                        }
                    });
                },
                { threshold: 0.15 }
            );

            videoObserver.observe(showcaseVideo);
        }
    }

    // ------------------------------------------------------------------------
    // 8. MOBILE NAVIGATION DRAWER
    // ------------------------------------------------------------------------
    // Below the 768px CSS breakpoint, .nav-menu switches from an inline row
    // to an absolutely positioned dropdown (see style.css) that this toggle
    // opens/closes. Without this, Specs/Features/Showcase/Comparison/
    // Pricing/FAQ have zero entry point on any phone or tablet.
    const navToggle = document.getElementById("nav-toggle");
    const navMenu = document.getElementById("nav-menu");

    if (navToggle && navMenu) {
        const openDrawer = () => {
            navMenu.classList.add("is-open");
            navToggle.setAttribute("aria-expanded", "true");
            document.body.classList.add("nav-open");
        };

        const closeDrawer = () => {
            navMenu.classList.remove("is-open");
            navToggle.setAttribute("aria-expanded", "false");
            document.body.classList.remove("nav-open");
        };

        const isDrawerOpen = () => navMenu.classList.contains("is-open");

        navToggle.addEventListener("click", () => {
            if (isDrawerOpen()) {
                closeDrawer();
            } else {
                openDrawer();
            }
        });

        // Tapping a section link (or the drawer's own Request Access CTA)
        // should navigate AND close the drawer, otherwise it stays open
        // over the destination section/form.
        navMenu.querySelectorAll(".nav-link, .nav-menu-cta").forEach((link) => {
            link.addEventListener("click", closeDrawer);
        });

        // Escape key closes the drawer and returns focus to the toggle,
        // keeping keyboard users oriented.
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && isDrawerOpen()) {
                closeDrawer();
                navToggle.focus();
            }
        });

        // Tapping/clicking anywhere outside the open drawer or the toggle
        // button itself closes it — standard mobile menu expectation.
        document.addEventListener("click", (event) => {
            if (!isDrawerOpen()) return;
            if (navMenu.contains(event.target) || navToggle.contains(event.target)) return;
            closeDrawer();
        });

        // If the viewport is resized/rotated past the mobile breakpoint
        // (e.g. phone rotated to landscape wide enough, or a foldable
        // unfolds) while the drawer is open, reset state so the menu
        // doesn't get stuck open under the desktop layout.
        window.addEventListener("resize", () => {
            if (window.innerWidth > 768 && isDrawerOpen()) {
                closeDrawer();
            }
        });
    }
});
