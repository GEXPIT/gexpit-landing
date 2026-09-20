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
    // Edge Gateway Resolution:
    // 1. Explicit override: window.GEXPIT_API_ENDPOINT
    // 2. Official Cloudflare Worker Edge Gateway: https://gexpitnuovosito.pitball85.workers.dev
    // Note: GitHub Pages hosts static assets and responds with 405 Method Not Allowed to POST requests.
    // Telemetry and lead ingestion are therefore dispatched directly to the Cloudflare Worker edge gateway.
    const DIRECT_WORKER_ENDPOINT = "https://gexpitnuovosito.pitball85.workers.dev";
    const WORKER_ENDPOINT = (typeof window !== "undefined" && window.GEXPIT_API_ENDPOINT)
        ? window.GEXPIT_API_ENDPOINT
        : DIRECT_WORKER_ENDPOINT;
    const MAX_REQUESTS = 5;
    const COOLDOWN_MS = 60000; // 60 seconds rolling window
    const STORAGE_KEY = "gexpit_telemetry_ts";

    // Self-healing: clear stale or expired rate limits on page initialization
    try {
        const rawStorage = localStorage.getItem(STORAGE_KEY);
        if (rawStorage) {
            const initNow = Date.now();
            const parsed = JSON.parse(rawStorage);
            if (Array.isArray(parsed)) {
                const active = parsed.filter(ts => typeof ts === "number" && initNow - ts < COOLDOWN_MS);
                if (active.length === 0 || (active.length > 0 && initNow - Math.max(...active) > 20000)) {
                    localStorage.removeItem(STORAGE_KEY);
                } else {
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(active));
                }
            }
        }
    } catch (_) {}

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
     * Read-only client-side rolling window throttling check via localStorage telemetry.
     * Restricts submissions to a maximum of 5 requests per 60-second window.
     * Does NOT mutate localStorage or consume attempts on validation or network errors.
     * @returns {boolean} True if within rate limit, false if exceeded.
     */
    function checkRateLimit() {
        try {
            const now = Date.now();
            const rawStorage = localStorage.getItem(STORAGE_KEY);
            if (!rawStorage) return true;
            const parsed = JSON.parse(rawStorage);
            if (!Array.isArray(parsed)) return true;
            const active = parsed.filter(ts => typeof ts === "number" && now - ts < COOLDOWN_MS);
            return active.length < MAX_REQUESTS;
        } catch (storageError) {
            console.warn("[GEXPIT SECURITY] Local telemetry unavailable. Proceeding with in-memory execution.");
            return true;
        }
    }

    /**
     * Records an authorized submission attempt in localStorage telemetry.
     * Executed strictly on successful HTTP 200 response or authorized local preview.
     */
    function recordRateLimitAttempt() {
        try {
            const now = Date.now();
            const rawStorage = localStorage.getItem(STORAGE_KEY);
            let timestamps = [];
            if (rawStorage) {
                const parsed = JSON.parse(rawStorage);
                if (Array.isArray(parsed)) {
                    timestamps = parsed.filter(ts => typeof ts === "number" && now - ts < COOLDOWN_MS);
                }
            }
            timestamps.push(now);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(timestamps));
        } catch (_) {}
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
                submitBtn.innerHTML = "<span>✓ APPLICATION RECEIVED</span>";
                submitBtn.style.backgroundColor = "var(--accent-green)";
                submitBtn.style.color = "#05070a";
                submitBtn.style.borderColor = "var(--accent-green)";
                submitBtn.style.boxShadow = "0 0 25px rgba(0, 230, 118, 0.4)";
                submitBtn.disabled = true;
                emailInput.disabled = true;
                emailInput.style.borderColor = "var(--accent-green)";
                openConfirmationModal(userEmail);
                form.tabIndex = -1;
                dialogOpeners.set(confirmationModal, form);
            }, 800);
            return;
        }

        // Step 3b: Local Offline Preview Mode (enables instant testing when opening directly from disk)
        const isLocalPreview = typeof window !== "undefined" && window.location && window.location.protocol === "file:";
        if (isLocalPreview) {
            setTimeout(() => {
                recordRateLimitAttempt();
                submitBtn.innerHTML = "<span>✓ APPLICATION RECEIVED</span>";
                submitBtn.style.backgroundColor = "var(--accent-green)";
                submitBtn.style.color = "#05070a";
                submitBtn.style.borderColor = "var(--accent-green)";
                submitBtn.style.boxShadow = "0 0 25px rgba(0, 230, 118, 0.45)";
                submitBtn.disabled = true;
                emailInput.disabled = true;
                emailInput.style.borderColor = "var(--accent-green)";
                openConfirmationModal(userEmail);
                form.tabIndex = -1;
                dialogOpeners.set(confirmationModal, form);
            }, 250);
            return;
        }

        // Step 4: Cloudflare Turnstile Readiness Pre-Flight Guard
        const turnstileWrapper = form.querySelector(".cf-turnstile-wrapper");
        const turnstileWidget = form.querySelector(".cf-turnstile");
        let turnstileInput = form.querySelector('[name="cf-turnstile-response"]');
        let turnstileToken = turnstileInput ? turnstileInput.value.trim() : "";
        if (!turnstileToken && typeof window !== "undefined" && window.turnstile && typeof window.turnstile.getResponse === "function") {
            try { turnstileToken = window.turnstile.getResponse() || ""; } catch (_) {}
        }

        // If Turnstile widget is active in this form, ensure token is ready before network dispatch
        if (turnstileWidget && !turnstileToken) {
            submitBtn.innerHTML = "<span>VERIFYING CLOUDFLARE...</span>";
            if (turnstileWrapper) {
                turnstileWrapper.classList.add("highlight-turnstile");
            }

            // Non-blocking poll for up to 2.5 seconds to allow managed challenge completion
            const pollStart = Date.now();
            while (!turnstileToken && (Date.now() - pollStart < 2500)) {
                await new Promise(r => setTimeout(r, 150));
                turnstileInput = form.querySelector('[name="cf-turnstile-response"]');
                turnstileToken = turnstileInput ? turnstileInput.value.trim() : "";
                if (!turnstileToken && typeof window !== "undefined" && window.turnstile && typeof window.turnstile.getResponse === "function") {
                    try { turnstileToken = window.turnstile.getResponse() || ""; } catch (_) {}
                }
            }

            if (turnstileWrapper) {
                turnstileWrapper.classList.remove("highlight-turnstile");
            }

            // If challenge still pending or waiting for user checkbox ("Non sono un robot")
            if (!turnstileToken) {
                submitBtn.innerHTML = "<span>CHECK 'NOT A ROBOT' ↗</span>";
                submitBtn.style.borderColor = "var(--accent-spot)";
                submitBtn.style.color = "var(--accent-spot)";
                if (turnstileWrapper) {
                    turnstileWrapper.scrollIntoView({ behavior: "smooth", block: "nearest" });
                    turnstileWrapper.classList.add("highlight-turnstile");
                }

                // Restore button after 2.5s without burning quota or dispatching invalid payload
                setTimeout(() => {
                    if (turnstileWrapper) {
                        turnstileWrapper.classList.remove("highlight-turnstile");
                    }
                    submitBtn.innerHTML = originalBtnHTML;
                    submitBtn.style.borderColor = "";
                    submitBtn.style.color = "";
                    submitBtn.disabled = false;
                }, 2500);
                return;
            }
        }

        // Step 5: Dispatch Async Fetch Request to Edge Gateway with Cloudflare Turnstile & Micro-PoW
        try {
            submitBtn.innerHTML = "<span>PROCESSING...</span>";
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
                    pow_nonce: powNonce,
                    cf_turnstile_token: turnstileToken
                })
            });

            if (response.ok) {
                // Record rate limit attempt strictly upon successful registration
                recordRateLimitAttempt();

                // UI Mutation: State -> Success (Base Emerald Green #00E676 with dark black text)
                submitBtn.innerHTML = "<span>✓ APPLICATION RECEIVED</span>";
                submitBtn.style.backgroundColor = "var(--accent-green)";
                submitBtn.style.color = "#05070a";
                submitBtn.style.borderColor = "var(--accent-green)";
                submitBtn.style.boxShadow = "0 0 25px rgba(0, 230, 118, 0.45)";
                submitBtn.disabled = true;

                emailInput.disabled = true;
                emailInput.style.borderColor = "var(--accent-green)";

                // Trigger institutional confirmation pop-up modal
                setTimeout(() => {
                    openConfirmationModal(userEmail);
                    form.tabIndex = -1;
                    dialogOpeners.set(confirmationModal, form);
                }, 200);
            } else {
                let errDetail = "";
                try {
                    const errData = await response.json();
                    if (errData && errData.message) {
                        errDetail = ` - ${errData.message}`;
                    }
                } catch (_) {}
                throw new Error(`[GEXPIT GATEWAY] Server responded with status: ${response.status}${errDetail}`);
            }
        } catch (networkError) {
            console.error("[GEXPIT GATEWAY ERROR]", networkError);

            // Reset Cloudflare Turnstile widget if active
            if (window.turnstile) {
                const widgetEl = form.querySelector(".cf-turnstile");
                if (widgetEl) {
                    try { window.turnstile.reset(widgetEl); } catch (_) {}
                }
            }

            // UI Mutation: State -> Error & Retry (Zero rate-limit penalty for failed request)
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

    /**
     * Global callback triggered when Cloudflare Turnstile successfully verifies human visitor.
     * Instantly reactivates submit button if user was previously prompted.
     * @param {string} token
     */
    window.onGexpitTurnstileSuccess = function(token) {
        document.querySelectorAll(".access-form").forEach(form => {
            const btn = form.querySelector('button[type="submit"]');
            if (btn && btn.innerHTML.includes("NOT A ROBOT")) {
                btn.innerHTML = "<span>APPLY FOR EARLY ACCESS</span>";
                btn.style.borderColor = "";
                btn.style.color = "";
                btn.disabled = false;
            }
            const wrapper = form.querySelector(".cf-turnstile-wrapper");
            if (wrapper) {
                wrapper.classList.remove("highlight-turnstile");
            }
        });
    };

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
    // 7. SHOWCASE VIDEO AUTOPLAY & OFFSCREEN PAUSE (Hero & Terminal Videos)
    // ------------------------------------------------------------------------
    // Continuous loop autoplay when visible in viewport; pause offscreen to save resources.
    const showcaseVideos = document.querySelectorAll(".hero-showcase-video, .terminal-video");

    showcaseVideos.forEach((video) => {
        // Guarantee WebKit / iOS Safari inline autoplay compliance
        video.muted = true;
        video.defaultMuted = true;
        video.playsInline = true;
        video.setAttribute("muted", "");
        video.setAttribute("playsinline", "");
        video.setAttribute("webkit-playsinline", "");

        // Robust seamless loop failsafe for mobile browsers
        video.addEventListener("ended", () => {
            video.currentTime = 0;
            video.play().catch(() => {});
        });
    });

    if ("IntersectionObserver" in window) {
        const videoObserver = new IntersectionObserver((entries) => {
            entries.forEach(({ target, isIntersecting }) => {
                if (isIntersecting) {
                    target.play().catch(() => {
                        /* Autoplay can be delayed by browser policy; non-fatal. */
                    });
                } else {
                    target.pause();
                }
            });
        }, { threshold: 0.15 });

        showcaseVideos.forEach((video) => {
            videoObserver.observe(video);
            // Autoplay immediately on load if video is already inside the viewport
            const rect = video.getBoundingClientRect();
            if (rect.top < window.innerHeight && rect.bottom > 0) {
                video.play().catch(() => {});
            }
        });
    } else {
        showcaseVideos.forEach((video) => video.play().catch(() => {}));
    }

    // Low Power Mode / iOS battery saver fallback: trigger playback on first user gesture
    const resumeVideosOnFirstTouch = () => {
        showcaseVideos.forEach((video) => {
            const rect = video.getBoundingClientRect();
            if (video.paused && rect.top < window.innerHeight && rect.bottom > 0) {
                video.play().catch(() => {});
            }
        });
        window.removeEventListener("touchstart", resumeVideosOnFirstTouch, { passive: true });
        window.removeEventListener("pointerdown", resumeVideosOnFirstTouch, { passive: true });
        window.removeEventListener("scroll", resumeVideosOnFirstTouch, { passive: true });
    };

    window.addEventListener("touchstart", resumeVideosOnFirstTouch, { passive: true, once: true });
    window.addEventListener("pointerdown", resumeVideosOnFirstTouch, { passive: true, once: true });
    window.addEventListener("scroll", resumeVideosOnFirstTouch, { passive: true, once: true });

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            showcaseVideos.forEach((video) => video.pause());
        } else {
            showcaseVideos.forEach((video) => {
                const rect = video.getBoundingClientRect();
                if (rect.top < window.innerHeight && rect.bottom > 0) {
                    video.play().catch(() => {});
                }
            });
        }
    });

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

    // ------------------------------------------------------------------------
    // STICKY CTA BAR — appare dopo il 50% di scroll, chiudibile dall'utente
    // ------------------------------------------------------------------------
    const stickyCta   = document.getElementById("sticky-cta");
    const stickyClose = document.getElementById("sticky-cta-close");

    if (stickyCta && stickyClose) {
        let ctaDismissed = false;

        // Mostra la bar quando l'utente ha scrollato oltre il 50% della pagina
        const showStickyCta = () => {
            if (ctaDismissed) return;
            const scrolled  = window.scrollY + window.innerHeight;
            const docHeight = document.documentElement.scrollHeight;
            if (scrolled / docHeight >= 0.50) {
                stickyCta.classList.add("visible");
            } else {
                stickyCta.classList.remove("visible");
            }
        };

        window.addEventListener("scroll", showStickyCta, { passive: true });

        // Pulsante X — nasconde definitivamente la bar per questa sessione
        stickyClose.addEventListener("click", () => {
            ctaDismissed = true;
            stickyCta.classList.remove("visible");
        });
    }
    const dialogOpeners = new WeakMap();
    function activateDialog(modal, firstControl) {
        dialogOpeners.set(modal, document.activeElement);
        modal.classList.add("active");
        modal.setAttribute("aria-hidden", "false");
        document.querySelectorAll("header, main, footer").forEach((region) => { region.inert = true; });
        document.body.style.overflow = "hidden";
        if (firstControl) firstControl.focus();
    }
    function deactivateDialog(modal) {
        modal.classList.remove("active");
        modal.setAttribute("aria-hidden", "true");
        document.querySelectorAll("header, main, footer").forEach((region) => { region.inert = false; });
        document.body.style.overflow = "";
        const opener = dialogOpeners.get(modal);
        if (opener && opener.isConnected) {
            // A successful submission disables its button; return to its email
            // form heading instead of dropping keyboard focus into the page.
            if (opener.disabled) {
                const form = opener.closest("form");
                if (form) { form.tabIndex = -1; form.focus(); }
            } else opener.focus();
        }
    }
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Tab") return;
        const modal = document.querySelector('[role="dialog"].active');
        if (!modal) return;
        const controls = [...modal.querySelectorAll('button:not(:disabled), a[href], [tabindex="0"]')]
            .filter((control) => control.getClientRects().length);
        if (!controls.length) return;
        const first = controls[0], last = controls[controls.length - 1];
        if (event.shiftKey && (document.activeElement === first || !modal.contains(document.activeElement))) {
            event.preventDefault(); last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !modal.contains(document.activeElement))) {
            event.preventDefault(); first.focus();
        }
    });

    // ------------------------------------------------------------------------
    // Manual screenshot galleries. Without JavaScript all descriptions remain visible.
    document.querySelectorAll("[data-gallery]").forEach((gallery) => {
        const slides = [...gallery.querySelectorAll("[data-slide]")];
        if (slides.length < 2) return;
        const choices = document.createElement("div");
        choices.className = "gallery-choices";
        choices.setAttribute("role", "group");
        choices.setAttribute("aria-label", "Choose a platform view");
        const controls = document.createElement("div");
        controls.className = "gallery-controls";
        const previous = document.createElement("button");
        const next = document.createElement("button");
        const status = document.createElement("span");
        previous.type = next.type = "button";
        previous.textContent = "← Previous";
        next.textContent = "Next →";
        status.className = "gallery-status";
        status.setAttribute("aria-live", "polite");
        status.setAttribute("aria-atomic", "true");
        let current = 0;
        const buttons = slides.map((slide, index) => {
            const button = document.createElement("button");
            button.type = "button";
            button.textContent = slide.dataset.label;
            button.setAttribute("aria-controls", slide.id);
            button.addEventListener("click", () => select(index));
            button.addEventListener("keydown", (event) => {
                let target;
                if (event.key === "ArrowRight") target = (index + 1) % slides.length;
                if (event.key === "ArrowLeft") target = (index - 1 + slides.length) % slides.length;
                if (event.key === "Home") target = 0;
                if (event.key === "End") target = slides.length - 1;
                if (target === undefined) return;
                event.preventDefault();
                select(target);
                buttons[target].focus();
            });
            choices.append(button);
            return button;
        });
        function select(index) {
            current = (index + slides.length) % slides.length;
            slides.forEach((slide, i) => {
                slide.hidden = i !== current;
                buttons[i].setAttribute("aria-pressed", String(i === current));
            });
            status.textContent = `${current + 1} / ${slides.length} · ${slides[current].dataset.label}`;
        }
        previous.addEventListener("click", () => select(current - 1));
        next.addEventListener("click", () => select(current + 1));
        controls.append(previous, status, next);
        gallery.querySelector(".gallery-intro").after(choices, controls);
        gallery.classList.add("gallery-ready");
        select(0);
    });

    // 9. HIGH-RESOLUTION CHART LIGHTBOX (Pure Vanilla, Zero Dependencies)
    // ------------------------------------------------------------------------
    const lightboxModal = document.getElementById("lightbox-modal");
    const lightboxImg = document.getElementById("lightbox-img");
    const lightboxCaption = document.getElementById("lightbox-caption");
    const lightboxClose = document.getElementById("lightbox-close");

    if (lightboxModal && lightboxImg) {
        const featureImages = document.querySelectorAll(".feature-visual img");

        const openLightbox = (img) => {
            lightboxImg.src = img.src;
            lightboxImg.alt = img.alt || "GEXPIT High-Resolution Chart Detail";
            const header = img.closest(".feature-visual")?.querySelector(".screenshot-header");
            lightboxCaption.textContent = header ? header.textContent.trim() : (img.alt || "");
            activateDialog(lightboxModal, lightboxClose);
        };

        const closeLightbox = () => {
            deactivateDialog(lightboxModal);
            lightboxImg.removeAttribute("src");
        };

        featureImages.forEach((img) => {
            img.tabIndex = 0;
            img.setAttribute("role", "button");
            img.setAttribute("aria-label", `Enlarge: ${img.alt}`);
            img.setAttribute("aria-haspopup", "dialog");
            img.addEventListener("click", () => { img.focus(); openLightbox(img); });
            img.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openLightbox(img);
                }
            });
        });

        if (lightboxClose) {
            lightboxClose.addEventListener("click", closeLightbox);
        }

        lightboxModal.addEventListener("click", (e) => {
            if (e.target === lightboxModal || e.target.classList.contains("lightbox-wrapper")) {
                closeLightbox();
            }
        });

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && lightboxModal.classList.contains("active")) {
                closeLightbox();
            }
        });
    }

    // ------------------------------------------------------------------------
    // 10. INSTITUTIONAL PRIVACY MODAL (GDPR & Data Rights Governance)
    // ------------------------------------------------------------------------
    const privacyModal = document.getElementById("privacy-modal");
    const privacyClose = document.getElementById("privacy-modal-close");
    const privacyBackdrop = document.getElementById("privacy-modal-backdrop");
    const privacyConfirm = document.getElementById("privacy-modal-confirm");
    const privacyTriggers = document.querySelectorAll(".privacy-modal-trigger");

    if (privacyModal) {
        const openPrivacyModal = (e) => {
            if (e) e.preventDefault();
            activateDialog(privacyModal, privacyClose);
        };

        const closePrivacyModal = () => {
            deactivateDialog(privacyModal);
        };

        privacyTriggers.forEach((trigger) => {
            trigger.addEventListener("click", openPrivacyModal);
        });

        if (privacyClose) {
            privacyClose.addEventListener("click", closePrivacyModal);
        }

        if (privacyBackdrop) {
            privacyBackdrop.addEventListener("click", closePrivacyModal);
        }

        if (privacyConfirm) {
            privacyConfirm.addEventListener("click", closePrivacyModal);
        }

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && privacyModal.classList.contains("active")) {
                closePrivacyModal();
            }
        });
    }

    // ------------------------------------------------------------------------
    // 11. REGISTRATION CONFIRMATION POP-UP MODAL
    // ------------------------------------------------------------------------
    const confirmationModal = document.getElementById("confirmation-modal");
    const confirmationClose = document.getElementById("confirmation-modal-close");
    const confirmationBackdrop = document.getElementById("confirmation-modal-backdrop");
    const confirmationConfirm = document.getElementById("confirmation-modal-confirm");
    const confirmationEmailDisplay = document.getElementById("confirmation-email-display");

    function openConfirmationModal(email) {
        if (!confirmationModal) return;
        if (confirmationEmailDisplay && email) {
            confirmationEmailDisplay.textContent = email;
        }
        activateDialog(confirmationModal, confirmationConfirm);
    }

    function closeConfirmationModal() {
        if (!confirmationModal) return;
        deactivateDialog(confirmationModal);
    }

    if (confirmationModal) {
        if (confirmationClose) {
            confirmationClose.addEventListener("click", closeConfirmationModal);
        }
        if (confirmationBackdrop) {
            confirmationBackdrop.addEventListener("click", closeConfirmationModal);
        }
        if (confirmationConfirm) {
            confirmationConfirm.addEventListener("click", closeConfirmationModal);
        }

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && confirmationModal.classList.contains("active")) {
                closeConfirmationModal();
            }
        });
    }

    // ------------------------------------------------------------------------
    // 12. SMOOTH CENTERED SCROLL FOR APPLICATION FORM (Mobile & Desktop)
    // ------------------------------------------------------------------------
    const bottomFormLinks = document.querySelectorAll('a[href="#bottom-form"], a[href="#bottom-form-email"]');
    bottomFormLinks.forEach((link) => {
        link.addEventListener("click", (e) => {
            const emailInput = document.getElementById("bottom-form-email");
            if (emailInput) {
                e.preventDefault();
                emailInput.scrollIntoView({ behavior: "smooth", block: "center" });
                if (window.history && window.history.pushState) {
                    window.history.pushState(null, "", "#bottom-form");
                }
                emailInput.classList.remove("input-highlight-pulse");
                void emailInput.offsetWidth;
                emailInput.classList.add("input-highlight-pulse");
                setTimeout(() => {
                    emailInput.classList.remove("input-highlight-pulse");
                }, 1800);
            }
        });
    });
});
