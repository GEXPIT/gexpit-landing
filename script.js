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
    // Production Zone WAF Shield:
    // 1. Custom override: window.GEXPIT_API_ENDPOINT
    // 2. Production same-origin: /api/request-access (zone WAF inheritance, hides workers.dev)
    // 3. Fallback: direct edge gateway for local testing / development
    const isProductionZone = typeof window !== "undefined" && window.location &&
        (window.location.hostname === "gexpit.com" || window.location.hostname === "www.gexpit.com");
    const WORKER_ENDPOINT = (typeof window !== "undefined" && window.GEXPIT_API_ENDPOINT)
        ? window.GEXPIT_API_ENDPOINT
        : (isProductionZone ? "/api/request-access" : "https://gexpitnuovosito.pitball85.workers.dev");
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
                submitBtn.innerHTML = "<span>✓ ACCESS CONFIRMED</span>";
                submitBtn.style.backgroundColor = "var(--accent-green)";
                submitBtn.style.color = "#05070a";
                submitBtn.style.borderColor = "var(--accent-green)";
                submitBtn.style.boxShadow = "0 0 25px rgba(0, 230, 118, 0.4)";
                submitBtn.disabled = true;
                emailInput.disabled = true;
                emailInput.style.borderColor = "var(--accent-green)";
                openConfirmationModal(userEmail);
            }, 800);
            return;
        }

        // Step 3b: Local Offline Preview Mode (enables instant testing when opening directly from disk)
        const isLocalPreview = typeof window !== "undefined" && window.location && window.location.protocol === "file:";
        if (isLocalPreview) {
            setTimeout(() => {
                recordRateLimitAttempt();
                submitBtn.innerHTML = "<span>✓ ACCESS CONFIRMED</span>";
                submitBtn.style.backgroundColor = "var(--accent-green)";
                submitBtn.style.color = "#05070a";
                submitBtn.style.borderColor = "var(--accent-green)";
                submitBtn.style.boxShadow = "0 0 25px rgba(0, 230, 118, 0.45)";
                submitBtn.disabled = true;
                emailInput.disabled = true;
                emailInput.style.borderColor = "var(--accent-green)";
                openConfirmationModal(userEmail);
            }, 250);
            return;
        }

        // Step 4: Cloudflare Turnstile Readiness Pre-Flight Guard
        const turnstileWrapper = form.querySelector(".cf-turnstile-wrapper");
        const turnstileWidget = form.querySelector(".cf-turnstile");
        let turnstileInput = form.querySelector('[name="cf-turnstile-response"]');
        let turnstileToken = turnstileInput ? turnstileInput.value.trim() : "";

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
                submitBtn.innerHTML = "<span>✓ ACCESS CONFIRMED</span>";
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
                }, 200);
            } else {
                throw new Error(`[GEXPIT GATEWAY] Server responded with status: ${response.status}`);
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
                btn.innerHTML = "<span>REQUEST ACCESS</span>";
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
    // 7. OFFSCREEN VIDEO PAUSE (Hero & Terminal Showcase Videos)
    // ------------------------------------------------------------------------
    // Marketing rationale for keeping it at all: the looping replay demo is
    // the single best proof of "zero lag" the page has. Marketing rationale
    // for THIS block: a decoding, looping video costs real CPU/GPU for as
    // long as it is running, even scrolled far out of view. Pausing it when
    // it leaves the viewport (and resuming on return) keeps that cost paid
    // only while a visitor is actually looking at it.
    if ("IntersectionObserver" in window) {
        const showcaseVideos = document.querySelectorAll(".hero-showcase-video, .terminal-video");

        if (showcaseVideos.length > 0) {
            const videoObserver = new IntersectionObserver(
                (entries) => {
                    entries.forEach((entry) => {
                        const vid = entry.target;
                        if (entry.isIntersecting) {
                            vid.play().catch(() => {
                                /* Autoplay can be blocked by the browser; non-fatal. */
                            });
                        } else {
                            vid.pause();
                        }
                    });
                },
                { threshold: 0.15 }
            );

            showcaseVideos.forEach((vid) => videoObserver.observe(vid));
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
    // ------------------------------------------------------------------------
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
            lightboxModal.classList.add("active");
            lightboxModal.setAttribute("aria-hidden", "false");
            document.body.style.overflow = "hidden";
        };

        const closeLightbox = () => {
            lightboxModal.classList.remove("active");
            lightboxModal.setAttribute("aria-hidden", "true");
            lightboxImg.src = "";
            document.body.style.overflow = "";
        };

        featureImages.forEach((img) => {
            img.addEventListener("click", () => openLightbox(img));
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
            privacyModal.classList.add("active");
            privacyModal.setAttribute("aria-hidden", "false");
            document.body.style.overflow = "hidden";
            if (privacyClose) privacyClose.focus();
        };

        const closePrivacyModal = () => {
            privacyModal.classList.remove("active");
            privacyModal.setAttribute("aria-hidden", "true");
            document.body.style.overflow = "";
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
        confirmationModal.classList.add("active");
        confirmationModal.setAttribute("aria-hidden", "false");
        document.body.style.overflow = "hidden";
        if (confirmationConfirm) {
            confirmationConfirm.focus();
        }
    }

    function closeConfirmationModal() {
        if (!confirmationModal) return;
        confirmationModal.classList.remove("active");
        confirmationModal.setAttribute("aria-hidden", "true");
        document.body.style.overflow = "";
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
});
