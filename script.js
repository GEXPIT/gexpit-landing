document.addEventListener('DOMContentLoaded', () => {
    const waitlistForms = document.querySelectorAll('.cta-form');
    
    waitlistForms.forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const emailInput = form.querySelector('input[type="email"]');
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.innerText;
            const email = emailInput.value.trim();

            if (!email) return;

            // UI feedback: Loading state
            submitBtn.innerText = 'Processing...';
            submitBtn.disabled = true;
            submitBtn.style.opacity = '0.7';

            // URL DEL CLOUDFLARE WORKER
            // SOSTITUISCI QUESTO URL CON QUELLO REALE DEL TUO WORKER CLOUDFLARE
            const WORKER_URL = "https://gexpit-api.pitball85.workers.dev/";
            
            try {
                const response = await fetch(WORKER_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Secret-Token': 'ARCfrpf_piSICUREZZA'
                    },
                    body: JSON.stringify({ email: email })
                });

                if (response.ok) {
                    // UI feedback: Success state
                    submitBtn.innerText = 'Access Granted ✓';
                    submitBtn.style.borderColor = 'var(--emerald-glow)';
                    submitBtn.style.background = 'rgba(0, 245, 160, 0.1)';
                    emailInput.value = '';
                } else {
                    throw new Error('Network response was not ok');
                }
            } catch (error) {
                console.error('Error submitting form:', error);
                // UI feedback: Error state
                submitBtn.innerText = 'Network Error';
                submitBtn.style.borderColor = 'var(--red-glow)';
                submitBtn.style.background = 'rgba(255, 42, 75, 0.1)';
                
                // Revert after 3 seconds
                setTimeout(() => {
                    submitBtn.innerText = originalBtnText;
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '1';
                    submitBtn.style.borderColor = '';
                    submitBtn.style.background = '';
                }, 3000);
            }
        });
    });
});
