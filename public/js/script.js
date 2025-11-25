// Mobile Menu Toggle
const menuToggle = document.getElementById('menuToggle');
const navLinks = document.getElementById('navLinks');

if (menuToggle) {
    menuToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        menuToggle.classList.toggle('active');
    });
}

// Close mobile menu when a link is clicked
const navItems = document.querySelectorAll('.nav-links a');
navItems.forEach(item => {
    item.addEventListener('click', () => {
        navLinks.classList.remove('active');
        if (menuToggle) menuToggle.classList.remove('active');
    });
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        const href = this.getAttribute('href');
        if (href && href !== '#') {
            e.preventDefault();
            const target = document.querySelector(href);
            if (target) {
                const offsetTop = target.offsetTop - 80;
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        }
    });
});

// CTA Button handlers
const ctaButtons = document.querySelectorAll('[data-testid="button-open-account"], [data-testid="button-open-account-cta"], [data-testid="button-showcase-cta"]');
ctaButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        showModal('Open Your MANS Bank Account', 'Fill in the form below to get started');
    });
});

// Get Started button
const getStartedBtn = document.querySelector('[data-testid="button-get-started"]');
if (getStartedBtn) {
    getStartedBtn.addEventListener('click', () => {
        showModal('Get Started with MANS Bank', 'Join thousands of users already banking smarter');
    });
}


// Modal functionality
function showModal(title, subtitle) {
    const existingModal = document.getElementById('customModal');
    if (existingModal) existingModal.remove();

    const modal = document.createElement('div');
    modal.id = 'customModal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 2000;
        animation: fadeIn 0.3s ease;
    `;

    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: white;
        padding: 2.5rem;
        border-radius: 12px;
        max-width: 500px;
        width: 90%;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        animation: slideUp 0.3s ease;
    `;

    modalContent.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
            <h2 style="margin: 0; color: #003D99; font-size: 1.5rem;">${title}</h2>
            <button class="close-modal" style="background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #666;">×</button>
        </div>
        <p style="color: #666; margin-bottom: 2rem;">${subtitle}</p>
        <form id="accountForm" style="display: flex; flex-direction: column; gap: 1rem;">
            <input type="text" placeholder="Full Name" required style="padding: 0.75rem; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1rem;">
            <input type="email" placeholder="Email Address" required style="padding: 0.75rem; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1rem;">
            <input type="tel" placeholder="Phone Number" required style="padding: 0.75rem; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1rem;">
            <button type="submit" style="padding: 0.9rem; background: #0052CC; color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 1rem; cursor: pointer; transition: all 0.3s ease;">
                Create Account
            </button>
        </form>
    `;

    modal.appendChild(modalContent);
    document.body.appendChild(modal);

    // Add keyframes animation
    if (!document.querySelector('style[data-modal-animations]')) {
        const style = document.createElement('style');
        style.setAttribute('data-modal-animations', 'true');
        style.textContent = `
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Close modal
    const closeModal = () => {
        modal.style.opacity = '0';
        setTimeout(() => modal.remove(), 300);
    };

    const closeButton = modalContent.querySelector('.close-modal');
    if (closeButton) {
        closeButton.addEventListener('click', closeModal);
    }

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    // Handle form submission
    const accountForm = modalContent.querySelector('#accountForm');
    if (accountForm) {
        accountForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = accountForm.querySelector('input[type="text"]').value;
            const email = accountForm.querySelector('input[type="email"]').value;
            const phone = accountForm.querySelector('input[type="tel"]').value;

            try {
                const response = await fetch('/api/accounts', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ name, email, phone })
                });

                if (response.ok) {
                    showNotification('Account created successfully! Check your email for next steps.', 'success');
                    closeModal();
                } else {
                    showNotification('Error creating account. Please try again.', 'error');
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('An error occurred. Please try again.', 'error');
            }
        });
    }
}

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 90px;
        right: 20px;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        font-weight: 500;
        z-index: 3000;
        animation: slideInRight 0.3s ease;
        max-width: 400px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    `;

    if (type === 'success') {
        notification.style.background = '#10b981';
        notification.style.color = 'white';
    } else if (type === 'error') {
        notification.style.background = '#ef4444';
        notification.style.color = 'white';
    } else {
        notification.style.background = '#0052CC';
        notification.style.color = 'white';
    }

    notification.textContent = message;
    document.body.appendChild(notification);

    // Add animation keyframes
    if (!document.querySelector('style[data-notification-animations]')) {
        const style = document.createElement('style');
        style.setAttribute('data-notification-animations', 'true');
        style.textContent = `
            @keyframes slideInRight {
                from {
                    opacity: 0;
                    transform: translateX(400px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
        `;
        document.head.appendChild(style);
    }

    setTimeout(() => {
        notification.style.animation = 'slideInRight 0.3s ease reverse';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Scroll animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('scroll-reveal');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe feature cards and other elements
document.querySelectorAll('.feature-card, .product-showcase, .cta-section').forEach(element => {
    element.classList.remove('scroll-reveal');
    observer.observe(element);
});

// Navbar scroll effect
let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', () => {
    let scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    if (scrollTop > 50) {
        navbar.style.boxShadow = '0 4px 20px rgba(0, 82, 204, 0.15)';
    } else {
        navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.05)';
    }
    
    lastScrollTop = scrollTop;
});

// Add keyboard support for modal
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('customModal');
        if (modal) {
            modal.style.opacity = '0';
            setTimeout(() => modal.remove(), 300);
        }
    }
});

// Prevent menu toggle animation on page load
window.addEventListener('load', () => {
    if (menuToggle) {
        menuToggle.classList.remove('active');
    }
});

// ==================== PRICING PLANS ==================== 

const pricingButtons = document.querySelectorAll('[data-testid^="button-"][data-testid$="-plan"]');
pricingButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const planName = btn.getAttribute('data-testid').replace('button-', '').replace('-plan', '');
        showModal(`Get Started with ${planName.charAt(0).toUpperCase() + planName.slice(1)} Plan`, 
                  `Join thousands of users on our ${planName} plan and start banking smarter today!`);
    });
});

// ==================== CARD BEAM ANIMATION ==================== 

class CardStreamController {
    constructor() {
        this.container = document.getElementById("cardStream");
        this.cardLine = document.getElementById("cardLine");

        if (!this.container || !this.cardLine) return;

        this.position = 0;
        this.velocity = 120;
        this.direction = -1;
        this.isAnimating = true;
        this.isDragging = false;
        this.lastTime = 0;
        this.lastMouseX = 0;
        this.mouseVelocity = 0;
        this.friction = 0.95;
        this.minVelocity = 30;
        this.containerWidth = 0;
        this.cardLineWidth = 0;

        this.init();
    }

    init() {
        this.populateCardLine();
        this.calculateDimensions();
        this.setupEventListeners();
        this.updateCardPosition();
        this.animate();
        this.startPeriodicUpdates();
    }

    calculateDimensions() {
        this.containerWidth = this.container.offsetWidth;
        const cardWidth = 400;
        const cardGap = 60;
        const cardCount = this.cardLine.children.length;
        this.cardLineWidth = (cardWidth + cardGap) * cardCount;
    }

    setupEventListeners() {
        this.cardLine.addEventListener("mousedown", (e) => this.startDrag(e));
        document.addEventListener("mousemove", (e) => this.onDrag(e));
        document.addEventListener("mouseup", () => this.endDrag());
        this.cardLine.addEventListener("wheel", (e) => this.onWheel(e));
        this.cardLine.addEventListener("selectstart", (e) => e.preventDefault());
        this.cardLine.addEventListener("dragstart", (e) => e.preventDefault());
        window.addEventListener("resize", () => this.calculateDimensions());
    }

    startDrag(e) {
        e.preventDefault();
        this.isDragging = true;
        this.isAnimating = false;
        this.lastMouseX = e.clientX;
        this.mouseVelocity = 0;

        const transform = window.getComputedStyle(this.cardLine).transform;
        if (transform !== "none") {
            const matrix = new DOMMatrix(transform);
            this.position = matrix.m41;
        }

        this.cardLine.style.animation = "none";
        this.cardLine.classList.add("dragging");
        document.body.style.userSelect = "none";
        document.body.style.cursor = "grabbing";
    }

    onDrag(e) {
        if (!this.isDragging) return;
        e.preventDefault();
        const deltaX = e.clientX - this.lastMouseX;
        this.position += deltaX;
        this.mouseVelocity = deltaX * 60;
        this.lastMouseX = e.clientX;
        this.cardLine.style.transform = `translateX(${this.position}px)`;
        this.updateCardClipping();
    }

    endDrag() {
        if (!this.isDragging) return;
        this.isDragging = false;
        this.cardLine.classList.remove("dragging");

        if (Math.abs(this.mouseVelocity) > this.minVelocity) {
            this.velocity = Math.abs(this.mouseVelocity);
            this.direction = this.mouseVelocity > 0 ? 1 : -1;
        } else {
            this.velocity = 120;
        }

        this.isAnimating = true;
        document.body.style.userSelect = "";
        document.body.style.cursor = "";
    }

    animate() {
        const currentTime = performance.now();
        const deltaTime = (currentTime - this.lastTime) / 1000;
        this.lastTime = currentTime;

        if (this.isAnimating && !this.isDragging) {
            if (this.velocity > this.minVelocity) {
                this.velocity *= this.friction;
            } else {
                this.velocity = Math.max(this.minVelocity, this.velocity);
            }
            this.position += this.velocity * this.direction * deltaTime;
            this.updateCardPosition();
        }

        requestAnimationFrame(() => this.animate());
    }

    updateCardPosition() {
        const containerWidth = this.containerWidth;
        const cardLineWidth = this.cardLineWidth;

        if (this.position < -cardLineWidth) {
            this.position = containerWidth;
        } else if (this.position > containerWidth) {
            this.position = -cardLineWidth;
        }

        this.cardLine.style.transform = `translateX(${this.position}px)`;
        this.updateCardClipping();
    }

    onWheel(e) {
        e.preventDefault();
        const scrollSpeed = 20;
        const delta = e.deltaY > 0 ? scrollSpeed : -scrollSpeed;
        this.position += delta;
        this.updateCardPosition();
    }

    generateCode(width, height) {
        const codeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789(){}[]<>;:,._-+=!@#$%^&*|\\\"\\'`~?";
        const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
        const pick = (arr) => arr[randInt(0, arr.length - 1)];

        const header = [
            "// card scanning • digital asset",
            "const SCAN_MODE = true;",
            "const PARTICLES = 2500;",
            "const FADE = 35;",
        ];

        const helpers = [
            "function clamp(n,a,b){return Math.max(a,Math.min(b,n));}",
            "function lerp(a,b,t){return a+(b-a)*t;}",
            "const time=()=>performance.now();",
        ];

        let library = [...header, ...helpers];
        for (let i = 0; i < 20; i++) {
            library.push(`const v${i}=${randInt(1, 99)};`);
        }

        let flow = library.join(" ");
        flow = flow.replace(/\s+/g, " ").trim();
        const totalChars = width * height;

        while (flow.length < totalChars + width) {
            flow += " " + pick(library).replace(/\s+/g, " ").trim();
        }

        let out = "";
        let offset = 0;
        for (let row = 0; row < height; row++) {
            let line = flow.slice(offset, offset + width);
            if (line.length < width) line = line + " ".repeat(width - line.length);
            out += line + (row < height - 1 ? "\n" : "");
            offset += width;
        }
        return out;
    }

    calculateCodeDimensions(cardWidth, cardHeight) {
        const fontSize = 11;
        const lineHeight = 13;
        const charWidth = 6;
        const width = Math.floor(cardWidth / charWidth);
        const height = Math.floor(cardHeight / lineHeight);
        return { width, height, fontSize, lineHeight };
    }

    createCardWrapper(index) {
        const wrapper = document.createElement("div");
        wrapper.className = "card-wrapper";

        const normalCard = document.createElement("div");
        normalCard.className = "card card-normal";

        const cardImages = [
            "https://cdn.prod.website-files.com/68789c86c8bc802d61932544/689f20b55e654d1341fb06f8_4.1.png",
            "https://cdn.prod.website-files.com/68789c86c8bc802d61932544/689f20b5a080a31ee7154b19_1.png",
            "https://cdn.prod.website-files.com/68789c86c8bc802d61932544/689f20b5c1e4919fd69672b8_3.png",
        ];

        const cardImage = document.createElement("img");
        cardImage.className = "card-image";
        cardImage.src = cardImages[index % cardImages.length];
        cardImage.alt = "Digital Card";

        cardImage.onerror = () => {
            const canvas = document.createElement("canvas");
            canvas.width = 400;
            canvas.height = 250;
            const ctx = canvas.getContext("2d");
            const gradient = ctx.createLinearGradient(0, 0, 400, 250);
            gradient.addColorStop(0, "#0052CC");
            gradient.addColorStop(1, "#0038A8");
            ctx.fillStyle = gradient;
            ctx.fillRect(0, 0, 400, 250);
            cardImage.src = canvas.toDataURL();
        };

        normalCard.appendChild(cardImage);

        const asciiCard = document.createElement("div");
        asciiCard.className = "card card-ascii";

        const asciiContent = document.createElement("div");
        asciiContent.className = "ascii-content";

        const { width, height, fontSize, lineHeight } = this.calculateCodeDimensions(400, 250);
        asciiContent.style.fontSize = fontSize + "px";
        asciiContent.style.lineHeight = lineHeight + "px";
        asciiContent.textContent = this.generateCode(width, height);

        asciiCard.appendChild(asciiContent);
        wrapper.appendChild(normalCard);
        wrapper.appendChild(asciiCard);

        return wrapper;
    }

    updateCardClipping() {
        const scannerX = window.innerWidth / 2;
        const scannerWidth = 8;
        const scannerLeft = scannerX - scannerWidth / 2;
        const scannerRight = scannerX + scannerWidth / 2;

        document.querySelectorAll(".card-wrapper").forEach((wrapper) => {
            const rect = wrapper.getBoundingClientRect();
            const cardLeft = rect.left;
            const cardRight = rect.right;
            const cardWidth = rect.width;

            const normalCard = wrapper.querySelector(".card-normal");
            const asciiCard = wrapper.querySelector(".card-ascii");

            if (cardLeft < scannerRight && cardRight > scannerLeft) {
                const scannerIntersectLeft = Math.max(scannerLeft - cardLeft, 0);
                const scannerIntersectRight = Math.min(scannerRight - cardLeft, cardWidth);
                const normalClipRight = (scannerIntersectLeft / cardWidth) * 100;
                const asciiClipLeft = (scannerIntersectRight / cardWidth) * 100;

                normalCard.style.setProperty("--clip-right", `${normalClipRight}%`);
                asciiCard.style.setProperty("--clip-left", `${asciiClipLeft}%`);

                if (!wrapper.hasAttribute("data-scanned") && scannerIntersectLeft > 0) {
                    wrapper.setAttribute("data-scanned", "true");
                    const scanEffect = document.createElement("div");
                    scanEffect.className = "scan-effect";
                    wrapper.appendChild(scanEffect);
                    setTimeout(() => {
                        if (scanEffect.parentNode) scanEffect.parentNode.removeChild(scanEffect);
                    }, 600);
                }
            } else {
                if (cardRight < scannerLeft) {
                    normalCard.style.setProperty("--clip-right", "100%");
                    asciiCard.style.setProperty("--clip-left", "100%");
                } else if (cardLeft > scannerRight) {
                    normalCard.style.setProperty("--clip-right", "0%");
                    asciiCard.style.setProperty("--clip-left", "0%");
                }
                wrapper.removeAttribute("data-scanned");
            }
        });
    }

    updateAsciiContent() {
        document.querySelectorAll(".ascii-content").forEach((content) => {
            if (Math.random() < 0.15) {
                const { width, height } = this.calculateCodeDimensions(400, 250);
                content.textContent = this.generateCode(width, height);
            }
        });
    }

    populateCardLine() {
        this.cardLine.innerHTML = "";
        const cardsCount = 20;
        for (let i = 0; i < cardsCount; i++) {
            const cardWrapper = this.createCardWrapper(i);
            this.cardLine.appendChild(cardWrapper);
        }
    }

    startPeriodicUpdates() {
        setInterval(() => this.updateAsciiContent(), 200);

        const updateClipping = () => {
            this.updateCardClipping();
            requestAnimationFrame(updateClipping);
        };
        updateClipping();
    }
}

// Initialize card stream when page loads
document.addEventListener("DOMContentLoaded", () => {
    const cardStream = new CardStreamController();
});
