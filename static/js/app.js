/* ============================================================
   VigiScan Enterprise Platform — Shared JavaScript
   ============================================================ */

// ================= NOTIFICATIONS =================
function loadNotifications() {
    fetch("/api/notifications")
        .then(res => res.json())
        .then(data => {
            const badge = document.getElementById("notifBadge");
            const list = document.getElementById("notifList");
            const unread = data.filter(n => !n.is_read).length;

            if (badge) {
                if (unread > 0) {
                    badge.innerText = unread;
                    badge.style.display = "block";
                } else {
                    badge.style.display = "none";
                }
            }

            if (list) {
                if (data.length === 0) {
                    list.innerHTML = `<p style="font-size:0.8rem; color:var(--text-secondary); padding:1rem;">No notifications</p>`;
                } else {
                    list.innerHTML = data.map(n => `
                        <div style="padding:0.75rem; border-bottom:1px solid rgba(0,0,0,0.05); cursor:pointer; opacity: ${n.is_read ? 0.6 : 1}" onclick="markRead(${n.id})">
                            <div style="font-size:0.7rem; color:var(--accent-primary); text-transform:uppercase; font-weight:bold;">${n.type}</div>
                            <div style="font-size:0.85rem; margin-top:0.25rem;">${n.message}</div>
                            <div style="font-size:0.6rem; color:var(--text-secondary); margin-top:0.25rem;">${n.date}</div>
                        </div>
                    `).join('') + `<button onclick="clearNotifs()" style="width:100%; padding:0.5rem; background:none; border:none; color:var(--text-secondary); font-size:0.7rem; cursor:pointer;">Mark all as read</button>`;
                }
            }
        });
}

function markRead(id) {
    fetch(`/api/notifications/read/${id}`, { method: 'POST' })
        .then(() => loadNotifications());
}

function clearNotifs() {
    fetch('/api/notifications/clear', { method: 'POST' })
        .then(() => loadNotifications());
}

// ================= LANGUAGE =================
const LANG_LABELS = {
    'en': 'English (US)',
    'uk_en': 'English (UK)',
    'es': 'Español',
    'fr': 'Français',
    'zh-CN': '简体中文'
};

function setLang(lang) {
    document.cookie = `googtrans=/en/${lang}; path=/`;
    const gtSelect = document.querySelector(".goog-te-combo");
    if (gtSelect) {
        gtSelect.value = lang;
        gtSelect.dispatchEvent(new Event("change"));
    } else {
        window.location.reload();
    }
    // Update button label
    const btnText = document.getElementById("langBtnText");
    if (btnText && LANG_LABELS[lang]) {
        btnText.innerText = LANG_LABELS[lang];
    }
    fetch("/api/save_language", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: lang })
    }).catch(err => console.error("Error saving language preference", err));
}

function applyLang(lang) {
    if (!lang) return;
    document.cookie = `googtrans=/en/${lang}; path=/`;
    const gtSelect = document.querySelector(".goog-te-combo");
    if (gtSelect) {
        gtSelect.value = lang;
        gtSelect.dispatchEvent(new Event("change"));
    }
    // Update button label
    const btnText = document.getElementById("langBtnText");
    if (btnText && LANG_LABELS[lang]) {
        btnText.innerText = LANG_LABELS[lang];
    }
}

// ================= THEME =================
function setTheme(mode) {
    const body = document.documentElement;
    body.setAttribute("data-theme", mode);
    const icon = document.getElementById("themeIcon");
    if (icon) {
        icon.className = mode === 'light' ? "fas fa-sun" : "fas fa-moon";
    }
    localStorage.setItem("theme", mode);
}

function toggleTheme() {
    const body = document.documentElement;
    const current = body.getAttribute("data-theme") || "light";
    setTheme(current === "light" ? "dark" : "light");
}

// ================= UTILITIES =================
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(iso) {
    if (!iso) return 'N/A';
    try {
        return new Date(iso).toLocaleString();
    } catch (e) {
        return iso;
    }
}

function riskBadge(risk) {
    const r = (risk || 'Info').toLowerCase();
    return `<span class="risk-badge risk-${r}">${risk || 'Info'}</span>`;
}

function statusBadge(status) {
    const s = (status || 'Open').toLowerCase().replace(/\s+/g, '-');
    return `<span class="status-badge status-${s}">${status || 'Open'}</span>`;
}

// ================= INIT =================
document.addEventListener("DOMContentLoaded", () => {
    // Apply saved theme
    const savedTheme = localStorage.getItem("theme") || "light";
    setTheme(savedTheme);

    // Apply saved theme name
    const savedThemeName = localStorage.getItem("theme-name") || "default";
    document.documentElement.setAttribute("data-theme-name", savedThemeName);

    // Apply saved language
    const savedLang = document.body.getAttribute("data-user-lang") || localStorage.getItem("language") || "en";
    applyLang(savedLang);

    // Load notifications
    loadNotifications();
    setInterval(loadNotifications, 30000);

    // Escape key closes modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => {
                if (modal.style.display === 'block') {
                    modal.style.display = 'none';
                }
            });
        }
    });
});