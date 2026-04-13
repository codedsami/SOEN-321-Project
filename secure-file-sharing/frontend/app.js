// ============================================================
//  app.js — shared utilities, auth helpers, navbar
// ============================================================

// --- Auth helpers ---
const getToken  = () => localStorage.getItem('sfs_token');
const setToken  = t  => localStorage.setItem('sfs_token', t);
const getEmail  = () => localStorage.getItem('sfs_email');

function setUser(id, email) {
    localStorage.setItem('sfs_uid',   String(id));
    localStorage.setItem('sfs_email', email);
}

function clearAuth() {
    ['sfs_token', 'sfs_uid', 'sfs_email'].forEach(k => localStorage.removeItem(k));
}

function requireAuth() {
    if (!getToken()) window.location.replace('/ui/index.html');
}

// --- Fetch wrapper: attaches JWT header automatically ---
async function apiFetch(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (getToken()) headers['Authorization'] = `Bearer ${getToken()}`;
    return fetch(path, { ...opts, headers });
}

// --- Query string helper ---
const qs = key => new URLSearchParams(window.location.search).get(key);

// --- Formatters ---
function fmtDate(iso) {
    return iso ? new Date(iso).toLocaleString() : '—';
}

function fmtSize(bytes) {
    if (!bytes && bytes !== 0) return '—';
    if (bytes < 1024)    return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// --- Error key helper ---
// Backend uses uppercase 'ERROR' in most routes — this handles both
function getError(data, fallback = 'An error occurred') {
    return data.ERROR || data.error || fallback;
}

// --- Alert helper ---
function showAlert(containerId, msg, type = 'danger') {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${msg}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>`;
}

// --- Navbar injection ---
function injectNav(active) {
    const el = document.getElementById('navbar');
    if (!el) return;
    el.innerHTML = `
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/ui/dashboard.html">SecureShare</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navContent">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navContent">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link ${active === 'dashboard' ? 'active' : ''}"
                           href="/ui/dashboard.html">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link ${active === 'upload' ? 'active' : ''}"
                           href="/ui/upload.html">Upload</a>
                    </li>
                </ul>
                <ul class="navbar-nav ms-auto align-items-center gap-3">
                    <li class="nav-item">
                        <span class="navbar-text text-secondary small">${getEmail() || ''}</span>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" id="logoutBtn">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>`;

    document.getElementById('logoutBtn').addEventListener('click', async e => {
        e.preventDefault();
        await apiFetch('/logout', { method: 'POST' });
        clearAuth();
        window.location.href = '/ui/index.html';
    });
}
