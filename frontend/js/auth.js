// ============================================================
// frontend/js/auth.js — Auth helpers used across all pages
// ============================================================
'use strict';

/** Guard: redirect to login if no token. Call at top of every protected page. */
function requireAuth() {
  if (!getToken()) {
    window.location.href = '/login.html';
    return false;
  }
  return true;
}

/** Guard: redirect to dashboard if already logged in. */
function requireGuest() {
  if (getToken()) {
    window.location.href = '/dashboard.html';
    return false;
  }
  return true;
}

/** Populate sidebar user info */
async function initUserInfo() {
  const user = getUser();
  if (!user) {
    try {
      const data = await api.me();
      setUser(data);
      _renderUser(data);
    } catch {
      clearToken();
      window.location.href = '/login.html';
    }
  } else {
    _renderUser(user);
  }
}

function _renderUser(user) {
  const nameEl   = document.getElementById('sidebar-user-name');
  const roleEl   = document.getElementById('sidebar-user-role');
  const avatarEl = document.getElementById('sidebar-user-avatar');
  if (nameEl)   nameEl.textContent   = user.name || 'User';
  if (roleEl)   roleEl.textContent   = capitalize(user.role || 'user');
  if (avatarEl) avatarEl.textContent = (user.name || 'U')[0].toUpperCase();
}

/** Logout */
function logout() {
  clearToken();
  window.location.href = '/login.html';
}

/** Mark active nav link */
function setActiveNav(page) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
}

/** Toast notifications */
function toast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  t.innerHTML = `<span>${icons[type] || 'ℹ'}</span> <span>${escHtml(message)}</span>`;
  container.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(120%)'; t.style.transition = '.3s'; setTimeout(() => t.remove(), 350); }, duration);
}

/** Sidebar mobile toggle */
function initSidebar() {
  const toggle   = document.getElementById('menu-toggle');
  const sidebar  = document.getElementById('sidebar');
  const overlay  = document.getElementById('sidebar-overlay');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay && overlay.classList.toggle('show');
    });
  }
  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar && sidebar.classList.remove('open');
      overlay.classList.remove('show');
    });
  }
  // logout button
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', () => {
    if (confirm('Sign out of your session?')) logout();
  });
}

/** Loading overlay */
function showLoading(msg = 'Processing…') {
  let el = document.getElementById('loading-overlay');
  if (!el) {
    el = document.createElement('div');
    el.id = 'loading-overlay';
    el.className = 'loading-overlay';
    el.innerHTML = `<div class="spinner"></div><p>${escHtml(msg)}</p>`;
    document.body.appendChild(el);
  }
}
function hideLoading() {
  document.getElementById('loading-overlay')?.remove();
}

/** Escape HTML for safe rendering */
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/** Format date */
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-IN', { dateStyle:'medium', timeStyle:'short' });
}

/** Capitalize first letter */
function capitalize(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }

/** Risk badge HTML */
function riskBadge(level) {
  const cls = { 'High Risk':'badge-high','Medium Risk':'badge-medium','Low Risk':'badge-low' }[level] || 'badge-muted';
  return `<span class="badge ${cls}">${escHtml(level)}</span>`;
}

/** Classification badge HTML */
function clsBadge(cls) {
  const map = { 'Restricted':'cls-restricted','Confidential':'cls-confidential','Internal':'cls-internal','Public':'cls-public' };
  return `<span class="badge ${map[cls] || 'badge-muted'}">${escHtml(cls)}</span>`;
}

/** Format file size */
function fmtSize(bytes) {
  if (bytes >= 1048576) return (bytes/1048576).toFixed(1)+' MB';
  if (bytes >= 1024)    return (bytes/1024).toFixed(0)+' KB';
  return bytes+' B';
}

window.requireAuth  = requireAuth;
window.requireGuest = requireGuest;
window.initUserInfo = initUserInfo;
window.logout       = logout;
window.setActiveNav = setActiveNav;
window.toast        = toast;
window.initSidebar  = initSidebar;
window.showLoading  = showLoading;
window.hideLoading  = hideLoading;
window.escHtml      = escHtml;
window.fmtDate      = fmtDate;
window.capitalize   = capitalize;
window.riskBadge    = riskBadge;
window.clsBadge     = clsBadge;
window.fmtSize      = fmtSize;
