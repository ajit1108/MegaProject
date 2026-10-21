// ============================================================
// frontend/js/api.js — Centralised API client
// ============================================================
'use strict';

const API_BASE = '';   // same origin — FastAPI serves both

const api = {
  // ── Auth ─────────────────────────────────────────────────
  async register(name, email, password) {
    return request('POST', '/api/auth/register', { name, email, password });
  },
  async login(email, password) {
    return request('POST', '/api/auth/login', { email, password });
  },
  async me() {
    return request('GET', '/api/auth/me');
  },

  // ── Dashboard ─────────────────────────────────────────────
  async dashboardStats() {
    return request('GET', '/api/dashboard/stats');
  },

  // ── Documents ─────────────────────────────────────────────
  async uploadDocument(file, onProgress) {
    const formData = new FormData();
    formData.append('file', file);
    return uploadRequest('/api/documents/upload', formData, onProgress);
  },
  async listDocuments() {
    return request('GET', '/api/documents');
  },
  async getDocument(id) {
    return request('GET', `/api/documents/${id}`);
  },
  async deleteDocument(id) {
    return request('DELETE', `/api/documents/${id}`);
  },

  // ── Analysis ──────────────────────────────────────────────
  async analyzeDocument(documentId) {
    return request('POST', `/api/analysis/analyze/${documentId}`);
  },
  async getAnalysis(id) {
    return request('GET', `/api/analysis/${id}`);
  },
  async analysisHistory(riskLevel = '', skip = 0, limit = 20) {
    let url = `/api/analysis/history?skip=${skip}&limit=${limit}`;
    if (riskLevel) url += `&risk_level=${encodeURIComponent(riskLevel)}`;
    return request('GET', url);
  },
  async sanitize(analysisId, mode = 'redact') {
    return request('POST', `/api/analysis/${analysisId}/sanitize?mode=${mode}`);
  },
  async downloadSanitized(analysisId) {
    return downloadRequest(`/api/analysis/${analysisId}/sanitized-download`);
  },
  async deleteAnalysis(id) {
    return request('DELETE', `/api/analysis/${id}`);
  },

  // ── Privacy Gateway ───────────────────────────────────────
  async gatewayInspect(text, allowForward = false) {
    return request('POST', '/api/privacy-gateway/inspect', { text, allow_forward: allowForward });
  },

  // ── Reports ───────────────────────────────────────────────
  async reportSummary() {
    return request('GET', '/api/reports/summary');
  },
  async exportCsv() {
    return downloadRequest('/api/reports/export');
  },

  // ── Health ────────────────────────────────────────────────
  async health() {
    return request('GET', '/api/health');
  },
};

// ── Core HTTP helpers ─────────────────────────────────────────
async function request(method, path, body = null) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const opts = { method, headers };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);

  try {
    const res  = await fetch(API_BASE + path, opts);
    const data = await res.json().catch(() => ({ detail: 'Invalid server response.' }));

    if (!res.ok) {
      if (res.status === 401 && !path.startsWith('/api/auth/login')) {
        clearToken();
        if (!window.location.pathname.endsWith('login.html') && !window.location.pathname.endsWith('register.html')) {
          window.location.href = '/login.html?expired=1';
          return;
        }
      }
      const msg = data.detail || data.message || `HTTP ${res.status}`;
      throw new ApiError(msg, res.status, data);
    }
    return data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError('Network error. Is the server running?', 0);
  }
}

async function uploadRequest(path, formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const token = getToken();
    xhr.open('POST', API_BASE + path);
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);

    if (onProgress) {
      xhr.upload.addEventListener('progress', e => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      });
    }

    xhr.onload = () => {
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(data);
        } else {
          if (xhr.status === 401) {
            clearToken();
            if (!window.location.pathname.endsWith('login.html')) {
              window.location.href = '/login.html?expired=1';
              return;
            }
          }
          reject(new ApiError(data.detail || `HTTP ${xhr.status}`, xhr.status, data));
        }
      } catch {
        reject(new ApiError('Invalid response from server.', xhr.status));
      }
    };
    xhr.onerror = () => reject(new ApiError('Network error.', 0));
    xhr.send(formData);
  });
}

async function downloadRequest(path) {
  const token = getToken();
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_BASE + path, { headers });
  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      if (!window.location.pathname.endsWith('login.html')) {
        window.location.href = '/login.html?expired=1';
        return;
      }
    }
    const data = await res.json().catch(() => ({}));
    throw new ApiError(data.detail || `HTTP ${res.status}`, res.status);
  }
  const blob     = await res.blob();
  const cd       = res.headers.get('Content-Disposition') || '';
  const match    = cd.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : 'download.txt';
  const url      = URL.createObjectURL(blob);
  const a        = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

class ApiError extends Error {
  constructor(message, status = 0, data = {}) {
    super(message);
    this.status = status;
    this.data   = data;
  }
}

// ── Token helpers ─────────────────────────────────────────────
function isTokenExpired(token) {
  if (!token) return true;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return true;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp) return false;
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
}

function getToken() {
  const t = localStorage.getItem('sdd_token');
  if (!t) return null;
  if (isTokenExpired(t)) {
    clearToken();
    return null;
  }
  return t;
}

function setToken(t) { localStorage.setItem('sdd_token', t); }
function clearToken(){ localStorage.removeItem('sdd_token'); localStorage.removeItem('sdd_user'); }
function getUser()   {
  try { return JSON.parse(localStorage.getItem('sdd_user') || 'null'); } catch { return null; }
}
function setUser(u)  { localStorage.setItem('sdd_user', JSON.stringify(u)); }

window.api            = api;
window.getToken       = getToken;
window.setToken       = setToken;
window.clearToken     = clearToken;
window.getUser        = getUser;
window.setUser        = setUser;
window.isTokenExpired = isTokenExpired;
window.ApiError       = ApiError;
