// ============================================================
// frontend/js/analysis.js
// ============================================================
'use strict';

let _analysis = null;

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initSidebar(); initUserInfo();

  const params = new URLSearchParams(location.search);
  const id     = params.get('id');
  if (!id) { toast('No analysis ID provided.','error'); return; }

  try {
    _analysis = await api.getAnalysis(id);
    renderAnalysis(_analysis);
    document.getElementById('loading-section').classList.add('hidden');
    document.getElementById('content-section').classList.remove('hidden');
  } catch (err) {
    toast(err.message,'error');
  }

  // Filter detections
  ['filter-class','filter-method'].forEach(fid => {
    document.getElementById(fid)?.addEventListener('change', () => {
      if (_analysis) renderDetections(_analysis.detections);
    });
  });

  // Sanitize
  document.getElementById('sanitize-btn')?.addEventListener('click', async () => {
    const mode = document.getElementById('san-mode').value;
    const btn  = document.getElementById('sanitize-btn');
    btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing…';
    try {
      const res = await api.sanitize(id, mode);
      renderSanitization(res, _analysis);
      toast('Sanitization complete!','success');
    } catch(err){ toast(err.message,'error'); }
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Sanitize Document';
  });

  document.getElementById('download-btn')?.addEventListener('click', async () => {
    try { await api.downloadSanitized(id); toast('Download started.','success'); }
    catch(err){ toast(err.message,'error'); }
  });
});

// ── Render ───────────────────────────────────────────────────
function renderAnalysis(a) {
  document.title = `Analysis — ${a.document_name}`;
  setText('doc-name', a.document_name);
  setText('doc-meta', `Scanned on ${fmtDate(a.created_at)} · ${a.total_detections} detections`);

  // Risk panel
  const score = a.risk_score || 0;
  const level = a.risk_level || 'Low Risk';
  const cls   = riskClass(level);
  document.getElementById('risk-panel').className = `risk-panel ${cls}`;
  setText('risk-number', score.toFixed(1));
  setText('risk-level-txt', level);
  setText('det-count-txt', `${a.total_detections} detection${a.total_detections !== 1 ? 's' : ''}`);
  document.getElementById('risk-bar').style.width = Math.min(score,100)+'%';
  setText('risk-explanation', a.risk_explanation || '');

  // Class summary
  const cs = a.class_summary || {};
  const total = Object.values(cs).reduce((s,v)=>s+v,0) || 1;
  const summaryEl = document.getElementById('class-summary');
  const order = ['Restricted','Confidential','Internal','Public'];
  summaryEl.innerHTML = order.map(c => {
    const cnt = cs[c] || 0;
    const pct = Math.round((cnt/total)*100);
    return `<div class="flex justify-between items-center mb-8">
      <div class="flex gap-8 items-center">
        ${clsBadge(c)} <span class="text-sm">${escHtml(c)}</span>
      </div>
      <span class="text-sm fw-600">${cnt}</span>
    </div>
    <div class="progress mb-16"><div class="progress-bar" style="width:${pct}%;background:${classColor(c)}"></div></div>`;
  }).join('');

  // OCR warning
  if (a.used_ocr) {
    document.getElementById('ocr-warn').classList.remove('hidden');
    if (a.extraction_warnings?.length) {
      document.getElementById('extraction-warnings').innerHTML =
        a.extraction_warnings.map(w=>`<div>${escHtml(w)}</div>`).join('');
    }
  }

  // Text preview with highlights
  renderTextPreview(a.extracted_text_preview || '', a.detections || []);

  // Detections table
  renderDetections(a.detections || []);
}

function renderTextPreview(text, detections) {
  const el = document.getElementById('text-preview');
  if (!text) { el.textContent = 'No text preview available.'; return; }

  // Build highlighted HTML safely
  const sorted = [...detections].sort((a,b) => a.start - b.start);
  let result = ''; let cursor = 0;
  const safeText = text; // preview from server (max 500 chars)

  for (const det of sorted) {
    if (det.start >= safeText.length) break;
    const start = Math.min(det.start, safeText.length);
    const end   = Math.min(det.end,   safeText.length);
    if (start > cursor) result += escHtml(safeText.slice(cursor, start));
    const hlClass = classToHl(det.privacy_class);
    result += `<mark class="${hlClass}" title="${escHtml(det.entity_type)} — ${escHtml(det.privacy_class)}">${escHtml(safeText.slice(start, end))}</mark>`;
    cursor = end;
  }
  if (cursor < safeText.length) result += escHtml(safeText.slice(cursor));
  el.innerHTML = result + (text.length >= 500 ? '<span class="text-muted"> … (truncated)</span>' : '');
}

function renderDetections(detections) {
  const tbody  = document.getElementById('det-tbody');
  const cls    = document.getElementById('filter-class')?.value || '';
  const method = document.getElementById('filter-method')?.value || '';

  const filtered = detections.filter(d =>
    (!cls    || d.privacy_class     === cls) &&
    (!method || d.detection_method  === method)
  );

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted)">
      ${detections.length ? 'No results match the selected filters.' : 'No sensitive entities detected.'}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(d => `
    <tr>
      <td><span class="badge badge-muted text-mono">${escHtml(d.entity_type)}</span></td>
      <td class="text-mono text-sm">${escHtml(d.matched_value || '***')}</td>
      <td>${clsBadge(d.privacy_class)}</td>
      <td><span class="badge badge-primary">${escHtml(d.detection_method)}</span></td>
      <td><span class="text-sm">${((d.confidence||0)*100).toFixed(0)}%</span></td>
      <td class="text-sm text-muted">${escHtml(d.classification_reason||'')}</td>
    </tr>`).join('');
}

function renderSanitization(res, a) {
  const section = document.getElementById('san-result');
  const alert   = document.getElementById('san-alert');
  const warn    = document.getElementById('san-warning');
  section.classList.remove('hidden');
  alert.innerHTML = `<i class="fa-solid fa-circle-check"></i> Sanitization complete.
    <strong>${res.remaining_detections}</strong> pattern(s) may still be detectable in the output.`;
  document.getElementById('orig-preview').textContent = res.original_text_preview || '';
  document.getElementById('san-preview').textContent  = (res.sanitized_text||'').slice(0,800);
  if (res.warnings?.length) {
    warn.classList.remove('hidden');
    warn.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${res.warnings.map(escHtml).join('<br>')}`;
  }
}

// ── Helpers ──────────────────────────────────────────────────
function setText(id, val) { const e=document.getElementById(id); if(e) e.textContent=val; }
function riskClass(l) { return {'High Risk':'risk-high','Medium Risk':'risk-medium','Low Risk':'risk-low'}[l]||'risk-low'; }
function classColor(c) { return {'Restricted':'#ff4757','Confidential':'#ff6b35','Internal':'#ffa502','Public':'#2ed573'}[c]||'#8a93b8'; }
function classToHl(c)  { return {'Restricted':'hl-restricted','Confidential':'hl-confidential','Internal':'hl-internal','Public':'hl-public'}[c]||'hl-internal'; }
