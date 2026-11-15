// ============================================================
// frontend/js/reports.js
// ============================================================
'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initSidebar(); initUserInfo();
  await loadReports();

  document.getElementById('export-csv-btn').addEventListener('click', async () => {
    try { await api.exportCsv(); toast('CSV download started.','success'); }
    catch(err){ toast(err.message,'error'); }
  });
});

async function loadReports() {
  try {
    const [data, activity] = await Promise.all([
      api.reportSummary(),
      api.analyticsSummary().catch(() => ({})),
    ]);

    setText('r-total-analyses', data.total_analyses  ?? 0);
    setText('r-total-det',      data.total_detections ?? 0);
    setText('r-high',   (data.risk_distribution||{})['High Risk']   ?? 0);
    setText('r-medium', (data.risk_distribution||{})['Medium Risk'] ?? 0);
    setText('r-low',    (data.risk_distribution||{})['Low Risk']    ?? 0);

    // Activity stats come from real audit/analysis rows.
    setText('r-sanitized', activity.sanitized_documents ?? 0);
    setText('r-gateway',   activity.gateway_inspections ?? 0);
    setText('r-blocked',   activity.gateway_blocked ?? 0);
    setText('r-rag',       activity.rag_queries ?? 0);

    renderDistribution('cat-breakdown', activity.category_distribution || {}, '#5b8def');
    renderDistribution('method-breakdown', activity.method_distribution || {}, '#a06cd5');

    // Classification breakdown bars
    const cd    = data.class_distribution || {};
    const total = Object.values(cd).reduce((s,v)=>s+v,0) || 1;
    const order = ['Restricted','Confidential','Internal','Public'];
    document.getElementById('cls-breakdown').innerHTML = order.map(c => {
      const cnt = cd[c] || 0;
      const pct = Math.round((cnt/total)*100);
      const color = {'Restricted':'#ff4757','Confidential':'#ff6b35','Internal':'#ffa502','Public':'#2ed573'}[c]||'#8a93b8';
      return `<div class="flex justify-between items-center mb-8">
        ${clsBadge(c)}<span class="text-sm fw-600">${cnt} (${pct}%)</span>
      </div>
      <div class="progress mb-16"><div class="progress-bar" style="width:${pct}%;background:${color}"></div></div>`;
    }).join('');

    // Entity types table
    const tbody = document.getElementById('entity-tbody');
    const top   = data.top_entity_types || [];
    tbody.innerHTML = top.length
      ? top.map(e=>`<tr><td><span class="badge badge-muted text-mono">${escHtml(e.entity_type)}</span></td>
                        <td class="fw-600">${e.count}</td></tr>`).join('')
      : '<tr><td colspan="2" style="text-align:center;padding:20px;color:var(--text-muted)">No data yet.</td></tr>';

    // Charts
    if (typeof Chart !== 'undefined') {
      Chart.defaults.color       = '#8a93b8';
      Chart.defaults.borderColor = '#2a3150';
      Chart.defaults.font.family = "'Inter',sans-serif";

      const clsCtx = document.getElementById('cls-pie');
      if (clsCtx) {
        new Chart(clsCtx, {
          type:'doughnut',
          data:{ labels:order, datasets:[{ data:order.map(c=>cd[c]||0),
            backgroundColor:['#ff4757','#ff6b35','#ffa502','#2ed573'], borderWidth:0, hoverOffset:6 }]},
          options:{ cutout:'65%', plugins:{ legend:{ position:'bottom', labels:{ padding:12, boxWidth:12 }}},
            responsive:true, maintainAspectRatio:false }
        });
      }
      const rd = data.risk_distribution || {};
      const riskCtx = document.getElementById('risk-bar-chart');
      if (riskCtx) {
        new Chart(riskCtx, {
          type:'bar',
          data:{ labels:['High Risk','Medium Risk','Low Risk'],
            datasets:[{ label:'Documents', data:[rd['High Risk']||0,rd['Medium Risk']||0,rd['Low Risk']||0],
              backgroundColor:['#ff4757','#ffa502','#2ed573'], borderRadius:6, borderSkipped:false }]},
          options:{ plugins:{ legend:{ display:false }},
            scales:{ y:{ grid:{ color:'#2a3150' }, ticks:{ stepSize:1 }}, x:{ grid:{ display:false }}},
            responsive:true, maintainAspectRatio:false }
        });
      }
    }
  } catch(err){ toast(err.message,'error'); }
}

function renderDistribution(elId, dist, color) {
  const el = document.getElementById(elId);
  if (!el) return;
  const entries = Object.entries(dist).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    el.innerHTML = '<p class="text-sm text-muted">No data yet.</p>';
    return;
  }
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  el.innerHTML = entries.map(([label, count]) => {
    const pct = Math.round((count / total) * 100);
    return `<div class="flex justify-between items-center mb-8">
      <span class="text-sm">${escHtml(label)}</span>
      <span class="text-sm fw-600">${count} (${pct}%)</span>
    </div>
    <div class="progress mb-16"><div class="progress-bar" style="width:${pct}%;background:${color}"></div></div>`;
  }).join('');
}

function setText(id,v){ const e=document.getElementById(id); if(e) e.textContent=v; }
