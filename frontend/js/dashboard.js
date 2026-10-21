// ============================================================
// frontend/js/dashboard.js
// ============================================================
'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initSidebar();
  setActiveNav('dashboard');
  await initUserInfo();
  await loadDashboard();
});

async function loadDashboard() {
  try {
    showLoading('Loading dashboard…');
    const stats = await api.dashboardStats();
    hideLoading();
    renderStats(stats);
    renderRecentTable(stats.recent_analyses || []);
    renderCharts(stats);
  } catch (err) {
    hideLoading();
    toast(err.message, 'error');
  }
}

function renderStats(s) {
  setText('stat-total-docs',    s.total_documents     ?? 0);
  setText('stat-total-analyses',s.total_analyses      ?? 0);
  setText('stat-total-det',     s.total_detections    ?? 0);
  setText('stat-high',          s.high_risk           ?? 0);
  setText('stat-medium',        s.medium_risk         ?? 0);
  setText('stat-low',           s.low_risk            ?? 0);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function renderRecentTable(analyses) {
  const tbody = document.getElementById('recent-tbody');
  if (!tbody) return;
  if (!analyses.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">
      No analyses yet. <a href="/upload.html">Upload a document</a> to get started.
    </td></tr>`;
    return;
  }
  tbody.innerHTML = analyses.map(a => `
    <tr>
      <td><span class="fw-600">${escHtml(a.document_name)}</span></td>
      <td>${fmtDate(a.created_at)}</td>
      <td><span class="badge badge-muted">${a.total_detections}</span></td>
      <td>${riskBadge(a.risk_level)}</td>
      <td>
        <a href="/analysis.html?id=${a.id}" class="btn btn-outline btn-sm">
          <i class="fa-solid fa-eye"></i> View
        </a>
      </td>
    </tr>`).join('');
}

function renderCharts(stats) {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color       = '#8a93b8';
  Chart.defaults.borderColor = '#2a3150';
  Chart.defaults.font.family = "'Inter',sans-serif";

  // Risk distribution donut
  const riskCtx = document.getElementById('risk-chart');
  if (riskCtx) {
    const rd = stats.risk_distribution || {};
    new Chart(riskCtx, {
      type: 'doughnut',
      data: {
        labels: ['High Risk','Medium Risk','Low Risk'],
        datasets: [{ data: [rd['High Risk']||0, rd['Medium Risk']||0, rd['Low Risk']||0],
          backgroundColor:['#ff4757','#ffa502','#2ed573'], borderWidth:0, hoverOffset:6 }]
      },
      options: { cutout:'68%', plugins:{ legend:{ position:'bottom', labels:{ padding:14, boxWidth:12 }}},
        responsive:true, maintainAspectRatio:false }
    });
  }

  // Classification bar chart
  const clsCtx = document.getElementById('cls-chart');
  if (clsCtx) {
    const cd = stats.class_distribution || {};
    const labels = Object.keys(cd); const values = Object.values(cd);
    new Chart(clsCtx, {
      type: 'bar',
      data: { labels, datasets:[{ label:'Detections', data:values,
        backgroundColor:['#2ed573','#ffa502','#ff6b35','#ff4757'], borderRadius:6, borderSkipped:false }]},
      options: { plugins:{ legend:{ display:false }},
        scales:{ y:{ grid:{ color:'#2a3150' }, ticks:{ stepSize:1 }}, x:{ grid:{ display:false }}},
        responsive:true, maintainAspectRatio:false }
    });
  }
}
