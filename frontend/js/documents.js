// ============================================================
// frontend/js/documents.js — Upload + Documents list
// ============================================================
'use strict';

// ── Shared sidebar HTML (reused in every protected page) ──────
function getSidebarHTML(activePage) {
  const links = [
    ['dashboard','dashboard.html','fa-gauge-high','Dashboard'],
    ['upload','upload.html','fa-cloud-arrow-up','Upload &amp; Scan'],
    ['documents','documents.html','fa-folder-open','My Documents'],
    ['history','history.html','fa-clock-rotate-left','History'],
    ['gateway','privacy-gateway.html','fa-shield-virus','Privacy Gateway'],
    ['reports','reports.html','fa-chart-column','Reports'],
    ['profile','profile.html','fa-user-shield','Profile'],
  ];
  return links.map(([page, href, icon, label]) =>
    `<a href="/${href}" class="nav-link${activePage===page?' active':''}" data-page="${page}">
      <i class="fa-solid ${icon}"></i> ${label}
    </a>`
  ).join('');
}

window.getSidebarHTML = getSidebarHTML;
