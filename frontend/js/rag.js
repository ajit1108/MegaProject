// ============================================================
// frontend/js/rag.js — Privacy-aware document Q&A
// ============================================================
'use strict';

let _conversationId = null;

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initSidebar(); initUserInfo();

  await Promise.all([loadStats(), loadConversations(), loadDocuments()]);

  document.getElementById('rag-ask-btn').addEventListener('click', ask);
  document.getElementById('rag-question').addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) ask();
  });
  document.getElementById('new-convo-btn').addEventListener('click', () => {
    _conversationId = null;
    document.getElementById('rag-convo-label').textContent = 'New conversation';
    document.getElementById('rag-answer-card').classList.add('hidden');
    document.getElementById('rag-citations-card').classList.add('hidden');
    document.getElementById('rag-question').value = '';
    document.getElementById('rag-question').focus();
  });
});

async function loadStats() {
  try {
    const s = await api.ragStats();
    setText('rag-analyses', s.indexed_analyses ?? 0);
    setText('rag-chunks', s.indexed_chunks ?? 0);
    setText('rag-convos', s.conversations ?? 0);
    setText('rag-embedded', s.embedded_chunks ?? 0);
    if ((s.indexing_failures || 0) > 0) {
      toast(`${s.indexing_failures} document(s) failed to index.`, 'warning');
    }
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function loadConversations() {
  const container = document.getElementById('rag-convo-list');
  try {
    const rows = await api.ragConversations();
    if (!rows.length) {
      container.innerHTML = '<p class="text-sm text-muted">No conversations yet.</p>';
      return;
    }
    container.innerHTML = rows.map(c => `
      <div class="flex justify-between items-center mb-8" style="gap:8px">
        <a href="#" class="text-sm" data-convo="${escHtml(c.id)}" style="flex:1;color:var(--text-primary)">
          ${escHtml(c.title || 'Conversation')}
          <span class="text-muted"> · ${c.message_count} msg</span>
        </a>
        <button class="btn-icon btn-ghost" data-delete="${escHtml(c.id)}" title="Delete conversation">
          <i class="fa-solid fa-trash-can"></i>
        </button>
      </div>`).join('');

    container.querySelectorAll('[data-convo]').forEach(el => {
      el.addEventListener('click', e => {
        e.preventDefault();
        openConversation(el.dataset.convo);
      });
    });
    container.querySelectorAll('[data-delete]').forEach(el => {
      el.addEventListener('click', async () => {
        try {
          await api.ragDeleteConversation(el.dataset.delete);
          if (_conversationId === el.dataset.delete) {
            _conversationId = null;
            document.getElementById('rag-convo-label').textContent = 'New conversation';
          }
          toast('Conversation deleted.', 'success');
          await Promise.all([loadStats(), loadConversations()]);
        } catch (err) { toast(err.message, 'error'); }
      });
    });
  } catch (err) {
    container.innerHTML = `<p class="text-sm text-muted">${escHtml(err.message)}</p>`;
  }
}

async function loadDocuments() {
  const container = document.getElementById('rag-doc-list');
  if (!container) return;
  const previously = new Set(selectedDocumentIds());
  try {
    const rows = await api.ragDocuments();
    if (!rows.length) {
      container.innerHTML = '<p class="text-muted">No indexed documents yet. Analyse a document first.</p>';
      return;
    }
    container.innerHTML = rows.map(doc => `
      <label class="flex items-center gap-8 mb-8" style="cursor:pointer">
        <input type="checkbox" value="${escHtml(doc.document_id)}" ${previously.has(String(doc.document_id)) ? 'checked' : ''}>
        <span>${escHtml(doc.document_name || 'document')}
          <span class="text-muted"> · ${doc.chunks} chunks · ${doc.embedded_chunks} embedded</span>
        </span>
      </label>`).join('');
  } catch (err) {
    container.innerHTML = `<p class="text-muted">${escHtml(err.message)}</p>`;
  }
}

function selectedDocumentIds() {
  const box = document.getElementById('rag-doc-list');
  if (!box) return [];
  return [...box.querySelectorAll('input[type="checkbox"]:checked')].map(el => el.value);
}

async function ask() {
  const question = document.getElementById('rag-question').value.trim();
  if (!question) { toast('Please enter a question.', 'warning'); return; }

  const btn = document.getElementById('rag-ask-btn');
  btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Thinking…';
  try {
    const res = await api.ragQuery(question, {
      topK: parseInt(document.getElementById('rag-topk').value, 10),
      conversationId: _conversationId,
      documentIds: selectedDocumentIds(),
    });
    _conversationId = res.conversation_id;
    document.getElementById('rag-convo-label').textContent =
      `Conversation ${_conversationId.slice(-6)}`;
    renderAnswer(res);
    document.getElementById('rag-question').value = '';
    await Promise.all([loadStats(), loadConversations(), loadDocuments()]);
  } catch (err) {
    toast(err.message, 'error');
  }
  btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Ask';
}

async function openConversation(id) {
  try {
    const convo = await api.ragConversation(id);
    _conversationId = convo.id;
    document.getElementById('rag-convo-label').textContent = `Conversation ${convo.id.slice(-6)}`;
    const lastAssistant = [...(convo.messages || [])].reverse()
      .find(m => m.role === 'assistant');
    if (lastAssistant) {
      renderAnswer({
        answer: lastAssistant.content,
        citations: lastAssistant.citations || [],
        used_llm: lastAssistant.used_llm,
        retrieved_chunks: (lastAssistant.citations || []).length,
        warnings: [],
      });
    }
  } catch (err) {
    toast(err.message, 'error');
  }
}

function renderAnswer(res) {
  const card = document.getElementById('rag-answer-card');
  card.classList.remove('hidden');
  document.getElementById('rag-answer').textContent = res.answer || '';
  document.getElementById('rag-answer-meta').textContent =
    res.used_llm ? 'External AI (sanitized context)' : 'Local retrieval';

  const warnEl = document.getElementById('rag-warnings');
  warnEl.innerHTML = (res.warnings || []).map(w =>
    `<div class="alert alert-warning"><i class="fa-solid fa-triangle-exclamation"></i> ${escHtml(w)}</div>`
  ).join('');

  const citCard = document.getElementById('rag-citations-card');
  const tbody = document.getElementById('rag-citations');
  const citations = res.citations || [];
  if (!citations.length) {
    citCard.classList.add('hidden');
    return;
  }
  citCard.classList.remove('hidden');
  tbody.innerHTML = citations.map(c => `
    <tr>
      <td class="fw-600">[${c.index}]</td>
      <td class="text-sm">${escHtml(c.document_name || 'document')}</td>
      <td class="text-sm text-muted">${c.page || 1}</td>
      <td class="text-sm">${escHtml(c.snippet || '')}</td>
    </tr>`).join('');
}

function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }
