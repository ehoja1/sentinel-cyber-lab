'use strict';

const state = {
  filename: '',
  sourceText: '',
  events: [],
  alerts: [],
  filesAnalyzed: 0,
  lastResults: null
};

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.log', '.txt', '.csv'];
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const sampleLog = `2026-10-20T08:10:02Z INFO service=auth message="Service started successfully"
2026-10-20T08:11:12Z INFO user=joao message="Login successful"
2026-10-20T08:12:05Z WARN ip=192.0.2.45 message="Failed login attempt for user admin"
2026-10-20T08:12:08Z WARN ip=192.0.2.45 message="Failed login attempt for user admin"
2026-10-20T08:12:11Z ERROR ip=192.0.2.45 message="Authentication failed: invalid password"
2026-10-20T08:13:20Z INFO service=api message="Request completed"
2026-10-20T08:14:01Z CRITICAL service=auth message="Account locked after repeated failed login attempts"
2026-10-20T08:15:40Z ERROR service=database message="Connection timeout"
2026-10-20T08:16:03Z INFO user=joao message="Logout successful"`;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}

function switchView(viewName) {
  const labels = { overview: 'Visão geral', analyzer: 'Analisador de logs', alerts: 'Alertas' };
  if (!labels[viewName]) return;
  $$('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${viewName}`));
  $$('.nav-link').forEach((link) => link.classList.toggle('active', link.dataset.view === viewName));
  $('#breadcrumb-current').textContent = labels[viewName];
  $('#sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function classifyLine(line) {
  const matches = [];
  const failedLogin = /failed\s+(login|log-in|authentication)|authentication\s+failed|invalid\s+password|login\s+failure|falha\s+de\s+login|autentica(?:ção|cao)\s+falhou/i.test(line);
  const critical = /\bcritical\b|\bemergency\b|\bpanic\b|\bsevere\b|cr[ií]tico|emerg[eê]ncia/i.test(line);
  const serviceError = /\b(error|exception|fatal)\b|\btimeout\b|connection refused|service unavailable|erro|exce[cç][aã]o/i.test(line);
  const suspiciousCommand = /\b(permission denied|unauthorized access|privilege escalation|malware detected|rootkit|ransomware)\b/i.test(line);

  if (failedLogin) matches.push({ name: 'Falha de autenticação', severity: 'Média', description: 'A linha contém um padrão associado a falha de autenticação.' });
  if (critical || suspiciousCommand) matches.push({ name: suspiciousCommand ? 'Indicador de segurança' : 'Evento crítico', severity: 'Alta', description: 'A linha contém palavras-chave que justificam revisão prioritária.' });
  if (serviceError && !critical) matches.push({ name: 'Erro de serviço', severity: 'Baixa', description: 'A linha contém um erro ou falha de serviço.' });
  return matches;
}

function parseLog(text) {
  return text.split(/\r?\n/).map((content, index) => ({
    line: index + 1,
    content: content.trim()
  })).filter((item) => item.content.length > 0);
}

function analyzeText(text, filename) {
  const lines = parseLog(text);
  const detections = [];
  for (const item of lines) {
    for (const rule of classifyLine(item.content)) {
      detections.push({
        line: item.line,
        name: rule.name,
        severity: rule.severity,
        description: rule.description,
        content: item.content,
        filename
      });
    }
  }
  state.events = detections;
  state.alerts = detections;
  state.filesAnalyzed += 1;
  state.lastResults = { filename, analyzedAt: new Date().toISOString(), lineCount: lines.length, detections };
  renderAll();
  $('#analysis-results').hidden = false;
  $('#result-lines').textContent = String(lines.length);
  $('#result-alerts').textContent = String(detections.length);
  $('#result-high').textContent = String(detections.filter((item) => item.severity === 'Alta').length);
  $('#analysis-summary').textContent = `${filename} · análise local concluída`;
  renderAnalysisTable(detections);
  showToast(`Análise concluída: ${lines.length} linhas verificadas.`);
}

function severityClass(severity) {
  return severity.toLocaleLowerCase('pt-BR').replace('é', 'e');
}

function severityBadge(severity) {
  return `<span class="severity ${severityClass(severity)}">${escapeHtml(severity)}</span>`;
}

function renderRecentEvents() {
  const tbody = $('#recent-events');
  const rows = state.events.slice(-6).reverse();
  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">Nenhum evento analisado ainda. Importe um log para começar.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map((event) => `<tr>
    <td><span class="event-name">${escapeHtml(event.name)}</span></td>
    <td>${escapeHtml(event.filename)}</td>
    <td>${severityBadge(event.severity)}</td>
    <td>${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</td>
  </tr>`).join('');
}

function renderAnalysisTable(events) {
  const tbody = $('#analysis-table');
  if (!events.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">Nenhuma regra correspondeu às linhas analisadas.</td></tr>';
    return;
  }
  tbody.innerHTML = events.map((event) => `<tr>
    <td>${event.line}</td><td><span class="event-name">${escapeHtml(event.name)}</span><br><span class="event-detail">${escapeHtml(event.description)}</span></td>
    <td>${severityBadge(event.severity)}</td><td><span class="event-detail">${escapeHtml(event.content)}</span></td>
  </tr>`).join('');
}

function renderAlertsTable() {
  const tbody = $('#alerts-table');
  const query = $('#alert-search').value.trim().toLocaleLowerCase('pt-BR');
  const severity = $('#severity-filter').value;
  const filtered = state.alerts.filter((event) => {
    const matchesQuery = `${event.name} ${event.content} ${event.filename}`.toLocaleLowerCase('pt-BR').includes(query);
    return matchesQuery && (severity === 'all' || event.severity === severity);
  });
  if (!filtered.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">Nenhum alerta corresponde aos filtros atuais.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map((event) => `<tr>
    <td>${event.line}</td><td><span class="event-name">${escapeHtml(event.name)}</span></td>
    <td>${severityBadge(event.severity)}</td><td><span class="event-detail">${escapeHtml(event.content)}</span></td>
  </tr>`).join('');
}

function renderAll() {
  $('#metric-events').textContent = String(state.lastResults?.lineCount ?? 0);
  $('#metric-alerts').textContent = String(state.alerts.length);
  $('#metric-high').textContent = String(state.alerts.filter((event) => event.severity === 'Alta').length);
  $('#metric-files').textContent = String(state.filesAnalyzed);
  $('#nav-alert-count').textContent = String(state.alerts.length);
  renderRecentEvents();
  renderAlertsTable();
}

async function handleFile(file) {
  if (!file) return;
  const extension = `.${file.name.split('.').pop().toLowerCase()}`;
  if (!ALLOWED_EXTENSIONS.includes(extension)) {
    showToast('Formato não permitido. Use .log, .txt ou .csv.');
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    showToast('Arquivo maior que 2 MB. Escolha um arquivo menor.');
    return;
  }
  try {
    state.sourceText = await file.text();
    state.filename = file.name;
    $('#file-status').textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB · pronto para analisar`;
    $('#analyze-button').disabled = false;
    $('#analysis-results').hidden = true;
  } catch (error) {
    console.error('Falha ao ler arquivo:', error);
    showToast('Não foi possível ler o arquivo selecionado.');
  }
}

function exportResults() {
  if (!state.lastResults) {
    showToast('Faça uma análise antes de exportar.');
    return;
  }
  const blob = new Blob([JSON.stringify(state.lastResults, null, 2)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'sentinel-analysis.json';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast('Relatório JSON exportado.');
}

$$('.nav-link, [data-view]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
$('#go-analyzer').addEventListener('click', () => switchView('analyzer'));
$('#go-analyzer-bottom').addEventListener('click', () => switchView('analyzer'));
$('#mobile-menu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
$('#log-file').addEventListener('change', (event) => handleFile(event.target.files[0]));
$('#load-sample').addEventListener('click', () => {
  state.filename = 'security-sample.log';
  state.sourceText = sampleLog;
  $('#file-status').textContent = 'security-sample.log · exemplo fictício carregado · pronto para analisar';
  $('#analyze-button').disabled = false;
  $('#analysis-results').hidden = true;
  showToast('Exemplo carregado. Clique em “Analisar arquivo”.');
});
$('#analyze-button').addEventListener('click', () => {
  if (!state.sourceText) return;
  analyzeText(state.sourceText, state.filename || 'arquivo.log');
});
$('#export-results').addEventListener('click', exportResults);
$('#alert-search').addEventListener('input', renderAlertsTable);
$('#severity-filter').addEventListener('change', renderAlertsTable);
$('#clear-alerts').addEventListener('click', () => {
  state.events = [];
  state.alerts = [];
  state.filesAnalyzed = 0;
  state.lastResults = null;
  renderAll();
  $('#analysis-results').hidden = true;
  showToast('Os resultados desta sessão foram limpos.');
});

const dropZone = $('#drop-zone');
['dragenter', 'dragover'].forEach((name) => dropZone.addEventListener(name, (event) => {
  event.preventDefault();
  dropZone.classList.add('dragging');
}));
['dragleave', 'drop'].forEach((name) => dropZone.addEventListener(name, (event) => {
  event.preventDefault();
  dropZone.classList.remove('dragging');
}));
dropZone.addEventListener('drop', (event) => handleFile(event.dataTransfer.files[0]));

renderAll();
