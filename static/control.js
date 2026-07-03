const $ = (id) => document.getElementById(id);

let selectedJobId = null;
let lastLogSeq = 0;
let lastJobsKey = '';
let lastDetailKey = '';
let polling = false;
let saveConfigTimer = null;
let applyingPrefs = false;

const configKeys = [
  'jobName', 'outlookAccounts',
  'workspaceId', 'emailMode', 'countPerAccount', 'concurrency', 'attempts', 'aliasPrefix',
  'otpMaxRetries', 'otpPollInterval', 'workspaceJoinTimeout', 'registerProxy', 'sub2apiUrl',
  'sub2apiBearer', 'sub2apiUpload', 'purgeAfterUpload'
];

const statusText = {
  queued: '排队',
  running: '运行中',
  completed: '完成',
  completed_with_errors: '完成/有失败',
  failed: '失败',
  cancelling: '取消中',
  cancelled: '已取消',
  interrupted: '已中断'
};

const artifactNames = {
  summary: 'summary',
  results_full: 'results',
  access_tokens: 'AT',
  sub2api_product: 'sub2api JSON',
  sub2api_receipt: 'receipt',
  sub2api_failed_receipt: 'failed receipt',
  run_log: 'log'
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function shortId(id) {
  const text = String(id || '');
  return text.length > 10 ? `${text.slice(0, 6)}…${text.slice(-4)}` : text;
}

function relTime(iso) {
  if (!iso) return '-';
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return iso;
  const diff = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (diff < 10) return '刚刚';
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.round(diff / 60)}m`;
  return `${Math.round(diff / 3600)}h`;
}

function headers(json = true) {
  const out = {};
  if (json) out['Content-Type'] = 'application/json';
  const key = $('apiKey').value.trim();
  if (key) out['X-API-Key'] = key;
  return out;
}

function setError(text) {
  const el = $('formError');
  if (!text) {
    el.classList.add('hidden');
    el.textContent = '';
    return;
  }
  el.textContent = text;
  el.classList.remove('hidden');
}

function badge(status) {
  const safe = escapeHtml(status || '-');
  const cls = `badge-${String(status || 'queued').replaceAll(' ', '_')}`;
  return `<span class="badge ${cls}">${escapeHtml(statusText[status] || safe)}</span>`;
}

function collectPrefs() {
  const config = {};
  configKeys.forEach((id) => {
    const el = $(id);
    if (!el) return;
    config[id] = el.type === 'checkbox' ? el.checked : el.value;
  });
  return config;
}

function applyPrefs(config) {
  applyingPrefs = true;
  Object.entries(config || {}).forEach(([id, value]) => {
    const el = $(id);
    if (!el || value === undefined || value === null) return;
    if (el.type === 'checkbox') el.checked = value === true || value === 'true';
    else el.value = String(value);
  });
  applyingPrefs = false;
}

function savePrefs(opts = {}) {
  if (applyingPrefs) return;
  const { remote = true } = opts;
  const config = collectPrefs();
  Object.entries(config).forEach(([id, value]) => {
    localStorage.setItem(`gr_${id}`, typeof value === 'boolean' ? String(value) : value);
  });
  if (remote) scheduleSavePrefs();
}

async function savePrefsNow() {
  clearTimeout(saveConfigTimer);
  const config = collectPrefs();
  savePrefs({ remote: false });
  try {
    await fetch('/batch/config', {
      method: 'PUT',
      headers: headers(true),
      body: JSON.stringify(config)
    });
  } catch {}
}

function scheduleSavePrefs() {
  clearTimeout(saveConfigTimer);
  saveConfigTimer = setTimeout(savePrefsNow, 400);
}

function loadLocalPrefs() {
  $('apiKey').value = localStorage.getItem('gr_api_key') || '';
  const config = {};
  configKeys.forEach((id) => {
    const value = localStorage.getItem(`gr_${id}`);
    if (value !== null) config[id] = value;
  });
  applyPrefs(config);
}

async function loadServerPrefs() {
  try {
    const res = await fetch('/batch/config', { headers: headers(false) });
    if (!res.ok) return;
    const config = await res.json();
    applyPrefs(config);
    savePrefs({ remote: false });
  } catch {}
}

function updateMetrics(job) {
  $('metricStatus').textContent = job ? (statusText[job.status] || job.status || '-') : '-';
  $('metricProgress').textContent = job ? `${job.ok || 0}/${job.total || 0}` : '0/0';
  $('metricFailed').textContent = job ? String(job.failed || 0) : '0';
  $('metricPending').textContent = job ? String(job.pending || 0) : '0';
}

function renderJobs(jobs) {
  const key = JSON.stringify(jobs.map((j) => [j.id, j.name, j.status, j.ok, j.failed, j.pending, j.total, j.updated_at, selectedJobId]));
  if (key === lastJobsKey) return;
  lastJobsKey = key;

  $('jobCountText').textContent = `${jobs.length} 个任务`;
  const body = $('jobsBody');
  body.innerHTML = '';
  if (!jobs.length) {
    body.innerHTML = '<tr><td class="empty-row" colspan="4">暂无任务</td></tr>';
    return;
  }

  const frag = document.createDocumentFragment();
  jobs.forEach((job) => {
    const tr = document.createElement('tr');
    if (selectedJobId === job.id) tr.classList.add('is-selected');
    tr.dataset.jobId = job.id;
    tr.innerHTML = `
      <td>
        <div class="cell-main" title="${escapeHtml(job.name || job.id)}">${escapeHtml(job.name || job.id)}</div>
        <div class="cell-sub" title="${escapeHtml(job.id || '')}">${escapeHtml(shortId(job.id))} · ${escapeHtml(job.email_mode || '-')} · ${job.mailbox_count || 0} 邮箱</div>
      </td>
      <td>${badge(job.status)}</td>
      <td class="progress-cell">${job.ok || 0}/${job.total || 0}<span class="cell-sub">失败 ${job.failed || 0}</span></td>
      <td class="progress-cell" title="${escapeHtml(job.updated_at || '')}">${escapeHtml(relTime(job.updated_at))}</td>`;
    tr.addEventListener('click', () => selectJob(job.id));
    frag.appendChild(tr);
  });
  body.appendChild(frag);
}

async function loadJobs() {
  const res = await fetch('/batch/register-jobs', { headers: headers(false) });
  if (!res.ok) return;
  const jobs = await res.json();
  renderJobs(jobs);
  if (!selectedJobId && jobs.length) await selectJob(jobs[0].id, { skipJobs: true });
}

async function selectJob(id, opts = {}) {
  if (selectedJobId !== id) {
    selectedJobId = id;
    lastLogSeq = 0;
    lastDetailKey = '';
    $('logs').textContent = '';
    lastJobsKey = '';
  }
  await loadJob();
  await loadLogs();
  if (!opts.skipJobs) await loadJobs();
}

function renderArtifacts(artifacts) {
  const box = $('artifactButtons');
  box.innerHTML = '';
  const names = Object.keys(artifacts || {});
  if (!names.length) return;
  names.forEach((name) => {
    const btn = document.createElement('button');
    btn.className = 'btn btn-secondary artifact-btn';
    btn.type = 'button';
    btn.textContent = artifactNames[name] || name;
    btn.title = artifacts[name];
    btn.addEventListener('click', () => downloadArtifact(name));
    box.appendChild(btn);
  });
}

function renderDetail(job) {
  const key = JSON.stringify([job.id, job.status, job.ok, job.failed, job.pending, job.total, job.updated_at, job.out_dir, Object.keys(job.artifacts || {})]);
  if (key === lastDetailKey) return;
  lastDetailKey = key;

  $('selectedTitle').textContent = `${job.name || job.id} · ${statusText[job.status] || job.status || '-'}`;
  $('selectedMeta').textContent = `进度 ${job.ok || 0}/${job.total || 0}，失败 ${job.failed || 0}，${shortId(job.id)}，${relTime(job.updated_at)} 更新`;
  $('selectedMeta').title = job.out_dir || '';
  renderArtifacts(job.artifacts || {});
  updateMetrics(job);
}

async function loadJob() {
  if (!selectedJobId) {
    updateMetrics(null);
    return;
  }
  const res = await fetch(`/batch/register-jobs/${selectedJobId}`, { headers: headers(false) });
  if (!res.ok) return;
  renderDetail(await res.json());
}

async function loadLogs() {
  if (!selectedJobId) return;
  const res = await fetch(`/batch/register-jobs/${selectedJobId}/logs?after=${lastLogSeq}`, { headers: headers(false) });
  if (!res.ok) return;
  const data = await res.json();
  if (data.logs && data.logs.length) {
    const pre = $('logs');
    pre.textContent += data.logs.map((item) => item.line).join('\n') + '\n';
    pre.scrollTop = pre.scrollHeight;
  }
  lastLogSeq = data.last_seq || lastLogSeq;
}

async function downloadArtifact(name) {
  if (!selectedJobId) return;
  const res = await fetch(`/batch/register-jobs/${selectedJobId}/artifacts/${encodeURIComponent(name)}`, { headers: headers(false) });
  if (!res.ok) {
    alert(await res.text());
    return;
  }
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${selectedJobId}-${name}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

function buildJobPayload() {
  return {
    name: $('jobName').value.trim() || null,
    outlook_accounts: $('outlookAccounts').value,
    workspace_id: $('workspaceId').value.trim(),
    count_per_account: Number($('countPerAccount').value || 1),
    email_mode: $('emailMode').value,
    alias_prefix: $('aliasPrefix').value.trim() || 'b',
    concurrency: Number($('concurrency').value || 5),
    attempts: Number($('attempts').value || 2),
    register_proxy: $('registerProxy').value.trim() || null,
    otp_max_retries: Number($('otpMaxRetries').value || 40),
    otp_poll_interval_s: Number($('otpPollInterval').value || 3),
    workspace_join_timeout_s: Number($('workspaceJoinTimeout').value || 20),
    chatgpt_web: true,
    sub2api_upload: $('sub2apiUpload').checked,
    sub2api_url: $('sub2apiUrl').value.trim() || 'https://sub2api.example.com',
    sub2api_authorization: $('sub2apiBearer').value.trim() || null,
    sub2api_mode: 'batch',
    purge_after_upload: $('purgeAfterUpload').checked
  };
}

async function startJob(event) {
  event.preventDefault();
  setError('');
  savePrefs();
  const button = $('startJob');
  button.disabled = true;
  button.textContent = '启动中...';
  try {
    await savePrefsNow();
    const res = await fetch('/batch/register-jobs', {
      method: 'POST',
      headers: headers(true),
      body: JSON.stringify(buildJobPayload())
    });
    if (!res.ok) {
      let msg = await res.text();
      try { msg = JSON.parse(msg).detail || msg; } catch {}
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
      return;
    }
    const job = await res.json();
    await selectJob(job.id);
  } finally {
    button.disabled = false;
    button.textContent = '启动任务';
  }
}

async function uploadSelected() {
  if (!selectedJobId) return;
  savePrefs();
  await savePrefsNow();
  const res = await fetch(`/batch/register-jobs/${selectedJobId}/upload-sub2api`, {
    method: 'POST',
    headers: headers(true),
    body: JSON.stringify({
      sub2api_url: $('sub2apiUrl').value.trim() || 'https://sub2api.example.com',
      sub2api_authorization: $('sub2apiBearer').value.trim() || null,
      sub2api_mode: 'batch',
      purge_after_upload: $('purgeAfterUpload').checked
    })
  });
  if (!res.ok) alert(await res.text());
  await loadJob();
  await loadLogs();
}

async function cancelSelected() {
  if (!selectedJobId) return;
  await fetch(`/batch/register-jobs/${selectedJobId}/cancel`, { method: 'POST', headers: headers(false) });
  await loadJob();
}

async function tick() {
  if (polling) return;
  polling = true;
  try {
    await loadJobs();
    await loadJob();
    await loadLogs();
  } finally {
    polling = false;
  }
}

loadLocalPrefs();
loadServerPrefs();
$('saveApiKey').addEventListener('click', async () => {
  localStorage.setItem('gr_api_key', $('apiKey').value.trim());
  await loadServerPrefs();
});
$('refreshJobs').addEventListener('click', tick);
$('jobForm').addEventListener('submit', startJob);
$('uploadSelected').addEventListener('click', uploadSelected);
$('cancelSelected').addEventListener('click', cancelSelected);
configKeys.forEach((id) => {
  const el = $(id);
  if (!el) return;
  el.addEventListener('change', savePrefs);
  el.addEventListener('input', savePrefs);
});
$('emailMode').addEventListener('change', () => {
  if ($('emailMode').value === 'base') $('countPerAccount').value = '1';
  savePrefs();
});

tick();
setInterval(tick, 3000);
