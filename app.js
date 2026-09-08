'use strict';

/* ============================================================
   Branchward — GitHub Branch Protection Audit
   Pure client-side tool. All GitHub API calls are made directly
   from the browser to api.github.com using the token the user
   supplies. Nothing is sent to any other server.
   ============================================================ */

const API_ROOT = 'https://api.github.com';
const CONCURRENCY = 6;

const state = {
  owner: '',
  ownerKind: '', // 'org' | 'user'
  token: '',
  minApprovals: 1,
  includeArchived: false,
  rows: [], // classified repo rows
  sort: { col: 'compliance', dir: 'asc' },
  search: '',
  statusFilter: 'all',
  aborted: false,
  lastRunAt: null,
};

let abortController = null;

// ---------- Element refs ----------
const el = (id) => document.getElementById(id);
const viewSetup = el('view-setup');
const viewProgress = el('view-progress');
const viewDashboard = el('view-dashboard');
const errorBanner = el('error-banner');
const errorMessage = el('error-message');

// ---------- Theme toggle (JS-only, no localStorage: sandboxed iframes block it) ----------
(function initTheme() {
  const root = document.documentElement;
  const toggle = el('theme-toggle');
  let mode = matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light';
  root.setAttribute('data-theme', mode);
  toggle.addEventListener('click', () => {
    mode = mode === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', mode);
    toggle.setAttribute('aria-label', 'Switch to ' + (mode === 'dark' ? 'light' : 'dark') + ' mode');
  });
})();

// ---------- Error banner ----------
function showError(msg) {
  errorMessage.textContent = msg;
  errorBanner.hidden = false;
}
function hideError() {
  errorBanner.hidden = true;
}
el('error-dismiss').addEventListener('click', hideError);

// ---------- View switching ----------
function showView(name) {
  viewSetup.hidden = name !== 'setup';
  viewProgress.hidden = name !== 'progress';
  viewDashboard.hidden = name !== 'dashboard';
}

// ---------- GitHub API helpers ----------
function ghHeaders(token) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `token ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

async function ghFetch(path, token, signal) {
  const res = await fetch(`${API_ROOT}${path}`, { headers: ghHeaders(token), signal });
  return res;
}

function parseLinkHeader(header) {
  if (!header) return {};
  const links = {};
  header.split(',').forEach((part) => {
    const match = part.match(/<([^>]+)>;\s*rel="([^"]+)"/);
    if (match) links[match[2]] = match[1];
  });
  return links;
}

async function checkRateLimit(res) {
  if (res.status === 403) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') {
      const reset = res.headers.get('x-ratelimit-reset');
      const resetDate = reset ? new Date(Number(reset) * 1000) : null;
      throw new Error(
        `GitHub API rate limit reached. It resets at ${resetDate ? resetDate.toLocaleTimeString() : 'an unknown time'}. Wait and try again.`
      );
    }
  }
}

// Fetch every repo for an org or user, paginating through all pages.
async function fetchAllRepos(owner, token, signal, onProgress) {
  // Try org endpoint first, fall back to user endpoint.
  let kind = 'org';
  let basePath = `/orgs/${encodeURIComponent(owner)}/repos?per_page=100&type=all`;
  let probe = await ghFetch(basePath, token, signal);

  if (probe.status === 404) {
    kind = 'user';
    basePath = `/users/${encodeURIComponent(owner)}/repos?per_page=100&type=owner`;
    probe = await ghFetch(basePath, token, signal);
  }

  if (probe.status === 401) {
    throw new Error('GitHub rejected the token (401 Unauthorized). Double-check it is valid and not expired.');
  }
  await checkRateLimit(probe);
  if (probe.status === 404) {
    throw new Error(`No organization or user named "${owner}" was found (or your token can't see it).`);
  }
  if (!probe.ok) {
    const body = await probe.json().catch(() => ({}));
    throw new Error(`GitHub API error (${probe.status}): ${body.message || probe.statusText}`);
  }

  let repos = await probe.json();
  let links = parseLinkHeader(probe.headers.get('link'));
  onProgress(repos.length, null);

  let page = 2;
  while (links.next && !signal.aborted) {
    const nextUrl = links.next.replace(API_ROOT, '');
    const res = await ghFetch(nextUrl, token, signal);
    await checkRateLimit(res);
    if (!res.ok) break;
    const batch = await res.json();
    repos = repos.concat(batch);
    links = parseLinkHeader(res.headers.get('link'));
    onProgress(repos.length, null);
    page++;
  }

  return { repos, kind };
}

// Simple concurrency-limited async pool.
async function asyncPool(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function run() {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await worker(items[idx], idx);
    }
  }
  const runners = Array.from({ length: Math.min(limit, items.length) }, run);
  await Promise.all(runners);
  return results;
}

// Fetch branch protection for one repo; classify into a row.
async function fetchProtectionForRepo(repo, token, signal) {
  const base = {
    name: repo.name,
    fullName: repo.full_name,
    url: repo.html_url,
    private: repo.private,
    archived: repo.archived,
    fork: repo.fork,
    branch: repo.default_branch || null,
  };

  if (!repo.default_branch) {
    return { ...base, protection: 'empty', reviewRequired: false, approvals: null, adminBypass: null, statusChecks: false, statusNote: 'Repository has no default branch (likely empty).' };
  }

  const path = `/repos/${repo.full_name}/branches/${encodeURIComponent(repo.default_branch)}/protection`;
  let res;
  try {
    res = await ghFetch(path, token, signal);
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    return { ...base, protection: 'error', reviewRequired: false, approvals: null, adminBypass: null, statusChecks: false, statusNote: 'Network error contacting GitHub.' };
  }

  if (res.status === 404) {
    return { ...base, protection: 'unprotected', reviewRequired: false, approvals: 0, adminBypass: true, statusChecks: false, statusNote: 'No branch protection rule exists on the default branch.' };
  }

  if (res.status === 403) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') throw new Error('rate-limited');
    const body = await res.json().catch(() => ({}));
    const msg = body.message || '';
    const planRestricted = /upgrade|pro|team plan/i.test(msg);
    return {
      ...base,
      protection: 'unknown',
      reviewRequired: null,
      approvals: null,
      adminBypass: null,
      statusChecks: null,
      statusNote: planRestricted
        ? 'Branch protection API is unavailable for this private repo on the current GitHub plan (requires Pro/Team/Enterprise).'
        : `Access denied checking protection (${msg || 'insufficient token permissions'}).`,
    };
  }

  if (res.status === 401) {
    throw new Error('GitHub rejected the token while checking a repository (401 Unauthorized).');
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    return { ...base, protection: 'unknown', reviewRequired: null, approvals: null, adminBypass: null, statusChecks: null, statusNote: `Unexpected response (${res.status}): ${body.message || res.statusText}` };
  }

  const data = await res.json();
  const prReview = data.required_pull_request_reviews || null;
  const reviewRequired = !!prReview;
  const approvals = prReview ? (prReview.required_approving_review_count ?? 0) : 0;
  const adminEnforced = !!(data.enforce_admins && data.enforce_admins.enabled);
  const statusChecks = !!data.required_status_checks;

  return {
    ...base,
    protection: 'protected',
    reviewRequired,
    approvals,
    adminBypass: !adminEnforced,
    statusChecks,
    codeOwnerReview: !!(prReview && prReview.require_code_owner_reviews),
    statusNote: '',
  };
}

function computeCompliance(row, minApprovals) {
  if (row.protection === 'unknown' || row.protection === 'error' || row.protection === 'empty') return 'needsreview';
  if (row.protection === 'unprotected') return 'noncompliant';
  const ok = row.reviewRequired && (row.approvals ?? 0) >= minApprovals && row.adminBypass === false;
  return ok ? 'compliant' : 'noncompliant';
}

// ---------- Progress UI ----------
function setProgress(label, done, total) {
  el('progress-label').textContent = label;
  const pct = total ? Math.round((done / total) * 100) : 0;
  el('progress-fill').style.width = pct + '%';
  el('progress-count').textContent = total ? `${done} / ${total} repositories checked` : '';
}

// ---------- Main audit runner ----------
async function runAudit({ owner, token, minApprovals, includeArchived }) {
  hideError();
  state.owner = owner;
  state.token = token;
  state.minApprovals = minApprovals;
  state.includeArchived = includeArchived;

  abortController = new AbortController();
  const signal = abortController.signal;

  showView('progress');
  setProgress('Fetching repository list…', 0, 0);

  try {
    const { repos: rawRepos, kind } = await fetchAllRepos(owner, token, signal, (n) => {
      setProgress('Fetching repository list…', n, 0);
    });
    state.ownerKind = kind;

    let repos = rawRepos;
    if (!includeArchived) repos = repos.filter((r) => !r.archived);

    if (repos.length === 0) {
      state.rows = [];
      state.lastRunAt = new Date();
      renderDashboard();
      showView('dashboard');
      return;
    }

    let done = 0;
    const rows = await asyncPool(repos, CONCURRENCY, async (repo) => {
      const row = await fetchProtectionForRepo(repo, token, signal);
      done++;
      setProgress(`Checking branch protection…`, done, repos.length);
      return row;
    });

    if (signal.aborted) return;

    state.rows = rows.map((r) => ({ ...r, compliance: computeCompliance(r, minApprovals) }));
    state.lastRunAt = new Date();
    renderDashboard();
    showView('dashboard');
  } catch (err) {
    if (err.name === 'AbortError') {
      showView('setup');
      return;
    }
    showView('setup');
    showError(err.message || 'Something went wrong while running the audit.');
  }
}

// ---------- Demo data ----------
function demoRows() {
  const now = () => '';
  const rows = [
    { name: 'client-portal-web', fullName: 'acme-legal/client-portal-web', url: '#', private: true, archived: false, branch: 'main', protection: 'protected', reviewRequired: true, approvals: 2, adminBypass: false, statusChecks: true, statusNote: '' },
    { name: 'billing-service', fullName: 'acme-legal/billing-service', url: '#', private: true, archived: false, branch: 'main', protection: 'protected', reviewRequired: true, approvals: 1, adminBypass: false, statusChecks: false, statusNote: '' },
    { name: 'matter-management-api', fullName: 'acme-legal/matter-management-api', url: '#', private: true, archived: false, branch: 'main', protection: 'protected', reviewRequired: true, approvals: 1, adminBypass: true, statusChecks: true, statusNote: '' },
    { name: 'legacy-intake-form', fullName: 'acme-legal/legacy-intake-form', url: '#', private: false, archived: false, branch: 'master', protection: 'unprotected', reviewRequired: false, approvals: 0, adminBypass: true, statusChecks: false, statusNote: 'No branch protection rule exists on the default branch.' },
    { name: 'marketing-site', fullName: 'acme-legal/marketing-site', url: '#', private: false, archived: false, branch: 'main', protection: 'protected', reviewRequired: false, approvals: 0, adminBypass: true, statusChecks: false, statusNote: '' },
    { name: 'internal-tools', fullName: 'acme-legal/internal-tools', url: '#', private: true, archived: false, branch: 'main', protection: 'unknown', reviewRequired: null, approvals: null, adminBypass: null, statusChecks: null, statusNote: 'Branch protection API is unavailable for this private repo on the current GitHub plan (requires Pro/Team/Enterprise).' },
    { name: 'document-templates', fullName: 'acme-legal/document-templates', url: '#', private: true, archived: true, branch: 'main', protection: 'protected', reviewRequired: true, approvals: 1, adminBypass: false, statusChecks: false, statusNote: '' },
    { name: 'e-signature-webhook', fullName: 'acme-legal/e-signature-webhook', url: '#', private: true, archived: false, branch: 'main', protection: 'protected', reviewRequired: true, approvals: 3, adminBypass: false, statusChecks: true, statusNote: '' },
    { name: 'compliance-scripts', fullName: 'acme-legal/compliance-scripts', url: '#', private: true, archived: false, branch: 'main', protection: 'empty', reviewRequired: false, approvals: null, adminBypass: null, statusChecks: false, statusNote: 'Repository has no default branch (likely empty).' },
    { name: 'client-mobile-app', fullName: 'acme-legal/client-mobile-app', url: '#', private: true, archived: false, branch: 'develop', protection: 'unprotected', reviewRequired: false, approvals: 0, adminBypass: true, statusChecks: false, statusNote: 'No branch protection rule exists on the default branch.' },
  ];
  return rows.map((r) => ({ ...r, compliance: computeCompliance(r, state.minApprovals) }));
}

function loadDemo() {
  hideError();
  state.owner = 'acme-legal';
  state.ownerKind = 'org';
  state.token = '';
  state.minApprovals = Number(el('input-min-approvals').value || 1);
  state.includeArchived = el('input-include-archived').checked;
  let rows = demoRows();
  if (!state.includeArchived) rows = rows.filter((r) => !r.archived);
  state.rows = rows;
  state.lastRunAt = new Date();
  renderDashboard();
  showView('dashboard');
}

// ---------- Rendering ----------
function badgeFor(compliance) {
  if (compliance === 'compliant') return `<span class="badge badge-success">Compliant</span>`;
  if (compliance === 'noncompliant') return `<span class="badge badge-error">Non-compliant</span>`;
  return `<span class="badge badge-warning">Needs review</span>`;
}

function boolCell(val) {
  if (val === true) return `<span class="check-yes">Yes</span>`;
  if (val === false) return `<span class="check-no">No</span>`;
  return `<span class="check-unknown">—</span>`;
}

function getFilteredSortedRows() {
  let rows = state.rows.map((r) => ({ ...r, compliance: computeCompliance(r, state.minApprovals) }));

  if (state.search.trim()) {
    const q = state.search.trim().toLowerCase();
    rows = rows.filter((r) => r.name.toLowerCase().includes(q));
  }
  if (state.statusFilter !== 'all') {
    rows = rows.filter((r) => r.compliance === state.statusFilter);
  }

  const { col, dir } = state.sort;
  const mult = dir === 'asc' ? 1 : -1;
  const keyFn = {
    name: (r) => r.name.toLowerCase(),
    visibility: (r) => (r.private ? 'private' : 'public'),
    branch: (r) => r.branch || '',
    protected: (r) => r.protection,
    reviewRequired: (r) => (r.reviewRequired === true ? 1 : r.reviewRequired === false ? 0 : -1),
    approvals: (r) => (r.approvals ?? -1),
    adminBypass: (r) => (r.adminBypass === true ? 1 : r.adminBypass === false ? 0 : -1),
    statusChecks: (r) => (r.statusChecks === true ? 1 : r.statusChecks === false ? 0 : -1),
    compliance: (r) => ({ noncompliant: 0, needsreview: 1, compliant: 2 }[r.compliance]),
  }[col];

  rows.sort((a, b) => {
    const av = keyFn(a), bv = keyFn(b);
    if (av < bv) return -1 * mult;
    if (av > bv) return 1 * mult;
    return a.name.localeCompare(b.name);
  });

  return rows;
}

function renderKPIs(allRows) {
  const total = allRows.length;
  const compliant = allRows.filter((r) => r.compliance === 'compliant').length;
  const noncompliant = allRows.filter((r) => r.compliance === 'noncompliant').length;
  const needsreview = allRows.filter((r) => r.compliance === 'needsreview').length;
  const rateBase = compliant + noncompliant;
  const rate = rateBase ? Math.round((compliant / rateBase) * 100) : 0;

  el('kpi-total').textContent = total;
  el('kpi-compliant').textContent = compliant;
  el('kpi-noncompliant').textContent = noncompliant;
  el('kpi-needsreview').textContent = needsreview;
  el('kpi-rate').textContent = rate + '%';
}

function renderTable(rows) {
  const tbody = el('table-body');
  const emptyState = el('empty-state');

  if (rows.length === 0) {
    tbody.innerHTML = '';
    emptyState.hidden = false;
    return;
  }
  emptyState.hidden = true;

  tbody.innerHTML = rows
    .map((r) => {
      const flags = [];
      if (r.archived) flags.push('<span class="mini-tag">Archived</span>');
      if (r.fork) flags.push('<span class="mini-tag">Fork</span>');
      const titleAttr = r.statusNote ? ` title="${r.statusNote.replace(/"/g, '&quot;')}"` : '';
      return `
      <tr${titleAttr}>
        <td>
          <div class="repo-cell">
            <a class="repo-name" href="${r.url}" target="_blank" rel="noopener">${escapeHtml(r.name)}</a>
            ${flags.length ? `<div class="repo-flags">${flags.join('')}</div>` : ''}
          </div>
        </td>
        <td>${r.private ? 'Private' : 'Public'}</td>
        <td class="mono-num">${r.branch || '—'}</td>
        <td>${protectionCell(r.protection)}</td>
        <td>${boolCell(r.reviewRequired)}</td>
        <td class="mono-num">${r.approvals === null || r.approvals === undefined ? '—' : r.approvals}</td>
        <td>${boolCell(r.adminBypass)}</td>
        <td>${boolCell(r.statusChecks)}</td>
        <td>${badgeFor(r.compliance)}</td>
      </tr>`;
    })
    .join('');
}

function protectionCell(protection) {
  if (protection === 'protected') return '<span class="check-yes">Yes</span>';
  if (protection === 'unprotected') return '<span class="check-no">No</span>';
  if (protection === 'empty') return '<span class="check-unknown">No branch</span>';
  return '<span class="check-unknown">Unknown</span>';
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderScopePill() {
  const pill = el('scope-pill');
  const changeBtn = el('btn-change-target');
  if (!state.owner) { pill.hidden = true; changeBtn.hidden = true; return; }
  pill.hidden = false;
  changeBtn.hidden = false;
  pill.textContent = `${state.owner} · ${state.ownerKind === 'org' ? 'organization' : 'user'}`;
}

function renderLastRun() {
  const note = el('last-run-note');
  if (!state.lastRunAt) { note.textContent = ''; return; }
  note.textContent = `Audited ${state.rows.length} repos at ${state.lastRunAt.toLocaleTimeString()}`;
}

function updateSortHeaders() {
  document.querySelectorAll('#audit-table thead th').forEach((th) => {
    th.classList.remove('sort-active', 'sort-desc');
    if (th.dataset.sort === state.sort.col) {
      th.classList.add('sort-active');
      if (state.sort.dir === 'desc') th.classList.add('sort-desc');
    }
  });
}

function renderDashboard() {
  renderScopePill();
  renderLastRun();
  const allComputed = state.rows.map((r) => ({ ...r, compliance: computeCompliance(r, state.minApprovals) }));
  renderKPIs(allComputed);
  const rows = getFilteredSortedRows();
  renderTable(rows);
  updateSortHeaders();
}

// ---------- CSV export ----------
function exportCsv() {
  const rows = getFilteredSortedRows();
  const headers = ['Repository', 'Visibility', 'Default Branch', 'Protected', 'PR Review Required', 'Min Approvals', 'Admins Can Bypass', 'Status Checks Required', 'Compliance', 'Notes'];
  const lines = [headers.join(',')];
  rows.forEach((r) => {
    const cells = [
      r.name,
      r.private ? 'Private' : 'Public',
      r.branch || '',
      r.protection,
      r.reviewRequired === null ? 'Unknown' : r.reviewRequired ? 'Yes' : 'No',
      r.approvals ?? '',
      r.adminBypass === null ? 'Unknown' : r.adminBypass ? 'Yes' : 'No',
      r.statusChecks === null ? 'Unknown' : r.statusChecks ? 'Yes' : 'No',
      r.compliance,
      (r.statusNote || '').replace(/,/g, ';'),
    ].map((c) => `"${String(c).replace(/"/g, '""')}"`);
    lines.push(cells.join(','));
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `branch-protection-audit-${state.owner || 'demo'}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------- Event wiring ----------
el('audit-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const owner = el('input-owner').value.trim();
  const token = el('input-token').value.trim();
  const minApprovals = Number(el('input-min-approvals').value);
  const includeArchived = el('input-include-archived').checked;
  if (!owner || !token) return;
  runAudit({ owner, token, minApprovals, includeArchived });
});

el('btn-demo').addEventListener('click', loadDemo);

el('btn-cancel-audit').addEventListener('click', () => {
  if (abortController) abortController.abort();
});

el('btn-change-target').addEventListener('click', () => {
  showView('setup');
});

el('btn-rerun').addEventListener('click', () => {
  if (!state.token) {
    showView('setup');
    return;
  }
  runAudit({ owner: state.owner, token: state.token, minApprovals: state.minApprovals, includeArchived: state.includeArchived });
});

el('input-search').addEventListener('input', (e) => {
  state.search = e.target.value;
  renderTable(getFilteredSortedRows());
  updateSortHeaders();
});

el('input-status-filter').addEventListener('change', (e) => {
  state.statusFilter = e.target.value;
  renderTable(getFilteredSortedRows());
});

el('input-min-approvals-live').addEventListener('change', (e) => {
  state.minApprovals = Number(e.target.value);
  el('input-min-approvals').value = e.target.value;
  renderDashboard();
});

document.querySelectorAll('#audit-table thead th[data-sort]').forEach((th) => {
  const activate = () => {
    const col = th.dataset.sort;
    if (state.sort.col === col) {
      state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sort.col = col;
      state.sort.dir = 'asc';
    }
    renderTable(getFilteredSortedRows());
    updateSortHeaders();
  };
  th.addEventListener('click', activate);
  th.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
  });
});

el('btn-export-csv').addEventListener('click', exportCsv);

showView('setup');
