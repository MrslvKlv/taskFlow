// ─── AWS DEPLOYMENT CONFIG ─────────────────────────────────────────────────
// Fill in these values after running: sam deploy --guided
// See AWS/template.yaml Outputs section for the exact values.
const CONFIG = {
  // Cognito Hosted UI domain (e.g. "taskflow-prod.auth.us-east-1.amazoncognito.com")
  cognitoDomain:   'YOUR_COGNITO_DOMAIN',
  // App Client ID from Cognito User Pool
  cognitoClientId: 'YOUR_COGNITO_CLIENT_ID',
  // Must match exactly what's configured in Cognito App Client callback URLs.
  // Uses current page URL (strips ?code= and #hash) — works for any subdirectory path.
  redirectUri:     (() => { const u = new URL(window.location.href); u.search = ''; u.hash = ''; return u.toString(); })(),
  // API Gateway HTTP API invoke URL (e.g. "https://abc123.execute-api.us-east-1.amazonaws.com/prod")
  apiBase:         'YOUR_API_GATEWAY_URL',
};

// ─── AUTH — PKCE FLOW (no SDK required) ────────────────────────────────────
// Uses Cognito Hosted UI with PKCE. No client secret needed.
// Tokens stored in sessionStorage (cleared on tab close — safer than localStorage).

let currentUser = null; // { id, email }

function _b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCodeVerifier() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return _b64url(buf);
}

async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return _b64url(digest);
}

async function login() {
  const verifier = generateCodeVerifier();
  sessionStorage.setItem('pkce_verifier', verifier);
  const challenge = await generateCodeChallenge(verifier);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     CONFIG.cognitoClientId,
    redirect_uri:  CONFIG.redirectUri,
    scope:         'openid email profile',
    code_challenge_method: 'S256',
    code_challenge: challenge,
  });
  window.location.href = `https://${CONFIG.cognitoDomain}/oauth2/authorize?${params}`;
}

async function exchangeCode(code) {
  const verifier = sessionStorage.getItem('pkce_verifier');
  if (!verifier) { showAuthScreen(); return; }
  const params = new URLSearchParams({
    grant_type:    'authorization_code',
    client_id:     CONFIG.cognitoClientId,
    redirect_uri:  CONFIG.redirectUri,
    code,
    code_verifier: verifier,
  });
  const res = await fetch(`https://${CONFIG.cognitoDomain}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!res.ok) { showAuthScreen(); return; }
  const tokens = await res.json();
  sessionStorage.setItem('access_token',  tokens.access_token);
  sessionStorage.setItem('id_token',      tokens.id_token);
  sessionStorage.setItem('refresh_token', tokens.refresh_token);
  sessionStorage.removeItem('pkce_verifier');
  window.history.replaceState({}, document.title, '/');
}

async function refreshTokens() {
  const refresh = sessionStorage.getItem('refresh_token');
  if (!refresh) return false;
  const params = new URLSearchParams({
    grant_type:    'refresh_token',
    client_id:     CONFIG.cognitoClientId,
    refresh_token: refresh,
  });
  const res = await fetch(`https://${CONFIG.cognitoDomain}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!res.ok) return false;
  const tokens = await res.json();
  sessionStorage.setItem('access_token', tokens.access_token);
  sessionStorage.setItem('id_token',     tokens.id_token);
  return true;
}

function getToken() { return sessionStorage.getItem('access_token'); }

function logout() {
  sessionStorage.clear();
  const params = new URLSearchParams({
    client_id:  CONFIG.cognitoClientId,
    logout_uri: CONFIG.redirectUri,
  });
  window.location.href = `https://${CONFIG.cognitoDomain}/logout?${params}`;
}

function decodeJwt(token) {
  try {
    return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
  } catch { return null; }
}

function isTokenExpired(token) {
  const payload = decodeJwt(token);
  if (!payload) return true;
  return payload.exp * 1000 < Date.now();
}

function showAuthScreen() {
  document.getElementById('auth-overlay').style.display = 'flex';
  document.getElementById('loading-overlay').style.display = 'none';
  document.getElementById('auth-signin-btn').onclick = login;
}

function showLoadingScreen() {
  document.getElementById('loading-overlay').style.display = 'flex';
  document.getElementById('auth-overlay').style.display = 'none';
}

function hideOverlays() {
  document.getElementById('auth-overlay').style.display = 'none';
  document.getElementById('loading-overlay').style.display = 'none';
}

async function checkAuth() {
  // Handle Cognito callback: ?code=...
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  if (code) {
    showLoadingScreen();
    await exchangeCode(code);
  }

  let token = getToken();
  if (!token) { showAuthScreen(); return; }

  // Auto-refresh if expired
  if (isTokenExpired(token)) {
    const ok = await refreshTokens();
    if (!ok) { showAuthScreen(); return; }
    token = getToken();
  }

  const payload = decodeJwt(token);
  if (!payload) { showAuthScreen(); return; }

  currentUser = {
    id:    payload.sub,
    email: payload.email || payload['cognito:username'] || 'user',
  };
  const emailEl = document.getElementById('user-email');
  if (emailEl) emailEl.textContent = currentUser.email;

  showLoadingScreen();
  await loadState();
}

// ─── API LAYER ─────────────────────────────────────────────────────────────

async function apiCall(method, path, body) {
  let token = getToken();

  // Proactively refresh if close to expiry (< 60s)
  const payload = decodeJwt(token);
  if (payload && payload.exp * 1000 - Date.now() < 60_000) {
    await refreshTokens();
    token = getToken();
  }

  const res = await fetch(CONFIG.apiBase + path, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    // Token truly expired; force re-login
    sessionStorage.removeItem('access_token');
    showAuthScreen();
    return null;
  }

  if (!res.ok) {
    const msg = await res.text().catch(() => 'Unknown error');
    showToast('API error: ' + msg, true);
    return null;
  }

  return res.json();
}

// Load complete workspace state from server and re-render
async function loadState() {
  const data = await apiCall('GET', '/state');
  if (!data) return;
  // Merge server data into local state, preserving ephemeral UI state
  state.categories    = data.categories;
  state.projects      = data.projects;
  // Keep local UI selections if still valid
  if (!state.projects.find(p => p.id === state.activeProjectId)) {
    state.activeProjectId = null;
  }
  if (!getTask(state.activeTaskId)) {
    state.activeTaskId = null;
  }
  hideOverlays();
  render();
}

// ─── TOAST ─────────────────────────────────────────────────────────────────
let _toastTimer = null;
function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.className = 'toast'; }, 3500);
}

// ─── CONSTANTS ─────────────────────────────────────────────────────────────
const COLORS = ['#f59e0b','#3b82f6','#22c55e','#ef4444','#8b5cf6','#ec4899','#06b6d4','#f97316'];

const ICONS = {
  folder:     `<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>`,
  layers:     `<path d="M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>`,
  bell:       `<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>`,
  palette:    `<circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/>`,
  code:       `<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>`,
  barchart:   `<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>`,
  flask:      `<path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/>`,
  settings:   `<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>`,
  zap:        `<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>`,
  briefcase:  `<rect width="20" height="14" x="2" y="7" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>`,
  crosshair:  `<circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>`,
  shield:     `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
  pencil:     `<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>`,
  trash:      `<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>`,
};

const CAT_ICONS = ['folder','layers','bell','palette','code','barchart','flask','settings','zap','briefcase','crosshair','shield'];
const STATUS_LABELS = { todo:'To Do', inprogress:'In Progress', done:'Done' };

// ─── STATE ─────────────────────────────────────────────────────────────────
// categories and projects are loaded from the server.
// activeProjectId, view, activeTaskId are ephemeral UI state — in memory only.
let state = { categories:[], projects:[], activeProjectId:null, view:'kanban', activeTaskId:null };
let dragTaskId=null, _color=COLORS[0], _icon=CAT_ICONS[0];

// ─── HELPERS ───────────────────────────────────────────────────────────────
function uid(){ return Date.now().toString(36)+Math.random().toString(36).slice(2); }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function getProject(id){ return state.projects.find(p=>p.id===id); }
function getActive(){ return getProject(state.activeProjectId); }
function getTask(tid){ for(const p of state.projects){ const t=p.tasks.find(t=>t.id===tid); if(t) return t; } return null; }
function getCat(id){ return state.categories.find(c=>c.id===id); }
function fmtDate(d){ if(!d) return ''; return new Date(d+'T12:00:00').toLocaleDateString('en-GB',{day:'numeric',month:'short'}); }
function overdue(d,st){ return d && st!=='done' && new Date(d+'T23:59:59')<new Date(); }
function av(name){ return name?name.trim().charAt(0).toUpperCase():'?'; }

function renderIcon(name, size=14){
  const content = ICONS[name] || ICONS.folder;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${content}</svg>`;
}

// ─── RENDER ────────────────────────────────────────────────────────────────
function render(){ renderSidebar(); renderMain(); renderPanel(); updateOverdueBadge(); }

function updateOverdueBadge(){
  const count = state.projects.reduce((n,p)=>n+p.tasks.filter(t=>overdue(t.dueDate,t.status)).length,0);
  const badge = document.getElementById('overdue-count');
  const btn   = document.getElementById('overdue-nav-btn');
  if(!badge || !btn) return;
  if(count > 0){
    badge.textContent = count;
    badge.style.display = 'inline-flex';
    btn.classList.add('has-overdue');
  } else {
    badge.style.display = 'none';
    btn.classList.remove('has-overdue');
  }
  btn.classList.toggle('active', state.view==='overdue');
}

function renderSidebar(){
  let html = '';

  for(const cat of state.categories){
    const projs = state.projects.filter(p=>p.categoryId===cat.id);
    const tasks  = projs.reduce((n,p)=>n+p.tasks.length,0);
    const cls    = cat.collapsed?'collapsed':'';
    html += `
      <div class="cat-block">
        <div class="cat-header" onclick="toggleCat('${cat.id}')">
          <span class="cat-chevron ${cls}">▾</span>
          <span class="cat-icon">${renderIcon(cat.icon)}</span>
          <span class="cat-name">${esc(cat.name)}</span>
          <span class="cat-count">${tasks}</span>
          <button class="cat-add" title="Add project" onclick="event.stopPropagation();showAddProject('${cat.id}')">＋</button>
        </div>
        <div class="cat-projects ${cls}">
          ${projs.length
            ? projs.map(p=>projRow(p)).join('')
            : `<div style="padding:4px 8px;font-size:11px;color:var(--text-muted)">No projects — hover above and click ＋</div>`}
        </div>
      </div>`;
  }

  const uncat = state.projects.filter(p=>!p.categoryId);
  if(uncat.length){
    html += `
      <div style="margin-top:6px">
        <div class="uncat-label">
          <div class="uncat-line"></div>
          <span class="uncat-text">Uncategorized</span>
          <div class="uncat-line"></div>
        </div>
        <div style="padding:2px 4px 4px">${uncat.map(p=>projRow(p)).join('')}</div>
      </div>`;
  }

  if(!state.categories.length && !state.projects.length){
    html = `<div style="padding:20px 14px;font-size:12px;color:var(--text-muted);line-height:1.7">
      Start by creating a <strong style="color:var(--text-dim)">category</strong> then add <strong style="color:var(--text-dim)">projects</strong> inside it.
    </div>`;
  }

  document.getElementById('sidebar-scroll').innerHTML = html;
}

function projRow(p){
  const act = p.id===state.activeProjectId?'active':'';
  return `<div class="project-item ${act}" onclick="selectProject('${p.id}')">
    <div class="project-dot" style="background:${p.color}"></div>
    <span class="project-name">${esc(p.name)}</span>
    <span class="project-count">${p.tasks.length}</span>
    <button class="proj-edit-btn" title="Edit project" onclick="event.stopPropagation();showEditProject('${p.id}')">${renderIcon('pencil',11)}</button>
  </div>`;
}

function renderMain(){
  const el = document.getElementById('main-inner');
  if(state.view==='overdue'){ el.innerHTML=renderOverdue(); return; }
  if(!state.activeProjectId){
    el.innerHTML=`<div class="center-state" style="height:100vh">
      <div class="icon">⬡</div>
      <p>Select a project from the sidebar<br>or create a new one to get started</p>
      <button class="btn-primary" onclick="showAddProject(null)">+ New Project</button>
    </div>`; return;
  }
  const p=getActive();
  const cat=p.categoryId?getCat(p.categoryId):null;
  el.innerHTML=`
    <div class="main-header">
      <div class="project-dot" style="background:${p.color};width:9px;height:9px;border-radius:50%"></div>
      <h2>${esc(p.name)}</h2>
      ${cat?`<span class="cat-badge">${renderIcon(cat.icon,11)} ${esc(cat.name)}</span>`:''}
      <div class="view-toggle">
        <button class="view-btn ${state.view==='kanban'?'active':''}" onclick="setView('kanban')">kanban</button>
        <button class="view-btn ${state.view==='list'?'active':''}" onclick="setView('list')">list</button>
      </div>
      <button class="add-task-btn" onclick="addTask()">+ Task</button>
    </div>
    <div class="content-area">${state.view==='kanban'?renderKanban(p):renderList(p)}</div>`;
}

function renderKanban(p){
  const cols=[{id:'todo',label:'TO DO'},{id:'inprogress',label:'IN PROGRESS'},{id:'done',label:'DONE'}];
  return `<div class="kanban-board">`+cols.map(col=>{
    const tasks=p.tasks.filter(t=>t.status===col.id);
    return `<div class="kanban-column">
      <div class="kanban-column-header">
        <div class="col-dot ${col.id}"></div>
        <span class="kanban-col-title">${col.label}</span>
        <span class="col-count">${tasks.length}</span>
      </div>
      <div class="kanban-tasks" ondragover="event.preventDefault();this.classList.add('drag-over')"
        ondragleave="this.classList.remove('drag-over')" ondrop="onDrop(event,'${col.id}')">
        ${tasks.map(t=>taskCard(t)).join('')}
        ${!tasks.length?`<div style="text-align:center;padding:18px 0;font-size:11px;color:var(--text-muted)">Drop here</div>`:''}
      </div>
    </div>`;
  }).join('')+`</div>`;
}

function taskCard(t){
  const ds=t.subtasks.filter(s=>s.done).length, tot=t.subtasks.length;
  const od=overdue(t.dueDate,t.status);
  return `<div class="task-card" draggable="true" onclick="openTask('${t.id}')"
    ondragstart="dragStart(event,'${t.id}')" ondragend="this.classList.remove('dragging')">
    <div class="task-card-title">${esc(t.title)}</div>
    <div class="task-card-meta">
      ${t.assignee?`<div class="task-assignee"><div class="avatar">${esc(av(t.assignee))}</div><span>${esc(t.assignee)}</span></div>`:''}
      ${t.dueDate?`<span class="task-due ${od?'overdue':''}">${od?'⚑ ':''}${fmtDate(t.dueDate)}</span>`:''}
    </div>
    ${tot?`<div class="subtask-bar"><div class="subtask-progress"><div class="subtask-fill" style="width:${ds/tot*100}%"></div></div><span class="subtask-text">${ds}/${tot}</span></div>`:''}
    ${t.comments.length?`<div class="comment-count">💬 ${t.comments.length}</div>`:''}
  </div>`;
}

function renderList(p){
  if(!p.tasks.length) return `<div style="text-align:center;padding:60px;color:var(--text-muted);font-size:13px">No tasks yet — click "+ Task" to add one.</div>`;

  const now = new Date();
  const thisMonthKey = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
  const groups = new Map();

  for(const t of p.tasks){
    let key, label;
    if(!t.dueDate){
      key = 'zz-nodate'; label = 'No Due Date';
    } else {
      const d = new Date(t.dueDate+'T12:00:00');
      key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
      label = d.toLocaleDateString('en-US',{month:'long',year:'numeric'}).toUpperCase();
    }
    if(!groups.has(key)) groups.set(key,{label,tasks:[]});
    groups.get(key).tasks.push(t);
  }

  const sorted = [...groups.entries()].sort((a,b)=>a[0].localeCompare(b[0]));

  function listRow(t){
    const ds=t.subtasks.filter(s=>s.done).length,tot=t.subtasks.length,od=overdue(t.dueDate,t.status);
    return `<tr onclick="openTask('${t.id}')">
      <td style="font-weight:500">${esc(t.title)}</td>
      <td><span class="status-pill ${t.status}">${STATUS_LABELS[t.status]}</span></td>
      <td>${t.assignee?`<div class="task-assignee"><div class="avatar">${esc(av(t.assignee))}</div><span style="font-size:12px">${esc(t.assignee)}</span></div>`:'<span style="color:var(--text-muted)">—</span>'}</td>
      <td style="font-family:var(--font-mono);font-size:11px;${od?'color:var(--red)':''}">${t.dueDate?fmtDate(t.dueDate):'—'}</td>
      <td style="font-family:var(--font-mono);font-size:11px">${tot?`${ds}/${tot}`:'—'}</td>
    </tr>`;
  }

  return sorted.map(([key,group])=>{
    const isPast = key !== 'zz-nodate' && key < thisMonthKey;
    const isCurrent = key === thisMonthKey;
    return `<div class="month-group">
      <div class="month-group-header${isPast?' past':''}${isCurrent?' current':''}">
        <span class="month-group-label">${group.label}</span>
        <span class="month-group-count">${group.tasks.length} task${group.tasks.length!==1?'s':''}</span>
      </div>
      <table class="list-table">
        <thead><tr><th>Task</th><th>Status</th><th>Assignee</th><th>Due</th><th>Subtasks</th></tr></thead>
        <tbody>${group.tasks.map(t=>listRow(t)).join('')}</tbody>
      </table>
    </div>`;
  }).join('');
}

function renderOverdue(){
  const groups = [];
  for(const p of state.projects){
    const tasks = p.tasks.filter(t=>overdue(t.dueDate,t.status));
    if(!tasks.length) continue;
    const cat = p.categoryId ? getCat(p.categoryId) : null;
    groups.push({p, cat, tasks});
  }

  if(!groups.length) return `
    <div class="overdue-empty">
      <div style="font-size:32px;margin-bottom:12px">&#10003;</div>
      <p>No overdue tasks — you're all caught up!</p>
    </div>`;

  function overdueRow(t){
    return `<tr onclick="openTask('${t.id}')">
      <td style="font-weight:500">${esc(t.title)}</td>
      <td><span class="status-pill ${t.status}">${STATUS_LABELS[t.status]}</span></td>
      <td>${t.assignee?`<div class="task-assignee"><div class="avatar">${esc(av(t.assignee))}</div><span style="font-size:12px">${esc(t.assignee)}</span></div>`:'<span style="color:var(--text-muted)">—</span>'}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--red)">⛑ ${fmtDate(t.dueDate)}</td>
      <td style="font-family:var(--font-mono);font-size:11px">${t.subtasks.length?`${t.subtasks.filter(s=>s.done).length}/${t.subtasks.length}`:'—'}</td>
    </tr>`;
  }

  return `
    <div class="overdue-view">
      <div class="overdue-view-header">
        <span style="color:var(--red);font-size:15px">&#9873;</span>
        <h2>Overdue Tasks</h2>
        <span class="overdue-total">${groups.reduce((n,g)=>n+g.tasks.length,0)} task${groups.reduce((n,g)=>n+g.tasks.length,0)!==1?'s':''} overdue</span>
      </div>
      ${groups.map(({p,cat,tasks})=>`
        <div class="month-group">
          <div class="month-group-header">
            <div class="project-dot" style="background:${p.color};width:7px;height:7px;border-radius:50%;flex-shrink:0"></div>
            <span class="month-group-label">${esc(p.name)}</span>
            ${cat?`<span class="cat-badge" style="margin-left:4px">${renderIcon(cat.icon,10)} ${esc(cat.name)}</span>`:''}
            <span class="month-group-count">${tasks.length} overdue</span>
          </div>
          <table class="list-table">
            <thead><tr><th>Task</th><th>Status</th><th>Assignee</th><th>Due</th><th>Subtasks</th></tr></thead>
            <tbody>${tasks.map(t=>overdueRow(t)).join('')}</tbody>
          </table>
        </div>`).join('')}
    </div>`;
}

function renderPanel(){
  const panel=document.getElementById('task-panel');
  if(!state.activeTaskId){ panel.classList.remove('open'); return; }
  const t=getTask(state.activeTaskId);
  if(!t){ panel.classList.remove('open'); return; }
  panel.classList.add('open');
  document.getElementById('panel-title').value=t.title;
  document.getElementById('panel-body').innerHTML=`
    <div class="panel-field">
      <div class="panel-field-label">Status</div>
      <select class="status-select" onchange="updateField('status',this.value)">
        <option value="todo" ${t.status==='todo'?'selected':''}>To Do</option>
        <option value="inprogress" ${t.status==='inprogress'?'selected':''}>In Progress</option>
        <option value="done" ${t.status==='done'?'selected':''}>Done</option>
      </select>
    </div>
    <div class="panel-field">
      <div class="panel-field-label">Assignee</div>
      <input class="panel-input" value="${esc(t.assignee||'')}" placeholder="Name…" onblur="updateField('assignee',this.value)">
    </div>
    <div class="panel-field">
      <div class="panel-field-label">Due Date</div>
      <input class="panel-input" type="date" value="${t.dueDate||''}" onchange="updateField('dueDate',this.value)">
    </div>
    <div class="panel-field">
      <div class="panel-field-label">Subtasks (${t.subtasks.filter(s=>s.done).length}/${t.subtasks.length})</div>
      <div class="subtask-list">${t.subtasks.map(s=>`
        <div class="subtask-item">
          <input type="checkbox" class="subtask-check" ${s.done?'checked':''} onchange="toggleSub('${s.id}',this.checked)">
          <span class="subtask-label ${s.done?'done':''}">${esc(s.title)}</span>
          <button class="subtask-del" onclick="deleteSub('${s.id}')">×</button>
        </div>`).join('')}
      </div>
      <div class="row-flex" style="margin-top:6px">
        <input class="add-sub-input" id="new-sub" placeholder="Add subtask…" onkeydown="if(event.key==='Enter')addSub()">
        <button class="small-btn" onclick="addSub()">Add</button>
      </div>
    </div>
    <div class="panel-field">
      <div class="panel-field-label">Comments (${t.comments.length})</div>
      <div class="comments-list">
        ${!t.comments.length?`<div style="font-size:12px;color:var(--text-muted)">No comments yet.</div>`:''}
        ${t.comments.map(c=>`
          <div class="comment-item">
            <div class="comment-meta">
              <div class="avatar" style="width:18px;height:18px;font-size:9px">${esc(av(c.author))}</div>
              <span class="comment-author">${esc(c.author)}</span>
              <span class="comment-time">${new Date(c.ts).toLocaleDateString('en-GB',{day:'numeric',month:'short'})}</span>
            </div>
            <div class="comment-text">${esc(c.text)}</div>
          </div>`).join('')}
      </div>
      <div class="comment-inputs">
        <input class="comment-name" id="c-name" placeholder="Name…">
        <textarea class="comment-text-input" id="c-text" placeholder="Write a comment…" rows="1"></textarea>
        <button class="small-btn" onclick="addComment()">→</button>
      </div>
    </div>`;
}

// ─── ACTIONS (async — call API then reload state) ──────────────────────────

function selectProject(id){
  if(state.view==='overdue') state.view='kanban';
  state.activeProjectId=id; state.activeTaskId=null; render();
}
function setView(v){ state.view=v; renderMain(); }
function openTask(id){ state.activeTaskId=id; renderPanel(); }
function closePanel(){ state.activeTaskId=null; renderPanel(); }

function showOverdue(){
  state.view='overdue'; state.activeTaskId=null;
  renderMain(); renderPanel(); updateOverdueBadge();
}

async function toggleCat(id){
  const c=getCat(id); if(!c) return;
  c.collapsed=!c.collapsed;
  renderSidebar(); // Optimistic update
  await apiCall('PATCH', `/categories/${id}`, { collapsed: c.collapsed });
  // No full reload needed — collapsed is purely visual
}

async function addTask(){
  const p=getActive(); if(!p) return;
  const result = await apiCall('POST', `/projects/${p.id}/tasks`, { title:'New Task' });
  if(!result) return;
  state.activeTaskId=result.id;
  await loadState();
  setTimeout(()=>{ const el=document.getElementById('panel-title'); if(el){el.focus();el.select();} },50);
}

async function updateTaskTitle(val){
  if(!state.activeTaskId) return;
  const title=val.trim()||'Untitled';
  await apiCall('PATCH', `/tasks/${state.activeTaskId}`, { title });
  await loadState();
}

async function updateField(f,v){
  if(!state.activeTaskId) return;
  await apiCall('PATCH', `/tasks/${state.activeTaskId}`, { [f]:v });
  await loadState();
}

async function addSub(){
  const inp=document.getElementById('new-sub'), v=inp?inp.value.trim():''; if(!v) return;
  if(!state.activeTaskId) return;
  await apiCall('POST', `/tasks/${state.activeTaskId}/subtasks`, { title:v });
  if(inp) inp.value='';
  await loadState();
}

async function toggleSub(sid,done){
  await apiCall('PATCH', `/subtasks/${sid}`, { done });
  await loadState();
}

async function deleteSub(sid){
  await apiCall('DELETE', `/subtasks/${sid}`);
  await loadState();
}

async function addComment(){
  const ne=document.getElementById('c-name'), te=document.getElementById('c-text');
  const author=(ne?ne.value.trim():'')||'Anonymous';
  const text=te?te.value.trim():''; if(!text) return;
  await apiCall('POST', `/tasks/${state.activeTaskId}/comments`, { author, text });
  if(te) te.value='';
  await loadState();
}

// ─── DRAG ──────────────────────────────────────────────────────────────────
function dragStart(e,tid){ dragTaskId=tid; setTimeout(()=>{ if(e.target) e.target.classList.add('dragging'); },0); }
async function onDrop(e,col){
  e.preventDefault(); e.currentTarget.classList.remove('drag-over');
  if(!dragTaskId) return;
  const tid=dragTaskId; dragTaskId=null;
  await apiCall('PATCH', `/tasks/${tid}`, { status:col });
  await loadState();
}

// ─── CATEGORY MODAL ────────────────────────────────────────────────────────
function showAddCategory(){
  _icon=CAT_ICONS[0];
  document.getElementById('modal-content').innerHTML=`
    <h3>New Category</h3>
    <div class="modal-field">
      <div class="modal-label">Name</div>
      <input class="modal-input" id="cat-name" placeholder="e.g. Engineering, Marketing, Design…" maxlength="40"
        onkeydown="if(event.key==='Enter')createCategory()">
    </div>
    <div class="modal-field">
      <div class="modal-label" style="margin-bottom:7px">Icon</div>
      <div class="icon-grid">${CAT_ICONS.map((ic,i)=>`
        <div class="icon-opt ${i===0?'selected':''}" onclick="pickIcon(this,'${ic}')">${renderIcon(ic,16)}</div>`).join('')}
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-primary" onclick="createCategory()">Create</button>
    </div>`;
  document.getElementById('modal').style.display='flex';
  setTimeout(()=>document.getElementById('cat-name').focus(),50);
}

function pickIcon(el,ic){
  _icon=ic;
  document.querySelectorAll('.icon-opt').forEach(e=>e.classList.remove('selected'));
  el.classList.add('selected');
}

async function createCategory(){
  const name=(document.getElementById('cat-name').value||'').trim();
  if(!name){ document.getElementById('cat-name').focus(); return; }
  closeModal();
  await apiCall('POST', '/categories', { name, icon:_icon });
  await loadState();
}

// ─── PROJECT MODAL ─────────────────────────────────────────────────────────
function showAddProject(presetCat){
  _color=COLORS[0];
  const opts=state.categories.map(c=>`<option value="${c.id}" ${c.id===presetCat?'selected':''}>${esc(c.name)}</option>`).join('');
  document.getElementById('modal-content').innerHTML=`
    <h3>New Project</h3>
    <div class="modal-field">
      <div class="modal-label">Name</div>
      <input class="modal-input" id="proj-name" placeholder="Project name…" maxlength="40"
        onkeydown="if(event.key==='Enter')createProject()">
    </div>
    <div class="modal-field">
      <div class="modal-label">Category</div>
      <select class="modal-select" id="proj-cat">
        <option value="">— None (uncategorized) —</option>
        ${opts}
      </select>
    </div>
    <div class="modal-field">
      <div class="modal-label" style="margin-bottom:7px">Color</div>
      <div class="color-picker">${COLORS.map((c,i)=>`
        <div class="color-swatch ${i===0?'selected':''}" style="background:${c}"
          onclick="pickColor(this,'${c}')"></div>`).join('')}
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-primary" onclick="createProject()">Create</button>
    </div>`;
  document.getElementById('modal').style.display='flex';
  setTimeout(()=>document.getElementById('proj-name').focus(),50);
}

function pickColor(el,c){
  _color=c;
  document.querySelectorAll('.color-swatch').forEach(s=>s.classList.remove('selected'));
  el.classList.add('selected');
}

async function createProject(){
  const name=(document.getElementById('proj-name').value||'').trim();
  if(!name){ document.getElementById('proj-name').focus(); return; }
  const catId=document.getElementById('proj-cat').value||null;
  closeModal();
  const result = await apiCall('POST', '/projects', { name, color:_color, categoryId:catId });
  if(result){ state.activeProjectId=result.id; }
  await loadState();
}

function closeModal(){ document.getElementById('modal').style.display='none'; }

// ─── EDIT / DELETE PROJECT ─────────────────────────────────────────────────
function showEditProject(id){
  const p = getProject(id);
  if(!p) return;
  _color = p.color;
  const opts = state.categories.map(c=>`<option value="${c.id}" ${c.id===p.categoryId?'selected':''}>${esc(c.name)}</option>`).join('');
  document.getElementById('modal-content').innerHTML=`
    <h3>Edit Project</h3>
    <div class="modal-field">
      <div class="modal-label">Name</div>
      <input class="modal-input" id="edit-proj-name" value="${esc(p.name)}" maxlength="40"
        onkeydown="if(event.key==='Enter')updateProject('${id}')">
    </div>
    <div class="modal-field">
      <div class="modal-label">Category</div>
      <select class="modal-select" id="edit-proj-cat">
        <option value="">— None (uncategorized) —</option>
        ${opts}
      </select>
    </div>
    <div class="modal-field">
      <div class="modal-label" style="margin-bottom:7px">Color</div>
      <div class="color-picker">${COLORS.map(c=>`
        <div class="color-swatch ${c===p.color?'selected':''}" style="background:${c}"
          onclick="pickColor(this,'${c}')"></div>`).join('')}
      </div>
    </div>
    <div class="modal-actions" style="justify-content:space-between">
      <button class="btn-danger" onclick="deleteProject('${id}')">${renderIcon('trash',13)} Delete</button>
      <div style="display:flex;gap:8px">
        <button class="btn-cancel" onclick="closeModal()">Cancel</button>
        <button class="btn-primary" onclick="updateProject('${id}')">Save</button>
      </div>
    </div>`;
  document.getElementById('modal').style.display='flex';
  setTimeout(()=>{ const el=document.getElementById('edit-proj-name'); if(el){el.focus();el.select();} },50);
}

async function updateProject(id){
  const name=(document.getElementById('edit-proj-name').value||'').trim();
  if(!name){ document.getElementById('edit-proj-name').focus(); return; }
  const catId=document.getElementById('edit-proj-cat').value||null;
  closeModal();
  await apiCall('PATCH', `/projects/${id}`, { name, color:_color, categoryId:catId });
  await loadState();
}

async function deleteProject(id){
  closeModal();
  if(state.activeProjectId===id){ state.activeProjectId=null; state.activeTaskId=null; }
  await apiCall('DELETE', `/projects/${id}`);
  await loadState();
}

// ─── WINDOW EXPOSURES ──────────────────────────────────────────────────────
window.showAddCategory = showAddCategory;
window.showAddProject  = showAddProject;
window.closePanel      = closePanel;
window.updateTaskTitle = updateTaskTitle;
window.closeModal      = closeModal;
window.selectProject   = selectProject;
window.toggleCat       = toggleCat;
window.setView         = setView;
window.addTask         = addTask;
window.openTask        = openTask;
window.updateField     = updateField;
window.addSub          = addSub;
window.toggleSub       = toggleSub;
window.deleteSub       = deleteSub;
window.addComment      = addComment;
window.dragStart       = dragStart;
window.onDrop          = onDrop;
window.pickIcon        = pickIcon;
window.createCategory  = createCategory;
window.pickColor       = pickColor;
window.createProject   = createProject;
window.showEditProject = showEditProject;
window.updateProject   = updateProject;
window.deleteProject   = deleteProject;
window.showOverdue     = showOverdue;
window.logout          = logout;

// ─── INIT ──────────────────────────────────────────────────────────────────
checkAuth();
