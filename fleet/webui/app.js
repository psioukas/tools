'use strict';
// No framework, no innerHTML: every dynamic string goes through textContent, so names
// and messages from files or the vault can never inject markup.
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of kids) if (c) n.append(c);
  return n;
};

let csrf = '';
let status = {};
let apps = [];
const states = {};            // app name -> array of target statuses
const logEntries = [];
const isAdmin = () => !!status.admin;

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-CSRF-Token'] = csrf;
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch (_) {}
  if (r.status === 401 && path !== '/api/login' && path !== '/api/admin/elevate') { showLogin(); throw new Error('Session expired'); }
  if (r.status === 403 && /admin/i.test(data.error || '')) refreshStatus();
  if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
  return data;
}

function logLine(ok, text) {
  logEntries.unshift({ ok, text, at: new Date() });
  if (logEntries.length > 200) logEntries.pop();
  if (!$('logview').hidden) renderLog();
}

// ---- session ------------------------------------------------------------------------------
function showLogin() {
  csrf = ''; status = {};
  $('app').hidden = true; $('login').hidden = false;
  for (const id of ['logout', 'vault', 'adminbtn', 'admindrop', 'adminpill']) $(id).hidden = true;
  $('pw').value = ''; $('code').value = '';
}

async function refreshStatus() {
  try {
    const st = await api('GET', '/api/status');
    if (st.logged_in) { status = st; updateAdminUI(); }
  } catch (_) {}
}

async function start() {
  const st = await api('GET', '/api/status');
  if (!st.logged_in) return showLogin();
  csrf = st.csrf; status = st;
  $('login').hidden = true; $('app').hidden = false; $('logout').hidden = false; $('vault').hidden = false;
  updateAdminUI();
  const r = await api('GET', '/api/apps');
  apps = r.apps;
  showView('overview');
}

$('loginform').addEventListener('submit', async (e) => {
  e.preventDefault(); $('loginerr').textContent = '';
  try {
    await api('POST', '/api/login', { password: $('pw').value, code: $('code').value.trim() });
    $('pw').value = '';
    await start();
  } catch (err) { $('loginerr').textContent = err.message; $('pw').value = ''; }
});
$('logout').addEventListener('click', async () => { try { await api('POST', '/api/logout'); } catch (_) {} showLogin(); });

// ---- admin elevation ---------------------------------------------------------------------------
let tick = null;
const fmt = (s) => Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');

function updateAdminUI() {
  const on = isAdmin();
  $('adminbtn').hidden = !status.admin_enabled || on;
  $('admindrop').hidden = !on;
  $('adminpill').hidden = !on;
  if (on) $('adminpill').textContent = 'Admin · ' + fmt(status.admin_seconds);
  clearInterval(tick);
  if (on) tick = setInterval(() => {
    status.admin_seconds -= 1;
    if (status.admin_seconds <= 0) { refreshStatus().then(rerender); return; }
    $('adminpill').textContent = 'Admin · ' + fmt(status.admin_seconds);
  }, 1000);
}

const dlg = $('admindlg');
function openAdminDialog() { $('adminerr').textContent = ''; $('adminpw').value = ''; $('admincode').value = ''; dlg.showModal(); $('adminpw').focus(); }
$('adminbtn').addEventListener('click', openAdminDialog);
$('admincancel').addEventListener('click', () => dlg.close());
$('adminform').addEventListener('submit', async (e) => {
  e.preventDefault(); $('adminerr').textContent = '';
  try {
    await api('POST', '/api/admin/elevate', { passphrase: $('adminpw').value, code: $('admincode').value.trim() });
    $('adminpw').value = ''; dlg.close();
    await refreshStatus(); rerender();
  } catch (err) { $('adminerr').textContent = err.message; $('adminpw').value = ''; }
});
$('admindrop').addEventListener('click', async () => { try { await api('POST', '/api/admin/drop'); } catch (_) {} await refreshStatus(); rerender(); });

// A button that needs admin: opens the sign-in dialog when not elevated.
function adminButton(text, cls, onclick) {
  const b = el('button', { class: cls + (isAdmin() ? '' : ' locked'), text, title: isAdmin() ? '' : 'Admin sign-in required' });
  b.addEventListener('click', () => { if (!isAdmin()) { if (status.admin_enabled) openAdminDialog(); else alert('Admin features are not configured on the server (run "fleet ui admin-init").'); return; } onclick(b); });
  return b;
}

// ---- views --------------------------------------------------------------------------------------
let view = 'overview';
function showView(name) {
  view = name;
  document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.view === name)));
  $('overview').hidden = name !== 'overview';
  $('vaultview').hidden = name !== 'vault';
  $('logview').hidden = name !== 'log';
  rerender();
}
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => showView(t.dataset.view)));

function rerender() {
  if (view === 'overview') renderOverview();
  else if (view === 'vault') renderVault();
  else renderLog();
}

// ---- overview ------------------------------------------------------------------------------------
const selected = {};          // "app/target" -> bool (push selection)
const opts = {};              // app -> {prune, reload}

// append only real nodes (native append() would print "null")
const put = (parent, ...kids) => { for (const k of kids) if (k) parent.append(k); return parent; };

function names(prefix, cls, list) {
  if (!list.length) return null;
  return el('div', { class: 'names' }, el('span', { class: cls, text: prefix + ' ' + list.join(', ') }));
}

function renderOverview() {
  const box = $('overview'); box.replaceChildren();
  if (!apps.length) { box.append(el('p', { class: 'muted', text: 'No apps in apps.yaml.' })); return; }
  for (const a of apps) {
    opts[a.name] = opts[a.name] || { prune: false, reload: false };
    const card = el('section', { class: 'card', 'data-app': a.name });
    const refresh = el('button', { text: 'Check', onclick: () => loadState(a.name) });
    card.append(el('div', { class: 'apphead' }, el('h2', { text: a.name }),
      el('span', { class: 'muted', text: 'vault item ' + a.vault_item }), refresh));
    const sts = states[a.name];
    for (const t of a.targets) card.append(targetRow(a, t, sts && sts.find((x) => x.target === t.name)));
    // push controls
    const o = opts[a.name];
    const prune = checkbox('Also remove variables only on the target', o.prune, (v) => { o.prune = v; });
    const reload = checkbox('Run the reload command afterwards', o.reload, (v) => { o.reload = v; });
    const out = el('div', { class: 'names', id: 'out-' + a.name, 'aria-live': 'polite' });
    card.append(el('div', { class: 'apphead', style: 'margin-top:.6rem' }, prune, reload,
      adminButton('Push selected', 'primary', () => doPush(a)), ), out);
    box.append(card);
  }
  if (!Object.keys(states).length) apps.forEach((a) => loadState(a.name));
}

function checkbox(label, checked, onchange) {
  const i = el('input', { type: 'checkbox' }); i.checked = !!checked;
  i.addEventListener('change', () => onchange(i.checked));
  return el('label', { class: 'check' }, i, label);
}

function stateText(s) {
  return { in_sync: 'in sync', drifted: 'drifted', missing: 'file missing', error: 'error' }[s] || s;
}

function targetRow(a, t, st) {
  const key = a.name + '/' + t.name;
  const sel = el('input', { type: 'checkbox', 'aria-label': 'Select ' + key });
  sel.checked = !!selected[key];
  sel.addEventListener('change', () => { selected[key] = sel.checked; });
  const head = el('div', {}, el('span', { class: 'tname', text: t.name }), el('span', { class: 'chip driver', text: t.driver }));
  if (st) head.append(el('span', { class: 'chip ' + st.state, text: stateText(st.state) }));
  const main = el('div', { class: 'main' }, head, el('div', { class: 'where', text: st ? st.where : t.where }));
  if (st) {
    if (st.error) main.append(el('div', { class: 'names' }, el('span', { class: 'rem', text: st.error })));
    put(main, names('+ missing', 'add', st.missing), names('~ changed', 'chg', st.changed), names('- only on target', 'rem', st.extra));
    if (st.runtime_differs.length) main.append(el('div', { class: 'names' }, el('span', { class: 'chg', text: 'running app differs: ' + st.runtime_differs.join(', ') })));
  }
  if (t.overrides.length) main.append(el('div', { class: 'names' }, el('span', { class: 'rem', text: 'overrides: ' + t.overrides.join(', ') })));
  const act = el('div', { class: 'actions' },
    adminButton('Push', '', () => doPush(a, [t.name])),
    el('button', { text: 'Pull…', onclick: () => planPull(a, t, row) }));
  main.append(act);
  const row = el('div', { class: 'trow', 'data-target': key }, sel, main);
  return row;
}

async function loadState(app) {
  const out = $('out-' + app);
  try {
    const r = await api('GET', '/api/state?app=' + encodeURIComponent(app));
    states[app] = r.targets;
    if (view === 'overview') renderOverview();
  } catch (e) { if (out) out.textContent = e.message; }
}

async function doPush(a, only) {
  const targets = only || a.targets.filter((t) => selected[a.name + '/' + t.name]).map((t) => t.name);
  const out = $('out-' + a.name);
  if (!targets.length) { out.textContent = 'Select at least one target first.'; return; }
  const o = opts[a.name];
  const sts = (states[a.name] || []).filter((s) => targets.includes(s.target));
  const pending = sts.filter((s) => s.state !== 'in_sync' || (o.prune && s.extra.length));
  const summary = pending.length ? pending.map((s) => s.target + ': ' + [].concat(s.missing.map((k) => '+' + k), s.changed.map((k) => '~' + k), o.prune ? s.extra.map((k) => '-' + k) : []).join(' ')).join('\n') : 'No known differences (will re-check on the server).';
  if (!confirm('Push to ' + targets.join(', ') + '?\n\n' + summary + (o.reload ? '\n\nThe reload command will run afterwards.' : ''))) return;
  out.textContent = 'Pushing…';
  try {
    const r = await api('POST', '/api/admin/push', { app: a.name, targets, prune: o.prune, reload: o.reload });
    const lines = r.results.map((x) => x.target + ': ' + (x.err ? x.err : x.error ? x.error : ('wrote' + (x.reload === 'ok' ? ', reloaded' : x.reload === 'skipped' && x.reload_hint ? ', not reloaded' : x.reload === 'none' ? ', no reload command' : ''))));
    if (r.unchanged > 0) lines.push(r.unchanged + ' target(s) already in sync');
    out.textContent = lines.join('\n'); out.style.whiteSpace = 'pre-wrap';
    r.results.forEach((x) => logLine(!x.error, 'push ' + x.app + '/' + x.target + ': ' + (x.error || 'ok')));
    await loadState(a.name);
  } catch (e) { out.textContent = e.message; logLine(false, 'push ' + a.name + ': ' + e.message); }
}

async function planPull(a, t, row) {
  const old = row.querySelector('.panel'); if (old) { old.remove(); return; }
  const panel = el('div', { class: 'panel' }, 'Checking…');
  row.append(panel);
  try {
    const p = await api('POST', '/api/pull/plan', { app: a.name, target: t.name });
    panel.replaceChildren();
    put(panel, el('div', { text: 'Import into vault item "' + p.item + '"' + (p.creating ? ' (will be created)' : '') + ':' }),
      names('+ new', 'add', p.add) || el('div', { class: 'muted', text: 'nothing new' }), names('~ different', 'chg', p.update));
    if (p.add.length + p.update.length) {
      panel.append(el('div', { class: 'actions' }, adminButton('Store in vault', 'primary', async () => {
        if (!confirm('Store ' + (p.add.length + p.update.length) + ' variable(s) from ' + a.name + '/' + t.name + ' in the vault item "' + p.item + '"?')) return;
        try {
          const r = await api('POST', '/api/admin/pull', { app: a.name, target: t.name });
          panel.replaceChildren(el('div', { class: 'ok', text: 'Stored ' + r.stored + ' variable(s) in "' + r.item + '".' }));
          logLine(true, 'pull ' + a.name + '/' + t.name + ' -> ' + r.item + ': ' + r.stored);
        } catch (e) { panel.append(el('div', { class: 'err', text: e.message })); }
      }), el('button', { text: 'Close', onclick: () => panel.remove() })));
    } else panel.append(el('div', { class: 'actions' }, el('button', { text: 'Close', onclick: () => panel.remove() })));
  } catch (e) { panel.replaceChildren(el('div', { class: 'err', text: e.message }), el('div', { class: 'actions' }, el('button', { text: 'Close', onclick: () => panel.remove() }))); }
}

// ---- vault variables -------------------------------------------------------------------------------
let vaultItem = '';
function renderVault() {
  const box = $('vaultview'); box.replaceChildren();
  const items = [...new Set(apps.flatMap((a) => [a.vault_item, ...a.targets.map((t) => t.vault_item)]))];
  const sel = el('select', { 'aria-label': 'Vault item' }, ...items.map((i) => el('option', { value: i, text: i })));
  if (vaultItem && items.includes(vaultItem)) sel.value = vaultItem; else vaultItem = sel.value;
  const table = el('div');
  const card = el('section', { class: 'card' }, el('h2', { text: 'Vault variables' }),
    el('p', { class: 'muted', text: 'Only items named in apps.yaml are shown. Values stay hidden until an admin reveals them.' }),
    el('label', { text: 'Item' }, sel), table);
  sel.addEventListener('change', () => { vaultItem = sel.value; loadVars(table); });
  box.append(card);
  loadVars(table);
}

async function loadVars(table, msg) {
  table.replaceChildren('Loading…');
  try {
    const r = await api('GET', '/api/vault/vars?item=' + encodeURIComponent(vaultItem));
    table.replaceChildren();
    const out = el('p', { class: msg && msg.err ? 'err' : 'ok', 'aria-live': 'polite', text: msg ? msg.text : '' });
    if (!r.exists) table.append(el('p', { class: 'muted', text: 'This item does not exist in the vault yet. Adding a variable creates it.' }));
    if (r.vars.length) {
      const tb = el('tbody');
      for (const v of r.vars) {
        const val = el('td', { class: 'mono', text: '(' + v.length + ' chars)' });
        const reveal = adminButton('Reveal', 'ghost', async (b) => {
          if (b.dataset.on) { val.textContent = '(' + v.length + ' chars)'; b.textContent = 'Reveal'; delete b.dataset.on; return; }
          try { val.textContent = (await api('GET', '/api/admin/value?item=' + encodeURIComponent(vaultItem) + '&key=' + encodeURIComponent(v.name))).value; b.textContent = 'Hide'; b.dataset.on = '1'; } catch (e) { out.className = 'err'; out.textContent = e.message; }
        });
        const act = (fn, okText) => async () => { try { await fn(); logLine(true, okText); await loadVars(table, { text: okText }); } catch (e) { out.className = 'err'; out.textContent = e.message; logLine(false, e.message); } };
        tb.append(el('tr', {}, el('td', { class: 'mono', text: v.name }), val, el('td', {}, el('div', { class: 'actions' }, reveal,
          adminButton('Set value', '', act(async () => {
            const nv = prompt('New value for ' + v.name + ' (it replaces the current one)');
            if (nv === null) throw new Error('cancelled');
            await api('POST', '/api/admin/set', { item: vaultItem, key: v.name, value: nv });
          }, 'set ' + v.name)),
          adminButton('Rename', '', act(async () => {
            const n = prompt('New name for ' + v.name, v.name);
            if (!n || n === v.name) throw new Error('cancelled');
            await api('POST', '/api/admin/rename', { item: vaultItem, old: v.name, new: n });
          }, 'renamed ' + v.name)),
          adminButton('Delete', 'danger', act(async () => {
            if (!confirm('Delete ' + v.name + ' from the vault item "' + vaultItem + '"? Machines keep their current files until the next push.')) throw new Error('cancelled');
            await api('POST', '/api/admin/delete', { item: vaultItem, keys: [v.name] });
          }, 'deleted ' + v.name))))));
      }
      table.append(el('table', {}, el('thead', {}, el('tr', {}, ...['Variable', 'Value', ''].map((t) => el('th', { text: t })))), tb));
    }
    // add form
    const k = el('input', { placeholder: 'NEW_VARIABLE', autocomplete: 'off', 'aria-label': 'New variable name' });
    const v = el('input', { type: 'password', placeholder: 'value', autocomplete: 'off', 'aria-label': 'New variable value' });
    table.append(el('h2', { text: 'Add or replace a variable', style: 'margin-top:1rem' }),
      el('div', { class: 'inline' }, el('label', { text: 'Name' }, k), el('label', { text: 'Value (hidden)' }, v),
        adminButton('Save to vault', 'primary', async () => {
          try { await api('POST', '/api/admin/set', { item: vaultItem, key: k.value.trim(), value: v.value }); logLine(true, 'set ' + k.value.trim()); await loadVars(table, { text: 'Saved ' + k.value.trim() }); } catch (e) { out.className = 'err'; out.textContent = e.message; }
        })), out);
  } catch (e) { table.replaceChildren(el('p', { class: 'err', text: e.message })); }
}

// ---- activity ---------------------------------------------------------------------------------------
function renderLog() {
  const box = $('logview'); box.replaceChildren();
  const ul = el('ul');
  if (!logEntries.length) ul.append(el('li', { class: 'muted', text: 'Nothing yet in this session.' }));
  for (const e of logEntries) ul.append(el('li', { class: e.ok ? 'ok' : 'err', text: e.at.toLocaleTimeString() + '  ' + e.text }));
  box.append(el('section', { class: 'card' }, el('h2', { text: 'Activity in this session' }), el('div', { class: 'log' }, ul)));
}

start().catch((e) => { showLogin(); $('loginerr').textContent = e.message; });
