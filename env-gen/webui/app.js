'use strict';
// No framework, no innerHTML: all dynamic text goes through textContent, so file
// contents and vault names can never inject markup.
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
let current = null; // {path, example, vars, project, ops: Map(key -> op), added: []}

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
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Session expired'); }
  if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
  return data;
}

function showLogin() {
  csrf = '';
  $('app').hidden = true; $('login').hidden = false;
  $('logout').hidden = true; $('vault').hidden = true;
  $('pw').value = ''; $('code').value = '';
}

async function start() {
  const st = await api('GET', '/api/status');
  if (!st.logged_in) return showLogin();
  csrf = st.csrf;
  $('login').hidden = true; $('app').hidden = false; $('logout').hidden = false;
  const pill = $('vault'); pill.hidden = false;
  pill.textContent = 'Vault unlocked' + (st.server ? ' · ' + st.server.replace(/^https?:\/\//, '') : '');
  await loadProjects();
}

$('loginform').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginerr').textContent = '';
  try {
    await api('POST', '/api/login', { password: $('pw').value, code: $('code').value.trim() });
    $('pw').value = '';
    await start();
  } catch (err) { $('loginerr').textContent = err.message; $('pw').value = ''; }
});
$('logout').addEventListener('click', async () => { try { await api('POST', '/api/logout'); } catch (_) {} showLogin(); });

async function loadProjects() {
  const { projects } = await api('GET', '/api/projects');
  const nav = $('projects'); nav.replaceChildren();
  if (!projects.length) nav.append(el('p', { class: 'muted', text: 'No .env files found under the root.' }));
  for (const p of projects) {
    nav.append(el('div', { class: 'dir', text: p.dir === '.' ? '(root)' : p.dir }));
    for (const f of p.files) {
      const path = p.dir === '.' ? f : p.dir + '/' + f;
      nav.append(el('button', { text: f, 'data-path': path, onclick: () => openFile(path) }));
    }
  }
}

async function openFile(path) {
  document.querySelectorAll('#projects button').forEach((b) => b.setAttribute('aria-current', String(b.dataset.path === path)));
  try {
    const f = await api('GET', '/api/file?path=' + encodeURIComponent(path));
    current = { ...f, ops: new Map(), added: [], deleted: new Set() };
    if (f.example) for (const v of f.vars) current.ops.set(v.key, defaultOp(v, f.project));
    render();
  } catch (err) { $('editor').replaceChildren(el('p', { class: 'err', text: err.message })); }
}

function defaultOp(v, project) {
  if (v.suggest === 'vwgen') return { op: 'set', key: v.key, source: { kind: 'vwgen', item: project, field: v.key, length: 32, charset: 'alnum' } };
  return { op: 'set', key: v.key, source: { kind: 'literal', value: v.value || '' } };
}

// ---- source editor -----------------------------------------------------------------
function sourceEditor(initial, project, key) {
  const s = Object.assign({ kind: 'literal', value: '', item: project || '', field: key || 'password', length: 32, charset: 'alnum' }, initial || {});
  const kind = el('select', {},
    ...[['literal', 'Type a value'], ['gen', 'Generate random'], ['vw', 'Read from vault'], ['vwgen', 'Vault: read, or generate + store']]
      .map(([v, t]) => el('option', { value: v, text: t })));
  kind.value = s.kind;
  const value = el('input', { type: 'password', autocomplete: 'off', value: s.value });
  const show = el('button', { type: 'button', class: 'ghost', text: 'Show', onclick: () => { value.type = value.type === 'password' ? 'text' : 'password'; show.textContent = value.type === 'password' ? 'Show' : 'Hide'; } });
  const length = el('input', { type: 'number', min: '5', max: '128', value: String(s.length) });
  const charset = el('select', {}, ...['alnum', 'hex', 'symbols'].map((c) => el('option', { value: c, text: c })));
  charset.value = s.charset;
  const item = el('input', { list: 'items', value: s.item, autocomplete: 'off', placeholder: 'vault item name' });
  const field = el('input', { list: 'fields', value: s.field, autocomplete: 'off' });
  const rows = {
    literal: el('div', {}, el('label', { text: 'Value' }, value), show),
    gen: el('div', {}, el('label', { text: 'Length (5-128)' }, length), el('label', { text: 'Characters' }, charset)),
    vault: el('div', {}, el('label', { text: 'Vault item' }, item), el('label', { text: 'Field' }, field)),
  };
  const wrap = el('div', {}, el('label', { text: 'Source' }, kind), rows.literal, rows.gen, rows.vault);
  const sync = () => {
    const k = kind.value;
    rows.literal.hidden = k !== 'literal';
    rows.gen.hidden = !(k === 'gen' || k === 'vwgen');
    rows.vault.hidden = !(k === 'vw' || k === 'vwgen');
  };
  kind.addEventListener('change', sync); sync();
  let t;
  item.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => fillItems(item.value), 250); });
  item.addEventListener('change', () => fillFields(item.value));
  fillItems('');
  return { el: wrap, get: () => ({ kind: kind.value, value: value.value, item: item.value.trim(), field: field.value.trim() || 'password', length: parseInt(length.value, 10) || 32, charset: charset.value }) };
}

let datalistsReady = false;
function ensureDatalists() {
  if (datalistsReady) return;
  document.body.append(el('datalist', { id: 'items' }), el('datalist', { id: 'fields' }));
  datalistsReady = true;
}
async function fillItems(q) {
  ensureDatalists();
  const dl = $('items'); const names = new Set();
  try {
    const rec = await api('GET', '/api/vault/recent');
    (rec.items || []).forEach((r) => names.add(r.name));
    if (q) (await api('GET', '/api/vault/search?q=' + encodeURIComponent(q))).items.forEach((n) => names.add(n));
  } catch (_) {}
  dl.replaceChildren(...[...names].map((n) => el('option', { value: n })));
}
async function fillFields(item) {
  ensureDatalists();
  try {
    const r = await api('GET', '/api/vault/fields?item=' + encodeURIComponent(item));
    $('fields').replaceChildren(...r.fields.map((n) => el('option', { value: n })));
  } catch (_) {}
}

// ---- editor -----------------------------------------------------------------------------
function describe(op) {
  if (op.op === 'delete') return 'delete';
  if (op.op === 'rename') return 'rename to ' + op.new_key;
  const s = op.source;
  if (current.example && s.kind === 'literal') {
    const orig = current.vars.find((x) => x.key === op.key);
    if (orig && !orig.secret && (orig.value || '') === s.value) return 'keep example value';
  }
  return { literal: 'new typed value', gen: 'generated (' + s.length + ' ' + s.charset + ')', vw: 'vault: ' + s.item + '/' + s.field, vwgen: 'vault (generate if missing): ' + s.item + '/' + s.field }[s.kind];
}

function render() {
  const c = current; const box = $('editor'); box.replaceChildren();
  box.append(el('h2', { text: c.path }, c.example ? el('span', { class: 'badge', text: 'example' }) : null));
  if (c.example) box.append(el('p', { class: 'muted', text: 'Secret-looking names are pre-set to "generate and store in vault item ' + c.project + '"; everything else keeps the example value. Adjust, then create the file below.' }));
  const vars = [...c.vars, ...c.added];
  for (const v of vars) box.append(varRow(v));
  box.append(el('div', { class: 'actions' }, el('button', { text: '+ Add variable', onclick: addVariable })));

  const dir = c.path.includes('/') ? c.path.slice(0, c.path.lastIndexOf('/') + 1) : '';
  const to = c.example ? el('input', { id: 'to', value: dir + '.env' }) : null;
  const backup = el('input', { id: 'backup', value: c.project, placeholder: 'vault item (empty = no backup)' });
  const out = el('pre', { class: 'changes', id: 'result', 'aria-live': 'polite' });
  box.append(el('div', { class: 'bar' },
    to ? el('label', { text: 'Create file' }, to) : null,
    el('label', { text: 'Back up ALL variables to vault item' }, backup),
    el('button', { text: 'Preview', onclick: () => submit(true) }),
    el('button', { class: 'primary', id: 'savebtn', text: c.example ? 'Create' : 'Save', onclick: () => submit(false) })), out);
}

function varRow(v) {
  const c = current; const op = c.ops.get(v.key);
  const row = el('div', { class: 'row' });
  const shown = v.secret ? (v.has_value ? '••••••••' : '(empty)') : (v.value === undefined ? '' : v.value) || '(empty)';
  const val = el('div', { class: 'val' + (op && op.op === 'delete' ? ' del' : ''), text: v.isNew ? '(new)' : shown });
  const pend = el('div', { class: 'val pending', text: op ? describe(op) : '' });
  const actions = el('div', { class: 'actions' });
  if (v.secret && v.has_value && !v.isNew && !c.example) {
    const rev = el('button', { class: 'ghost', text: 'Reveal', onclick: async () => {
      if (rev.dataset.on) { val.textContent = '••••••••'; rev.textContent = 'Reveal'; delete rev.dataset.on; return; }
      try { val.textContent = (await api('GET', '/api/value?path=' + encodeURIComponent(c.path) + '&key=' + encodeURIComponent(v.key))).value; rev.textContent = 'Hide'; rev.dataset.on = '1'; } catch (e) { val.textContent = e.message; }
    } });
    actions.append(rev);
  }
  actions.append(
    el('button', { text: 'Change', onclick: () => openPanel(row, v) }),
    el('button', { text: 'Rename', onclick: () => { const n = prompt('New name for ' + v.key, v.key); if (n && n !== v.key) { c.ops.set(v.key, { op: 'rename', key: v.key, new_key: n }); render(); } } }),
    el('button', { class: 'danger', text: 'Delete', onclick: () => { c.ops.set(v.key, { op: 'delete', key: v.key }); render(); } }));
  if (op) actions.append(el('button', { class: 'ghost', text: 'Undo', onclick: () => { if (c.example && !v.isNew) c.ops.set(v.key, defaultOp(v, c.project)); else c.ops.delete(v.key); render(); } }));
  row.append(el('div', { class: 'key', text: v.key }), el('div', {}, val, pend), actions);
  return row;
}

function openPanel(row, v) {
  const old = row.querySelector('.panel'); if (old) { old.remove(); return; }
  const c = current; const op = c.ops.get(v.key);
  const ed = sourceEditor(op && op.op === 'set' ? op.source : null, c.project, v.key);
  const panel = el('div', { class: 'panel' }, ed.el, el('div', { class: 'actions' },
    el('button', { class: 'primary', text: 'Apply', onclick: () => { c.ops.set(v.key, { op: 'set', key: v.key, source: ed.get() }); render(); } }),
    el('button', { text: 'Cancel', onclick: () => panel.remove() })));
  row.append(panel);
}

function addVariable() {
  const key = prompt('Variable name (letters, digits, underscore)');
  if (!key) return;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) { alert('Invalid name'); return; }
  if ([...current.vars, ...current.added].some((v) => v.key === key)) { alert('Already exists'); return; }
  const v = { key, secret: false, has_value: false, isNew: true };
  current.added.push(v);
  current.ops.set(key, { op: 'set', key, source: { kind: 'literal', value: '' } });
  render();
  const rows = document.querySelectorAll('#editor .row'); const last = rows[rows.length - 1];
  if (last) openPanel(last, v);
}

async function submit(preview) {
  const c = current; const out = $('result'); out.className = 'changes'; out.textContent = '';
  const ops = [...c.ops.values()];
  const body = { path: c.path, ops, preview, backup_item: $('backup').value.trim() };
  if (c.example) body.to = $('to').value.trim();
  const btn = $('savebtn'); btn.disabled = true;
  try {
    const r = await api('POST', '/api/save', body);
    const lines = (r.changes || []).map((x) => x.sign + ' ' + x.key);
    out.textContent = (preview ? 'Preview of ' + r.target + ':\n' : 'Saved ' + r.path + ' (previous version kept as .bak).\n') + (lines.join('\n') || 'no changes');
    if (!preview) { out.className = 'changes ok'; await loadProjects(); }
  } catch (err) { out.className = 'changes err'; out.textContent = err.message; } finally { btn.disabled = false; }
}

start().catch((e) => { showLogin(); $('loginerr').textContent = e.message; });
