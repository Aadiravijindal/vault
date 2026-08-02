/* Vault control surface — all 14 screens. Zero dependencies, no build step. */
(() => {
  const $ = (s) => document.querySelector(s);
  const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
  const esc = (s) => String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  const fmt = (n) => (typeof n === 'number' ? n.toLocaleString() : (n ?? '—'));
  const pct = (n) => (n == null ? '—' : `${Math.round(n * 100)}%`);

  let token = localStorage.getItem('vault.token') || '';
  let me = null;
  let current = 'map';

  // ---- language ----------------------------------------------------------
  // window.VaultI18n comes from /i18n-bundle.js, which the server generates
  // from src/ui/i18n.js so the string table has exactly one source.
  const i18n = new (window.VaultI18n?.I18n || class { constructor() { this.locale = 'en'; this.dir = 'ltr'; } t(k) { return k; } number(n) { return String(n ?? '—'); } date(t) { return t ? new Date(t).toISOString() : '—'; } })(
    { locale: localStorage.getItem('vault.locale') || (window.VaultI18n?.negotiate?.(navigator.language) ?? 'en') }
  );
  const t = (k, vars) => i18n.t(k, vars);

  function applyLocale(locale) {
    const { dir } = i18n.setLocale(locale);
    localStorage.setItem('vault.locale', i18n.locale);
    // Direction goes on the document, not on a stylesheet. That is what flips
    // scroll gutters, text selection and the logical CSS properties together.
    document.documentElement.lang = i18n.locale;
    document.documentElement.dir = dir;
    document.querySelectorAll('[data-i18n]').forEach((n) => { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll('[data-i18n-aria-label]').forEach((n) => { n.setAttribute('aria-label', t(n.dataset.i18nAriaLabel)); });
    if (me) renderNav();
  }

  /**
   * Announce to assistive technology.
   *
   * Two channels, because interrupting someone mid-sentence is a cost: routine
   * results go to the polite region, and only things a person must not miss —
   * a broken chain, an engaged kill switch — go to the assertive one.
   */
  function announce(message, urgent = false) {
    const region = document.getElementById(urgent ? 'alertLive' : 'live');
    if (!region) return;
    // Clearing first forces a re-announcement when the same text repeats;
    // without it, a second identical failure is silent.
    region.textContent = '';
    setTimeout(() => { region.textContent = message; }, 30);
  }

  // ---- api ---------------------------------------------------------------
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) throw Object.assign(new Error(data.message || res.statusText), { data, status: res.status });
    return data;
  }

  function toast(msg, bad) {
    const t = el('div', `toast${bad ? ' bad' : ''}`, esc(msg));
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 5200);
  }

  // ---- screens -----------------------------------------------------------
  const SCREENS = [
    { id: 'map', icon: '🗺️', name: 'Map', roles: ['platform', 'security', 'admin', 'department_head', 'risk'] },
    { id: 'connectors', icon: '🔌', name: 'Connectors', roles: ['platform', 'admin', 'security'] },
    { id: 'memory', icon: '🧠', name: 'Memory', roles: null },
    { id: 'librarian', icon: '🗂️', name: 'Librarian', roles: ['platform', 'admin', 'security', 'compliance'] },
    { id: 'journal', icon: '📓', name: 'Journal', roles: ['admin', 'platform', 'security', 'compliance', 'auditor', 'legal'] },
    { id: 'review', icon: '⏳', name: 'Needs Review', roles: null },
    { id: 'rules', icon: '📜', name: 'Rules', roles: null },
    { id: 'trace', icon: '🔍', name: 'Trace', roles: ['security', 'legal', 'compliance', 'auditor', 'platform', 'admin'] },
    { id: 'archive', icon: '📚', name: 'Archive', roles: ['legal', 'compliance', 'security', 'auditor'] },
    { id: 'observability', icon: '🔭', name: 'Observability', roles: null },
    { id: 'cases', icon: '⚖️', name: 'Cases', roles: ['legal', 'compliance', 'admin'] },
    { id: 'security', icon: '🛡️', name: 'Security', roles: ['security', 'admin', 'platform', 'risk'] },
    { id: 'comply', icon: '📋', name: 'Comply', roles: ['compliance', 'security', 'auditor', 'admin', 'legal', 'risk'] },
    { id: 'insure', icon: '🏛️', name: 'Insure', roles: ['risk', 'compliance', 'admin', 'security'] },
    { id: 'value', icon: '📈', name: 'Value', roles: null },
    { id: 'mydata', icon: '👤', name: 'My Data', roles: null },
    { id: 'admin', icon: '⚙️', name: 'Admin', roles: ['admin', 'platform', 'security', 'legal', 'works_council'] }
  ];

  const RENDER = {};

  // 🗺️ MAP
  RENDER.map = async (v) => {
    const m = await api('/api/map');
    v.append(cards([
      ['Registered agents', m.agents.length],
      ['Shadow agents', m.shadowAgents.length, m.shadowAgents.length ? 'bad' : 'good'],
      ['Folders', m.folders.length],
      ['Findings', m.findings.length, m.findings.length ? 'warn' : 'good'],
      ['Memory health', `${m.health.grade}`, m.health.score >= 80 ? 'good' : 'warn'],
      ['Insurance ready', m.insuranceReadiness.ready ? 'yes' : 'gaps', m.insuranceReadiness.ready ? 'good' : 'warn']
    ]));

    v.append(card('Agents — mode, owners, coverage, risk', table(
      ['Agent', 'Mode', 'Owners', 'Model pinned', 'Coverage', 'Risk'],
      m.agents.map((a) => [
        `${esc(a.name)}<div class="tiny dimmer">${esc(a.id)}</div>`,
        `<span class="pill ${a.mode === 'inline' ? 'g' : a.mode === 'gateway' ? 'b' : 'a'}">${a.mode}</span>`,
        `${esc(a.businessOwner || '⚠️ none')}<div class="tiny dimmer">${esc(a.technicalOwner || '⚠️ none')}</div>`,
        a.pinnedModel ? `<span class="tiny mono">${esc(a.pinnedModel)}</span>` : '<span class="warn tiny">not pinned</span>',
        `<span class="tiny">${esc(a.coverage)}</span>`,
        `<span class="pill ${a.risk.band === 'high' ? 'r' : a.risk.band === 'medium' ? 'a' : 'g'}">${a.risk.score}</span>`
      ])
    )));

    if (m.shadowAgents.length) {
      v.append(card('⚠️ Shadow agents — unregistered, observed writing or calling models', table(
        ['Identifier', 'First seen', 'Observations', 'Models', 'Finding'],
        m.shadowAgents.map((s) => [esc(s.identifier), esc(s.age), s.observations, esc((s.models || []).join(', ') || '—'), `<span class="warn tiny">${esc(s.finding)}</span>`])
      )));
    }

    v.append(card('Folders & walls', table(
      ['Folder', 'Wall', 'Business owner', 'Facts'],
      m.folders.map((f) => [`<span class="mono tiny">${esc(f.path)}</span>`, esc(f.wall), f.businessOwner ? esc(f.businessOwner) : '<span class="warn">⚠️ unowned</span>', f.facts])
    )));

    const cm = m.coverageMap;
    v.append(card('Coverage map — what Vault can and cannot see (published, deliberately)', `
      <p class="muted tiny">${esc(cm.honesty)}</p>
      ${table(['Tool', 'Convos', 'Memories', 'Can block?', 'Mode', 'Notes'],
        cm.rows.slice(0, 60).map((r) => [
          esc(r.tool),
          badge(r.convos), badge(r.memories), badge(r.canBlock),
          `<span class="tiny">${esc(r.mode)}</span>`,
          `<span class="tiny dimmer">${esc(r.notes)}</span>`
        ]))}
    `));

    if (m.findings.length) {
      v.append(card('Findings', table(['Area', 'Finding', 'Severity'],
        m.findings.map((f) => [esc(f.agentId || f.path || '—'), esc(f.finding), sev(f.severity)]))));
    }
  };

  // 🔌 CONNECTORS — browse the catalog, connect one, manage what is connected
  let connectorFilter = { category: 'all', q: '' };
  RENDER.connectors = async (v) => {
    const cat = await api('/api/connectors/catalog');

    v.append(cards([
      ['In catalog', cat.total],
      ['Connected', cat.connected, cat.connected ? 'good' : 'warn'],
      ['Inline (can block)', cat.entries.filter((e) => e.instances.some((i) => i.mode === 'inline')).length, 'good'],
      ['Watch only', cat.entries.filter((e) => e.connected && e.instances.every((i) => i.mode === 'watch')).length, 'warn']
    ]));

    const modeNote = el('div', 'card');
    modeNote.innerHTML = `<h3>Before you pick a mode</h3><p class="muted tiny">${esc(cat.note)}</p>`;
    v.append(modeNote);

    const controls = el('div', 'card');
    controls.innerHTML = `<h3>Find a connector</h3>
      <div class="row">
        <input id="connQ" placeholder="search by name or vendor…" style="flex:1" aria-label="Search connectors">
        <select id="connCat" aria-label="Filter by category">
          <option value="all">All categories</option>
          ${cat.categories.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join('')}
        </select>
      </div>`;
    v.append(controls);

    const listWrap = el('div');
    v.append(listWrap);

    const draw = () => {
      const q = connectorFilter.q.toLowerCase();
      const shown = cat.entries.filter((e) =>
        (connectorFilter.category === 'all' || e.category === connectorFilter.category)
        && (!q || e.name.toLowerCase().includes(q) || String(e.vendor).toLowerCase().includes(q)));

      listWrap.innerHTML = '';
      if (!shown.length) { listWrap.append(el('div', 'empty', 'No connector matches that search.')); return; }

      // Connected first — this screen is for managing as much as for browsing.
      shown.sort((a, b) => (b.connected ? 1 : 0) - (a.connected ? 1 : 0) || a.name.localeCompare(b.name));

      const grid = el('div', 'grid g2');
      for (const e of shown) {
        const c = el('div', 'card connector');
        const live = e.instances.filter((i) => i.status === 'connected');
        const killed = e.instances.filter((i) => i.killed);
        c.innerHTML = `
          <div class="row">
            <strong>${esc(e.name)}</strong>
            <span class="pill">${esc(e.category)}</span>
            ${e.connected
    ? `<span class="pill ${killed.length ? 'r' : 'g'}">${killed.length ? 'killed' : `connected ×${live.length}`}</span>`
    : '<span class="pill">not connected</span>'}
            <span class="spacer"></span>
            <span class="tiny dimmer">${esc(e.vendor)}</span>
          </div>
          <div class="tiny muted" style="margin-top:8px">${esc(e.auth)} · ${e.setupMinutes ?? '?'} min setup · ${esc(e.rateLimit)}</div>
          <div class="tiny" style="margin-top:8px"><span class="dimmer">pulls:</span> ${esc((e.pulls || []).join(', ') || '—')}</div>
          <div class="tiny warn" style="margin-top:4px"><span class="dimmer">cannot pull:</span> ${esc((e.cannotPull || []).join(', ') || '—')}</div>
          <div class="row" style="margin-top:12px">
            ${e.modes.map((m) => `<span class="pill ${m === 'inline' ? 'g' : m === 'gateway' ? 'b' : 'a'}">${esc(m)}</span>`).join('')}
            <span class="spacer"></span>
            <button class="ghost" data-open="${esc(e.id)}" type="button">${e.connected ? 'Manage' : 'Connect'}</button>
          </div>
          ${e.instances.length ? `<div class="sep"></div>${e.instances.map((i) => `
            <div class="row tiny" style="margin-bottom:6px">
              <span class="mono dimmer">${esc(i.id)}</span>
              <span class="pill ${i.mode === 'inline' ? 'g' : i.mode === 'gateway' ? 'b' : 'a'}">${esc(i.mode)}</span>
              <span class="${i.killed ? 'bad' : i.status === 'connected' ? 'good' : 'dimmer'}">${esc(i.killed ? 'killed' : i.status)}</span>
              <span class="dimmer">${fmt(i.eventsIngested)} events</span>
              ${i.openGaps ? `<span class="bad">${i.openGaps} gap(s)</span>` : ''}
              <span class="spacer"></span>
              <span class="dimmer">${esc(i.owner || 'unowned')}</span>
            </div>`).join('')}` : ''}`;
        grid.append(c);
      }
      listWrap.append(grid);
      listWrap.querySelectorAll('[data-open]').forEach((n) =>
        n.addEventListener('click', () => openConnector(cat.entries.find((x) => x.id === n.dataset.open))));
    };

    const qEl = controls.querySelector('#connQ');
    const catEl = controls.querySelector('#connCat');
    qEl.value = connectorFilter.q;
    catEl.value = connectorFilter.category;
    qEl.addEventListener('input', () => { connectorFilter.q = qEl.value; draw(); });
    catEl.addEventListener('change', () => { connectorFilter.category = catEl.value; draw(); });
    draw();
  };

  /** Connect a new instance, or manage the ones already connected. */
  function openConnector(entry) {
    if (!entry) return;
    const body = el('div');
    body.innerHTML = `
      <p class="muted tiny">${esc(entry.vendor)} · ${esc(entry.auth)} · scopes requested: ${esc((entry.scopes || []).join(', ') || 'none')}</p>
      <div class="warn tiny" style="margin:10px 0">Cannot pull: ${esc((entry.cannotPull || []).join(', ') || '—')}</div>`;

    for (const m of entry.modesSupported || []) {
      body.append(el('div', 'item', `<strong class="tiny">${esc(m.name)}</strong>
        <div class="tiny muted" style="margin-top:4px">${esc(m.how)}</div>
        <div class="tiny dimmer" style="margin-top:4px">${esc(m.power)}</div>`));
    }

    if (entry.instances.length) {
      const mgmt = el('div');
      mgmt.innerHTML = '<h4>Connected instances</h4>';
      for (const i of entry.instances) {
        const row = el('div', 'item');
        row.innerHTML = `
          <div class="row">
            <span class="mono tiny">${esc(i.id)}</span>
            <span class="pill ${i.mode === 'inline' ? 'g' : i.mode === 'gateway' ? 'b' : 'a'}">${esc(i.mode)}</span>
            <span class="tiny ${i.killed ? 'bad' : 'good'}">${esc(i.killed ? 'killed' : i.status)}</span>
            <span class="spacer"></span>
            <span class="tiny dimmer">${esc(i.owner || 'unowned')} / ${esc(i.technicalOwner || 'unowned')}</span>
          </div>
          <div class="tiny dimmer" style="margin-top:6px">${fmt(i.eventsIngested)} events · $${(i.costUsd ?? 0).toFixed(4)}${i.openGaps ? ` · <span class="bad">${i.openGaps} open gap(s)</span>` : ''}</div>
          <div class="row" style="margin-top:10px">
            ${i.killed
    ? `<button class="ghost" data-act="revive" data-id="${esc(i.id)}" type="button">Revive</button>`
    : `<button class="ghost" data-act="kill" data-id="${esc(i.id)}" type="button">Kill switch</button>`}
            <button class="ghost" data-act="disconnect" data-id="${esc(i.id)}" type="button">Disconnect</button>
          </div>`;
        mgmt.append(row);
      }
      mgmt.querySelectorAll('[data-act]').forEach((btn) => btn.addEventListener('click', async () => {
        const act = btn.dataset.act;
        const reason = prompt(`Reason for ${act}? (recorded in the ledger against your name)`);
        if (!reason) return;
        try {
          await api(`/api/connectors/${encodeURIComponent(btn.dataset.id)}/${act}`, { method: 'POST', body: { reason } });
          toast(`${act} recorded`);
          closeSheet();
          go('connectors');
        } catch (e) { toast(e.message, true); }
      }));
      body.append(mgmt);
    }

    const form = el('form', 'item');
    form.innerHTML = `
      <h4>${entry.connected ? 'Connect another instance' : 'Connect'}</h4>
      <label>Mode</label>
      <select name="mode">${entry.modes.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join('')}</select>
      <label>Business owner</label>
      <input name="owner" placeholder="who answers for this connector existing" required>
      <label>Technical owner</label>
      <input name="technicalOwner" placeholder="who gets paged when it breaks" required>
      <p class="tiny dimmer">Both are required. The same person may hold both roles — what is not allowed is neither being anybody.</p>
      <button type="submit">Connect</button>`;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = new FormData(form);
      try {
        await api('/api/connectors', {
          method: 'POST',
          body: {
            catalogId: entry.id, mode: f.get('mode'),
            owner: f.get('owner'), technicalOwner: f.get('technicalOwner')
          }
        });
        toast(`${entry.name} connected in ${f.get('mode')} mode`);
        closeSheet();
        go('connectors');
      } catch (e) { toast(e.message, true); }
    });
    body.append(form);

    openSheet(entry.name, body);
  }

  // 🧠 MEMORY
  RENDER.memory = async (v) => {
    const tabs = tabbar(['Ask', 'Facts', 'Golden facts', 'Folders', 'Entities', 'Search'], async (i, body) => {
      body.innerHTML = '';
      if (i === 0) { body.append(askPanel()); return; }
      i -= 1;                                   // 'Ask' is new; the rest shift
      return renderMemoryTab(i, body);
    });
    v.append(tabs);
  };

  // 🗂️ LIBRARIAN — the model organising the file room
  RENDER.librarian = async (v) => {
    const s = await api('/api/librarian');

    v.append(cards([
      ['Model', s.model?.available ? (s.model.local ? 'local' : s.model.provider) : 'not configured', s.model?.available ? 'good' : 'warn'],
      ['Learned entries', s.memory?.size?.entries ?? 0],
      ['Folders proposed', s.proposals.open, s.proposals.open ? 'warn' : 'good'],
      ['Flagged for a human', s.notices.open, s.notices.open ? 'warn' : 'good'],
      ['Distinct tags', s.tags.distinct]
    ]));

    for (const w of s.warnings ?? []) {
      v.append(card('⚠️ Facts filed here can be read by nobody',
        `<p class="tiny warn"><span class="mono">${esc(w.path)}</span> — ${esc(w.detail)}.</p>
         <p class="tiny dimmer" style="margin-top:6px">Writes into it succeed and the ledger stays clean, which is why this does not
         look like a fault from any single operation. Fix: ${esc(w.fix)}.</p>`));
    }

    const head = el('div', 'card');
    head.innerHTML = `<h3>The librarian</h3>
      <p class="tiny dimmer">${esc(s.statement)}</p>
      <div class="row" style="margin-top:12px">
        <button id="organizeNow" style="margin:0" type="button">Organise now</button>
        <span class="tiny dimmer">Runs off the write path. Facts are filed instantly by the rules and tidied afterwards — never unprotected in between.</span>
      </div>
      <div id="organizeOut" style="margin-top:12px" aria-live="polite"></div>`;
    v.append(head);
    head.querySelector('#organizeNow').addEventListener('click', async () => {
      const out = head.querySelector('#organizeOut');
      out.innerHTML = '<div class="loading">organising…</div>';
      try {
        const r = await api('/api/librarian/organize', { method: 'POST', body: { limit: 50 } });
        out.innerHTML = `<div class="tiny">${esc(r.statement)}</div>`;
        toast(r.ran ? `${r.considered} considered · ${r.moved.length} moved · ${r.proposed.length} proposed` : r.reason);
        if (r.ran) go('librarian');
      } catch (e) { out.innerHTML = ''; out.append(el('div', 'empty bad', esc(e.message))); }
    });

    // Proposals — the whole point is that these are decisions, not notifications.
    v.append(card(`Folders the librarian wants — ${s.proposals.open} awaiting a decision`,
      s.proposals.items.length
        ? `<p class="tiny dimmer" style="margin-bottom:12px">${esc(s.proposals.note)}</p>` + table(
          ['Proposed folder', 'Why', 'Wanted for', 'Decide'],
          s.proposals.items.map((p) => [
            `<span class="mono tiny">${esc(p.path)}</span>${p.parentExists ? '' : '<div class="warn tiny">parent does not exist</div>'}`,
            `<span class="tiny">${esc(p.because)}</span>${p.suggestedWall ? `<div class="tiny dimmer">model suggested: ${esc(p.suggestedWall)} — you set the real one</div>` : ''}`,
            `<span class="pill">${p.wantedFor}</span>`,
            `<button class="tiny" data-approve="${esc(p.id)}" data-path="${esc(p.path)}" type="button">Approve</button>
             <button class="tiny danger" data-reject="${esc(p.id)}" type="button">Reject</button>`
          ]))
        : '<div class="empty">Nothing proposed. The librarian files into folders that already exist and only asks when none of them fit.</div>'));

    v.querySelectorAll('[data-approve]').forEach((n) => n.addEventListener('click', () => approveFolder(n.dataset.approve, n.dataset.path)));
    v.querySelectorAll('[data-reject]').forEach((n) => n.addEventListener('click', async () => {
      const reason = prompt('Why is this folder not wanted? The librarian will propose it again otherwise, and nobody will know why it was refused.');
      if (!reason) return;
      await api(`/api/librarian/proposals/${n.dataset.reject}/reject`, { method: 'POST', body: { reason } });
      toast('rejected'); go('librarian');
    }));

    // Notices — messages to a human, never actions taken on the record.
    v.append(card(`Flagged for a human — ${s.notices.open} open`,
      (s.notices.items.length
        ? table(['', 'What', 'Where', 'When'], s.notices.items.map((n) => [
          n.level === 'urgent' ? '<span class="pill r">today</span>' : '<span class="pill a">this week</span>',
          `<div>${esc(n.why)}</div>${n.excerpt ? `<div class="tiny dimmer">"${esc(n.excerpt)}"</div>` : ''}`,
          `<span class="mono tiny">${esc(n.folder ?? '—')}</span>`,
          `<span class="tiny dimmer">${esc(String(n.createdAt).slice(0, 16).replace('T', ' '))}</span>`
        ]))
        : '<div class="empty">Nothing flagged. A notice is a message to a human — raising one never changes the record it is about.</div>')
      + (s.notices.withheld
        ? `<p class="tiny warn" style="margin-top:10px">${esc(s.notices.note ?? '')}</p>`
          + table(['', 'Folder', 'Waiting', 'Latest'], (s.notices.withheldSummary ?? []).map((r) => [
            r.urgent ? '<span class="pill r">urgent</span>' : '<span class="pill a">—</span>',
            `<span class="mono tiny">${esc(r.folder)}</span>`,
            `<span class="tiny">${r.total} notice(s)${r.urgent ? `, ${r.urgent} urgent` : ''}</span>`,
            `<span class="tiny dimmer">${esc(String(r.latestAt).slice(0, 16).replace('T', ' '))}</span>`
          ]))
        : '')));

    // What it has learned — the file that makes it fast.
    if (s.memory) {
      const m = s.memory;
      v.append(card('What filing has learned about this company',
        `<p class="tiny dimmer">${esc(m.statement)}</p>
         <div class="row tiny" style="margin-top:10px">
           <span class="pill ${m.integrity.ok ? 'g' : 'r'}">${m.integrity.ok ? 'intact' : 'ALTERED'}</span>
           <span class="dimmer mono">${esc(m.format)}</span>
           <span class="dimmer">${m.size.tokens} vocabulary · ${m.size.clients} entities · ${m.revisions} revisions${m.bytesOnDisk ? ` · ${m.bytesOnDisk} bytes` : ''}</span>
         </div>`
        + (m.topClients?.length ? table(['Client or entity', 'Observations', 'Usually filed in'],
          m.topClients.map((c) => [esc(c.name), Math.round(c.observations), `<span class="mono tiny">${esc(c.usualFolder ?? '—')}</span>`])) : '')
        + (m.recentCorrections?.length ? `<div class="tiny dimmer" style="margin-top:10px">Recent human corrections — weighted far above anything the model decided alone:</div>`
          + table(['When', 'From', 'To', 'By'], m.recentCorrections.map((c) => [
            `<span class="tiny dimmer">${esc(String(c.at).slice(0, 10))}</span>`,
            `<span class="mono tiny">${esc(c.from)}</span>`, `<span class="mono tiny">${esc(c.to)}</span>`, esc(c.by)
          ])) : '')));
    }

    if (s.tags.top.length) {
      v.append(card(`Tags in use (${s.tags.distinct})`,
        `<p class="tiny dimmer">The librarian invents these freely. A tag is an index, not a wall — every read through one is still checked against the folder wall underneath, which is exactly why it cannot invent a folder.</p>
         <div class="row" style="flex-wrap:wrap;gap:6px;margin-top:10px">
           ${s.tags.top.map((t) => `<span class="pill">${esc(t)}</span>`).join('')}
         </div>`));
    }
  };

  function approveFolder(id, path) {
    const c = el('div');
    c.innerHTML = `<p class="tiny dimmer">Approving creates <span class="mono">${esc(path)}</span>. You set the wall, not the model — an access boundary a model chose is one nobody chose.</p>
      <form id="approveForm">
        <label>Who may READ it <input name="read" placeholder="sales, support — blank inherits the parent"></label>
        <label>Who may WRITE it <input name="write" placeholder="sales — blank inherits the parent"></label>
        <label><input type="checkbox" name="adminOnly"> Administrator-only (named administrators read it; nothing automated moves a fact out)</label>
        <label>Why are you approving this? <input name="reason" required placeholder="an auditor will be shown this, and your name"></label>
        <button type="submit">Create folder</button>
      </form>`;
    c.querySelector('#approveForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      const split = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
      try {
        await api(`/api/librarian/proposals/${id}/approve`, {
          method: 'POST',
          body: {
            reason: f.get('reason'),
            read: split(f.get('read')).length ? split(f.get('read')) : null,
            write: split(f.get('write')).length ? split(f.get('write')) : null,
            adminOnly: f.get('adminOnly') === 'on'
          }
        });
        closeSheet(); toast(`created ${path}`); go('librarian');
      } catch (e) { toast(e.message, true); }
    });
    openSheet(`Approve ${path}`, c);
  }

  // 📓 JOURNAL — the complete record of who did what
  RENDER.journal = async (v) => {
    const { entries, stats } = await api('/api/journal?limit=200');

    v.append(cards([
      ['Recorded actions', stats.entries],
      ['Distinct actors', stats.actors],
      ['Refusals', stats.refusals, stats.refusals ? 'warn' : 'good'],
      ['Subjects touched', stats.subjects],
      ['Chain', stats.integrity.ok ? 'intact' : 'BROKEN', stats.integrity.ok ? 'good' : 'bad']
    ]));

    const tools = el('div', 'card');
    tools.innerHTML = `<h3>The complete record</h3>
      <p class="tiny dimmer">${esc(stats.statement)}</p>
      <div class="row" style="margin-top:12px">
        <input id="jSubject" placeholder="fact id — see everything that ever happened to one record" style="flex:1">
        <button id="jGo" style="margin:0" type="button">Open dossier</button>
        <button id="jRefusals" style="margin:0" type="button">Refusals only</button>
        <button id="jExport" style="margin:0" type="button">Export for an auditor</button>
      </div>`;
    v.append(tools);
    tools.querySelector('#jGo').addEventListener('click', () => {
      const s = tools.querySelector('#jSubject').value.trim();
      if (s) openDossier(s);
    });
    tools.querySelector('#jRefusals').addEventListener('click', async () => {
      const r = await api('/api/journal/refusals');
      openSheet('Refused', el('div', '', `<p class="tiny dimmer">${esc(r.note)}</p>` + (r.refusals.length ? table(
        ['When', 'Who', 'What', 'Subject', 'Reason'],
        r.refusals.map((e) => [
          `<span class="tiny dimmer">${esc(e.atIso.slice(0, 16).replace('T', ' '))}</span>`,
          esc(e.actor?.id ?? '—'), `<span class="pill r">${esc(e.action)}</span>`,
          `<span class="mono tiny">${esc(e.subject ?? '—')}</span>`,
          `<span class="tiny">${esc(e.why ?? e.outcome ?? '')}</span>`
        ])) : '<div class="empty">Nothing has been refused.</div>')));
    });
    tools.querySelector('#jExport').addEventListener('click', () => exportJournal());

    v.append(card(`Recent activity (${entries.length})`, entries.length ? table(
      ['When', 'Who', 'Action', 'Subject', 'Where', 'Why'],
      entries.map((e) => [
        `<span class="tiny dimmer">${esc(e.atIso.slice(0, 16).replace('T', ' '))}</span>`,
        `${esc(e.actor?.id ?? '—')}<div class="tiny dimmer">${esc(e.actor?.kind ?? '')}</div>`,
        `<span class="pill ${e.refusal ? 'r' : ''}">${esc(e.action)}</span>`,
        `<span class="clickable mono tiny" data-dossier="${esc(e.subject ?? '')}">${esc(e.subject ?? '—')}</span>`,
        `<span class="mono tiny">${esc(e.where?.folder ?? '—')}</span>`,
        `<span class="tiny">${esc((e.why ?? '').slice(0, 70))}</span>`
      ])) : '<div class="empty">Nothing recorded yet.</div>'));

    v.querySelectorAll('[data-dossier]').forEach((n) => n.addEventListener('click', () => {
      if (n.dataset.dossier) openDossier(n.dataset.dossier);
    }));
  };

  async function openDossier(subject) {
    let d;
    try { d = await api(`/api/journal/${encodeURIComponent(subject)}`); }
    catch (e) { return toast(e.message, true); }
    const c = el('div');
    c.innerHTML = `${d.fact ? `<div class="item"><div class="claim">${esc(d.fact.claim)}</div>
        <div class="tiny dimmer" style="margin-top:6px">${esc(d.fact.folder)} · ${esc(d.fact.sensitivity)} · v${d.fact.version} · ${esc(d.fact.status)}
        ${d.fact.locked ? ' · 🔒 locked' : ''}${d.fact.golden ? ' · ★ golden' : ''}
        ${(d.fact.tags || []).map((t) => ` · ${esc(t)}`).join('')}</div></div>` : ''}
      <p class="tiny">${esc(d.narrative)}</p>
      ${table(['When', 'Who', 'Action', 'Where', 'Detail'], d.timeline.map((t) => [
    `<span class="tiny dimmer">${esc(t.at.slice(0, 19).replace('T', ' '))}</span>`,
    `${esc(t.who)}<div class="tiny dimmer">${esc(t.kind)}</div>`,
    `<span class="pill ${t.allowed === false ? 'r' : ''}">${esc(t.action)}</span>`,
    `<span class="mono tiny">${esc(t.where ?? '—')}</span>`,
    `${t.why ? `<div class="tiny">${esc(t.why)}</div>` : ''}
         ${(t.changed || []).map((ch) => `<div class="tiny mono dimmer">${esc(ch.field)}: ${esc(JSON.stringify(ch.from))} → ${esc(JSON.stringify(ch.to))}</div>`).join('')}
         ${t.ledgerSeq ? `<div class="tiny dimmer">ledger #${t.ledgerSeq}</div>` : ''}`
  ]))}`;
    openSheet(`Everything that happened to ${subject}`, c);
  }

  function exportJournal() {
    const c = el('div');
    c.innerHTML = `<p class="tiny dimmer">A signed bundle that states its own completeness. A filtered extract presented as a full one is the oldest way to mislead an auditor using nothing but true statements, so the filters you choose are written into the bundle.</p>
      <form id="exportForm">
        <label>Why is this being taken? <input name="reason" required placeholder="e.g. FCA information request 2026-114"></label>
        <label>Limit to one subject (optional) <input name="subject" placeholder="blank = the complete journal"></label>
        <label>Limit to one actor (optional) <input name="actor"></label>
        <button type="submit">Generate bundle</button>
      </form>
      <div id="exportOut" style="margin-top:12px"></div>`;
    c.querySelector('#exportForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      try {
        const b = await api('/api/journal/export', {
          method: 'POST',
          body: { reason: f.get('reason'), subject: f.get('subject') || null, actor: f.get('actor') || null }
        });
        const blob = new Blob([JSON.stringify(b, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `vault-journal-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        c.querySelector('#exportOut').innerHTML =
          `<div class="tiny ${b.completeness.full ? '' : 'warn'}">${esc(b.completeness.statement)}</div>
           <div class="tiny dimmer" style="margin-top:6px">${b.signature ? 'Signed with the customer key.' : 'UNSIGNED — no customer signing key is configured.'}</div>`;
      } catch (e) { toast(e.message, true); }
    });
    openSheet('Export the audit record', c);
  }

  /**
   * Ask a question of the memory.
   *
   * Retrieval is the ordinary gated search, so answers are already scoped to
   * this person's clearance. The panel deliberately shows the withheld count
   * and every citation next to the prose: an answer nobody can check is the
   * thing this product exists not to produce.
   */
  function askPanel() {
    const c = el('div', 'card');
    c.innerHTML = `<h3>Ask the memory — answers cite the facts they came from</h3>
      <div class="row">
        <input id="askQ" placeholder="what did we promise this customer…" style="flex:1" aria-label="Your question">
        <button id="askGo" style="margin:0" type="button">Ask</button>
      </div>
      <p class="tiny dimmer" style="margin-top:8px">Only facts you are cleared to read are used. Anything withheld is counted, never silently dropped.</p>
      <div id="askOut" style="margin-top:16px" aria-live="polite"></div>`;

    const run = async () => {
      const q = c.querySelector('#askQ').value.trim();
      if (!q) return;
      const out = c.querySelector('#askOut');
      out.innerHTML = '<div class="loading">thinking…</div>';
      try {
        const r = await api('/api/ask', { method: 'POST', body: { question: q } });
        out.innerHTML = '';

        const head = el('div', 'row tiny dimmer');
        head.innerHTML = `<span>${r.retrieved} fact(s) used</span>
          ${r.withheld ? `<span class="warn">${r.withheld} withheld — exists, but not for your clearance</span>` : ''}
          <span class="spacer"></span>
          <span class="pill ${r.source === 'model' ? 'b' : ''}">${esc(r.source)}</span>`;
        out.append(head);

        const ans = el('div', 'item');
        ans.innerHTML = `<div class="claim">${esc(r.answer)}</div>
          ${r.caveat ? `<div class="warn tiny" style="margin-top:8px">⚠️ ${esc(r.caveat)}</div>` : ''}
          ${r.note ? `<div class="tiny dimmer" style="margin-top:6px">${esc(r.note)}</div>` : ''}`;
        out.append(ans);

        if (r.citations?.length) {
          out.append(card('Facts this answer was built from', table(
            ['Fact', 'Type', 'Sensitivity'],
            r.citations.map((x) => [
              `<span class="clickable" data-fact="${esc(x.id)}">${esc(x.claim)}</span><div class="tiny dimmer mono">${esc(x.id)}</div>`,
              `<span class="tiny">${esc(x.badge ?? '')}</span>`,
              `<span class="pill">${esc(x.sensitivity ?? '')}</span>`
            ])
          )));
          out.querySelectorAll('[data-fact]').forEach((n) =>
            n.addEventListener('click', () => openFact(n.dataset.fact)));
        }
      } catch (e) {
        out.innerHTML = '';
        out.append(el('div', 'empty bad', esc(e.message)));
      }
    };
    c.querySelector('#askGo').addEventListener('click', run);
    c.querySelector('#askQ').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') run(); });
    return c;
  }

  async function renderMemoryTab(i, body) {
    {
      body.innerHTML = '';
      if (i === 0) {
        const facts = await api('/api/facts?limit=200');
        body.append(card(`Facts (${facts.length})`, facts.length ? table(
          ['Claim', 'Type', 'Folder', 'Sensitivity', 'Status', 'Reads'],
          facts.map((f) => [
            `<span class="clickable" data-fact="${esc(f.id)}">${esc(f.claim)}</span>`
            + `<div class="tiny dimmer mono">${esc(f.id)}${f.locked ? ' · 🔒 locked' : ''}</div>`
            + ((f.tags || []).length ? `<div class="row tiny" style="flex-wrap:wrap;gap:4px;margin-top:4px">${f.tags.map((t) => `<span class="pill">${esc(t)}</span>`).join('')}</div>` : ''),
            claimBadge(f),
            `<span class="tiny mono">${esc(f.folder || '—')}</span>`,
            `<span class="pill">${esc(f.sensitivity)}</span>`,
            statusBadge(f.status),
            f.readCount
          ])
        ) : '<div class="empty">No facts yet — ingest a conversation.</div>'));
        body.querySelectorAll('[data-fact]').forEach((n) => n.addEventListener('click', () => openFact(n.dataset.fact)));
      } else if (i === 1) {
        const g = await api('/api/golden');
        const due = await api('/api/golden/due');
        if (due.length) body.append(card('★ Re-attestation due', table(['Fact', 'Owner', 'Message'], due.map((d) => [esc(d.claim), esc(d.owner || '—'), `<span class="warn tiny">${esc(d.message)}</span>`]))));
        body.append(card(`★ Golden facts (${g.length}) — human-authored, signed, unoverwritable by any AI`,
          g.length ? table(['Claim', 'Approved by', 'Folder', 'Sensitivity', 'Version'],
            g.map((f) => [`<span class="gold">${esc(f.claim)}</span>`, `${esc(f.approvedBy)}<div class="tiny dimmer">${esc(f.approverRole || '')}</div>`, `<span class="tiny mono">${esc(f.folder)}</span>`, esc(f.sensitivity), f.version]))
          : '<div class="empty">No golden facts. This is the strongest single control — define your policies, ceilings and legal names.</div>'));
      } else if (i === 2) {
        const folders = await api('/api/folders');
        body.append(card('Folder tree', table(['Path', 'Read', 'Write', 'Owners', 'Retention'],
          folders.filter((f) => !f.archived).map((f) => [
            `<span class="mono tiny">${esc(f.path)}</span> ${f.adminOnly ? '🔒' : ''}${f.hardWall ? '🧱' : ''}${f.privileged ? ' ⚖️' : ''}`,
            f.adminOnly
              ? '<span class="tiny warn">named administrators only</span>'
              : `<span class="tiny">${esc((f.read || []).join(', '))}</span>`,
            `<span class="tiny">${esc((f.write || []).join(', '))}</span>`,
            f.businessOwner ? esc(f.businessOwner) : '<span class="warn tiny">unowned</span>',
            `<span class="tiny dimmer">${esc(f.retention || 'inherited')}</span>`
          ]))));
      } else if (i === 3) {
        const ents = await api('/api/entities');
        body.append(card(`Entities (${ents.length}) — one thing, one entity, across every department`,
          ents.length ? table(['Name', 'Type', 'Aliases', 'Facts'],
            ents.map((e) => [esc(e.name), `<span class="pill">${esc(e.type)}</span>`, `<span class="tiny dimmer">${esc((e.aliases || []).join(', ') || '—')}</span>`, e.factCount]))
            : '<div class="empty">No entities yet.</div>'));
      } else {
        body.append(searchPanel());
      }
    }
  }

  function searchPanel() {
    const c = el('div', 'card');
    c.innerHTML = `<h3>Vault Search — permissions checked at query time, provenance on every result</h3>
      <div class="row"><input id="q" placeholder="what do we know about…" style="flex:1"><button id="go" style="margin:0">Search</button></div>
      <div id="results" style="margin-top:16px"></div>`;
    const run = async () => {
      const out = c.querySelector('#results');
      out.innerHTML = '<div class="loading">searching…</div>';
      try {
        const r = await api('/api/search', { method: 'POST', body: { query: c.querySelector('#q').value, naturalLanguage: true, limit: 25 } });
        out.innerHTML = '';
        out.append(el('div', 'muted tiny', `${r.results.length} returned · ${r.withheld} withheld${r.withheldReasons.length ? ` (${r.withheldReasons.map((w) => esc(w.reason)).join(', ')})` : ''} · ${r.tookMs}ms`));
        if (r.answer) out.append(el('pre', null, esc(r.answer.text) + (r.answer.caveat ? `\n\n⚠️ ${esc(r.answer.caveat)}` : '')));
        for (const f of r.results) {
          if (f.kind !== 'fact') continue;
          const d = el('div', 'item');
          d.innerHTML = `<div class="claim">${f.golden ? '<span class="gold">★ GOLDEN</span> ' : ''}${esc(f.claim)}</div>
            <div class="tiny muted">${esc(f.badge)} · ${esc(f.provenance.saidBy || 'unattributed')} · ${esc(f.provenance.channel)} · ${esc(f.provenance.age)} ago · ${esc(f.folder || '')}</div>
            ${f.warning ? `<div class="bad tiny" style="margin-top:6px">→ ${esc(f.warning)}</div>` : ''}
            ${f.stale ? `<div class="warn tiny" style="margin-top:6px">→ stale: ${esc(f.staleReason)}</div>` : ''}`;
          out.append(d);
        }
        if (!r.results.length) out.append(el('div', 'empty', 'Nothing matched — and nothing was invented to fill the gap.'));
      } catch (e) { out.innerHTML = `<div class="bad">${esc(e.message)}</div>`; }
    };
    c.querySelector('#go').addEventListener('click', run);
    c.querySelector('#q').addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    return c;
  }

  // ⏳ NEEDS REVIEW
  RENDER.review = async (v) => {
    const [items, stats] = await Promise.all([api('/api/review?status=open'), api('/api/review/stats')]);
    v.append(cards([
      ['Open', stats.open],
      ['High', stats.byPriority.high, stats.byPriority.high ? 'bad' : 'good'],
      ['Past SLA', stats.breaching, stats.breaching ? 'bad' : 'good'],
      ['Oldest', stats.oldest || '—'],
      ['SLA compliance', `${stats.slaCompliance}%`, stats.slaCompliance >= 90 ? 'good' : 'warn'],
      ['Closed 7d', stats.closedLast7Days]
    ]));
    if (stats.volumeAlarm?.alarm) {
      v.append(card('⚠️ Volume alarm', `<p class="bad">${esc(stats.volumeAlarm.message)}</p>`));
    }
    const sug = await api('/api/review/suggestions').catch(() => []);
    if (sug.length) {
      v.append(card('Auto-approve suggestions — suggests, never acts alone', table(['Pattern', 'Approvals', 'Rate', 'Suggestion'],
        sug.map((s) => [`<span class="tiny mono">${esc(s.pattern)}</span>`, `${s.approvals}/${s.total}`, pct(s.rate), `<span class="tiny">${esc(s.suggestion)}</span>`]))));
    }
    if (!items.length) { v.append(el('div', 'empty', 'Queue empty. Nothing is waiting on a human.')); return; }
    for (const r of items) {
      const d = el('div', `item ${r.priority}`);
      d.innerHTML = `
        <div class="row"><span class="pill ${r.priority === 'high' ? 'r' : r.priority === 'medium' ? 'a' : ''}">${r.priority.toUpperCase()}</span>
          <span class="tiny dimmer">${esc(r.age)} old · SLA ${r.slaBreached ? '<span class="bad">BREACHED</span>' : esc(r.slaIn || '')}</span>
          <span class="spacer"></span><span class="tiny dimmer">→ ${esc(r.assignedTo || 'unassigned')}</span></div>
        <div class="claim">"${esc(r.claim)}"</div>
        <div class="tiny muted">from ${esc([r.source.channel, r.source.sender, r.source.agentId].filter(Boolean).join(' · '))}</div>
        <ul class="reasons">${r.reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
        <div class="tiny">risk <b class="${r.riskScore >= .7 ? 'bad' : r.riskScore >= .35 ? 'warn' : ''}">${r.riskScore}</b> — ${r.riskSignals.map((s) => `<span class="pill ${s.includes('GOLDEN') ? 'r' : ''}">${esc(s)}</span>`).join('')}</div>
        <details style="margin-top:10px"><summary class="tiny muted" style="cursor:pointer">Explain why · show me the source</summary>
          <pre>${esc(r.explainWhy)}</pre>
          ${r.sourceLink ? `<div class="tiny muted">Source: <b>${esc(r.sourceLink.label)}</b> — ${esc(r.sourceLink.speaker || '')}<br><span class="dimmer">…${esc(r.sourceLink.excerpt || '')}…</span></div>` : ''}
        </details>
        <div class="row" style="margin-top:12px">${r.actions.map((a) => `<button class="ghost sm" data-act="${esc(a)}" data-id="${esc(r.id)}">${esc(a)}</button>`).join('')}</div>`;
      d.querySelectorAll('[data-act]').forEach((b) => b.addEventListener('click', async () => {
        const reason = prompt(`Reason for "${b.dataset.act}"?`, 'reviewed');
        if (reason === null) return;
        try {
          await api(`/api/review/${b.dataset.id}/decide`, { method: 'POST', body: { decision: b.dataset.act, reason } });
          toast('Decision recorded and logged.');
          go('review');
        } catch (e) { toast(e.message, true); }
      }));
      v.append(d);
    }
  };

  // 📜 RULES
  RENDER.rules = async (v) => {
    const [rules, conflicts] = await Promise.all([api('/api/rules'), api('/api/rules/conflicts').catch(() => [])]);
    const bt = el('div', 'card');
    bt.innerHTML = `<h3>Dry-run / backtest — nobody enables a rule blind</h3>
      <label>Plain language (or an expression)</label>
      <input id="plain" value="No payment authority above $50,000 becomes a fact without sign-off">
      <div class="row" style="margin-top:10px"><button id="run" style="margin:0">Backtest against history</button></div>
      <div id="btout" style="margin-top:14px"></div>`;
    bt.querySelector('#run').addEventListener('click', async () => {
      const out = bt.querySelector('#btout');
      out.innerHTML = '<div class="loading">running…</div>';
      try {
        const p = bt.querySelector('#plain').value;
        const body = /[=<>~]|matches|contains/.test(p) && !/^No |^Nothing |^Facts /i.test(p) ? { expression: p, action: 'hold' } : { plain: p };
        const r = await api('/api/rules/backtest', { method: 'POST', body });
        out.innerHTML = `<pre>POLICY BACKTEST — ${esc(r.rule.plain || r.rule.expression)}
Run against: ${esc(r.window)} · ${r.evaluated} evaluated writes

Would have matched:   ${r.wouldMatch}
   → ${r.legitimate} legitimate
   → ${r.suspicious} you should look at RIGHT NOW ${r.suspicious ? '⚠️' : ''}
By outcome:           ${Object.entries(r.byOutcome).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(' · ') || 'none'}
False positive rate:  est. ${esc(r.estimatedFalsePositiveRate)}
Reviewer load added:  ${esc(r.reviewerLoadAdded)}
Agents affected:      ${esc(r.agentsAffected.join(' · ') || 'none')}

${esc(r.recommendation)}</pre>
        <div class="row">${r.actions.map((a) => `<span class="pill b">${esc(a)}</span>`).join('')}</div>`;
      } catch (e) { out.innerHTML = `<div class="bad">${esc(e.message)}</div>`; }
    });
    v.append(bt);

    if (conflicts.length) {
      v.append(card('⚠️ Rule conflicts detected at authoring time', table(['Rule A', 'Rule B', 'Overlap', 'Resolution'],
        conflicts.map((c) => [esc(c.a.name), esc(c.b.name), c.overlap, `<span class="tiny">${esc(c.resolution)}</span>`]))));
    }
    v.append(card(`Rules (${rules.length})`, table(
      ['Name', 'Type', 'State', 'Action', 'Expression', 'v'],
      rules.map((r) => [
        esc(r.name),
        `<span class="pill">${esc(r.type)}</span>`,
        `<span class="pill ${r.state === 'enforce' ? 'g' : r.state === 'draft' ? '' : 'a'}">${esc(r.state)}</span>`,
        `<span class="pill ${r.action === 'block' ? 'r' : 'a'}">${esc(r.action)}</span>`,
        `<span class="tiny mono dimmer">${esc(r.expression)}</span>`,
        r.version
      ])
    )));
  };

  // 🔍 TRACE
  RENDER.trace = async (v) => {
    const c = el('div', 'card');
    c.innerHTML = `<h3>Trace any fact → its whole life</h3>
      <div class="row"><input id="fid" placeholder="fact id, e.g. f-…" style="flex:1"><button id="go" style="margin:0">Trace</button></div>
      <div id="out" style="margin-top:16px"></div>`;
    c.querySelector('#go').addEventListener('click', () => openFact(c.querySelector('#fid').value, c.querySelector('#out')));
    v.append(c);
    const facts = await api('/api/facts?limit=25').catch(() => []);
    if (facts.length) {
      v.append(card('Recent facts', table(['Claim', 'Folder', 'Trace'],
        facts.map((f) => [esc(f.claim), `<span class="tiny mono">${esc(f.folder || '')}</span>`, `<button class="ghost sm" data-t="${esc(f.id)}">trace</button>`]))));
      v.querySelectorAll('[data-t]').forEach((b) => b.addEventListener('click', () => openFact(b.dataset.t, c.querySelector('#out'))));
    }
  };

  async function openFact(id, target) {
    const out = target || $('#view');
    if (!target) { out.innerHTML = ''; }
    const box = el('div');
    out.prepend(box);
    box.innerHTML = '<div class="loading">tracing…</div>';
    try {
      const [t, cg] = await Promise.all([api(`/api/facts/${encodeURIComponent(id)}/trace`), api(`/api/facts/${encodeURIComponent(id)}/contagion`).catch(() => null)]);
      box.innerHTML = '';
      box.append(card(`Trace — ${esc(t.fact.id)}`, `
        <div class="claim">${esc(t.fact.claim)}</div>
        <dl class="kv">
          <dt>Said by</dt><dd>${esc(t.saidBy?.name || '—')} <span class="dimmer tiny">(${esc(t.saidBy?.kind || '')})</span></dd>
          <dt>Source</dt><dd class="mono tiny">${esc(t.saidBy?.sourceRef?.label || '—')}</dd>
          <dt>Captured by</dt><dd>${esc(t.capturedBy?.id || '—')} <span class="dimmer tiny">${esc(t.capturedBy?.mode || '')}</span></dd>
          <dt>Channel</dt><dd>${esc(t.channel.channel)} <span class="pill ${t.channel.trustAtTheTime === 'trusted' ? 'g' : 'a'}">${esc(t.channel.trustAtTheTime)}</span></dd>
          <dt>Model</dt><dd class="tiny mono">${esc(t.model.version || t.model.model || '—')}</dd>
          <dt>Gate outcome</dt><dd>${esc(t.gate.outcome)}</dd>
          <dt>Rules evaluated</dt><dd class="tiny mono">${esc((t.rulesEvaluated || []).join(', ') || 'none matched')}</dd>
          <dt>Human review</dt><dd>${t.humanReview ? esc(JSON.stringify(t.humanReview)) : 'auto-passed'}</dd>
          <dt>Reads</dt><dd>${t.readCount} ${t.reads.length ? `<span class="tiny dimmer">(${t.reads.map((r) => esc(r.agentId)).join(', ')})</span>` : ''}</dd>
          <dt>Ledger position</dt><dd class="mono tiny">#${t.integrity.ledgerPosition} · ${esc(String(t.integrity.contentHash).slice(0, 24))}…</dd>
          <dt>Integrity</dt><dd>${t.integrity.verified.ok ? '<span class="good">✓ verified</span>' : '<span class="bad">✗ FAILED</span>'}</dd>
        </dl>
        <h4>Every check that ran</h4>
        ${table(['Check', 'Name', 'Result'], (t.gate.checks || []).map((c) => [c.check, esc(c.name), c.result === 'pass' ? '<span class="good">pass</span>' : `<span class="warn">${esc(c.result)}</span>`]))}`));
      if (cg) {
        box.append(card('Contagion — who believed it, and what did they do about it?', `
          <dl class="kv">
            <dt>Live for</dt><dd>${cg.liveForDays} days (${esc(cg.liveFrom)} → ${esc(cg.liveTo)})</dd>
            <dt>Origin</dt><dd>${esc(cg.origin.channel)} · ${esc(cg.origin.saidBy || '')} ${cg.origin.gateWarning ? `<div class="bad tiny">${esc(cg.origin.gateWarning)}</div>` : '<span class="good tiny">gate ran</span>'}</dd>
            <dt>Blast radius</dt><dd>${cg.blastRadius.agents} agents · ${cg.blastRadius.folders} folders · ${cg.blastRadius.derivedFacts} derived facts · ${cg.blastRadius.summaries} summaries</dd>
          </dl>
          ${cg.readBy.length ? table(['Agent', 'Reads', 'Window', 'Owner'], cg.readBy.map((r) => [esc(r.agentName), r.reads, esc(r.window), esc(r.owner)])) : '<p class="muted tiny">Never read.</p>'}
          <div class="row" style="margin-top:12px">${cg.remediation.map((r) => `<button class="ghost sm" ${r.action.startsWith('Export') ? `data-bundle="${esc(cg.factId)}"` : ''}>${esc(r.action)}</button>`).join('')}</div>`));
        box.querySelectorAll('[data-bundle]').forEach((b) => b.addEventListener('click', async () => {
          const r = await api(`/api/facts/${encodeURIComponent(b.dataset.bundle)}/incident-bundle`, { method: 'POST', body: { matter: 'ad-hoc' } });
          box.append(card('Incident bundle', `<pre>${esc(r.humanReadable)}</pre>`));
          toast('Incident bundle generated and logged.');
        }));
      }
    } catch (e) { box.innerHTML = `<div class="bad">${esc(e.message)}</div>`; }
  }

  // 📚 ARCHIVE
  RENDER.archive = async (v) => {
    const stats = await api('/api/archive/stats');
    v.append(cards([
      ['Conversations', stats.conversations], ['Turns', stats.turns],
      ['WORM copies', stats.worm], ['Privileged', stats.privileged],
      ['Supervision open', stats.supervisionOpen, stats.supervisionOpen ? 'warn' : 'good'],
      ['Productions', stats.productions]
    ]));
    const c = el('div', 'card');
    c.innerHTML = `<h3>Search every raw conversation — whole, sealed, chain-verifiable</h3>
      <div class="row"><input id="aq" placeholder="search transcripts…" style="flex:1"><button id="ago" style="margin:0">Search</button></div>
      <div id="aout" style="margin-top:14px"></div>`;
    c.querySelector('#ago').addEventListener('click', async () => {
      const out = c.querySelector('#aout');
      out.innerHTML = '<div class="loading">…</div>';
      try {
        const rows = await api(`/api/archive/search?q=${encodeURIComponent(c.querySelector('#aq').value)}`);
        out.innerHTML = rows.length ? table(['Conversation', 'At', 'Channel', 'Turns', 'Snippet', 'Seal'],
          rows.map((r) => [`<span class="mono tiny">${esc(r.id)}</span>`, esc(r.age), esc(r.channel), r.turns, `<span class="tiny dimmer">${esc(r.snippet)}</span>`, `<span class="mono tiny">${esc(String(r.sealHash).slice(0, 12))}…</span>`]))
          : '<div class="empty">No conversations matched.</div>';
      } catch (e) { out.innerHTML = `<div class="bad">${esc(e.message)}</div>`; }
    });
    v.append(c);
    const sup = await api('/api/archive/supervision').catch(() => []);
    if (sup.length) {
      v.append(card('Supervision queue — the 2% worth reading', table(['Risk', 'Triggers', 'Age', 'Snippet'],
        sup.map((s) => [`<span class="pill ${s.riskScore >= .75 ? 'r' : 'a'}">${s.riskScore}</span>`, `<span class="tiny">${esc((s.triggers || []).join(', '))}</span>`, esc(s.age), `<span class="tiny dimmer">${esc(s.conversation?.snippet || '')}</span>`]))));
    }
  };

  // 🔭 OBSERVABILITY
  RENDER.observability = async (v) => {
    const s = await api('/api/observability/stats');
    v.append(cards([
      ['Traces', s.traces], ['Spans', s.spans],
      ['Memory events', s.memoryEvents], ['Cost', `$${s.totalCostUsd}`],
      ['Golden sets', s.goldenSets], ['Eval runs', s.evalRuns]
    ]));
    const evals = await api('/api/evals').catch(() => []);
    if (evals.length) {
      v.append(card('Eval runs', table(['Set', 'Label', 'Passed', 'Scorers'],
        evals.map((e) => [esc(e.setName), esc(e.label), `${e.passed}/${e.total}`, `<span class="tiny dimmer">${esc(Object.keys(e.aggregate || {}).join(', '))}</span>`]))));
    }
    const clusters = await api('/api/observability/clusters').catch(() => []);
    if (clusters.length) {
      v.append(card('Failure clusters — fix categories, not instances', table(['Cluster', 'Count', 'Failing scorers'],
        clusters.map((c) => [`<span class="tiny">${esc(c.exemplar)}</span>`, c.count, `<span class="tiny warn">${esc((c.failingScorers || []).join(', '))}</span>`]))));
    }
    v.append(card('Memory-aware tracing', '<p class="muted tiny">Every trace shows which facts were read, withheld, written, held or blocked — inline with the reasoning. No other observability tool can emit these attributes because it does not sit in the memory path.</p>'));
  };

  // ⚖️ CASES
  RENDER.cases = async (v) => {
    const tabs = tabbar(['Legal holds', 'Erasure', 'Subject access', 'Retention', 'Receipts'], async (i, body) => {
      body.innerHTML = '';
      if (i === 0) {
        const holds = await api('/api/legal/holds');
        body.append(card(`Active legal holds (${holds.length})`, holds.length ? table(['Matter', 'Scope', 'Facts', 'Conversations', 'Placed'],
          holds.map((h) => [esc(h.matter), `<span class="tiny mono">${esc(JSON.stringify(h.scope))}</span>`, h.factIds.length, h.conversationIds.length, esc(h.age)]))
          : '<div class="empty">No active holds.</div>'));
      } else if (i === 1) {
        const c = el('div', 'card');
        c.innerHTML = `<h3>Erase a person — delete-vs-keep resolved on screen</h3>
          <div class="row"><input id="subj" placeholder="subject name" style="flex:1"><button id="plan" style="margin:0">Plan</button></div>
          <div id="pout" style="margin-top:14px"></div>`;
        c.querySelector('#plan').addEventListener('click', async () => {
          const out = c.querySelector('#pout');
          out.innerHTML = '<div class="loading">…</div>';
          try {
            const p = await api(`/api/legal/erasure/plan?subject=${encodeURIComponent(c.querySelector('#subj').value)}`);
            out.innerHTML = `<pre>[ Erase person ] ${esc(p.subject)}    request ${esc(p.requestId)}

FOUND
  ${esc(p.found.summary)}
  → reaches the TRANSCRIPTS, not just the tidy summaries

${p.conflict ? `CONFLICT ⚠️
  ${p.conflict.count} item(s) under legal hold on a DIFFERENT matter (${esc(p.conflict.matters.join(', '))}).
  ${esc(p.conflict.statement)}
  VAULT'S ANSWER
${p.conflict.vaultsAnswer.map((a) => `  → ${esc(a)}`).join('\n')}
` : 'NO CONFLICT — everything found is free to delete.\n'}
METHOD
${Object.entries(p.method).map(([k, v2]) => `  ${k.padEnd(24)}${esc(v2)}`).join('\n')}

[ ${esc(p.action)} ] → signed receipt</pre>`;
          } catch (e) { out.innerHTML = `<div class="bad">${esc(e.message)}</div>`; }
        });
        body.append(c);
      } else if (i === 2) {
        const d = await api('/api/legal/dsar').catch(() => []);
        body.append(card('Subject access requests', d.length ? table(['Subject', 'Regime', 'Due', 'Days left', 'Status'],
          d.map((x) => [esc(x.subject), esc(x.regime), esc(x.dueAt), x.overdue ? '<span class="bad">overdue</span>' : x.daysRemaining, esc(x.status)]))
          : '<div class="empty">No open requests.</div>'));
      } else if (i === 3) {
        const r = await api('/api/legal/retention');
        const p = await api('/api/legal/retention/preview');
        body.append(card('Retention — conflicting obligations surfaced, never silently resolved', `
          <p class="${r.conflicts ? 'warn' : 'muted'}">${esc(r.statement)}</p>
          <p class="tiny dimmer">Rule: ${esc(r.rule)}</p>
          <div class="sep"></div>
          <p class="muted">${esc(p.message)}</p>
          ${p.sample.length ? table(['Fact', 'Expires'], p.sample.map((s) => [esc(s.claim), esc(s.expiresAt)])) : ''}`));
      } else {
        const rec = await api('/api/legal/receipts');
        body.append(card('Receipts — signed, verifiable, exportable', rec.length ? table(['Kind', 'At', 'Signed', 'Proof'],
          rec.map((x) => [esc(x.kind), esc(x.at), x.signed ? '<span class="good">✓</span>' : '—', `<span class="mono tiny">${esc(String(x.proof).slice(0, 28))}…</span>`]))
          : '<div class="empty">No receipts yet.</div>'));
      }
    });
    v.append(tabs);
  };

  // 🛡️ SECURITY
  RENDER.security = async (v) => {
    const [alerts, scorecard, detectors] = await Promise.all([
      api('/api/security/alerts'), api('/api/security/scorecard').catch(() => null), api('/api/security/detectors').catch(() => null)
    ]);
    if (scorecard) {
      v.append(cards([
        ['Posture', scorecard.grade, scorecard.score >= 80 ? 'good' : 'warn'],
        ['Score', `${scorecard.score}/100`],
        ['Controls effective', `${scorecard.controls.effective}/${scorecard.controls.total}`],
        ['Open alerts', alerts.length, alerts.length ? 'warn' : 'good']
      ]));
    }
    v.append(card(`Alerts (${alerts.length})`, alerts.length ? table(['Severity', 'Kind', 'Detail', 'Actor', 'Age', 'Suggested action'],
      alerts.map((a) => [sev(a.severity), `<span class="pill">${esc(a.kind)}</span>`, `<span class="tiny">${esc(a.detail)}</span>`, esc(a.actor || '—'), esc(a.age), `<span class="tiny dimmer">${esc(a.suggestedAction)}</span>`]))
      : '<div class="empty">No open alerts.</div>'));
    if (detectors?.contradictionRadar?.length) {
      v.append(card('Contradiction radar — facts quietly conflicting with a golden fact', table(['Fact', 'Golden', 'Why'],
        detectors.contradictionRadar.map((c) => [esc(c.fact), `<span class="gold">${esc(c.golden)}</span>`, `<span class="warn tiny">${esc(c.why)}</span>`]))));
    }
    if (scorecard?.rankedFixes?.length) {
      v.append(card('Ranked fixes', table(['#', 'Area', 'Finding', 'Severity'],
        scorecard.rankedFixes.map((f) => [f.rank, esc(f.area), esc(f.finding), sev(f.severity)]))));
    }
    const ks = await api('/api/killswitch');
    v.append(card('Kill switch — graduated, not binary', `
      <p>Current: <b class="${ks.level ? 'bad' : 'good'}">${ks.level} — ${esc(ks.label || 'Normal')}</b> · administrators: ${esc((ks.administrators || []).join(', ') || '⚠️ none named')}</p>
      <p class="tiny muted">Last tested: ${esc(ks.spec?.lastTest?.at || '⚠️ never')} · target &lt;60s for transaction-authority agents</p>
      ${table(['Level', 'Label', 'Effect', 'Business impact'], (ks.spec?.levels || []).map((l) => [l.level, esc(l.label), esc(l.effect), esc(l.impact)]))}
      <div class="row" style="margin-top:12px"><button class="ghost sm" id="kstest">Run quarterly test</button></div>`));
    v.querySelector('#kstest')?.addEventListener('click', async () => {
      try { const r = await api('/api/killswitch/test', { method: 'POST', body: { level: 3, note: 'UI-initiated quarterly test' } }); toast(`Tested in ${r.activationMs}ms — ${r.passed ? 'passed' : 'FAILED'}`); go('security'); }
      catch (e) { toast(e.message, true); }
    });
  };

  // 📋 COMPLY
  RENDER.comply = async (v) => {
    const tabs = tabbar(['Controls', 'Crosswalk', 'Gap analysis', 'AI register', 'Board pack'], async (i, body) => {
      body.innerHTML = '<div class="loading">…</div>';
      if (i === 0) {
        const c = await api('/api/comply/controls');
        body.innerHTML = '';
        body.append(cards([['Effective', c.effective, 'good'], ['Failing / attention', c.failing, c.failing ? 'warn' : 'good'], ['Total', c.total]]));
        body.append(card('Continuous control monitoring — a failing control alerts immediately', table(['Control', 'Name', 'Status'],
          c.results.map((r) => [`<span class="mono tiny">${esc(r.id)}</span>`, esc(r.name), r.status === 'effective' ? '<span class="good">effective</span>' : `<span class="warn">${esc(r.status)}</span>`]))));
      } else if (i === 1) {
        const x = await api('/api/comply/crosswalk');
        body.innerHTML = '';
        body.append(card(`Crosswalk — ${x.uniqueControls} controls satisfying ${x.frameworks} frameworks`, table(['Control', 'Framework', 'Reference', 'Status'],
          x.rows.map((r) => [`<span class="mono tiny">${esc(r.control)}</span>`, esc(r.framework), `<span class="tiny">${esc(r.reference)}</span>`, esc(r.status)]))));
      } else if (i === 2) {
        const g = await api('/api/comply/gaps?framework=ISO%2042001');
        body.innerHTML = '';
        body.append(card(`Gap analysis — ${esc(g.framework)}`, `<p class="stat">${g.score}%</p><p class="muted">${esc(g.statement)}</p>
          ${g.gaps.length ? table(['Control', 'Reference', 'Effort', 'Fix'], g.gaps.map((x) => [esc(x.name), `<span class="tiny">${esc(x.reference)}</span>`, `<span class="pill">${esc(x.effort)}</span>`, `<span class="tiny">${esc(x.fix)}</span>`])) : '<p class="good">No gaps.</p>'}`));
      } else if (i === 3) {
        const r = await api('/api/comply/register');
        body.innerHTML = '';
        body.append(card('AI register', table(['Name', 'Kind', 'Owner', 'Risk tier', 'EU AI Act'],
          r.map((s) => [esc(s.name), esc(s.kind), esc(s.owner || '⚠️ none'), `<span class="pill ${s.riskTier === 'high' ? 'r' : ''}">${esc(s.riskTier)}</span>`, `<span class="tiny">${esc(s.euAiActTier)}</span>`]))));
      } else {
        const b = await api('/api/comply/board-pack');
        body.innerHTML = '';
        body.append(card('Board reporting pack — plain language, for the risk committee', `
          ${b.headline.map((h) => `<p>${esc(h)}</p>`).join('')}
          <div class="sep"></div>
          <dl class="kv">${Object.entries(b.riskPosture).map(([k, v2]) => `<dt>${esc(k)}</dt><dd>${esc(v2)}</dd>`).join('')}</dl>
          ${b.decisionsNeeded.length ? `<h4>Decisions needed</h4><ul class="reasons">${b.decisionsNeeded.map((d) => `<li>${esc(d)}</li>`).join('')}</ul>` : ''}
          <p class="warn tiny">${esc(b.regulatoryExposure)}</p>
          <p class="muted tiny">${esc(b.plainLanguage)}</p>`));
      }
    });
    v.append(tabs);
  };

  // 🏛️ INSURE
  RENDER.insure = async (v) => {
    const [gaps, q] = await Promise.all([api('/api/insure/gaps'), api('/api/insure/questionnaire').catch(() => [])]);
    v.append(card('Ranked gaps — by likely premium impact', gaps.length ? table(['Impact', 'Gap', 'Premium effect', 'Fix'],
      gaps.map((g) => [sev(g.impact), esc(g.gap), `<span class="tiny dimmer">${esc(g.premiumEffect)}</span>`, `<span class="tiny">${esc(g.fix)}</span>`]))
      : '<div class="good">No open gaps. The pack is renewal-ready.</div>'));
    if (q.length) {
      v.append(card('Carrier AI questionnaire — pre-filled from the running system', q.map((x) => `
        <div style="margin-bottom:14px"><div class="muted tiny">${esc(x.q)}</div><div>${esc(x.a)}</div></div>`).join('')));
    }
    const btn = el('button', null, 'Generate the full evidence pack');
    btn.addEventListener('click', async () => {
      try { const p = await api('/api/insure/pack'); v.append(card('Evidence pack', `<pre>${esc(JSON.stringify({ inventory: p.inventory.registered, shadow: p.inventory.shadowFound, incidents: p.incidentRegister, killSwitch: p.killSwitch.namedAdministrators, proof: p.proof }, null, 2))}</pre>`)); toast('Pack generated — 1 hour of work, done.'); }
      catch (e) { toast(e.message, true); }
    });
    v.append(btn);
  };

  // 📈 VALUE
  RENDER.value = async (v) => {
    const [r, health, patterns] = await Promise.all([api('/api/value'), api('/api/value/health'), api('/api/value/patterns').catch(() => null)]);
    v.append(cards([
      ['Memory health', r.quality.memoryHealth, health.score >= 80 ? 'good' : 'warn'],
      ['Facts w/ provenance', r.quality.factsWithFullProvenance],
      ['Writes held', r.risk.writesHeld],
      ['Writes blocked', r.risk.writesBlocked, r.risk.writesBlocked ? 'warn' : 'good'],
      ['Credentials caught', r.risk.credentialsCaught, r.risk.credentialsCaught ? 'bad' : 'good'],
      ['Shadow agents', r.risk.shadowAgentsFound, r.risk.shadowAgentsFound ? 'bad' : 'good']
    ]));
    v.append(card('COST', `<dl class="kv">${Object.entries(r.cost).filter(([k]) => k !== 'storageByTier' && k !== 'basis').map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</dd>`).join('')}</dl><p class="tiny dimmer">${esc(r.cost.basis)}</p>`));
    v.append(card('TIME', `<dl class="kv">${Object.entries(r.time).filter(([k]) => k !== 'basis').map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(x)}</dd>`).join('')}</dl><p class="tiny dimmer">${esc(r.time.basis)}</p>`));
    v.append(card('QUALITY', `<dl class="kv">${Object.entries(r.quality).filter(([k]) => k !== 'baseline').map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(x)}</dd>`).join('')}</dl>`));
    v.append(card('RISK', `<dl class="kv">${Object.entries(r.risk).map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(x)}</dd>`).join('')}</dl>`));
    if (health.fixes?.length) {
      v.append(card('Ranked fixes by impact', table(['Fix', 'Impact', 'Effort', 'Detail'],
        health.fixes.map((f) => [esc(f.fix), f.impact, `<span class="pill">${esc(f.effort)}</span>`, `<span class="tiny dimmer">${esc(f.detail)}</span>`]))));
    }
    if (patterns?.contentPatterns?.length) {
      v.append(card('Patterns — one alert, not N silences', table(['Pattern', 'Occurrences', 'Sources', 'Alert'],
        patterns.contentPatterns.map((p) => [esc(p.pattern), p.occurrences, p.distinctSources, `<span class="tiny warn">${esc(p.alert)}</span>`]))));
    }
  };

  // 👤 MY DATA
  RENDER.mydata = async (v) => {
    const d = await api('/api/my-data');
    v.append(card(`What Vault holds about ${esc(d.employee)}`, `
      <dl class="kv">${Object.entries(d.whatWeHold).map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(x)}</dd>`).join('')}</dl>
      <h4>What we do NOT hold</h4>
      <ul class="reasons">${d.whatWeDoNotHold.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
      <h4>Your rights</h4>
      <ul class="reasons">${d.yourRights.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
      <p class="muted tiny">${esc(d.purposeLock)}</p>`));
    if (d.export.facts.length) {
      v.append(card('Your facts', table(['Claim', 'Type', 'Recorded', 'Object'],
        d.export.facts.map((f) => [esc(f.claim), esc(f.claimType), esc(f.createdAt), `<button class="ghost sm" data-obj="${esc(f.id)}">object</button>`]))));
      v.querySelectorAll('[data-obj]').forEach((b) => b.addEventListener('click', async () => {
        const objection = prompt('What is wrong with this fact?');
        if (!objection) return;
        await api('/api/my-data/object', { method: 'POST', body: { factId: b.dataset.obj, objection } });
        toast('Objection raised — it is tracked and must be answered.');
      }));
    }
  };

  // ⚙️ ADMIN
  RENDER.admin = async (v) => {
    const tabs = tabbar(['Modules', 'Employee Privacy Mode', 'Agents', 'Connectors', 'Storage & keys', 'Continuity'], async (i, body) => {
      body.innerHTML = '<div class="loading">…</div>';
      if (i === 0) {
        const m = await api('/api/admin/modules');
        body.innerHTML = '';
        body.append(card('Modules — built-in by default, bring-your-own by toggle', `
          ${table(['Module', 'State', 'Using', 'Action', 'Healthy', 'Vault keeps a copy'],
            m.map((r) => [
              esc(r.module), esc(r.state), esc(r.using),
              r.noAlternative
                ? '<span class="pill">—</span>'
                : `<button class="ghost sm" data-mod="${esc(r.key)}" data-next="${esc(r.nextState)}" data-vendors="${esc((r.vendorOptions || []).join('|'))}">${esc(r.action)}</button>`
                  + (r.rawState === 'builtin' ? '' : ` <button class="ghost sm" data-mod="${esc(r.key)}" data-next="both">Both</button>`),
              r.healthy ? '<span class="good">✓</span>' : '<span class="bad">✗</span>',
              r.keepOwnCopy ? '✓' : '—'
            ]))}
          <p class="tiny dimmer" style="margin-top:12px">Switching a module never loses data. The gate is not a module — it runs in every configuration and cannot be toggled off.</p>`));
        body.querySelectorAll('[data-mod]').forEach((b) => b.addEventListener('click', async () => {
          const next = b.dataset.next;
          const vendors = (b.dataset.vendors || '').split('|').filter(Boolean);
          let vendor = null, endpoint = null;
          if (next !== 'builtin') {
            vendor = prompt(`Which tool should Vault use?${vendors.length ? `\n\n${vendors.join(' · ')}` : ''}`, vendors[0] || '');
            if (!vendor) return;
            const url = prompt(`Endpoint Vault should call for ${vendor}:`, 'https://');
            if (!url || url === 'https://') return;
            const token = prompt('Bearer token (leave blank if none):', '') || undefined;
            endpoint = { url, token };
          }
          try {
            await api(`/api/admin/modules/${encodeURIComponent(b.dataset.mod)}`, {
              method: 'POST',
              body: { state: next, vendor, endpoint, reason: 'toggled from the Admin screen' }
            });
            toast(`${b.dataset.mod} → ${next}`);
            go('admin');
          } catch (e) { toast(e.message, true); }
        }));
      } else if (i === 1) {
        const p = await api('/api/admin/privacy');
        body.innerHTML = '';
        const opts = (p.available || []).map((j) => `<option value="${esc(j)}"${j === (p.jurisdiction || 'off') ? ' selected' : ''}>${esc(j)}</option>`).join('');
        body.append(card('🔒 Employee Privacy Mode', `
          <p>Status: <b class="${p.enabled ? 'good' : 'warn'}">${p.enabled ? '🟢 ON' : '🔴 OFF'}</b> — ${esc(p.jurisdictionName)}</p>
          <label style="margin-top:14px">Jurisdiction preset</label>
          <select id="jur">${opts}</select>
          <div class="row" style="margin-top:12px">
            <button class="ghost sm" id="prev">Preview what changes</button>
            <button class="ghost sm" id="apply">Apply</button>
            <button class="ghost sm" id="pack">Generate compliance pack</button>
          </div>
          <div id="pv" style="margin-top:14px"></div>
          <div class="sep"></div>
          <h4>Guarantees</h4>
          <ul class="reasons">${p.guarantees.map((g) => `<li>${esc(g)}</li>`).join('')}</ul>`));
        const jur = () => body.querySelector('#jur').value;
        body.querySelector('#prev').addEventListener('click', async () => {
          const r = await api(`/api/admin/privacy/preview?jurisdiction=${encodeURIComponent(jur())}`);
          body.querySelector('#pv').innerHTML = `<pre>${esc(JSON.stringify(r, null, 2))}</pre>`;
        });
        body.querySelector('#apply').addEventListener('click', async () => {
          try { const r = await api('/api/admin/privacy', { method: 'POST', body: { jurisdiction: jur(), reason: 'set from the admin screen' } }); toast(r.note); go('admin'); }
          catch (e) { toast(e.message, true); }
        });
        body.querySelector('#pack').addEventListener('click', async () => {
          const r = await api('/api/admin/privacy/pack');
          body.querySelector('#pv').innerHTML = `<h4>${esc(r.name)} compliance pack</h4>` +
            (r.documents || []).map((d) => `<details><summary style="cursor:pointer">${esc(d.name)}</summary><pre>${esc(d.body)}</pre></details>`).join('');
        });
      } else if (i === 2) {
        const a = await api('/api/admin/agents');
        body.innerHTML = '';
        body.append(card('Agents', table(['Agent', 'Mode', 'Status', 'Writes', 'Held', 'Blocked', 'Attested'],
          a.map((x) => [`${esc(x.name)}<div class="tiny dimmer mono">${esc(x.id)}</div>`, esc(x.mode), esc(x.status), x.writes, x.held, x.blocked, x.attestedAt ? esc(x.attestedAt.slice(0, 10)) : '<span class="warn">never</span>']))));
      } else if (i === 3) {
        const c = await api('/api/connectors');
        body.innerHTML = '';
        body.append(card('Connector health', c.health.length ? table(['Connector', 'Mode', 'Status', 'Events', 'Last event', 'Alert'],
          c.health.map((h) => [esc(h.name), esc(h.mode), h.healthy ? '<span class="good">healthy</span>' : `<span class="warn">${esc(h.status)}</span>`, h.eventsIngested, esc(h.lastEvent), `<span class="tiny warn">${esc(h.alert || '')}</span>`]))
          : '<div class="empty">No connectors configured.</div>'));
      } else if (i === 4) {
        const s = await api('/api/admin/storage');
        const k = await api('/api/admin/keys').catch(() => null);
        body.innerHTML = '';
        body.append(card('Storage', `<dl class="kv"><dt>Monthly cost</dt><dd>$${esc(s.tiers.monthlyTotal)}</dd><dt>Lifecycle preview</dt><dd>${esc(s.lifecycle.summary)}</dd></dl>
          ${table(['Collection', 'Records', 'WORM', 'Encrypted'], Object.entries(s.db).map(([n, d]) => [esc(n), d.records, d.worm ? '🔒' : '—', d.encrypted ? '🔑' : '—']))}`));
        if (k) body.append(card('Keys', table(['Scope', 'Key id', 'Version', 'Mode', 'Destroyed'],
          k.inventory.map((x) => [esc(x.scope), `<span class="mono tiny">${esc(x.keyId)}</span>`, x.version, esc(x.mode), x.destroyed ? `<span class="bad">${esc(x.destroyed)}</span>` : '—']))));
      } else {
        const c = await api('/api/admin/continuity');
        body.innerHTML = '';
        body.append(card('🚪 Exit & continuity — publish this page', `
          <dl class="kv">
            <dt>Continuous mirror</dt><dd>${esc(c.continuousMirrorExport.guarantee)}</dd>
            <dt>Open format</dt><dd>${esc(c.openDocumentedFormat.format)} — ${esc(c.openDocumentedFormat.license)}</dd>
            <dt>Self-host</dt><dd>${esc(c.selfHostEscapeHatch)}</dd>
            <dt>Ledger without us</dt><dd>${esc(c.ledgerVerifiableWithoutUs.statement)} (${esc(c.ledgerVerifiableWithoutUs.standaloneVerifier)})</dd>
            <dt>Free export</dt><dd>charge: ${esc(c.freeExport.charge)}, throttling: ${esc(c.freeExport.throttling)}</dd>
            <dt>Concentration risk</dt><dd>${c.concentrationRiskStatement.percentageInWritePath}% of agents have Vault in the write path</dd>
          </dl>
          <h4>If Vault is unavailable</h4>
          <ul class="reasons">${c.concentrationRiskStatement.ifVaultIsUnavailable.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
          <h4>Contract terms, pre-agreed</h4>
          <ul class="reasons">${c.contractTermsPreAgreed.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`));
      }
    });
    v.append(tabs);
  };

  // ---- helpers -----------------------------------------------------------

  /**
   * A slide-over panel for detail and forms.
   *
   * A real <dialog> rather than a positioned div: the browser gives us the
   * focus trap, Escape to close, and inert background for free, and every one
   * of those hand-rolled is a bug waiting to happen for keyboard users.
   */
  let sheetEl = null;
  function openSheet(title, content) {
    closeSheet();
    sheetEl = el('dialog', 'sheet');
    sheetEl.setAttribute('aria-label', title);
    const head = el('div', 'sheet-head');
    head.innerHTML = `<h2>${esc(title)}</h2>`;
    const close = el('button', 'ghost', 'Close');
    close.type = 'button';
    close.addEventListener('click', closeSheet);
    head.append(close);
    const bodyWrap = el('div', 'sheet-body');
    bodyWrap.append(content);
    sheetEl.append(head, bodyWrap);
    document.body.append(sheetEl);
    sheetEl.showModal();
    // Escape fires `cancel`, and the element has to come out of the DOM or the
    // next open stacks a second dialog behind the first.
    sheetEl.addEventListener('close', () => { sheetEl?.remove(); sheetEl = null; });
  }
  function closeSheet() {
    if (!sheetEl) return;
    sheetEl.close();
    sheetEl.remove();
    sheetEl = null;
  }

  let cardSeq = 0;
  function card(title, html) {
    const c = el('div', 'card');
    // A labelled region, so a screen-reader user can jump between cards instead
    // of reading the whole screen top to bottom to find one number.
    const id = `card-h-${++cardSeq}`;
    c.setAttribute('role', 'region');
    c.setAttribute('aria-labelledby', id);
    c.innerHTML = `<h3 id="${id}">${esc(title)}</h3>` + (typeof html === 'string' ? html : '');
    if (typeof html !== 'string' && html) c.append(html);
    return c;
  }
  function cards(list) {
    const g = el('div', 'grid g4');
    for (const [label, val, cls] of list) {
      // The label is read before the number. Rendered the other way round
      // visually, but "12 — shadow agents" is the useful reading order and
      // "12" alone is not, so the accessible name puts the label first.
      const accessible = `${label}: ${val}`;
      g.append(el('div', 'card', `<div class="stat ${cls || ''}" role="group" aria-label="${esc(accessible)}"><span aria-hidden="true">${esc(val)}</span><small aria-hidden="true">${esc(label)}</small></div>`));
    }
    const wrap = el('div');
    wrap.append(g);
    wrap.style.marginBottom = '14px';
    return wrap;
  }
  function table(head, rows, caption = null) {
    if (!rows.length) return `<div class="empty">${esc(t('state.empty'))}</div>`;
    // scope="col" on every header, and a caption: without them a screen reader
    // reads a grid of unlabelled values, which for a risk table is worse than
    // no table at all. The caption is visually hidden, not absent.
    return `<div class="scroll" tabindex="0" role="region" aria-label="${esc(caption || t('a11y.tableCaption'))}">
      <table>
      <caption class="sr-only">${esc(caption || t('a11y.tableCaption'))}</caption>
      <thead><tr>${head.map((h) => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map((r) => `<tr>${r.map((c, i) => (i === 0 ? `<th scope="row">${c}</th>` : `<td>${c}</td>`)).join('')}</tr>`).join('')}</tbody>
      </table></div>`;
  }
  let tabSeq = 0;
  function tabbar(names, onSelect) {
    const wrap = el('div');
    const bar = el('div', 'tabs');
    const body = el('div');
    const group = ++tabSeq;
    bar.setAttribute('role', 'tablist');
    body.setAttribute('role', 'tabpanel');
    body.id = `tabpanel-${group}`;
    body.tabIndex = 0;

    const select = (i) => {
      bar.querySelectorAll('.tab').forEach((x, j) => {
        x.classList.toggle('active', j === i);
        x.setAttribute('aria-selected', String(j === i));
        // Roving tabindex: one stop for the whole tablist, then arrow keys
        // within it. Fourteen tab stops for fourteen tabs is the pattern that
        // makes keyboard users give up.
        x.tabIndex = j === i ? 0 : -1;
      });
      body.setAttribute('aria-labelledby', `tab-${group}-${i}`);
      onSelect(i, body).catch((e) => { body.innerHTML = `<div class="bad">${esc(e.message)}</div>`; });
    };

    names.forEach((n, i) => {
      const tab = el('button', `tab${i === 0 ? ' active' : ''}`, esc(n));
      tab.type = 'button';
      tab.id = `tab-${group}-${i}`;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', `tabpanel-${group}`);
      tab.setAttribute('aria-selected', String(i === 0));
      tab.tabIndex = i === 0 ? 0 : -1;
      tab.addEventListener('click', () => select(i));
      tab.addEventListener('keydown', (e) => {
        const step = { ArrowRight: 1, ArrowLeft: -1, Home: -Infinity, End: Infinity }[e.key];
        if (step === undefined) return;
        e.preventDefault();
        const all = [...bar.querySelectorAll('.tab')];
        // Arrow direction follows reading direction, so in RTL the right arrow
        // moves the way the eye does.
        const rtl = document.documentElement.dir === 'rtl';
        const delta = Number.isFinite(step) && rtl ? -step : step;
        const next = delta === -Infinity ? 0 : delta === Infinity ? all.length - 1
          : (all.indexOf(e.currentTarget) + delta + all.length) % all.length;
        all[next].focus();
        select(next);
      });
      bar.append(tab);
    });
    wrap.append(bar, body);
    onSelect(0, body).catch((e) => { body.innerHTML = `<div class="bad">${esc(e.message)}</div>`; });
    return wrap;
  }
  const badge = (s) => s === '✓' ? '<span class="good">✓</span>' : s === '✗' || s === '✗*' ? `<span class="bad">${esc(s)}</span>` : `<span class="dimmer">${esc(s)}</span>`;
  const sev = (s) => `<span class="pill ${s === 'critical' || s === 'high' ? 'r' : s === 'medium' ? 'a' : ''}">${esc(s)}</span>`;
  const statusBadge = (s) => `<span class="pill ${s === 'live' ? 'g' : s === 'held' ? 'a' : s === 'rejected' ? 'r' : ''}">${esc(s)}</span>`;
  const claimBadge = (f) => f.golden ? '<span class="pill p">★ approved</span>'
    : `<span class="pill ${f.claimType === 'verified' ? 'g' : f.claimType === 'guessed' ? 'r' : ''}">${esc(f.claimType)}</span>`;

  // ---- shell -------------------------------------------------------------
  async function go(id) {
    current = id;
    const s = SCREENS.find((x) => x.id === id);
    const name = screenName(s);
    document.title = `${name} — Vault`;
    $('#title').textContent = `${s.icon} ${name}`;
    markCurrentScreen();

    const v = $('#view');
    // aria-busy so assistive technology waits rather than reading a half-built
    // screen, and an announcement so a screen change is audible at all — this
    // is a single-page app, so there is no page load to notice.
    v.setAttribute('aria-busy', 'true');
    v.innerHTML = `<div class="loading">${esc(t('state.loading'))}</div>`;
    announce(t('state.loading'));
    try {
      const box = el('div');
      await RENDER[id](box);
      v.innerHTML = '';
      v.append(box);
      announce(name);
    } catch (e) {
      v.innerHTML = `<div class="empty">${esc(e.message)}${e.status === 403 ? `<br><span class="tiny">Least privilege applies to your own product too — this role does not see this screen.</span>` : ''}</div>`;
      announce(`${name}: ${e.message}`, true);
    } finally {
      v.setAttribute('aria-busy', 'false');
    }
  }

  async function boot() {
    me = await api('/api/whoami');
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    renderNav();
    $('#whoName').textContent = me.name;
    $('#whoRole').textContent = me.role;
    refreshBadges();
    const allowed = SCREENS.filter((s) => !s.roles || s.roles.includes(me.role));
    go(allowed[0]?.id || 'mydata');
  }

  function screenName(s) {
    const translated = t(`screen.${s.id}`);
    return translated === `screen.${s.id}` ? s.name : translated;
  }

  function renderNav() {
    $('#screens').innerHTML = SCREENS.map((s) => {
      const ok = !s.roles || s.roles.includes(me.role);
      // Buttons, not clickable divs: they are focusable, Enter and Space work,
      // and assistive technology announces them as controls. `aria-disabled`
      // rather than `disabled` on the locked ones, so a keyboard user can still
      // reach them and hear why they cannot go there.
      return `<li>
        <button type="button" class="navbtn" data-id="${s.id}"${ok ? '' : ' aria-disabled="true"'}>
          <span aria-hidden="true">${s.icon}</span>${esc(screenName(s))}${ok ? '' : `<span class="sr-only"> — not available to the ${esc(me.role)} role</span>`}
        </button></li>`;
    }).join('');
    document.querySelectorAll('#screens .navbtn').forEach((b) => {
      b.parentElement.classList.toggle('locked', b.getAttribute('aria-disabled') === 'true');
      if (b.getAttribute('aria-disabled') === 'true') return;
      b.addEventListener('click', () => go(b.dataset.id));
    });
    markCurrentScreen();
  }

  function markCurrentScreen() {
    document.querySelectorAll('#screens .navbtn').forEach((b) => {
      const on = b.dataset.id === current;
      b.parentElement.classList.toggle('active', on);
      // aria-current is how a screen reader says "you are here". A CSS class
      // alone is invisible to everyone not looking at the highlight.
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
  }

  async function refreshBadges() {
    try {
      const v = await api('/api/ledger/verify');
      const b = $('#chainBadge');
      b.textContent = `chain ${v.ok ? '✓' : '✗'} ${i18n.number(v.checked)}`;
      b.className = `badge ${v.ok ? 'ok' : 'bad'}`;
      // A tick and a cross are the same to a screen reader without this.
      b.setAttribute('aria-label', `${t(v.ok ? 'chain.ok' : 'chain.broken')}, ${i18n.number(v.checked)}`);
      if (!v.ok) announce(t('chain.broken'), true);
    } catch { /* role may not see the ledger */ }
    try {
      const k = await api('/api/killswitch');
      const b = $('#ksBadge');
      const state = k.level ? `L${k.level} ${k.label}` : t('killswitch.normal');
      b.textContent = `${t('killswitch.label')}: ${state}`;
      b.className = `ks ${k.level ? 'ks-on' : 'ks-0'}`;
      if (k.level) announce(`${t('killswitch.label')}: ${state}`, true);
    } catch { /* ignore */ }
  }

  // ---- login -------------------------------------------------------------
  // A real form submit, so Enter works, password managers see it and the
  // browser's own validation applies — none of which a click handler on a
  // button gives you.
  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    token = $('#token').value.trim();
    const err = $('#loginErr');
    err.textContent = '';
    $('#token').setAttribute('aria-invalid', 'false');
    try {
      const res = await fetch('/api/health', { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error(t('auth.failed'));
      localStorage.setItem('vault.token', token);
      boot();
    } catch (ex) {
      err.textContent = ex.message;
      $('#token').setAttribute('aria-invalid', 'true');
      $('#token').focus();
      announce(ex.message, true);
    }
  });
  $('#signout')?.addEventListener('click', () => { localStorage.clear(); location.reload(); });
  $('#refresh')?.addEventListener('click', () => { refreshBadges(); go(current); });

  // The skip link moves focus, not just the scroll position. Jumping the
  // viewport while focus stays in the nav is the bug that makes skip links
  // useless for the people who need them.
  $('#skipLink')?.addEventListener('click', (e) => {
    e.preventDefault();
    const v = $('#view');
    v.focus();
    v.scrollIntoView();
  });

  // ---- language picker ---------------------------------------------------
  const picker = $('#locale');
  if (picker && window.VaultI18n) {
    for (const l of window.VaultI18n.coverage()) {
      const opt = document.createElement('option');
      opt.value = l.locale;
      // The completeness label is shown, not hidden: offering a language that
      // is 40% translated without saying so is how a works council ends up
      // reading a half-English screen and concluding nobody checked.
      opt.textContent = l.status === 'complete' ? l.native : `${l.native} — ${l.status}`;
      opt.selected = l.locale === i18n.locale;
      picker.append(opt);
    }
    picker.addEventListener('change', () => applyLocale(picker.value));
  }
  applyLocale(i18n.locale);

  // Installable on a phone, so the two things that need a human at 3am — the
  // review queue and the kill switch — are one tap away. The worker caches the
  // shell and never an API response; see sw.js for why that line is absolute.
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* offline shell is a bonus, not a requirement */ });
  }

  if (token) { $('#token').value = token; boot().catch(() => { localStorage.clear(); }); }
})();
