/*
  VAULT — site behaviour.

  Four jobs, in order of how much they matter if the file never loads:

    1. the hero background        — the canvas paints the same scene the video
                                    shows, so there is never a black rectangle
    2. the menu drawer            — the only thing here that is not decorative
    3. scroll reveal and counters — additive, with a deadline
    4. the video                  — loaded last, and only when it is wanted

  Nothing below is required for the page to be readable. With no JavaScript the
  drawer links still work (they are anchors inside a <div hidden> — see the
  no-JS note in the stylesheet), the content is visible, and the hero shows its
  CSS gradient. Everything here makes it better; nothing makes it work.
*/

const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

document.getElementById('year').textContent = new Date().getFullYear();

// ── 1 · the hero background ─────────────────────────────────────────────────
//
// The canvas runs the same scene as site/video.mjs, live. It exists because a
// <video> with preload="none" shows nothing until it has buffered, and a black
// hero for two seconds on a slow connection is worse than no video at all. The
// canvas paints on the first frame; the video crossfades over it if and when it
// can actually play, and pauses itself the moment the hero leaves the viewport.
(function heroBackground() {
  const canvas = document.getElementById('heroCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const TAU = Math.PI * 2;
  let W = 0; let H = 0; let raf = null; let t0 = performance.now();

  const rnd = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };

  function size() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  // The same room as the film, at a fraction of its detail: the aisle, the
  // ceiling strips, the desks and the far glass, with no chairs, no monitors,
  // no scratches and no grain. It has to paint in a single frame on a phone.
  // It is a stand-in for the seconds before the video plays, not a second
  // implementation of it, and the composition matches so the crossfade to the
  // film is not a cut.
  function frame(now) {
    const t = ((now - t0) / 8000) % 1;           // an 8s loop, same as the film
    const S = H / 720;

    const weaveX = (Math.sin(t * TAU * 3) * 0.6 + Math.sin(t * TAU * 7 + 1.3) * 0.34) * 3.4 * S;
    const weaveY = (Math.cos(t * TAU * 2) * 0.5 + Math.sin(t * TAU * 5 + 0.7) * 0.3) * 2.8 * S;

    ctx.fillStyle = '#040206';
    ctx.fillRect(0, 0, W, H);
    ctx.save();
    ctx.translate(weaveX, weaveY);

    const VPX = W * 0.6; const HOR = H * 0.44; const FL = 700 * S;
    const px = (X, Z) => VPX + (X * FL) / Z;
    const py = (Y, Z) => HOR + (Y * FL) / Z;
    const ROWS = 10; const SPACING = 2.6; const NEAR = 4.2;
    const FAR = NEAR + ROWS * SPACING;

    const quad = (pts, fill) => {
      ctx.beginPath();
      ctx.moveTo(pts[0][0], pts[0][1]);
      for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]);
      ctx.closePath(); ctx.fillStyle = fill; ctx.fill();
    };

    // the far glass and the city through it
    const wz = FAR + 3;
    const wl = px(-7.2, wz); const wr = px(7.2, wz);
    const wt = py(-2.6, wz); const wb = py(1.9, wz);
    quad([[wl, wt], [wr, wt], [wr, wb], [wl, wb]], 'rgba(10,7,18,1)');
    for (let i = 0; i < 60; i++) {
      const x = wl + rnd(i) * (wr - wl);
      const y = wt + rnd(i + 300) * (wb - wt);
      const tw = 0.55 + 0.45 * Math.sin((t + rnd(i + 600)) * TAU * 2);
      ctx.fillStyle = rnd(i + 90) > 0.35
        ? `rgba(255,168,90,${0.1 + 0.3 * tw})`
        : `rgba(150,180,235,${0.06 + 0.18 * tw})`;
      ctx.beginPath(); ctx.arc(x, y, (1.4 + rnd(i + 40) * 2.4) * S, 0, TAU); ctx.fill();
    }

    // floor, and the pool of light down the aisle
    quad([[0, py(1.55, NEAR)], [W, py(1.55, NEAR)], [wr, wb], [wl, wb]], 'rgba(9,6,12,1)');
    const aisle = ctx.createLinearGradient(0, py(1.55, FAR), 0, H);
    aisle.addColorStop(0, 'rgba(255,150,70,.16)');
    aisle.addColorStop(0.45, 'rgba(255,140,60,.06)');
    aisle.addColorStop(1, 'rgba(255,140,60,0)');
    quad([
      [px(-1.5, NEAR), py(1.55, NEAR)], [px(1.5, NEAR), py(1.55, NEAR)],
      [px(1.5, FAR), py(1.55, FAR)], [px(-1.5, FAR), py(1.55, FAR)]
    ], aisle);

    const rows = [];
    for (let i = 0; i < ROWS; i++) rows.push(NEAR + ((i + t) % ROWS) * SPACING);
    rows.sort((a, b) => b - a);

    for (const z of rows) {
      const fade = Math.max(0, Math.min(1, (FAR - z) / FAR)) * 0.55 + 0.2;

      for (const sx of [-1, 1]) {
        const x1 = px(sx * 1.1, z); const x2 = px(sx * 3.4, z);
        const yy = py(-2.35, z); const h = Math.max(1.2 * S, (0.09 * FL) / z);
        const g = ctx.createLinearGradient(x1, yy, x2, yy);
        g.addColorStop(0, `rgba(255,196,140,${0.1 * fade})`);
        g.addColorStop(0.5, `rgba(255,222,180,${0.72 * fade})`);
        g.addColorStop(1, `rgba(255,196,140,${0.1 * fade})`);
        ctx.fillStyle = g;
        ctx.fillRect(Math.min(x1, x2), yy, Math.abs(x2 - x1), h);
      }

      for (const sx of [-1, 1]) {
        const zf = z + 1.35; const inner = sx * 1.45; const outer = sx * 4.5;
        quad([
          [px(inner, z), py(0.35, z)], [px(outer, z), py(0.35, z)],
          [px(outer, z), py(1.1, z)], [px(inner, z), py(1.1, z)]
        ], `rgba(28,19,32,${0.7 + 0.3 * fade})`);
        quad([
          [px(inner, z), py(1.1, z)], [px(outer, z), py(1.1, z)],
          [px(outer, zf), py(1.1, zf)], [px(inner, zf), py(1.1, zf)]
        ], `rgba(52,33,34,${0.45 + 0.55 * fade})`);
        quad([
          [px(inner, zf), py(1.1, zf)], [px(outer, zf), py(1.1, zf)],
          [px(outer, zf), py(1.62, zf)], [px(inner, zf), py(1.62, zf)]
        ], 'rgba(17,11,18,.95)');
        ctx.strokeStyle = `rgba(255,178,110,${0.16 + 0.4 * fade})`;
        ctx.lineWidth = Math.max(1, 1.4 * S);
        ctx.beginPath();
        ctx.moveTo(px(inner, zf), py(1.1, zf));
        ctx.lineTo(px(outer, zf), py(1.1, zf));
        ctx.stroke();
      }
    }

    // haze, so depth reads
    const haze = ctx.createLinearGradient(0, HOR - H * 0.2, 0, H);
    haze.addColorStop(0, 'rgba(120,60,30,.1)');
    haze.addColorStop(0.45, 'rgba(60,26,14,.05)');
    haze.addColorStop(1, 'rgba(4,2,6,0)');
    ctx.fillStyle = haze; ctx.fillRect(0, 0, W, H);

    ctx.restore();

    // the film grade, minus the damage — the CSS .grain layer over the hero
    // supplies the texture, so this only has to carry the colour.
    ctx.save();
    ctx.globalCompositeOperation = 'color';
    ctx.fillStyle = 'rgba(255,106,19,.34)';
    ctx.fillRect(0, 0, W, H);
    ctx.restore();

    const v = ctx.createRadialGradient(W * 0.62, H * 0.42, H * 0.18, W * 0.62, H * 0.42, W * 0.85);
    v.addColorStop(0, 'rgba(4,2,7,0)');
    v.addColorStop(0.55, 'rgba(4,2,7,.3)');
    v.addColorStop(1, 'rgba(4,2,7,.9)');
    ctx.fillStyle = v; ctx.fillRect(0, 0, W, H);

    const pocket = ctx.createRadialGradient(W * 0.2, H * 0.82, 0, W * 0.2, H * 0.82, W * 0.62);
    pocket.addColorStop(0, 'rgba(4,2,7,.5)');
    pocket.addColorStop(0.6, 'rgba(4,2,7,.2)');
    pocket.addColorStop(1, 'rgba(4,2,7,0)');
    ctx.fillStyle = pocket; ctx.fillRect(0, 0, W, H);

    raf = requestAnimationFrame(frame);
  }

  size();
  addEventListener('resize', size, { passive: true });

  // Motion is a preference, not a default. With it turned off the canvas paints
  // exactly one frame — the composition is still there, it simply holds still.
  if (reduced) { frame(t0); cancelAnimationFrame(raf); raf = null; }
  else raf = requestAnimationFrame(frame);

  // Stop drawing when the hero is not on screen. A background animation that
  // keeps running behind eight sections of content is a battery bug.
  const hero = canvas.closest('.hero');
  if ('IntersectionObserver' in window && !reduced) {
    new IntersectionObserver((es) => {
      for (const e of es) {
        if (e.isIntersecting && raf === null) { t0 = performance.now(); raf = requestAnimationFrame(frame); }
        else if (!e.isIntersecting && raf !== null) { cancelAnimationFrame(raf); raf = null; }
      }
    }, { threshold: 0 }).observe(hero);
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && raf !== null) { cancelAnimationFrame(raf); raf = null; }
    else if (!document.hidden && !reduced && raf === null) { t0 = performance.now(); raf = requestAnimationFrame(frame); }
  });

  // ── the film ──────────────────────────────────────────────────────────
  // Held back deliberately. Not fetched at all under reduced motion or on a
  // metered connection, and only revealed once it can genuinely play — so the
  // worst case is the canvas, never a black box or a stalled first frame.
  const video = document.getElementById('heroVideo');
  const saveData = navigator.connection?.saveData;
  const slow = /2g/.test(navigator.connection?.effectiveType || '');
  if (video && !reduced && !saveData && !slow) {
    video.src = 'hero.webm';
    video.preload = 'auto';
    video.addEventListener('canplay', () => {
      video.play().then(() => {
        video.classList.add('ready');
        // The canvas has done its job; stop burning frames behind an opaque video.
        if (raf !== null) { cancelAnimationFrame(raf); raf = null; }
      }).catch(() => { /* autoplay refused — the canvas carries on */ });
    }, { once: true });
    video.load();
  }
})();

// ── 2 · the menu drawer ─────────────────────────────────────────────────────
(function drawer() {
  const btn = document.querySelector('.menu-btn');
  const panel = document.getElementById('drawer');
  if (!btn || !panel) return;

  const open = (on) => {
    btn.setAttribute('aria-expanded', String(on));
    document.body.classList.toggle('drawer-open', on);
    if (on) { panel.hidden = false; requestAnimationFrame(() => panel.classList.add('in')); }
    else {
      panel.classList.remove('in');
      // Kept in the DOM until the transition ends, so it animates out rather
      // than vanishing, but genuinely `hidden` afterwards — a closed menu that
      // is only transparent is still in the tab order.
      setTimeout(() => { if (!panel.classList.contains('in')) panel.hidden = true; }, 320);
    }
  };

  btn.addEventListener('click', () => open(btn.getAttribute('aria-expanded') !== 'true'));
  panel.addEventListener('click', (e) => { if (e.target.closest('a')) open(false); });
  addEventListener('keydown', (e) => { if (e.key === 'Escape' && !panel.hidden) { open(false); btn.focus(); } });
})();

// ── 3 · scroll reveal, counters, parallax ───────────────────────────────────
(function scrollFx() {
  if (reduced || !('IntersectionObserver' in window)) return;

  const targets = [...document.querySelectorAll('.band .wrap > *, .closer .wrap > *')];
  targets.forEach((el, i) => {
    el.classList.add('reveal');
    // The headline of a section comes from further back than the paragraph
    // under it, so a band arrives as a composition rather than as one slab.
    if (el.matches('h2, .eyebrow')) el.classList.add('deep');
    // A small stagger inside each section, capped so a long list never crawls.
    el.style.setProperty('--d', `${Math.min(i % 8, 5) * 55}ms`);
  });

  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      e.target.classList.add('in');
      io.unobserve(e.target);
      if (e.target.querySelector('[data-count]')) countUp(e.target);
    }
  }, { rootMargin: '0px 0px -8% 0px' });
  targets.forEach((el) => io.observe(el));

  // Failsafe: content that hides itself waiting for an event must have a
  // deadline, or a renderer that never scrolls shows a blank page.
  setTimeout(() => targets.forEach((el) => el.classList.add('in')), 4000);
  addEventListener('beforeprint', () => targets.forEach((el) => el.classList.add('in')));

  function countUp(scope) {
    for (const el of scope.querySelectorAll('[data-count]')) {
      const to = Number(el.dataset.count);
      const suffix = el.dataset.suffix ?? '';
      const started = performance.now();
      const tick = (now) => {
        const p = Math.min(1, (now - started) / 900);
        const eased = 1 - (1 - p) ** 3;
        el.textContent = Math.round(to * eased) + suffix;
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }
  }

  // Scroll progress, for the hairline under the header.
  const bar = document.createElement('div');
  bar.className = 'progress';
  document.body.appendChild(bar);
  let ticking = false;
  addEventListener('scroll', () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const max = document.documentElement.scrollHeight - innerHeight;
      bar.style.transform = `scaleX(${max > 0 ? scrollY / max : 0})`;
      document.body.classList.toggle('scrolled', scrollY > 40);
      ticking = false;
    });
  }, { passive: true });
})();

// ── 4 · the contact form ────────────────────────────────────────────────────
//
// Progressive enhancement, not a replacement: the form already works as a
// plain POST. This keeps the visitor on the page, reports what happened, and
// refuses to submit the honeypot — but if this file never loads, the form
// still submits and the message still arrives.
//
// The destination address is not here. It is not anywhere the browser can see
// it. The endpoint holds it.
(function contactForm() {
  const form = document.getElementById('contact');
  if (!form) return;
  const status = form.querySelector('.contact-status');
  const endpoint = form.dataset.endpoint || form.action;

  const say = (msg, kind) => {
    status.textContent = msg;
    status.className = `contact-status${kind ? ` ${kind}` : ''}`;
  };

  form.addEventListener('submit', async (e) => {
    // Let the browser's own validation speak first — it is localised and it
    // moves focus to the offending field, which is more than a custom message
    // usually manages.
    if (!form.reportValidity()) { e.preventDefault(); return; }
    e.preventDefault();

    if (form.elements.website.value) {
      // Silently accept. Telling a bot it was caught only teaches whoever
      // wrote it which field to leave alone next time.
      say('Thanks — we will be in touch.', 'ok');
      form.classList.add('sent');
      return;
    }

    form.classList.add('sending');
    say('Sending…');

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
      });
      if (!res.ok) throw new Error(`the server said ${res.status}`);
      form.classList.remove('sending');
      form.classList.add('sent');
      say('Thanks — we will be in touch.', 'ok');
      form.querySelectorAll('input,textarea').forEach((el) => { el.value = ''; el.disabled = true; });
    } catch (err) {
      form.classList.remove('sending');
      // Say what to do next, not just that something broke. A dead end here is
      // a lost conversation.
      say(`Could not send that (${err.message}). Please try again in a moment.`, 'bad');
    }
  });
})();
