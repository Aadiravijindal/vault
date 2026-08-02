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

  function frame(now) {
    const t = ((now - t0) / 8000) % 1;           // an 8s loop, same as the film
    const GATE = W * 0.31;                       // off-centre, as in the film —
    ctx.clearRect(0, 0, W, H);                   // centred it hides behind the copy

    // far field
    for (let i = 0; i < 60; i++) {
      const x = rnd(i) * W; const y = rnd(i + 500) * H;
      const pulse = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin((t + rnd(i + 900)) * TAU * 2));
      ctx.fillStyle = `rgba(255,120,40,${0.05 + 0.14 * pulse})`;
      ctx.beginPath(); ctx.arc(x, y, 1.1 + 1.5 * pulse, 0, TAU); ctx.fill();
    }

    // perspective floor
    ctx.save();
    ctx.strokeStyle = 'rgba(255,132,52,.3)'; ctx.lineWidth = 1;
    const horizon = H * 0.62;
    for (let i = 0; i < 26; i++) {
      const p = ((i + t) % 26) / 26;
      const y = horizon + p ** 2.6 * (H - horizon) * 1.9;
      if (y > H) continue;
      ctx.globalAlpha = Math.min(1, p * 2.2) * 0.7;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
    ctx.globalAlpha = 0.42;
    for (let i = -14; i <= 14; i++) {
      ctx.beginPath(); ctx.moveTo(W / 2 + i * 18, horizon); ctx.lineTo(W / 2 + i * 210, H); ctx.stroke();
    }
    ctx.restore();

    // the gate
    const g = ctx.createLinearGradient(GATE - 130, 0, GATE + 130, 0);
    g.addColorStop(0, 'rgba(255,106,19,0)');
    g.addColorStop(0.5, `rgba(255,140,43,${0.26 + 0.09 * Math.sin(t * TAU * 3)})`);
    g.addColorStop(1, 'rgba(255,106,19,0)');
    ctx.fillStyle = g; ctx.fillRect(GATE - 130, 0, 260, H);
    ctx.save();
    ctx.shadowColor = 'rgba(255,150,60,.9)'; ctx.shadowBlur = 22;
    ctx.strokeStyle = 'rgba(255,214,176,.9)'; ctx.lineWidth = 2.5;
    ctx.beginPath(); ctx.moveTo(GATE, 0); ctx.lineTo(GATE, H); ctx.stroke();
    ctx.restore();
    for (let i = 0; i < 10; i++) {
      const y = (H / 11) * (i + 1);
      const lit = (Math.sin((t * 2 - i / 14) * TAU) + 1) / 2;
      ctx.fillStyle = `rgba(255,196,130,${0.35 + 0.65 * lit})`;
      ctx.fillRect(GATE - 13, y - 2, 26, 4);
    }

    // packets
    for (let i = 0; i < 48; i++) {
      const y = 40 + rnd(i + 20) * (H - 80);
      const p = ((t * (0.55 + rnd(i + 40) * 0.75) + rnd(i + 60)) % 1);
      const x = p * (W + 260) - 130;
      const blocked = rnd(i + 80) > 0.83;
      const crossed = x > GATE;

      if (blocked && crossed) {
        const d = (x - GATE) / 90;
        if (d > 1) continue;
        const a = (1 - d) * 0.9;
        ctx.save();
        ctx.shadowColor = 'rgba(255,60,60,.9)'; ctx.shadowBlur = 22;
        ctx.fillStyle = `rgba(255,96,96,${a})`;
        ctx.beginPath(); ctx.arc(GATE, y, 3 + 10 * d, 0, TAU); ctx.fill();
        ctx.strokeStyle = `rgba(255,120,120,${a * 0.65})`; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(GATE, y, 6 + 26 * d, 0, TAU); ctx.stroke();
        ctx.restore();
        continue;
      }

      const len = 16 + rnd(i + 100) * 30;
      const tail = ctx.createLinearGradient(x - len, y, x, y);
      tail.addColorStop(0, crossed ? 'rgba(255,140,43,0)' : 'rgba(190,190,200,0)');
      tail.addColorStop(1, crossed ? 'rgba(255,190,120,.9)' : 'rgba(225,225,235,.55)');
      ctx.fillStyle = tail; ctx.fillRect(x - len, y - 1.1, len, 2.2);
      ctx.fillStyle = crossed ? 'rgba(255,205,150,.95)' : 'rgba(240,240,248,.7)';
      ctx.shadowColor = crossed ? 'rgba(255,140,43,.9)' : 'rgba(200,210,255,.5)';
      ctx.shadowBlur = crossed ? 12 : 7;
      ctx.beginPath(); ctx.arc(x, y, crossed ? 2.4 : 1.9, 0, TAU); ctx.fill();
      ctx.shadowBlur = 0;
    }

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
