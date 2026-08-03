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

  // The same room as the film, at a fraction of its detail. This has to paint
  // in a single frame on a phone, so there are no reflections, no dust and no
  // racks — just the three panels, their glow and the desk. It is a stand-in
  // for the two seconds before the video plays, not a second implementation of
  // it, and the composition matches so the crossfade is not a cut.
  function frame(now) {
    const t = ((now - t0) / 8000) % 1;           // an 8s loop, same as the film
    const S = H / 720;
    const camX = Math.sin(t * TAU) * 14 * S;
    const camY = Math.cos(t * TAU) * 7 * S;
    const deskY = H * 0.72;

    ctx.fillStyle = '#05030a';
    ctx.fillRect(0, 0, W, H);

    // racks, reduced to their status lights
    for (let i = 0; i < 7; i++) {
      const x = (i / 7) * W * 1.15 - W * 0.06;
      const w = W * 0.085;
      ctx.fillStyle = 'rgba(18,10,20,.85)';
      ctx.fillRect(x + camX * 0.25, H * 0.06 + camY * 0.25, w, deskY - H * 0.06);
      for (let j = 0; j < 10; j++) {
        const y = H * 0.1 + j * (deskY - H * 0.14) / 10 + camY * 0.25;
        const blink = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin((t + rnd(i * 7 + j)) * TAU * 2));
        ctx.fillStyle = rnd(i * 40 + j) > 0.55
          ? `rgba(255,140,43,${0.1 + 0.35 * blink})`
          : `rgba(90,110,130,${0.05 + 0.1 * blink})`;
        ctx.fillRect(x + w * 0.14 + camX * 0.25, y, w * 0.1, 2.5 * S);
      }
    }

    const panel = (x, y, w, h, shear, draw) => {
      ctx.save();
      ctx.translate(x + camX, y + camY);
      ctx.transform(1, shear, 0, 1, 0, 0);
      ctx.fillStyle = '#151020';
      ctx.fillRect(-7 * S, -7 * S, w + 14 * S, h + 14 * S);
      ctx.strokeStyle = 'rgba(255,150,70,.22)'; ctx.lineWidth = 1 * S;
      ctx.strokeRect(-7 * S, -7 * S, w + 14 * S, h + 14 * S);
      ctx.fillStyle = '#0b0814';
      ctx.fillRect(0, 0, w, h);
      ctx.save(); ctx.beginPath(); ctx.rect(0, 0, w, h); ctx.clip();
      draw(w, h);
      ctx.fillStyle = 'rgba(0,0,0,.22)';
      for (let yy = 0; yy < h; yy += 3 * S) ctx.fillRect(0, yy, w, 1 * S);
      ctx.restore();
      ctx.restore();
    };

    // centre: lines of output, as bars — the real text is in the film
    const cw = W * 0.40; const ch = H * 0.44;
    panel(W * 0.5 - cw / 2, H * 0.24, cw, ch, 0, (w, h) => {
      const lh = 13 * S;
      const rows = Math.ceil(h / lh);
      const scrolled = t * rows;
      for (let i = 0; i < rows + 1; i++) {
        const k = (Math.floor(scrolled) + i) % 37;
        const y = i * lh - (scrolled % 1) * lh + 8 * S;
        const kind = rnd(k * 3) > 0.86 ? 'bad' : rnd(k * 3) > 0.72 ? 'warn' : 'ok';
        ctx.fillStyle = kind === 'bad' ? 'rgba(255,110,110,.55)'
          : kind === 'warn' ? 'rgba(255,190,90,.5)' : 'rgba(196,206,224,.32)';
        ctx.fillRect(10 * S, y, (0.2 + rnd(k * 5) * 0.72) * (w - 20 * S), 4 * S);
      }
    });

    // left: the walls
    panel(W * 0.045, H * 0.30, W * 0.20, H * 0.34, 0.05, (w, h) => {
      const n = 12;
      for (let i = 0; i < n; i++) {
        const y = 22 * S + i * (h - 30 * S) / n;
        const hot = Math.floor(t * n) === i;
        if (hot) { ctx.fillStyle = 'rgba(255,106,19,.14)'; ctx.fillRect(0, y - 5 * S, w, 14 * S); }
        ctx.fillStyle = hot ? 'rgba(255,200,150,.8)' : 'rgba(180,190,210,.3)';
        ctx.fillRect(9 * S, y, (0.3 + rnd(i) * 0.4) * w, 4 * S);
        ctx.fillStyle = i % 3 === 0 ? 'rgba(255,110,110,.6)' : 'rgba(120,200,255,.35)';
        ctx.fillRect(w - 34 * S, y - 1 * S, 26 * S, 5 * S);
      }
    });

    // right: the ten checks
    panel(W * 0.755, H * 0.30, W * 0.20, H * 0.34, -0.05, (w, h) => {
      for (let i = 0; i < 10; i++) {
        const y = 26 * S + i * (h - 36 * S) / 10;
        const lit = (Math.sin((t * 2 - i / 13) * TAU) + 1) / 2;
        ctx.fillStyle = `rgba(170,180,200,${0.2 + 0.25 * lit})`;
        ctx.fillRect(9 * S, y, w * 0.34, 4 * S);
        ctx.fillStyle = 'rgba(255,255,255,.05)';
        ctx.fillRect(w * 0.52, y - 1 * S, w * 0.38, 6 * S);
        ctx.fillStyle = `rgba(255,166,77,${0.3 + 0.65 * lit})`;
        ctx.fillRect(w * 0.52, y - 1 * S, w * 0.38 * (0.35 + 0.65 * lit), 6 * S);
      }
    });

    // the light they throw
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (const [gx, gy, gr, a] of [
      [W * 0.5 + camX, H * 0.45 + camY, W * 0.42, 0.3],
      [W * 0.145 + camX, H * 0.47 + camY, W * 0.2, 0.15],
      [W * 0.855 + camX, H * 0.47 + camY, W * 0.2, 0.15]
    ]) {
      const g = ctx.createRadialGradient(gx, gy, 0, gx, gy, gr);
      g.addColorStop(0, `rgba(255,140,43,${a})`);
      g.addColorStop(0.45, `rgba(214,59,6,${a * 0.3})`);
      g.addColorStop(1, 'rgba(255,106,19,0)');
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(gx, gy, gr, 0, TAU); ctx.fill();
    }
    ctx.restore();

    // the desk
    const desk = ctx.createLinearGradient(0, deskY, 0, H);
    desk.addColorStop(0, 'rgba(26,14,10,.95)');
    desk.addColorStop(1, 'rgba(8,4,8,1)');
    ctx.fillStyle = desk;
    ctx.fillRect(0, deskY, W, H - deskY);
    ctx.fillStyle = 'rgba(255,140,43,.16)';
    ctx.fillRect(0, deskY, W, 1.5 * S);

    const v = ctx.createRadialGradient(W / 2, H / 2, H * 0.32, W / 2, H / 2, W * 0.78);
    v.addColorStop(0, 'rgba(4,2,7,0)');
    v.addColorStop(1, 'rgba(4,2,7,.8)');
    ctx.fillStyle = v;
    ctx.fillRect(0, 0, W, H);

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
