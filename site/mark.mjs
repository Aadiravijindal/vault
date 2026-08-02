#!/usr/bin/env node
/**
 * Generates the Vault mark as a single SVG path.
 *
 *   node site/mark.mjs            # the path data
 *   node site/mark.mjs --svg      # a whole SVG file, for checking
 *
 * ── WHY THIS IS COMPUTED AND NOT DRAWN ──────────────────────────────────────
 *
 * The mark is seven blobs joined by concave necks — a metaball. The joins are
 * not straight bars with rounded ends; they are circular fillets tangent to
 * both blobs, which is what gives the shape its liquid, pinched quality. Eyeing
 * those fillets in a path editor gets you something that looks nearly right at
 * poster size and visibly wrong at 24px, because the tangency is off by a
 * fraction of a degree and the neck develops a kink.
 *
 * So they are solved rather than drawn. For two blobs of radius rA and rB whose
 * centres are d apart, a fillet of radius F is tangent to both when its centre
 * sits at distance rA+F from one and rB+F from the other — two points, one each
 * side of the centre line. From those, the tangent points fall out exactly, and
 * the outline is: the outer arc of one blob, a concave fillet arc, the outer arc
 * of the other, and the second fillet back.
 *
 * The alternative was an SVG `feGaussianBlur` + `feColorMatrix` "gooey" filter,
 * which fakes the same effect. It was rejected: a filter cannot go in a favicon
 * data URI, costs a compositing pass on every paint of an element that is on
 * every page, and renders subtly differently across browsers. A path is exact,
 * free, and the same everywhere.
 *
 * ── THE GEOMETRY ────────────────────────────────────────────────────────────
 *
 * Six blobs on a regular hexagon with a vertex at twelve o'clock, one larger
 * blob at the centre, and four necks that leave the shape in three pieces:
 *
 *        ●───◐            {top, upper-left}
 *      ◐   ⬤   ●          {upper-right, CENTRE, lower-left}
 *        ◐───●            {bottom, lower-right}
 *
 * The gaps are the design. A fully connected lattice reads as a diagram; three
 * loose groups read as something alive.
 */

const VIEW = 100;                 // viewBox is 0 0 100 100
const CX = 50, CY = 50;
const R_HEX = 33.5;               // circumradius of the ring of six
const R_OUTER = 11.6;             // radius of each outer blob
const R_CENTRE = 14.6;            // the centre blob is deliberately larger
const FILLET = 6.0;               // radius of the concave neck — tuned to the supplied render

/** Hexagon vertex k, starting at twelve o'clock and going clockwise. */
const vertex = (k) => {
  const a = (-90 + k * 60) * Math.PI / 180;
  return { x: CX + R_HEX * Math.cos(a), y: CY + R_HEX * Math.sin(a), r: R_OUTER };
};

const NODES = {
  top: vertex(0),
  upperRight: vertex(1),
  lowerRight: vertex(2),
  bottom: vertex(3),
  lowerLeft: vertex(4),
  upperLeft: vertex(5),
  centre: { x: CX, y: CY, r: R_CENTRE }
};

/** The four necks, and so the three groups. */
const LINKS = [
  ['top', 'upperLeft'],
  ['upperRight', 'centre'],
  ['centre', 'lowerLeft'],
  ['bottom', 'lowerRight']
];

// ---------------------------------------------------------------------------

/**
 * The two fillet circles tangent to both blobs, one either side of the line
 * joining their centres.
 */
function fillets(a, b, F = FILLET) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const d = Math.hypot(dx, dy);
  const ra = a.r + F, rb = b.r + F;
  // Standard two-circle intersection: how far along AB the intersection sits,
  // and how far off the line.
  const along = (d * d + ra * ra - rb * rb) / (2 * d);
  const off2 = ra * ra - along * along;
  if (off2 <= 0) {
    throw new Error(`blobs ${d.toFixed(2)} apart cannot take a fillet of ${F} — widen the gap or shrink the fillet`);
  }
  const off = Math.sqrt(off2);
  const ux = dx / d, uy = dy / d;      // along AB
  const nx = -uy, ny = ux;             // perpendicular
  return [
    { x: a.x + along * ux + off * nx, y: a.y + along * uy + off * ny },
    { x: a.x + along * ux - off * nx, y: a.y + along * uy - off * ny }
  ];
}

/** Where a fillet centred at f touches a blob: on the line between them. */
function touch(blob, f) {
  const dx = f.x - blob.x, dy = f.y - blob.y;
  const m = Math.hypot(dx, dy);
  return { x: blob.x + (blob.r * dx) / m, y: blob.y + (blob.r * dy) / m };
}

const angleOf = (c, p) => Math.atan2(p.y - c.y, p.x - c.x);
const n2 = (v) => (Math.round(v * 100) / 100).toString();
const TAU = Math.PI * 2;
const norm = (a) => ((a % TAU) + TAU) % TAU;

/**
 * An arc command, with both flags DERIVED rather than assumed.
 *
 * SVG's `large-arc` and `sweep` are the two flags everyone guesses at, and
 * guessing is how the first attempt at this produced crescents: the blob arcs
 * took the short way between the tangent points, cutting straight through the
 * blob instead of going round the outside of it. Given a start, an end and a
 * direction, both flags follow from the swept angle, so neither is a choice.
 */
function arc(centre, r, from, to, clockwise) {
  const a1 = angleOf(centre, from);
  const a2 = angleOf(centre, to);
  const delta = clockwise ? norm(a2 - a1) : norm(a1 - a2);
  const large = delta > Math.PI ? 1 : 0;
  return `A${n2(r)} ${n2(r)} 0 ${large} ${clockwise ? 1 : 0} ${n2(to.x)} ${n2(to.y)}`;
}

/** Does travelling from a1 to a2 in this direction pass through `through`? */
function passesThrough(centre, from, to, through, clockwise) {
  const a1 = angleOf(centre, from);
  const a2 = angleOf(centre, to);
  const span = clockwise ? norm(a2 - a1) : norm(a1 - a2);
  const t = clockwise ? norm(through - a1) : norm(a1 - through);
  return t < span;
}

/**
 * The arc around a blob that goes the OUTSIDE way — the long way round, away
 * from whatever it is joined to. Chosen by asking which direction avoids the
 * neighbour rather than by picking a flag and hoping.
 */
function outerArc(blob, from, to, avoid) {
  const away = angleOf(blob, avoid);
  const cw = !passesThrough(blob, from, to, away, true);
  return arc(blob, blob.r, from, to, cw);
}

/**
 * The concave neck. Both candidate arcs between the tangent points are short;
 * the right one is whichever bows TOWARDS the line joining the two blobs,
 * because that is what pinches the waist rather than bulging it.
 */
function neckArc(f, from, to, a, b) {
  const mid = (clockwise) => {
    const a1 = angleOf(f, from);
    const delta = clockwise ? norm(angleOf(f, to) - a1) : -norm(a1 - angleOf(f, to));
    const m = a1 + delta / 2;
    return { x: f.x + FILLET * Math.cos(m), y: f.y + FILLET * Math.sin(m) };
  };
  // Distance from the centre line AB — smaller means it bows inward.
  const off = (p) => {
    const dx = b.x - a.x, dy = b.y - a.y;
    const len = Math.hypot(dx, dy);
    return Math.abs((p.x - a.x) * dy - (p.y - a.y) * dx) / len;
  };
  const clockwise = off(mid(true)) < off(mid(false));
  return arc(f, FILLET, from, to, clockwise);
}

/**
 * Outline of a chain of blobs joined end to end, walked as one closed loop:
 * along one side through every neck, around the far blob, back along the other
 * side, and around the first blob to close.
 */
function chain(names) {
  const blobs = names.map((n) => NODES[n]);
  const joins = [];
  for (let i = 0; i < blobs.length - 1; i++) {
    const a = blobs[i], b = blobs[i + 1];
    const [f1, f2] = fillets(a, b);
    joins.push({
      a, b,
      side1: { f: f1, ta: touch(a, f1), tb: touch(b, f1) },
      side2: { f: f2, ta: touch(a, f2), tb: touch(b, f2) }
    });
  }

  const seg = [`M${n2(joins[0].side1.ta.x)} ${n2(joins[0].side1.ta.y)}`];

  for (let i = 0; i < joins.length; i++) {
    const j = joins[i];
    seg.push(neckArc(j.side1.f, j.side1.ta, j.side1.tb, j.a, j.b));
    if (i < joins.length - 1) {
      // Across a middle blob: the short hop on this side, between two necks.
      seg.push(arc(j.b, j.b.r, j.side1.tb, joins[i + 1].side1.ta,
        !passesThrough(j.b, j.side1.tb, joins[i + 1].side1.ta, angleOf(j.b, j.a), true)));
    }
  }

  const last = joins[joins.length - 1];
  seg.push(outerArc(last.b, last.side1.tb, last.side2.tb, last.a));

  for (let i = joins.length - 1; i >= 0; i--) {
    const j = joins[i];
    seg.push(neckArc(j.side2.f, j.side2.tb, j.side2.ta, j.a, j.b));
    if (i > 0) {
      seg.push(arc(j.a, j.a.r, j.side2.ta, joins[i - 1].side2.tb,
        !passesThrough(j.a, j.side2.ta, joins[i - 1].side2.tb, angleOf(j.a, j.b), true)));
    }
  }

  seg.push(outerArc(joins[0].a, joins[0].side2.ta, joins[0].side1.ta, joins[0].b));
  seg.push('Z');
  return seg.join('');
}

export const MARK_PATH = [
  chain(['top', 'upperLeft']),
  chain(['upperRight', 'centre', 'lowerLeft']),
  chain(['bottom', 'lowerRight'])
].join('');

export const MARK_VIEWBOX = `0 0 ${VIEW} ${VIEW}`;

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes('--svg')) {
    console.log(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="${MARK_VIEWBOX}"><path fill="#000" d="${MARK_PATH}"/></svg>`);
  } else {
    console.log(MARK_PATH);
  }
}
