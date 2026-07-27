/**
 * Time helpers.
 *
 * A single injectable clock so tests can move time without sleeping, and so
 * "45 days later" in a demo is a real 45 days to every retention, decay and
 * temporal detector in the system.
 */
import { VaultError } from './errors.js';


let _now = () => Date.now();

/** Override the clock. Returns a restore function. */
export function setClock(fn) {
  const prev = _now;
  _now = fn;
  return () => { _now = prev; };
}

export function now() { return _now(); }
export function iso(ts = now()) { return new Date(ts).toISOString(); }

export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const WEEK = 7 * DAY;
export const MONTH = 30 * DAY;
export const YEAR = 365 * DAY;

const UNITS = { ms: 1, s: SECOND, m: MINUTE, h: HOUR, d: DAY, w: WEEK, mo: MONTH, y: YEAR };

/**
 * Parse a duration: "30d", "12h", "18mo", "7y", "never", or a number of ms.
 * @param {string|number|null|undefined} spec
 * @returns {number|null} milliseconds, or null for "never"
 */
export function duration(spec) {
  if (spec == null || spec === 'never' || spec === Infinity) return null;
  if (typeof spec === 'number') return spec;
  const m = /^(\d+(?:\.\d+)?)\s*(ms|mo|[smhdwy])$/.exec(String(spec).trim());
  if (!m) throw new VaultError('validation', `unparseable duration: ${spec}`, { expected: '30s, 15m, 4h, 7d, 2w, 6mo, 1y' });
  return Math.round(parseFloat(m[1]) * UNITS[m[2]]);
}

/** Human-readable age: "4 min", "12d", "8 months". */
export function ago(ts, from = now()) {
  const d = Math.max(0, from - ts);
  if (d < MINUTE) return `${Math.round(d / SECOND)}s`;
  if (d < HOUR) return `${Math.round(d / MINUTE)} min`;
  if (d < DAY) return `${Math.round(d / HOUR)}h`;
  if (d < 60 * DAY) return `${Math.round(d / DAY)}d`;
  if (d < 2 * YEAR) return `${Math.round(d / MONTH)} months`;
  return `${(d / YEAR).toFixed(1)} years`;
}

export function withinBusinessHours(ts, { start = 8, end = 19, tzOffsetHours = 0, days = [1, 2, 3, 4, 5] } = {}) {
  const d = new Date(ts + tzOffsetHours * HOUR);
  const day = d.getUTCDay();
  const hour = d.getUTCHours();
  return days.includes(day) && hour >= start && hour < end;
}

/** Bucket a timestamp for rate/anomaly windows. */
export function bucket(ts, size = HOUR) {
  return Math.floor(ts / size) * size;
}
