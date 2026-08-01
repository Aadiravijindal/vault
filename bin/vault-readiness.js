#!/usr/bin/env node
/**
 * What an auditor would find today.
 *
 *   node bin/vault-readiness.js [--json] [--window <days>]
 *
 * Exit code is always 0: this reports a position, it does not pass or fail
 * anything. A SOC 2 opinion is issued by a licensed firm and by nothing else.
 */
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { assessReadiness, renderReadiness } from '../src/comply/readiness.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const wIdx = args.indexOf('--window');
const windowDays = wIdx >= 0 ? Number(args[wIdx + 1]) : 90;

const vault = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] });
const report = assessReadiness(vault, { windowDays });

console.log(json ? JSON.stringify(report, null, 2) : renderReadiness(report));
