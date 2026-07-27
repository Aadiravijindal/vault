#!/usr/bin/env node
/**
 * VAULT AS AN MCP SERVER (§4.2 "Inline via MCP server is the right door here").
 *
 * Speaks MCP over stdio using JSON-RPC 2.0. Any MCP client — Claude Code,
 * Cursor, Cline, Continue, Windsurf — registers this server and gets:
 *
 *   vault_remember   write to shared memory THROUGH THE GATE
 *   vault_recall     read, with provenance labels the agent can see
 *   vault_check      dry-run: what would the gate do with this text?
 *   vault_status     what the agent is allowed to do, and what is held
 *
 * Two things matter here and are easy to get wrong:
 *
 *  - `vault_remember` cannot bypass the gate. There is no parameter for it.
 *  - Tool DESCRIPTIONS are untrusted content in the other direction too: this
 *    server scans any tool description a client sends it (§9.4).
 */
import { createInterface } from 'node:readline';
import { Vault } from '../index.js';
import { Ledger } from '../ledger/ledger.js';

const PROTOCOL_VERSION = '2024-11-05';

export class McpServer {
  /**
   * @param {object} opts
   * @param {Vault} [opts.vault]
   * @param {string} [opts.agentId]
   */
  constructor({ vault = null, agentId = process.env.VAULT_AGENT_ID || 'a-mcp-client', dir = process.env.VAULT_DATA || null } = {}) {
    this.vault = vault || new Vault({ dir, signingKey: Ledger.newSigningKey(), administrators: ['admin'] });
    this.agentId = agentId;
    this.credential = process.env.VAULT_CREDENTIAL || null;
    this._ensureAgent();
  }

  _ensureAgent() {
    if (this.vault.registry.get(this.agentId)) return;
    this.vault.registerAgent({
      id: this.agentId,
      name: process.env.VAULT_AGENT_NAME || 'MCP client',
      purpose: 'coding assistant connected over MCP',
      businessOwner: process.env.VAULT_BUSINESS_OWNER || 'unassigned',
      technicalOwner: process.env.VAULT_TECHNICAL_OWNER || 'unassigned',
      department: process.env.VAULT_DEPARTMENT || 'engineering',
      mode: 'inline',
      pinnedModel: process.env.VAULT_MODEL || null,
      folders: process.env.VAULT_FOLDERS ? process.env.VAULT_FOLDERS.split(',') : []
    });
    const c = this.vault.issueCredential(this.agentId, {});
    this.credential = this.credential || c.credential;
  }

  tools() {
    return [
      {
        name: 'vault_remember',
        description:
          'Write something to the company\'s shared AI memory. Every write passes ten governance checks '
          + 'before it can become a durable fact: identity, channel trust, source verification, private-information '
          + 'scanning, sensitivity labelling, department walls, instruction detection, policy rules, reconciliation '
          + 'against what is already known, and lawful basis. The result tells you whether it was written, held for '
          + 'a human, masked or rejected — and why. There is no way to skip the checks.',
        inputSchema: {
          type: 'object',
          properties: {
            content: { type: 'string', description: 'What to remember, in plain language. State facts about the world, not instructions.' },
            channel: {
              type: 'string',
              description: 'Where this came from. Be accurate — trust comes from the channel, not from a score.',
              enum: ['employee_session', 'system_of_record', 'signed_internal_service', 'agent_output', 'pr_comment', 'customer_chat', 'email', 'scraped_document', 'mcp_tool_output', 'third_party_api', 'unknown']
            },
            speaker: { type: 'string', description: 'Who said it. Unattributable claims are held.' },
            folder: { type: 'string', description: 'Optional. Where it belongs, e.g. engineering/project-atlas/decisions/. Omit and Vault routes it, or holds it for review if routing is uncertain.' },
            project: { type: 'string', description: 'Optional project scope.' }
          },
          required: ['content']
        }
      },
      {
        name: 'vault_recall',
        description:
          'Read from the shared AI memory. Every fact comes back wearing its provenance: who said it, over which '
          + 'channel, how it was verified, and whether it is an approved policy, a verified statement, or an AI guess. '
          + 'Facts marked GUESSED must not be repeated as established. Facts you are not cleared for are withheld and '
          + 'counted, never silently omitted.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'What you want to know.' },
            folder: { type: 'string', description: 'Optional folder to scope the search.' },
            entity: { type: 'string', description: 'Optional entity (customer, person, project).' },
            limit: { type: 'number', description: 'Max facts to return (default 15).' }
          },
          required: ['query']
        }
      },
      {
        name: 'vault_check',
        description:
          'Dry-run. Ask what the gate WOULD do with a piece of text without writing anything. Useful before you '
          + 'commit something you are unsure about, and for understanding why a previous write was held.',
        inputSchema: {
          type: 'object',
          properties: {
            content: { type: 'string' },
            channel: { type: 'string' }
          },
          required: ['content']
        }
      },
      {
        name: 'vault_status',
        description:
          'What this agent is permitted to do, what is currently held for review, and whether any emergency control '
          + 'is engaged. Check this if writes are being refused.',
        inputSchema: { type: 'object', properties: {} }
      }
    ];
  }

  /** @param {object} req JSON-RPC request */
  async handle(req) {
    const { id, method, params } = req;
    const reply = (result) => ({ jsonrpc: '2.0', id, result });
    const fail = (code, message, data) => ({ jsonrpc: '2.0', id, error: { code, message, data } });

    try {
      switch (method) {
        case 'initialize':
          return reply({
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: {}, logging: {} },
            serverInfo: { name: 'vault', version: '2.0.0', description: 'Shared AI memory with a gate at the door' }
          });
        case 'notifications/initialized':
        case 'initialized':
          return null;
        case 'ping':
          return reply({});
        case 'tools/list':
          return reply({ tools: this.tools() });
        case 'tools/call':
          return reply(await this.call(params?.name, params?.arguments || {}));
        default:
          return fail(-32601, `method not found: ${method}`);
      }
    } catch (e) {
      return fail(-32000, e.message, e.code ? { code: e.code } : undefined);
    }
  }

  async call(name, args) {
    const v = this.vault;
    const text = (s) => ({ content: [{ type: 'text', text: s }] });

    if (name === 'vault_remember') {
      const r = v.ingest({
        agentId: this.agentId,
        channel: args.channel || 'agent_output',
        connectorMode: 'inline',
        connector: 'mcp',
        participants: [{ name: args.speaker || this.agentId, kind: args.speaker ? 'employee' : 'agent' }],
        turns: [{ speaker: args.speaker || this.agentId, text: String(args.content ?? '') }]
      }, {
        credential: this.credential,
        folderHint: args.folder,
        project: args.project,
        purpose: 'memory_governance'
      });

      if (!r.captured) {
        return text(`Not captured: ${r.reason}${r.queued ? ` (queued at position ${r.position})` : ''}`);
      }
      const lines = [`Sealed as ${r.conversationId}. ${r.summary}.`, ''];
      for (const f of r.facts) {
        lines.push(`${OUTCOME_ICON[f.outcome] || '·'} ${f.outcome.toUpperCase()} — "${f.claim}"`);
        if (f.factId) lines.push(`   fact id: ${f.factId}`);
        for (const why of f.reasons || []) lines.push(`   why: ${why}`);
        if (f.outcome === 'hold') lines.push(`   A human will decide. This is not visible to any agent until then.`);
        if (f.outcome === 'block') lines.push(`   This never became a fact. Do not retry it — fix the cause.`);
        lines.push('');
      }
      return text(lines.join('\n'));
    }

    if (name === 'vault_recall') {
      const r = v.read(args.query, {
        agentId: this.agentId,
        credential: this.credential,
        folder: args.folder,
        entity: args.entity,
        limit: args.limit || 15,
        purpose: 'memory_governance'
      });
      return text(v.readPath.render(r));
    }

    if (name === 'vault_check') {
      // Run the whole pipeline in a throwaway Vault so nothing is written.
      const probe = new Vault({ seedRules: false });
      probe.registerAgent({
        id: 'a-probe', name: 'gate probe', purpose: 'dry run',
        businessOwner: 'probe', technicalOwner: 'probe', mode: 'inline'
      });
      const cred = probe.issueCredential('a-probe', {});
      const r = probe.ingest({
        agentId: 'a-probe', channel: args.channel || 'agent_output',
        turns: [{ speaker: 'probe', text: String(args.content ?? '') }]
      }, { credential: cred.credential });
      const lines = ['Dry run — nothing was written.', ''];
      for (const f of r.facts) {
        lines.push(`${OUTCOME_ICON[f.outcome] || '·'} would be ${f.outcome.toUpperCase()}: "${f.claim}"`);
        for (const why of f.reasons || []) lines.push(`   ${why}`);
      }
      if (!r.facts.length) lines.push('No candidate facts were extracted from that text.');
      probe.close();
      return text(lines.join('\n'));
    }

    if (name === 'vault_status') {
      const agent = v.registry.get(this.agentId);
      const ks = v.killswitch.state();
      const held = v.review.list({ status: 'open', limit: 5 });
      return text([
        `Agent:      ${agent.id} (${agent.mode} mode)`,
        `Owners:     ${agent.businessOwner} / ${agent.technicalOwner}`,
        `Scope:      ${agent.folders.length ? agent.folders.join(', ') : 'no folder restriction'}`,
        `Clearance:  up to ${agent.sensitivityCeiling}`,
        `Model pin:  ${agent.pinnedModel || 'not pinned — a silent model swap would go unnoticed'}`,
        `Writes:     ${agent.writes} written · ${agent.held} held · ${agent.blocked} blocked`,
        '',
        ks.active ? `⚠️  ${v.killswitch.agentMessage()}` : 'Emergency controls: normal.',
        '',
        held.length ? `${held.length} item(s) currently held for human review:` : 'Nothing of yours is waiting on a human.',
        ...held.map((h) => `  · "${h.claimExcerpt}" — ${h.reasons[0] ?? ''}`)
      ].join('\n'));
    }

    throw Object.assign(new Error(`unknown tool: ${name}`), { code: 'unknown_tool' });
  }

  /** Run over stdio. */
  listen() {
    const rl = createInterface({ input: process.stdin, terminal: false });
    rl.on('line', async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let req;
      try { req = JSON.parse(trimmed); } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }) + '\n');
        return;
      }
      const res = await this.handle(req);
      if (res) process.stdout.write(JSON.stringify(res) + '\n');
    });
    process.stderr.write(`vault mcp server ready — agent ${this.agentId}, inline mode, gate active\n`);
    return this;
  }
}

const OUTCOME_ICON = {
  pass: '✓', merged: '✓', refined: '✓', mask: '◐',
  hold: '⏳', escalate: '⏳', 'require-4-eyes': '⏳',
  block: '⛔', quarantine: '🔒'
};

// Run directly: node src/mcp/server.js
if (import.meta.url === `file://${process.argv[1]}`) {
  new McpServer().listen();
}
