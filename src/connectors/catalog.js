/**
 * THE CONNECTOR CATALOG and THE COVERAGE MAP (§4.2–4.3).
 *
 * Every connector ships with the same seven things: auth method, modes
 * supported, what data it pulls, what it CANNOT pull, setup time, scopes
 * required, and rate-limit profile.
 *
 * The coverage map publishes the holes. Vagueness here is what makes CISOs
 * distrust vendors; publishing what you cannot see is what makes them trust you.
 */

/** @typedef {'watch'|'inline'|'gateway'} Mode */

export const MODES = {
  watch: {
    id: 'watch',
    name: 'WATCH',
    how: "Read the tool's own logs. Vault sees what happened, after it happened.",
    setup: 'minutes to hours — one API credential',
    power: 'forensics, inventory, contagion trace. CANNOT BLOCK.',
    securityReview: 'fast — a read-only posture gets approval in days, not months',
    useFor: "SaaS agents you don't control, and everything on day one"
  },
  inline: {
    id: 'inline',
    name: 'INLINE',
    how: 'The agent calls Vault directly. Vault sits in the write path.',
    setup: '~20 min per agent — SDK, MCP server or webhook',
    power: 'FULL. Hold, block, mask, escalate, enforce — before a fact exists.',
    securityReview: 'medium',
    useFor: 'anything you built or control. This is where the product has teeth.'
  },
  gateway: {
    id: 'gateway',
    name: 'GATEWAY',
    how: 'Proxy in front of AI API traffic. Read-only or enforcing.',
    setup: 'network/DNS change — days',
    power: 'sees everything by construction, including agents nobody registered',
    securityReview: 'slower — it is in the network path',
    useFor: 'finding shadow agents, covering custom API bots at scale'
  }
};

export const RULE_OF_THUMB = 'Watch finds things. Inline stops things. Gateway finds things you didn\'t know existed.';

/**
 * The catalog. `cannotPull` is the field that matters — it is the honesty that
 * closes security reviews.
 */
export const CONNECTORS = [
  // ---- voice / calling agents -------------------------------------------
  {
    id: 'vapi', name: 'Vapi', category: 'voice', vendor: 'Vapi',
    auth: 'API key + webhook signing secret', modes: ['watch', 'inline'],
    pulls: ['transcript', 'recording', 'caller metadata', 'duration', 'outcome', 'disposition', 'DTMF/IVR path', 'transfer events', 'voicemail'],
    cannotPull: ['audio the caller spoke before the assistant answered', 'anything from a call that failed to connect'],
    setupMinutes: 20, scopes: ['calls:read', 'webhooks:write'], rateLimit: '100 req/min',
    inlineHook: 'webhook on call-end — full write control',
    channel: 'phone_call'
  },
  { id: 'bland', name: 'Bland', category: 'voice', vendor: 'Bland', auth: 'API key', modes: ['watch', 'inline'], pulls: ['transcript', 'recording', 'metadata', 'outcome'], cannotPull: ['real-time mid-call intervention'], setupMinutes: 20, scopes: ['calls:read'], rateLimit: '60 req/min', channel: 'phone_call' },
  { id: 'retell', name: 'Retell', category: 'voice', vendor: 'Retell', auth: 'API key + webhook secret', modes: ['watch', 'inline'], pulls: ['transcript', 'recording', 'metadata', 'sentiment-free disposition'], cannotPull: ['pre-connect audio'], setupMinutes: 20, scopes: ['calls:read'], rateLimit: '100 req/min', channel: 'phone_call' },
  { id: 'twilio', name: 'Twilio-based agents', category: 'voice', vendor: 'Twilio', auth: 'Account SID + auth token', modes: ['watch', 'inline'], pulls: ['recording', 'transcription (where enabled)', 'call metadata'], cannotPull: ['transcripts where transcription was not enabled at call time'], setupMinutes: 30, scopes: ['recordings:read', 'calls:read'], rateLimit: '100 req/s', channel: 'phone_call' },
  { id: 'elevenlabs', name: 'ElevenLabs agents', category: 'voice', vendor: 'ElevenLabs', auth: 'API key', modes: ['watch', 'inline'], pulls: ['transcript', 'audio', 'metadata'], cannotPull: ['voice cloning provenance'], setupMinutes: 20, scopes: ['convai:read'], rateLimit: 'plan-dependent', channel: 'phone_call' },
  { id: 'synthflow', name: 'Synthflow', category: 'voice', vendor: 'Synthflow', auth: 'API key', modes: ['watch', 'inline'], pulls: ['transcript', 'metadata', 'outcome'], cannotPull: ['recording where retention is disabled'], setupMinutes: 20, scopes: ['calls:read'], rateLimit: 'plan-dependent', channel: 'phone_call' },
  { id: 'sip', name: 'Custom SIP', category: 'voice', vendor: 'custom', auth: 'SIP credentials + RTP tap', modes: ['watch', 'inline'], pulls: ['audio', 'SIP metadata'], cannotPull: ['anything not routed through the tap'], setupMinutes: 240, scopes: [], rateLimit: 'n/a', channel: 'phone_call' },

  // ---- chat / LLM platforms ---------------------------------------------
  {
    id: 'chatgpt-enterprise', name: 'ChatGPT Enterprise/Edu/Business', category: 'chat', vendor: 'OpenAI',
    auth: 'Compliance API key (Enterprise tier only)', modes: ['watch', 'inline', 'gateway'],
    pulls: ['conversations', 'files', 'custom GPT configs', 'stored memories where exposed'],
    cannotPull: ['anything from personal ChatGPT accounts', 'conversations older than the platform retention window'],
    setupMinutes: 60, scopes: ['compliance.read'], rateLimit: '—',
    retentionWarning: 'the compliance API retains roughly 30 days — Vault must export continuously, which is itself a reason to buy',
    channel: 'customer_chat'
  },
  {
    id: 'claude-enterprise', name: 'Claude Enterprise/Team', category: 'chat', vendor: 'Anthropic',
    auth: 'Admin API key', modes: ['inline', 'gateway'],
    pulls: ['audit events', 'workspace and member configuration'],
    cannotPull: ['message content — the audit log excludes it BY DESIGN'],
    setupMinutes: 45, scopes: ['audit_logs.read'], rateLimit: '—',
    honestNote: 'content is not available from the audit log at all. Coverage requires Inline (MCP/SDK) or Gateway.',
    channel: 'customer_chat'
  },
  { id: 'gemini-enterprise', name: 'Gemini Enterprise', category: 'chat', vendor: 'Google', auth: 'Workspace admin + Vault API', modes: ['watch', 'gateway'], pulls: ['conversations where Google Vault covers them'], cannotPull: ['consumer Gemini accounts'], setupMinutes: 90, scopes: ['ediscovery.readonly'], rateLimit: 'quota-based', channel: 'customer_chat' },
  { id: 'copilot', name: 'Microsoft Copilot', category: 'chat', vendor: 'Microsoft', auth: 'Graph API app registration', modes: ['watch', 'gateway'], pulls: ['Copilot interaction history via Purview', 'prompts and responses where retention is enabled'], cannotPull: ['interactions predating the retention policy'], setupMinutes: 120, scopes: ['AiEnterpriseInteraction.Read.All'], rateLimit: 'Graph throttling', channel: 'customer_chat' },
  { id: 'perplexity', name: 'Perplexity Enterprise', category: 'chat', vendor: 'Perplexity', auth: 'Admin API key', modes: ['watch', 'gateway'], pulls: ['threads', 'sources cited'], cannotPull: ['personal accounts'], setupMinutes: 30, scopes: ['admin.read'], rateLimit: 'plan-dependent', channel: 'customer_chat' },
  { id: 'mistral', name: 'Mistral', category: 'chat', vendor: 'Mistral', auth: 'API key', modes: ['inline', 'gateway'], pulls: ['requests and responses through the gateway'], cannotPull: ['anything not routed through Vault'], setupMinutes: 20, scopes: [], rateLimit: 'plan-dependent', channel: 'third_party_api' },
  { id: 'cohere', name: 'Cohere', category: 'chat', vendor: 'Cohere', auth: 'API key', modes: ['inline', 'gateway'], pulls: ['requests and responses through the gateway'], cannotPull: ['anything not routed through Vault'], setupMinutes: 20, scopes: [], rateLimit: 'plan-dependent', channel: 'third_party_api' },

  // ---- coding agents ------------------------------------------------------
  {
    id: 'claude-code', name: 'Claude Code', category: 'coding', vendor: 'Anthropic',
    auth: 'MCP server registration', modes: ['inline'],
    pulls: ['session transcripts', 'decisions', 'file context', 'diffs', 'tool calls'],
    cannotPull: ['sessions run outside the configured MCP server'],
    setupMinutes: 15, scopes: [], rateLimit: 'n/a',
    inlineHook: 'Vault ships an MCP server — this is the right door for coding agents',
    channel: 'agent_output'
  },
  { id: 'cursor', name: 'Cursor', category: 'coding', vendor: 'Cursor', auth: 'MCP or extension hook', modes: ['inline'], pulls: ['session transcripts', 'file context', 'diffs'], cannotPull: ['local-only sessions with telemetry disabled'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'copilot-agent', name: 'GitHub Copilot Agent', category: 'coding', vendor: 'GitHub', auth: 'GitHub App', modes: ['watch'], pulls: ['PR/issue comments', 'CI logs', 'agent session summaries'], cannotPull: ['in-editor completions', 'full reasoning traces'], setupMinutes: 45, scopes: ['pull_requests:read', 'actions:read'], rateLimit: '5000/hr', channel: 'pr_comment' },
  { id: 'devin', name: 'Devin', category: 'coding', vendor: 'Cognition', auth: 'API key', modes: ['watch', 'inline'], pulls: ['session transcripts', 'plans', 'diffs'], cannotPull: ['internal reasoning not exposed by the API'], setupMinutes: 30, scopes: ['sessions:read'], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'windsurf', name: 'Windsurf', category: 'coding', vendor: 'Codeium', auth: 'MCP', modes: ['inline'], pulls: ['session transcripts', 'diffs'], cannotPull: ['local-only sessions'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'aider', name: 'Aider', category: 'coding', vendor: 'open source', auth: 'MCP / wrapper', modes: ['inline'], pulls: ['session transcripts', 'diffs', 'commit messages'], cannotPull: ['sessions run without the wrapper'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'cline', name: 'Cline', category: 'coding', vendor: 'open source', auth: 'MCP', modes: ['inline'], pulls: ['session transcripts', 'tool calls'], cannotPull: ['sessions without the MCP server configured'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'continue', name: 'Continue', category: 'coding', vendor: 'open source', auth: 'MCP', modes: ['inline'], pulls: ['session transcripts'], cannotPull: ['local sessions without the hook'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'jetbrains-ai', name: 'JetBrains AI', category: 'coding', vendor: 'JetBrains', auth: 'plugin hook', modes: ['inline'], pulls: ['session transcripts'], cannotPull: ['completions'], setupMinutes: 30, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'emergent', name: 'Emergent', category: 'coding', vendor: 'Emergent', auth: 'API key', modes: ['watch', 'inline'], pulls: ['session transcripts', 'artefacts'], cannotPull: ['pre-integration history'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'codex', name: 'Codex', category: 'coding', vendor: 'OpenAI', auth: 'API key / MCP', modes: ['inline', 'gateway'], pulls: ['session transcripts', 'diffs'], cannotPull: ['sessions outside the configured path'], setupMinutes: 20, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },

  // ---- customer-facing bots ----------------------------------------------
  { id: 'intercom-fin', name: 'Intercom Fin', category: 'customer', vendor: 'Intercom', auth: 'OAuth app', modes: ['watch'], pulls: ['conversation', 'customer identity', 'resolution', 'escalation', 'CSAT'], cannotPull: ['Fin\'s internal reasoning', 'anything before the app was installed'], setupMinutes: 30, scopes: ['read_conversations', 'read_users'], rateLimit: '1000/min', channel: 'customer_chat' },
  { id: 'zendesk-ai', name: 'Zendesk AI', category: 'customer', vendor: 'Zendesk', auth: 'OAuth / API token', modes: ['watch'], pulls: ['tickets', 'comments', 'AI suggestions applied'], cannotPull: ['suggestions the agent rejected'], setupMinutes: 30, scopes: ['tickets:read'], rateLimit: '700/min', channel: 'customer_chat' },
  { id: 'agentforce', name: 'Salesforce Agentforce', category: 'customer', vendor: 'Salesforce', auth: 'Connected App (OAuth)', modes: ['watch', 'inline'], pulls: ['conversation', 'actions taken', 'record changes'], cannotPull: ['org-level configuration history'], setupMinutes: 90, scopes: ['api', 'refresh_token'], rateLimit: 'org limits', channel: 'customer_chat' },
  { id: 'drift', name: 'Drift', category: 'customer', vendor: 'Salesloft', auth: 'OAuth', modes: ['watch'], pulls: ['conversations', 'lead identity'], cannotPull: ['anonymous pre-identification browsing'], setupMinutes: 30, scopes: ['conversation_read'], rateLimit: 'plan-dependent', channel: 'customer_chat' },
  { id: 'ada', name: 'Ada', category: 'customer', vendor: 'Ada', auth: 'API key', modes: ['watch'], pulls: ['conversations', 'resolution'], cannotPull: ['model reasoning'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'customer_chat' },
  { id: 'forethought', name: 'Forethought', category: 'customer', vendor: 'Forethought', auth: 'API key', modes: ['watch'], pulls: ['conversations', 'predictions applied'], cannotPull: ['discarded predictions'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'customer_chat' },

  // ---- internal bots ------------------------------------------------------
  { id: 'slack-bot', name: 'Slack bots', category: 'internal', vendor: 'Slack', auth: 'Bot token + Events API', modes: ['watch', 'inline'], pulls: ['thread content', 'channel', 'participants', 'reactions', 'thread resolution'], cannotPull: ['DMs the bot is not in', 'private channels without an invite'], setupMinutes: 30, scopes: ['channels:history', 'groups:history', 'users:read'], rateLimit: 'tier 3 (50+/min)', channel: 'slack_internal' },
  { id: 'teams-bot', name: 'Teams bots', category: 'internal', vendor: 'Microsoft', auth: 'Bot Framework + Graph', modes: ['watch', 'inline'], pulls: ['messages', 'channel', 'participants'], cannotPull: ['private chats without policy-based access'], setupMinutes: 60, scopes: ['ChannelMessage.Read.All'], rateLimit: 'Graph throttling', channel: 'slack_internal' },
  { id: 'discord-bot', name: 'Discord bots', category: 'internal', vendor: 'Discord', auth: 'Bot token', modes: ['watch', 'inline'], pulls: ['messages', 'threads', 'reactions'], cannotPull: ['servers the bot is not in'], setupMinutes: 20, scopes: ['MESSAGE_CONTENT intent'], rateLimit: '50/s', channel: 'slack_internal' },

  // ---- orchestration frameworks ------------------------------------------
  { id: 'langgraph', name: 'LangGraph', category: 'framework', vendor: 'LangChain', auth: 'SDK hook', modes: ['inline'], pulls: ['every memory read and write', 'node transitions', 'tool calls'], cannotPull: ['state kept only in process memory and never written'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'langchain', name: 'LangChain', category: 'framework', vendor: 'LangChain', auth: 'SDK hook', modes: ['inline'], pulls: ['chain steps', 'memory operations'], cannotPull: ['un-instrumented custom chains'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'crewai', name: 'CrewAI', category: 'framework', vendor: 'CrewAI', auth: 'SDK hook', modes: ['inline'], pulls: ['agent messages', 'task outputs', 'memory operations'], cannotPull: ['agents constructed outside the crew'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'autogen', name: 'AutoGen', category: 'framework', vendor: 'Microsoft', auth: 'SDK hook', modes: ['inline'], pulls: ['agent conversations', 'tool calls'], cannotPull: ['un-instrumented agents'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'letta', name: 'Letta', category: 'framework', vendor: 'Letta', auth: 'API key / SDK hook', modes: ['inline'], pulls: ['memory blocks', 'archival memory operations'], cannotPull: ['blocks edited directly in the database'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'semantic-kernel', name: 'Semantic Kernel', category: 'framework', vendor: 'Microsoft', auth: 'SDK hook', modes: ['inline'], pulls: ['plan steps', 'memory operations'], cannotPull: ['native functions without the filter installed'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'pydantic-ai', name: 'Pydantic AI', category: 'framework', vendor: 'Pydantic', auth: 'SDK hook', modes: ['inline'], pulls: ['run steps', 'tool calls'], cannotPull: ['un-instrumented runs'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'openai-agents', name: 'OpenAI Agents SDK', category: 'framework', vendor: 'OpenAI', auth: 'SDK hook', modes: ['inline'], pulls: ['agent runs', 'handoffs', 'tool calls'], cannotPull: ['runs outside the instrumented client'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'dspy', name: 'DSPy', category: 'framework', vendor: 'Stanford', auth: 'SDK hook', modes: ['inline'], pulls: ['module calls', 'optimised prompts'], cannotPull: ['compile-time traces unless captured'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'n8n', name: 'n8n', category: 'framework', vendor: 'n8n', auth: 'Webhook node', modes: ['inline'], pulls: ['workflow executions', 'AI node inputs and outputs'], cannotPull: ['workflows without the Vault node'], setupMinutes: 15, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'zapier', name: 'Zapier', category: 'framework', vendor: 'Zapier', auth: 'Webhook', modes: ['inline'], pulls: ['zap runs with AI steps'], cannotPull: ['zaps without the Vault step'], setupMinutes: 15, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'make', name: 'Make', category: 'framework', vendor: 'Make', auth: 'Webhook', modes: ['inline'], pulls: ['scenario runs'], cannotPull: ['scenarios without the Vault module'], setupMinutes: 15, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },

  // ---- memory layers -----------------------------------------------------
  { id: 'mem0', name: 'Mem0', category: 'memory', vendor: 'Mem0', auth: 'API key', modes: ['inline'], pulls: ['memories', 'metadata'], cannotPull: ['deleted memories'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', note: 'Vault sits in FRONT as the gate; their store becomes a backing store. Or import everything and retire theirs — the customer chooses.', channel: 'agent_output' },
  { id: 'zep', name: 'Zep / Graphiti', category: 'memory', vendor: 'Zep', auth: 'API key', modes: ['inline'], pulls: ['facts', 'graph edges', 'sessions'], cannotPull: ['expired sessions'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'cognee', name: 'Cognee', category: 'memory', vendor: 'Cognee', auth: 'API key', modes: ['inline'], pulls: ['knowledge graph nodes'], cannotPull: ['pipeline internals'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'supermemory', name: 'Supermemory', category: 'memory', vendor: 'Supermemory', auth: 'API key', modes: ['inline'], pulls: ['memories'], cannotPull: ['deleted memories'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'langmem', name: 'LangMem', category: 'memory', vendor: 'LangChain', auth: 'SDK hook', modes: ['inline'], pulls: ['memory operations'], cannotPull: ['un-instrumented stores'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },
  { id: 'pinecone', name: 'Pinecone', category: 'memory', vendor: 'Pinecone', auth: 'API key', modes: ['inline'], pulls: ['vectors', 'metadata'], cannotPull: ['original text where only vectors were stored'], setupMinutes: 30, scopes: [], rateLimit: 'plan-dependent', channel: 'agent_output' },
  { id: 'weaviate', name: 'Weaviate', category: 'memory', vendor: 'Weaviate', auth: 'API key', modes: ['inline'], pulls: ['objects', 'vectors'], cannotPull: ['tenant data without the key'], setupMinutes: 30, scopes: [], rateLimit: 'deployment-dependent', channel: 'agent_output' },
  { id: 'qdrant', name: 'Qdrant', category: 'memory', vendor: 'Qdrant', auth: 'API key', modes: ['inline'], pulls: ['points', 'payloads'], cannotPull: ['collections without access'], setupMinutes: 30, scopes: [], rateLimit: 'deployment-dependent', channel: 'agent_output' },
  { id: 'chroma', name: 'Chroma', category: 'memory', vendor: 'Chroma', auth: 'local or API key', modes: ['inline'], pulls: ['documents', 'embeddings'], cannotPull: ['ephemeral in-memory collections'], setupMinutes: 20, scopes: [], rateLimit: 'n/a', channel: 'agent_output' },

  // ---- systems of record ---------------------------------------------------
  { id: 'salesforce', name: 'Salesforce', category: 'sor', vendor: 'Salesforce', auth: 'Connected App (OAuth)', modes: ['watch', 'inline'], pulls: ['accounts', 'opportunities', 'cases', 'field history'], cannotPull: ['deleted records past the recycle bin window'], setupMinutes: 90, scopes: ['api', 'refresh_token'], rateLimit: 'org limits', channel: 'system_of_record' },
  { id: 'hubspot', name: 'HubSpot', category: 'sor', vendor: 'HubSpot', auth: 'Private app token', modes: ['watch', 'inline'], pulls: ['contacts', 'deals', 'engagements'], cannotPull: ['hard-deleted records'], setupMinutes: 45, scopes: ['crm.objects.read'], rateLimit: '100/10s', channel: 'system_of_record' },
  { id: 'jira', name: 'Jira', category: 'sor', vendor: 'Atlassian', auth: 'OAuth / API token', modes: ['watch', 'inline'], pulls: ['issues', 'comments', 'transitions'], cannotPull: ['projects without browse permission'], setupMinutes: 45, scopes: ['read:jira-work'], rateLimit: 'plan-dependent', channel: 'system_of_record' },
  { id: 'linear', name: 'Linear', category: 'sor', vendor: 'Linear', auth: 'API key / OAuth', modes: ['watch', 'inline'], pulls: ['issues', 'comments', 'projects'], cannotPull: ['private teams without access'], setupMinutes: 30, scopes: ['read'], rateLimit: '1500/hr', channel: 'system_of_record' },
  { id: 'servicenow', name: 'ServiceNow', category: 'sor', vendor: 'ServiceNow', auth: 'OAuth / basic', modes: ['watch', 'inline'], pulls: ['incidents', 'changes', 'work notes'], cannotPull: ['tables without ACL access'], setupMinutes: 120, scopes: [], rateLimit: 'instance limits', channel: 'system_of_record' },
  { id: 'workday', name: 'Workday', category: 'sor', vendor: 'Workday', auth: 'ISU + OAuth', modes: ['watch'], pulls: ['worker data (where permitted)'], cannotPull: ['compensation without explicit scope — and Vault defaults to not requesting it'], setupMinutes: 180, scopes: [], rateLimit: 'tenant limits', channel: 'system_of_record' },
  { id: 'sap', name: 'SAP', category: 'sor', vendor: 'SAP', auth: 'OData + technical user', modes: ['watch'], pulls: ['master data', 'documents'], cannotPull: ['tables outside the exposed OData services'], setupMinutes: 240, scopes: [], rateLimit: 'system-dependent', channel: 'system_of_record' },
  { id: 'netsuite', name: 'NetSuite', category: 'sor', vendor: 'Oracle', auth: 'Token-based auth', modes: ['watch'], pulls: ['transactions', 'records'], cannotPull: ['restricted roles'], setupMinutes: 180, scopes: [], rateLimit: 'account limits', channel: 'system_of_record' },
  { id: 'notion', name: 'Notion', category: 'sor', vendor: 'Notion', auth: 'Internal integration token', modes: ['watch'], pulls: ['pages', 'databases', 'comments'], cannotPull: ['pages not shared with the integration'], setupMinutes: 30, scopes: ['read content'], rateLimit: '3/s', channel: 'scraped_document' },
  { id: 'confluence', name: 'Confluence', category: 'sor', vendor: 'Atlassian', auth: 'OAuth / API token', modes: ['watch'], pulls: ['pages', 'comments', 'attachments'], cannotPull: ['restricted spaces'], setupMinutes: 45, scopes: ['read:confluence-content.all'], rateLimit: 'plan-dependent', channel: 'scraped_document' },
  { id: 'sharepoint', name: 'SharePoint', category: 'sor', vendor: 'Microsoft', auth: 'Graph app registration', modes: ['watch'], pulls: ['documents', 'lists', 'metadata'], cannotPull: ['sites without app permission'], setupMinutes: 120, scopes: ['Sites.Read.All'], rateLimit: 'Graph throttling', channel: 'scraped_document' },
  { id: 'google-workspace', name: 'Google Workspace', category: 'sor', vendor: 'Google', auth: 'Service account with domain delegation', modes: ['watch'], pulls: ['Drive documents', 'Gmail (where scoped)', 'Calendar'], cannotPull: ['personal accounts outside the domain'], setupMinutes: 120, scopes: ['drive.readonly'], rateLimit: 'quota-based', channel: 'scraped_document' },

  // ---- generic ------------------------------------------------------------
  { id: 'webhook', name: 'Webhook ingestion', category: 'generic', vendor: 'any', auth: 'HMAC signing secret', modes: ['inline'], pulls: ['anything you send, in any format, mapped'], cannotPull: ['what you do not send'], setupMinutes: 10, scopes: [], rateLimit: 'configurable', channel: 'third_party_api' },
  { id: 'rest', name: 'REST API', category: 'generic', vendor: 'any', auth: 'Bearer token', modes: ['inline'], pulls: ['direct writes and reads'], cannotPull: ['n/a'], setupMinutes: 5, scopes: [], rateLimit: 'configurable', channel: 'third_party_api' },
  { id: 'mcp', name: 'MCP server (Vault as tool provider)', category: 'generic', vendor: 'any', auth: 'MCP transport', modes: ['inline'], pulls: ['tool calls from any MCP client'], cannotPull: ['clients that do not register the server'], setupMinutes: 10, scopes: [], rateLimit: 'n/a', channel: 'mcp_tool_output' },
  { id: 'kafka', name: 'Kafka / Kinesis / Pub-Sub', category: 'generic', vendor: 'any', auth: 'SASL / IAM', modes: ['inline'], pulls: ['streamed events'], cannotPull: ['topics without read access'], setupMinutes: 60, scopes: [], rateLimit: 'broker-dependent', channel: 'third_party_api' },
  { id: 'sftp', name: 'SFTP batch drop', category: 'generic', vendor: 'any', auth: 'SSH key', modes: ['watch'], pulls: ['batch files on a schedule'], cannotPull: ['real-time events'], setupMinutes: 30, scopes: [], rateLimit: 'n/a', channel: 'scraped_document' },
  { id: 'otel', name: 'OTel receiver', category: 'generic', vendor: 'any', auth: 'OTLP endpoint + token', modes: ['watch'], pulls: ['spans with GenAI semantic conventions'], cannotPull: ['content not present in span attributes'], setupMinutes: 30, scopes: [], rateLimit: 'configurable', channel: 'agent_output' },
  { id: 'bulk', name: 'CSV/JSONL bulk import', category: 'generic', vendor: 'any', auth: 'authenticated upload', modes: ['inline'], pulls: ['historical records'], cannotPull: ['provenance you did not include'], setupMinutes: 10, scopes: [], rateLimit: 'n/a', channel: 'system_of_record' }
];

/**
 * THE COVERAGE MAP (§4.3) — a shipped product artifact.
 * Say this out loud in every sale.
 */
export function coverageMap({ connected = [] } = {}) {
  const rows = CONNECTORS.map((c) => ({
    tool: c.name,
    category: c.category,
    convos: c.cannotPull.some((x) => /content|transcript|message/i.test(x)) ? '✗*' : '✓',
    memories: c.category === 'memory' || c.pulls.some((p) => /memor/i.test(p)) ? '✓'
      : c.category === 'coding' || c.category === 'framework' ? '✓'
      : c.category === 'customer' ? '—' : (c.modes.includes('inline') ? '✓' : 'partial'),
    canBlock: c.modes.includes('inline') || c.modes.includes('gateway') ? '✓' : '✗',
    mode: c.modes.map((m) => ({ watch: 'Watch', inline: 'Inline', gateway: 'GW' }[m])).join('+'),
    notes: c.honestNote || c.retentionWarning || (c.cannotPull.length ? `cannot see: ${c.cannotPull[0]}` : ''),
    connected: connected.includes(c.id)
  }));

  // The row that matters most is the one that says NOT REACHABLE.
  rows.push({
    tool: 'Personal ChatGPT / Claude / Gemini accounts',
    category: 'unreachable',
    convos: '✗', memories: '✗', canBlock: '✗', mode: '—',
    notes: 'NOT REACHABLE → this is a policy problem, not a product one. Vault\'s job is to make the sanctioned path better than the unsanctioned one.',
    connected: false
  });

  return {
    generatedAt: new Date().toISOString(),
    rows,
    legend: { '✓': 'covered', '✗': 'not available', '✗*': 'excluded by the vendor by design', '—': 'not applicable', partial: 'partially covered' },
    honesty: 'Vault publishes what it cannot see. Vagueness here is what makes CISOs distrust vendors.',
    ruleOfThumb: RULE_OF_THUMB
  };
}

export function connector(id) {
  return CONNECTORS.find((c) => c.id === id) || null;
}

export function byCategory() {
  const out = {};
  for (const c of CONNECTORS) (out[c.category] ||= []).push(c);
  return out;
}
