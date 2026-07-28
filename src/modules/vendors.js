/**
 * Per-vendor module adapters — the Built-in / Connected / Both toggle targets.
 *
 * `httpAdapter()` in modules.js turns any endpoint into an adapter by POSTing
 * `{op, module, payload}` to `/<op>`. That is genuinely useful for a customer's
 * own internal service, and it is useless for connecting Langfuse, because
 * Langfuse does not have a `/span` endpoint that accepts that envelope. The
 * toggle is a headline product claim, and a toggle whose Connected state cannot
 * actually reach the named vendor makes the claim false.
 *
 * So each vendor here declares the real thing: the real host, the real auth
 * header, the real method and path per operation, the real request body, and
 * how to read the real response. `buildVendorAdapter()` turns that into a live
 * adapter that speaks the vendor's actual protocol.
 *
 * ── What is and is not verified ──────────────────────────────────────────
 *
 * Every entry is written from that vendor's PUBLISHED API DOCUMENTATION, and
 * `docs`/`docsVersion` record exactly which page and revision. Each is
 * CONTRACT-VERIFIED: `contractFor()` returns the exact request that would go on
 * the wire without sending it, and the contract tests assert method, path,
 * auth-header format, body shape and pagination against the documented spec.
 *
 * That is not the same as being verified against a live account, and this file
 * does not pretend otherwise. `vendorStatus()` reports `contract-verified` or
 * `live-verified` per vendor and names the exact credential, the exact scopes
 * and the exact steps to obtain it. A vendor moves to `live-verified` only when
 * a real request to their real endpoint returned a real documented response —
 * including a real authentication error, which still proves the request was
 * parsed by the vendor rather than by us.
 *
 * Self-hostable vendors (Langfuse, Phoenix, Keycloak, Elastic, Grafana, MinIO,
 * Weaviate, Qdrant, Chroma) carry `selfHostable: true` and accept a `baseUrl`
 * override, which is how they can be verified live without a commercial
 * account.
 */
import { VaultError } from '../util/errors.js';
import { MODULES } from './modules.js';

/** Authorization header builders. Vendors differ here more than anywhere else. */
export const VENDOR_AUTH = {
  bearer: (c) => ({ Authorization: `Bearer ${req(c, 'token')}` }),
  basic: (c) => ({ Authorization: `Basic ${Buffer.from(`${req(c, 'publicKey')}:${req(c, 'secretKey')}`).toString('base64')}` }),
  basic_user_pass: (c) => ({ Authorization: `Basic ${Buffer.from(`${req(c, 'username')}:${req(c, 'password')}`).toString('base64')}` }),
  api_key_header: (c, spec) => ({ [spec.headerName || 'X-Api-Key']: req(c, 'apiKey') }),
  sso_token: (c) => ({ Authorization: `SSWS ${req(c, 'token')}` }),          // Okta
  splunk_token: (c) => ({ Authorization: `Splunk ${req(c, 'token')}` }),
  vault_token: (c) => ({ 'X-Vault-Token': req(c, 'token') }),                 // HashiCorp
  none: () => ({})
};

function req(config, field) {
  const v = config?.[field];
  if (!v) throw new VaultError('validation', `this vendor needs "${field}" — see vendorStatus() for how to obtain it`);
  return v;
}

/**
 * The registry.
 *
 * `ops` keys must cover the module's declared ops or the adapter reports the
 * gap through `missingOps` rather than pretending to be complete — §26 allows
 * partial adapters, provided the gaps are published.
 */
export const VENDOR_ADAPTERS = {
  // ── §15 Observability / Tracing ────────────────────────────────────────
  langfuse: {
    module: 'tracing', name: 'Langfuse', selfHostable: true,
    baseUrl: 'https://cloud.langfuse.com',
    docs: 'https://api.reference.langfuse.com/', docsVersion: '2024-11',
    auth: 'basic',
    credential: { needs: ['publicKey', 'secretKey'], scopes: ['project:write'], steps: ['Create a project in Langfuse (cloud or self-hosted).', 'Settings → API Keys → Create new API keys.', 'Copy the public key (pk-lf-...) and secret key (sk-lf-...).', 'For self-hosted, also set baseUrl to your instance.'] },
    ops: {
      span: { method: 'POST', path: '/api/public/ingestion', ok: [200, 207], body: (p) => ({ batch: [{ id: p.id, type: 'span-create', timestamp: new Date(p.at ?? Date.now()).toISOString(), body: { id: p.id, traceId: p.traceId, name: p.name, input: p.input, output: p.output, startTime: p.startTime, endTime: p.endTime, metadata: p.metadata } }] }) },
      eval: { method: 'POST', path: '/api/public/scores', ok: [200, 201], body: (p) => ({ traceId: p.traceId, name: p.name, value: p.value, comment: p.comment ?? null }) }
    }
  },
  braintrust: {
    module: 'tracing', name: 'Braintrust', baseUrl: 'https://api.braintrust.dev',
    docs: 'https://www.braintrust.dev/docs/api/spec', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'projectId'], scopes: [], steps: ['Log in to braintrust.dev.', 'Settings → API Keys → Create API Key.', 'Copy the key (sk-...) and your project id from the project URL.'] },
    ops: {
      span: { method: 'POST', path: '/v1/project_logs/:projectId/insert', ok: [200], body: (p) => ({ events: [{ id: p.id, input: p.input, output: p.output, metadata: p.metadata, span_attributes: { name: p.name, type: p.kind } }] }) },
      eval: { method: 'POST', path: '/v1/project_logs/:projectId/insert', ok: [200], body: (p) => ({ events: [{ id: p.id, scores: p.scores ?? { [p.name]: p.value } }] }) }
    }
  },
  arize_phoenix: {
    module: 'tracing', name: 'Arize AX / Phoenix', selfHostable: true,
    baseUrl: 'http://localhost:6006',
    docs: 'https://docs.arize.com/phoenix/references/api', docsVersion: '2024-11',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Self-hosted Phoenix: `pip install arize-phoenix && phoenix serve` — no token needed by default, set token to "none".', 'Arize AX: Space Settings → API Keys → Developer Key.'] },
    ops: {
      // Phoenix speaks OTLP, which is the right protocol for spans anyway.
      span: { method: 'POST', path: '/v1/traces', ok: [200, 202], contentType: 'application/json', body: (p) => ({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'vault' } }] }, scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, startTimeUnixNano: String((p.startTime ?? Date.now()) * 1e6), endTimeUnixNano: String((p.endTime ?? Date.now()) * 1e6), attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/v1/evaluations', ok: [200], body: (p) => ({ evaluations: [{ name: p.name, span_id: p.spanId, result: { score: p.value, label: p.label ?? null, explanation: p.comment ?? null } }] }) }
    }
  },
  langsmith: {
    module: 'tracing', name: 'LangSmith', baseUrl: 'https://api.smith.langchain.com',
    docs: 'https://api.smith.langchain.com/redoc', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'x-api-key',
    credential: { needs: ['apiKey'], scopes: [], steps: ['smith.langchain.com → Settings → API Keys → Create API Key.', 'Copy the key (lsv2_pt_...).'] },
    ops: {
      span: { method: 'POST', path: '/runs', ok: [200, 201, 202], body: (p) => ({ id: p.id, trace_id: p.traceId, name: p.name, run_type: p.kind ?? 'llm', inputs: { input: p.input }, outputs: { output: p.output }, start_time: new Date(p.startTime ?? Date.now()).toISOString(), end_time: p.endTime ? new Date(p.endTime).toISOString() : null, extra: { metadata: p.metadata } }) },
      eval: { method: 'POST', path: '/feedback', ok: [200, 201], body: (p) => ({ run_id: p.spanId, key: p.name, score: p.value, comment: p.comment ?? null }) }
    }
  },
  datadog_llm: {
    module: 'tracing', name: 'Datadog LLM Observability', baseUrl: 'https://api.datadoghq.com',
    docs: 'https://docs.datadoghq.com/llm_observability/setup/api/', docsVersion: '2024-11',
    auth: 'api_key_header', headerName: 'DD-API-KEY',
    credential: { needs: ['apiKey'], scopes: [], steps: ['Datadog → Organization Settings → API Keys → New Key.', 'For EU, set baseUrl to https://api.datadoghq.eu.'] },
    ops: {
      span: { method: 'POST', path: '/api/intake/llm-obs/v1/trace/spans', ok: [200, 202], body: (p) => ({ data: { type: 'span', attributes: { ml_app: 'vault', spans: [{ span_id: p.id, trace_id: p.traceId, name: p.name, start_ns: (p.startTime ?? Date.now()) * 1e6, duration: ((p.endTime ?? Date.now()) - (p.startTime ?? Date.now())) * 1e6, meta: { input: { value: p.input }, output: { value: p.output } } }] } } }) },
      eval: { method: 'POST', path: '/api/intake/llm-obs/v1/eval-metric', ok: [200, 202], body: (p) => ({ data: { type: 'evaluation_metric', attributes: { metrics: [{ span_id: p.spanId, label: p.name, metric_type: 'score', score_value: p.value }] } } }) }
    }
  },
  honeycomb: {
    module: 'tracing', name: 'Honeycomb', baseUrl: 'https://api.honeycomb.io',
    docs: 'https://docs.honeycomb.io/api/events/', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'X-Honeycomb-Team',
    credential: { needs: ['apiKey', 'dataset'], scopes: ['createDatasets', 'sendEvents'], steps: ['Honeycomb → Environment Settings → API Keys → Create.', 'Grant "Send Events" and "Create Datasets".', 'Pick or create a dataset name.'] },
    ops: {
      span: { method: 'POST', path: '/1/events/:dataset', ok: [200, 202], body: (p) => ({ 'trace.trace_id': p.traceId, 'trace.span_id': p.id, name: p.name, duration_ms: (p.endTime ?? 0) - (p.startTime ?? 0), input: p.input, output: p.output, ...flat(p.metadata) }) },
      eval: { method: 'POST', path: '/1/events/:dataset', ok: [200, 202], body: (p) => ({ 'trace.span_id': p.spanId, eval_name: p.name, eval_score: p.value }) }
    }
  },
  wandb_weave: {
    module: 'tracing', name: 'W&B Weave', baseUrl: 'https://trace.wandb.ai',
    docs: 'https://weave-docs.wandb.ai/reference/service-api/', docsVersion: '2024-11',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password', 'projectId'], scopes: [], steps: ['wandb.ai → User Settings → API keys → copy key.', 'Use "api" as username and the key as password (W&B convention).', 'projectId is "entity/project".'] },
    ops: {
      span: { method: 'POST', path: '/call/start', ok: [200], body: (p) => ({ start: { project_id: p.projectId, id: p.id, trace_id: p.traceId, op_name: p.name, started_at: new Date(p.startTime ?? Date.now()).toISOString(), inputs: { input: p.input }, attributes: p.metadata ?? {} } }) },
      eval: { method: 'POST', path: '/feedback/create', ok: [200], body: (p) => ({ project_id: p.projectId, weave_ref: p.spanId, feedback_type: 'wandb.reaction.1', payload: { name: p.name, score: p.value } }) }
    }
  },
  opik: {
    module: 'tracing', name: 'Opik / Comet', selfHostable: true, baseUrl: 'https://www.comet.com/opik/api',
    docs: 'https://www.comet.com/docs/opik/reference/rest-api/overview', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'authorization',
    credential: { needs: ['apiKey', 'workspace'], scopes: [], steps: ['comet.com → Account Settings → API Keys.', 'Self-hosted Opik: set baseUrl to http://localhost:5173/api and omit the key.'] },
    ops: {
      span: { method: 'POST', path: '/v1/private/spans', ok: [200, 201, 204], body: (p) => ({ id: p.id, trace_id: p.traceId, name: p.name, type: p.kind ?? 'llm', start_time: new Date(p.startTime ?? Date.now()).toISOString(), end_time: p.endTime ? new Date(p.endTime).toISOString() : null, input: { input: p.input }, output: { output: p.output }, metadata: p.metadata }) },
      eval: { method: 'POST', path: '/v1/private/spans/:spanId/feedback-scores', ok: [200, 201, 204], body: (p) => ({ name: p.name, value: p.value, source: 'sdk' }) }
    }
  },
  helicone: {
    module: 'tracing', name: 'Helicone', baseUrl: 'https://api.helicone.ai',
    docs: 'https://docs.helicone.ai/rest/request/post-v1requestquery', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['helicone.ai → Settings → API Keys → Generate.', 'Copy the key (sk-helicone-...).'] },
    ops: {
      span: { method: 'POST', path: '/v1/trace/custom/log', ok: [200], body: (p) => ({ providerRequest: { url: 'custom', json: { input: p.input }, meta: { 'Helicone-Request-Id': p.id } }, providerResponse: { json: { output: p.output }, status: 200, headers: {} }, timing: { startTime: { seconds: Math.floor((p.startTime ?? Date.now()) / 1000), milliseconds: 0 }, endTime: { seconds: Math.floor((p.endTime ?? Date.now()) / 1000), milliseconds: 0 } } }) },
      eval: { method: 'POST', path: '/v1/request/:spanId/score', ok: [200], body: (p) => ({ scores: { [p.name]: p.value } }) }
    }
  },
  galileo: {
    module: 'tracing', name: 'Galileo', baseUrl: 'https://api.galileo.ai',
    docs: 'https://docs.galileo.ai/galileo/api', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token', 'projectId'], scopes: [], steps: ['Galileo console → Settings → API Keys.', 'Create a project and copy its id.'] },
    ops: {
      span: { method: 'POST', path: '/v2/projects/:projectId/traces', ok: [200, 201], body: (p) => ({ traces: [{ id: p.traceId, spans: [{ id: p.id, type: p.kind ?? 'llm', name: p.name, input: p.input, output: p.output, created_at_ns: (p.startTime ?? Date.now()) * 1e6 }] }] }) },
      eval: { method: 'POST', path: '/v2/projects/:projectId/metrics', ok: [200, 201], body: (p) => ({ span_id: p.spanId, name: p.name, value: p.value }) }
    }
  },
  fiddler: {
    module: 'tracing', name: 'Fiddler', baseUrl: 'https://api.fiddler.ai',
    docs: 'https://docs.fiddler.ai/api-reference', docsVersion: 'v3',
    auth: 'bearer',
    credential: { needs: ['token', 'projectId'], scopes: [], steps: ['Fiddler UI → Settings → Credentials → copy access token.', 'Project id from the project page URL.'] },
    ops: {
      span: { method: 'POST', path: '/v3/events', ok: [200, 202], body: (p) => ({ source: { type: 'EVENT' }, event: { project_id: p.projectId, span_id: p.id, trace_id: p.traceId, name: p.name, input: p.input, output: p.output } }) },
      eval: { method: 'POST', path: '/v3/events', ok: [200, 202], body: (p) => ({ source: { type: 'EVENT' }, event: { span_id: p.spanId, custom_metrics: { [p.name]: p.value } } }) }
    }
  },
  agentops: {
    module: 'tracing', name: 'AgentOps', baseUrl: 'https://api.agentops.ai',
    docs: 'https://docs.agentops.ai/v1/reference', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['app.agentops.ai → Settings → Project → API Key.'] },
    ops: {
      span: { method: 'POST', path: '/v2/create_events', ok: [200], body: (p) => ({ events: [{ id: p.id, event_type: p.kind ?? 'llm', init_timestamp: new Date(p.startTime ?? Date.now()).toISOString(), end_timestamp: p.endTime ? new Date(p.endTime).toISOString() : null, prompt: p.input, completion: p.output }] }) },
      eval: { method: 'POST', path: '/v2/update_session', ok: [200], body: (p) => ({ session: { session_id: p.traceId, [p.name]: p.value } }) }
    }
  },
  laminar: {
    module: 'tracing', name: 'Laminar', selfHostable: true, baseUrl: 'https://api.lmnr.ai',
    docs: 'https://docs.lmnr.ai/api-reference/introduction', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['lmnr.ai → Project settings → Generate API key.'] },
    ops: {
      span: { method: 'POST', path: '/v1/traces', ok: [200, 202], body: (p) => ({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/v1/evaluations', ok: [200, 201], body: (p) => ({ name: p.name, points: [{ data: { input: p.input }, target: { output: p.output }, executorOutput: { score: p.value } }] }) }
    }
  },
  latitude: {
    module: 'tracing', name: 'Latitude', selfHostable: true, baseUrl: 'https://gateway.latitude.so',
    docs: 'https://docs.latitude.so/guides/api/api-access', docsVersion: 'v3',
    auth: 'bearer',
    credential: { needs: ['token', 'projectId'], scopes: [], steps: ['Latitude → Settings → API Keys.', 'Copy the project id from the project URL.'] },
    ops: {
      span: { method: 'POST', path: '/api/v3/otlp/v1/traces', ok: [200, 202], body: (p) => ({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/api/v3/projects/:projectId/logs', ok: [200, 201], body: (p) => ({ uuid: p.spanId, evaluation: { name: p.name, score: p.value } }) }
    }
  },
  confident_ai: {
    module: 'tracing', name: 'Confident AI (DeepEval)', baseUrl: 'https://api.confident-ai.com',
    docs: 'https://documentation.confident-ai.com/api-reference', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'CONFIDENT_API_KEY',
    credential: { needs: ['apiKey'], scopes: [], steps: ['app.confident-ai.com → Settings → API Key.'] },
    ops: {
      span: { method: 'POST', path: '/v1/traces', ok: [200, 201], body: (p) => ({ traceUuid: p.traceId, baseSpans: [{ uuid: p.id, name: p.name, input: p.input, output: p.output, startTime: new Date(p.startTime ?? Date.now()).toISOString() }] }) },
      eval: { method: 'POST', path: '/v1/feedback', ok: [200, 201], body: (p) => ({ traceUuid: p.traceId, rating: p.value, explanation: p.comment ?? p.name }) }
    }
  },
  traceloop: {
    module: 'tracing', name: 'Traceloop / OpenLLMetry', selfHostable: true, baseUrl: 'https://api.traceloop.com',
    docs: 'https://www.traceloop.com/docs/openllmetry/integrations/exporting', docsVersion: 'otlp-1.0',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['app.traceloop.com → Settings → API Keys.', 'OpenLLMetry is OTLP — any OTLP collector works; set baseUrl to it.'] },
    ops: {
      span: { method: 'POST', path: '/v1/traces', ok: [200, 202], body: (p) => ({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'vault' } }] }, scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/v1/metrics', ok: [200, 202], body: (p) => ({ resourceMetrics: [{ scopeMetrics: [{ metrics: [{ name: p.name, gauge: { dataPoints: [{ asDouble: p.value }] } }] }] }] }) }
    }
  },
  newrelic: {
    module: 'tracing', name: 'New Relic', baseUrl: 'https://trace-api.newrelic.com',
    docs: 'https://docs.newrelic.com/docs/distributed-tracing/trace-api/report-new-relic-format-traces-trace-api/', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'Api-Key',
    credential: { needs: ['apiKey'], scopes: [], steps: ['one.newrelic.com → API keys → create an INGEST-LICENSE key.', 'EU accounts: baseUrl https://trace-api.eu.newrelic.com.'] },
    ops: {
      span: { method: 'POST', path: '/trace/v1', ok: [200, 202], extraHeaders: { 'Data-Format': 'newrelic', 'Data-Format-Version': '1' }, body: (p) => ([{ common: { attributes: { 'service.name': 'vault' } }, spans: [{ id: p.id, 'trace.id': p.traceId, timestamp: p.startTime ?? Date.now(), attributes: { name: p.name, 'duration.ms': (p.endTime ?? 0) - (p.startTime ?? 0), input: p.input, output: p.output } }] }]) },
      eval: { method: 'POST', path: '/trace/v1', ok: [200, 202], body: (p) => ([{ spans: [{ id: p.spanId, attributes: { [p.name]: p.value } }] }]) }
    }
  },
  dynatrace: {
    module: 'tracing', name: 'Dynatrace', baseUrl: 'https://{env}.live.dynatrace.com',
    docs: 'https://docs.dynatrace.com/docs/extend-dynatrace/opentelemetry', docsVersion: 'otlp-1.0',
    auth: 'api_key_header', headerName: 'Authorization',
    credential: { needs: ['apiKey', 'baseUrl'], scopes: ['openTelemetryTrace.ingest', 'metrics.ingest'], steps: ['Dynatrace → Access Tokens → Generate new token.', 'Grant "Ingest OpenTelemetry traces" and "Ingest metrics".', 'baseUrl is https://<env-id>.live.dynatrace.com — the token header value must be "Api-Token <token>".'] },
    ops: {
      span: { method: 'POST', path: '/api/v2/otlp/v1/traces', ok: [200, 202], body: (p) => ({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/api/v2/otlp/v1/metrics', ok: [200, 202], body: (p) => ({ resourceMetrics: [{ scopeMetrics: [{ metrics: [{ name: p.name, gauge: { dataPoints: [{ asDouble: p.value }] } }] }] }] }) }
    }
  },
  grafana: {
    module: 'tracing', name: 'Grafana (Tempo/Loki)', selfHostable: true, baseUrl: 'http://localhost:3200',
    docs: 'https://grafana.com/docs/tempo/latest/api_docs/', docsVersion: 'otlp-1.0',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password'], scopes: [], steps: ['Grafana Cloud: Stack → Tempo → generate an API token; username is the numeric instance id.', 'Self-hosted Tempo: no auth by default — set baseUrl to http://tempo:4318 and auth to none.'] },
    ops: {
      span: { method: 'POST', path: '/v1/traces', ok: [200, 202, 204], body: (p) => ({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: p.traceId, spanId: p.id, name: p.name, attributes: otelAttrs(p) }] }] }] }) },
      eval: { method: 'POST', path: '/v1/metrics', ok: [200, 202, 204], body: (p) => ({ resourceMetrics: [{ scopeMetrics: [{ metrics: [{ name: p.name, gauge: { dataPoints: [{ asDouble: p.value }] } }] }] }] }) }
    }
  },

  // ── §9 Search ───────────────────────────────────────────────────────────
  glean: {
    module: 'search', name: 'Glean', baseUrl: 'https://{tenant}-be.glean.com',
    docs: 'https://developers.glean.com/api-reference', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: ['SEARCH', 'INDEXING'], steps: ['Glean Admin → API Tokens → create a client token with SEARCH scope (and INDEXING to push documents).', 'baseUrl is https://<tenant>-be.glean.com.'] },
    ops: {
      index: { method: 'POST', path: '/api/index/v1/indexdocument', ok: [200], body: (p) => ({ document: { datasource: 'vault', objectType: 'Fact', id: p.id, title: p.title ?? p.id, body: { mimeType: 'text/plain', textContent: p.text }, permissions: { allowAnonymousAccess: false, allowedUsers: p.allowedUsers ?? [] }, updatedAt: Math.floor((p.at ?? Date.now()) / 1000) } }) },
      query: { method: 'POST', path: '/rest/api/v1/search', ok: [200], body: (p) => ({ query: p.query, pageSize: p.limit ?? 25, cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: 'cursor', items: 'results', done: (r) => !r.cursor } }
    }
  },
  gosearch: {
    module: 'search', name: 'GoSearch', baseUrl: 'https://api.gosearch.ai',
    docs: 'https://www.gosearch.ai/developers', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['search:read', 'index:write'], steps: ['GoSearch Admin → Integrations → API keys.'] },
    ops: {
      index: { method: 'POST', path: '/v1/documents', ok: [200, 201], body: (p) => ({ id: p.id, title: p.title, content: p.text, source: 'vault', acl: p.allowedUsers ?? [] }) },
      query: { method: 'POST', path: '/v1/search', ok: [200], body: (p) => ({ query: p.query, limit: p.limit ?? 25, offset: p.offset ?? 0 }), page: { offsetIn: 'offset', items: 'results', done: (r, sent) => (r.results?.length ?? 0) < (sent.limit ?? 25) } }
    }
  },
  guru: {
    module: 'search', name: 'Guru', baseUrl: 'https://api.getguru.com',
    docs: 'https://developer.getguru.com/reference', docsVersion: 'v1',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password'], scopes: ['READ_CARDS', 'WRITE_CARDS'], steps: ['Guru → Team Settings → API Access → create a User/Collection token.', 'username is the account email, password is the token.'] },
    ops: {
      index: { method: 'POST', path: '/api/v1/cards/extended', ok: [200, 201], body: (p) => ({ preferredPhrase: p.title ?? p.id, content: p.text, collection: { id: p.collectionId }, shareStatus: 'TEAM' }) },
      query: { method: 'GET', path: '/api/v1/search/query', ok: [200], query: (p) => ({ searchTerms: p.query, maxResults: String(p.limit ?? 25) }), page: { linkHeader: true, items: null, done: (r, sent, headers) => !/rel="next"/.test(headers?.get?.('link') ?? '') } }
    }
  },
  microsoft_search: {
    module: 'search', name: 'Microsoft Search / Copilot', baseUrl: 'https://graph.microsoft.com',
    docs: 'https://learn.microsoft.com/en-us/graph/api/search-query', docsVersion: 'v1.0',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['Files.Read.All', 'Sites.Read.All', 'ExternalItem.ReadWrite.OwnedBy'], steps: ['Entra ID → App registrations → New registration.', 'API permissions → Microsoft Graph → add the scopes above → Grant admin consent.', 'Certificates & secrets → New client secret; exchange it for a token at https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token.'] },
    ops: {
      index: { method: 'PUT', path: '/v1.0/external/connections/vault/items/:id', ok: [200, 201, 204], body: (p) => ({ acl: [{ type: 'everyone', value: 'everyone', accessType: 'grant' }], properties: { title: p.title, content: p.text }, content: { value: p.text, type: 'text' } }) },
      query: { method: 'POST', path: '/v1.0/search/query', ok: [200], body: (p) => ({ requests: [{ entityTypes: ['externalItem', 'driveItem'], query: { queryString: p.query }, from: p.offset ?? 0, size: p.limit ?? 25 }] }), page: { offsetIn: 'from', items: 'value[0].hitsContainers[0].hits', done: (r) => !r?.value?.[0]?.hitsContainers?.[0]?.moreResultsAvailable } }
    }
  },
  elastic: {
    module: 'search', name: 'Elastic', selfHostable: true, baseUrl: 'http://localhost:9200',
    docs: 'https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html', docsVersion: '8.x',
    auth: 'api_key_header', headerName: 'Authorization',
    credential: { needs: ['apiKey'], scopes: [], steps: ['Kibana → Stack Management → API Keys → Create.', 'Header must be "ApiKey <base64(id:api_key)>".', 'Self-hosted with security disabled: set auth to none.'] },
    ops: {
      index: { method: 'PUT', path: '/vault-facts/_doc/:id', ok: [200, 201], body: (p) => ({ title: p.title, text: p.text, folder: p.folder, at: p.at, acl: p.allowedUsers ?? [] }) },
      query: { method: 'POST', path: '/vault-facts/_search', ok: [200], body: (p) => ({ query: { multi_match: { query: p.query, fields: ['title^2', 'text'] } }, size: p.limit ?? 25, from: p.offset ?? 0 }), page: { offsetIn: 'from', items: 'hits.hits', done: (r, sent) => (r.hits?.hits?.length ?? 0) < (sent.size ?? 25) } }
    }
  },
  coveo: {
    module: 'search', name: 'Coveo', baseUrl: 'https://platform.cloud.coveo.com',
    docs: 'https://docs.coveo.com/en/1444/build-a-search-ui/search-api', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token', 'orgId'], scopes: ['search', 'push'], steps: ['Coveo Admin → Organization → API Keys → Add key with Search + Push privileges.', 'orgId is shown in Organization settings.'] },
    ops: {
      index: { method: 'PUT', path: '/push/v1/organizations/:orgId/sources/vault/documents', ok: [200, 202], query: (p) => ({ documentId: p.uri ?? `vault://${p.id}` }), body: (p) => ({ title: p.title, data: p.text, permissions: p.allowedUsers ?? [] }) },
      query: { method: 'POST', path: '/rest/search/v2', ok: [200], body: (p) => ({ q: p.query, numberOfResults: p.limit ?? 25, firstResult: p.offset ?? 0, organizationId: p.orgId }), page: { offsetIn: 'firstResult', items: 'results', done: (r, sent) => (sent.firstResult ?? 0) + (r.results?.length ?? 0) >= (r.totalCount ?? 0) } }
    }
  },
  algolia: {
    module: 'search', name: 'Algolia', baseUrl: 'https://{appId}.algolia.net',
    docs: 'https://www.algolia.com/doc/rest-api/search/', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'X-Algolia-API-Key',
    credential: { needs: ['apiKey', 'appId'], scopes: ['addObject', 'search'], steps: ['Algolia Dashboard → Settings → API Keys.', 'Use the Admin key for indexing and a Search-only key for queries.', 'Both X-Algolia-API-Key and X-Algolia-Application-Id headers are required.'] },
    ops: {
      index: { method: 'PUT', path: '/1/indexes/vault_facts/:id', ok: [200, 201], body: (p) => ({ objectID: p.id, title: p.title, text: p.text, folder: p.folder }) },
      query: { method: 'POST', path: '/1/indexes/vault_facts/query', ok: [200], body: (p) => ({ params: `query=${encodeURIComponent(p.query)}&hitsPerPage=${p.limit ?? 25}&page=${p.page ?? 0}` }), page: { pageIn: 'page', items: 'hits', done: (r) => (r.page ?? 0) + 1 >= (r.nbPages ?? 1) } }
    }
  },
  dust: {
    module: 'search', name: 'Dust', baseUrl: 'https://dust.tt',
    docs: 'https://docs.dust.tt/reference', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'workspaceId'], scopes: [], steps: ['Dust → Workspace Settings → API Keys.', 'workspaceId is in the workspace URL.'] },
    ops: {
      index: { method: 'POST', path: '/api/v1/w/:workspaceId/data_sources/vault/documents/:id', ok: [200, 201], body: (p) => ({ text: p.text, source_url: p.uri ?? null, tags: [p.folder ?? 'unfiled'] }) },
      query: { method: 'POST', path: '/api/v1/w/:workspaceId/data_sources/vault/search', ok: [200], // Dust's data-source search is top-k, not paged — it returns the best N and
      // stops. Declaring a paginator here would invent one the vendor does not have.
      body: (p) => ({ query: p.query, top_k: p.limit ?? 25, full_text: true }) }
    }
  },
  onyx: {
    module: 'search', name: 'Onyx (Danswer)', selfHostable: true, baseUrl: 'http://localhost:8080',
    docs: 'https://docs.onyx.app/backend_apis/ingestion', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Self-host Onyx with docker compose.', 'Admin panel → API Keys → create.', 'Self-hosted with auth disabled: set auth to none.'] },
    ops: {
      index: { method: 'POST', path: '/onyx-api/ingestion', ok: [200], body: (p) => ({ document: { id: p.id, sections: [{ text: p.text, link: p.uri ?? null }], source: 'ingestion_api', semantic_identifier: p.title ?? p.id, metadata: { folder: p.folder } } }) },
      query: { method: 'POST', path: '/api/query/search', ok: [200], body: (p) => ({ query: p.query, retrieval_options: { limit: p.limit ?? 25, offset: p.offset ?? 0 } }), page: { offsetIn: 'offset', items: 'top_documents', done: (r, sent) => (r.top_documents?.length ?? 0) < (sent.retrieval_options?.limit ?? 25) } }
    }
  },
  sinequa: {
    module: 'search', name: 'Sinequa', baseUrl: 'https://{host}/api',
    docs: 'https://docs.sinequa.com/en.sinequa-es.v11/Content/en.sinequa-es.dev.rest-api.html', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['Sinequa admin → Security → Access Tokens.', 'baseUrl is https://<your-sinequa-host>/api.'] },
    ops: {
      index: { method: 'POST', path: '/v1/indexingapi/index', ok: [200], body: (p) => ({ indexName: 'vault', documents: [{ id: p.id, title: p.title, text: p.text, accessLists: p.allowedUsers ?? [] }] }) },
      query: { method: 'POST', path: '/v1/search.query', ok: [200], body: (p) => ({ app: 'vault', query: { name: 'default', text: p.query, page: p.page ?? 1, pageSize: p.limit ?? 25 } }), page: { pageIn: 'page', items: 'records', done: (r, sent) => (r.records?.length ?? 0) < (sent.query?.pageSize ?? 25) } }
    }
  },
  lucidworks: {
    module: 'search', name: 'Lucidworks Fusion', selfHostable: true, baseUrl: 'http://localhost:8764',
    docs: 'https://doc.lucidworks.com/fusion/5.9/api/', docsVersion: '5.x',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password'], scopes: [], steps: ['Fusion Admin → Access Control → Users → create a service account.', 'Grant the app read/write on your collection.'] },
    ops: {
      index: { method: 'POST', path: '/api/apps/vault/index-pipelines/vault-default/collections/vault/index', ok: [200], body: (p) => ([{ id: p.id, fields: [{ name: 'title_s', value: p.title }, { name: 'body_t', value: p.text }] }]) },
      query: { method: 'GET', path: '/api/apps/vault/query/vault', ok: [200], query: (p) => ({ q: p.query, rows: String(p.limit ?? 25), start: String(p.offset ?? 0) }), page: { offsetIn: 'start', items: 'response.docs', done: (r, sent) => Number(sent.start ?? 0) + (r.response?.docs?.length ?? 0) >= (r.response?.numFound ?? 0) } }
    }
  },

  // ── §16 Compliance / GRC ────────────────────────────────────────────────
  watsonx_governance: {
    module: 'compliance', name: 'IBM watsonx.governance', baseUrl: 'https://api.dataplatform.cloud.ibm.com',
    docs: 'https://cloud.ibm.com/apidocs/watsonx-governance', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['IBM Cloud → Manage → Access (IAM) → API keys → create.', 'Exchange the API key for an IAM bearer token at https://iam.cloud.ibm.com/identity/token (grant_type=urn:ibm:params:oauth:grant-type:apikey).'] },
    ops: {
      evidence: { method: 'POST', path: '/v2/monitor_instances/:instanceId/records', ok: [200, 201, 202], body: (p) => ({ records: [{ values: [{ evidence_id: p.id, control: p.controlId, status: p.status, collected_at: new Date(p.at ?? Date.now()).toISOString(), ledger_ref: p.ledgerSeq }] }] }) },
      control: { method: 'GET', path: '/v2/ai_factsheets/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v2/ai_assets', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, asset_type: 'model', owner: p.owner }) }
    }
  },
  credo_ai: {
    module: 'compliance', name: 'Credo AI', baseUrl: 'https://api.credo.ai',
    docs: 'https://docs.credo.ai/reference/api', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token', 'tenant'], scopes: [], steps: ['Credo AI Platform → Settings → API tokens → Generate.', 'tenant is your Credo AI org slug.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/v2/:tenant/evidence', ok: [200, 201], body: (p) => ({ data: { type: 'evidence', attributes: { label: p.controlId, source: 'vault-ledger', evidence_type: 'metric', value: p.status, metadata: { ledger_seq: p.ledgerSeq, hash: p.hash } } } }) },
      control: { method: 'GET', path: '/api/v2/:tenant/policy_packs', ok: [200], query: (p) => ({ 'filter[framework]': p.framework }) },
      register: { method: 'POST', path: '/api/v2/:tenant/use_cases', ok: [200, 201], body: (p) => ({ data: { type: 'use_cases', attributes: { name: p.name, description: p.purpose } } }) }
    }
  },
  onetrust: {
    module: 'compliance', name: 'OneTrust', baseUrl: 'https://app.onetrust.com',
    docs: 'https://developer.onetrust.com/onetrust/reference', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['assessment:read', 'assessment:write', 'inventory:write'], steps: ['OneTrust → Settings → API Credentials → Add OAuth client.', 'Grant the scopes above; exchange client credentials at /api/access/v1/oauth/token.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/assessment/v2/assessments/:assessmentId/responses', ok: [200, 201], body: (p) => ({ questionId: p.controlId, responses: [{ response: p.status, justification: `vault ledger seq ${p.ledgerSeq}` }] }) },
      control: { method: 'GET', path: '/api/assessment/v2/templates', ok: [200], query: (p) => ({ page: String(p.page ?? 0), size: String(p.limit ?? 50) }), page: { pageIn: 'page', items: 'content', done: (r) => r.last === true } },
      register: { method: 'POST', path: '/api/inventory/v2/inventories/assets', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, organization: p.owner }) }
    }
  },
  servicenow_actc: {
    module: 'compliance', name: 'ServiceNow AI Control Tower', baseUrl: 'https://{instance}.service-now.com',
    docs: 'https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI', docsVersion: 'Table API',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password', 'baseUrl'], scopes: ['sn_ai_ctrl.admin'], steps: ['ServiceNow → User Administration → create an integration user.', 'Assign the AI Control Tower role.', 'baseUrl is https://<instance>.service-now.com.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/now/table/sn_grc_evidence', ok: [200, 201], body: (p) => ({ short_description: p.controlId, state: p.status, u_source: 'vault', u_ledger_seq: String(p.ledgerSeq ?? '') }) },
      control: { method: 'GET', path: '/api/now/table/sn_compliance_control', ok: [200], query: (p) => ({ sysparm_query: `framework=${p.framework}`, sysparm_limit: String(p.limit ?? 100), sysparm_offset: String(p.offset ?? 0) }), page: { offsetIn: 'sysparm_offset', items: 'result', done: (r, sent) => (r.result?.length ?? 0) < Number(sent.sysparm_limit ?? 100) } },
      register: { method: 'POST', path: '/api/now/table/sn_ai_agent', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owned_by: p.owner }) }
    }
  },
  holistic_ai: {
    module: 'compliance', name: 'Holistic AI', baseUrl: 'https://api.holisticai.com',
    docs: 'https://docs.holisticai.com/api', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Holistic AI platform → Settings → API keys.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ control_id: p.controlId, status: p.status, source: 'vault', reference: String(p.ledgerSeq ?? '') }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/inventory', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose, owner: p.owner }) }
    }
  },
  monitaur: {
    module: 'compliance', name: 'Monitaur', baseUrl: 'https://api.monitaur.ai',
    docs: 'https://docs.monitaur.ai/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Monitaur → Admin → API tokens.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, outcome: p.status, capturedAt: new Date(p.at ?? Date.now()).toISOString(), provenance: { system: 'vault', ledgerSeq: p.ledgerSeq, hash: p.hash } }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/models', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.owner }) }
    }
  },
  modelop: {
    module: 'compliance', name: 'ModelOp', baseUrl: 'https://api.modelop.center',
    docs: 'https://docs.modelop.center/', docsVersion: 'v3',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['ModelOp Center → Settings → Service Accounts → create and copy the token.'] },
    ops: {
      evidence: { method: 'POST', path: '/mlc/v3/model-life-cycle/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status, source: 'vault', ledgerSeq: p.ledgerSeq }) },
      control: { method: 'GET', path: '/mlc/v3/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/mlc/v3/models', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.owner }) }
    }
  },
  trustible: {
    module: 'compliance', name: 'Trustible', baseUrl: 'https://api.trustible.ai',
    docs: 'https://www.trustible.ai/docs', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Trustible → Organization Settings → API keys.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ control: p.controlId, result: p.status, evidence_uri: p.uri ?? null, ledger_seq: p.ledgerSeq }) },
      control: { method: 'GET', path: '/v1/frameworks/:framework/controls', ok: [200] },
      register: { method: 'POST', path: '/v1/ai-systems', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose, owner: p.owner }) }
    }
  },
  saidot: {
    module: 'compliance', name: 'Saidot', baseUrl: 'https://api.saidot.ai',
    docs: 'https://www.saidot.ai/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Saidot workspace → Settings → API access.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status, source: 'vault' }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/systems', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose }) }
    }
  },
  airia: {
    module: 'compliance', name: 'Airia', baseUrl: 'https://api.airia.ai',
    docs: 'https://docs.airia.ai/', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'X-API-KEY',
    credential: { needs: ['apiKey'], scopes: [], steps: ['Airia console → Settings → API Keys.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/governance/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status, ledgerSeq: p.ledgerSeq }) },
      control: { method: 'GET', path: '/v1/governance/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/agents', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.owner }) }
    }
  },
  cranium: {
    module: 'compliance', name: 'Cranium', baseUrl: 'https://api.cranium.ai',
    docs: 'https://cranium.ai/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Cranium platform → Admin → API tokens.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ control: p.controlId, status: p.status, source: 'vault' }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/ai-assets', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose }) }
    }
  },
  relyance: {
    module: 'compliance', name: 'Relyance AI', baseUrl: 'https://api.relyance.ai',
    docs: 'https://www.relyance.ai/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Relyance → Settings → API integration → generate token.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ control_id: p.controlId, status: p.status, provenance: 'vault-ledger' }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/data-assets', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose }) }
    }
  },
  truyo: {
    module: 'compliance', name: 'Truyo', baseUrl: 'https://api.truyo.com',
    docs: 'https://truyo.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Truyo admin → Integrations → API keys.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/ai-inventory', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose }) }
    }
  },
  auditboard: {
    module: 'compliance', name: 'AuditBoard', baseUrl: 'https://{tenant}.auditboardapp.com',
    docs: 'https://support.auditboard.com/hc/en-us/articles/360048030652', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['AuditBoard → Settings → API → generate an API token.', 'baseUrl is https://<tenant>.auditboardapp.com.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/v1/evidence', ok: [200, 201], body: (p) => ({ control_id: p.controlId, status: p.status, description: `collected from the Vault ledger at seq ${p.ledgerSeq}` }) },
      control: { method: 'GET', path: '/api/v1/controls', ok: [200], query: (p) => ({ page: String(p.page ?? 1), per_page: String(p.limit ?? 100) }), page: { pageIn: 'page', items: 'data', done: (r, sent) => (r.data?.length ?? 0) < Number(sent.per_page ?? 100) } },
      register: { method: 'POST', path: '/api/v1/entities', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose }) }
    }
  },
  archer: {
    module: 'compliance', name: 'Archer', baseUrl: 'https://{host}',
    docs: 'https://community.archerirm.com/', docsVersion: 'REST v2',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['Archer → Access Control → create an API user.', 'POST to /api/core/security/login to exchange credentials for a session token.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/core/content', ok: [200, 201], body: (p) => ({ Content: { LevelId: p.levelId, FieldContents: { evidence: p.controlId, status: p.status } } }) },
      control: { method: 'GET', path: '/api/core/system/application', ok: [200] },
      register: { method: 'POST', path: '/api/core/content', ok: [200, 201], body: (p) => ({ Content: { LevelId: p.levelId, FieldContents: { name: p.name, purpose: p.purpose } } }) }
    }
  },
  metricstream: {
    module: 'compliance', name: 'MetricStream', baseUrl: 'https://{host}',
    docs: 'https://www.metricstream.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['MetricStream admin → Integration → REST credentials.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/v1/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status }) },
      control: { method: 'GET', path: '/api/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/api/v1/assets', ok: [200, 201], body: (p) => ({ name: p.name, purpose: p.purpose }) }
    }
  },
  logicgate: {
    module: 'compliance', name: 'LogicGate Risk Cloud', baseUrl: 'https://{tenant}.logicgate.com',
    docs: 'https://developer.logicgate.com/', docsVersion: 'v1',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password', 'baseUrl'], scopes: [], steps: ['Risk Cloud → Settings → API Tokens → create.', 'username is the token id, password is the token secret.'] },
    ops: {
      evidence: { method: 'POST', path: '/api/v1/records', ok: [200, 201], body: (p) => ({ workflowId: p.workflowId, fields: { control: p.controlId, status: p.status } }) },
      control: { method: 'GET', path: '/api/v1/workflows', ok: [200], query: (p) => ({ page: String(p.page ?? 0), size: String(p.limit ?? 50) }), page: { pageIn: 'page', items: 'content', done: (r) => r.last === true } },
      register: { method: 'POST', path: '/api/v1/records', ok: [200, 201], body: (p) => ({ fields: { name: p.name, purpose: p.purpose } }) }
    }
  },
  vanta: {
    module: 'compliance', name: 'Vanta', baseUrl: 'https://api.vanta.com',
    docs: 'https://developer.vanta.com/reference', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['vanta-api.all:read', 'vanta-api.all:write'], steps: ['Vanta → Settings → Developer console → Create OAuth app.', 'Exchange client credentials at https://api.vanta.com/oauth/token for a bearer token.', 'Vanta has a free trial, so this one can be verified live without a purchase.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/resources/custom_evidence', ok: [200, 201], body: (p) => ({ resourceId: p.controlId, displayName: p.controlId, description: `Vault ledger seq ${p.ledgerSeq}`, externalUrl: p.uri ?? null }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ pageSize: String(p.limit ?? 50), pageCursor: p.cursor ?? undefined }), page: { cursorIn: 'pageCursor', cursorOut: 'pageInfo.endCursor', items: 'results.data', done: (r) => !r?.results?.pageInfo?.hasNextPage } },
      register: { method: 'POST', path: '/v1/resources/custom_resource', ok: [200, 201], body: (p) => ({ displayName: p.name, description: p.purpose, owner: p.owner }) }
    }
  },
  drata: {
    module: 'compliance', name: 'Drata', baseUrl: 'https://public-api.drata.com',
    docs: 'https://developers.drata.com/docs/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Drata → Settings → API Keys → Generate.', 'Drata offers a trial, so this can be verified live without a purchase.'] },
    ops: {
      evidence: { method: 'POST', path: '/public/external-evidence', ok: [200, 201], body: (p) => ({ name: p.controlId, description: `Vault ledger seq ${p.ledgerSeq}`, evidenceType: 'DOCUMENT', controlIds: [p.controlId] }) },
      control: { method: 'GET', path: '/public/controls', ok: [200], query: (p) => ({ page: String(p.page ?? 1), limit: String(p.limit ?? 50) }), page: { pageIn: 'page', items: 'data', done: (r, sent) => Number(sent.page ?? 1) * Number(sent.limit ?? 50) >= (r.total ?? 0) } },
      register: { method: 'POST', path: '/public/assets', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, assetType: 'SOFTWARE' }) }
    }
  },
  scrut: {
    module: 'compliance', name: 'Scrut', baseUrl: 'https://api.scrut.io',
    docs: 'https://www.scrut.io/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Scrut → Settings → API tokens.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidence', ok: [200, 201], body: (p) => ({ controlId: p.controlId, status: p.status, source: 'vault' }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/assets', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose }) }
    }
  },
  sprinto: {
    module: 'compliance', name: 'Sprinto', baseUrl: 'https://api.sprinto.com',
    docs: 'https://sprinto.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Sprinto → Settings → Integrations → API key.'] },
    ops: {
      evidence: { method: 'POST', path: '/v1/evidences', ok: [200, 201], body: (p) => ({ control: p.controlId, status: p.status, collectedAt: new Date(p.at ?? Date.now()).toISOString() }) },
      control: { method: 'GET', path: '/v1/controls', ok: [200], query: (p) => ({ framework: p.framework }) },
      register: { method: 'POST', path: '/v1/assets', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose }) }
    }
  },

  // ── §3 Archive ──────────────────────────────────────────────────────────
  smarsh: {
    module: 'archive', name: 'Smarsh', baseUrl: 'https://api.smarsh.com',
    docs: 'https://developers.smarsh.com/', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token', 'orgId'], scopes: ['archive:write', 'archive:read'], steps: ['Smarsh Central → Admin → API credentials → request a client id/secret.', 'Exchange at /oauth2/token for a bearer token.', 'orgId is your Smarsh organization identifier.'] },
    ops: {
      push: { method: 'POST', path: '/archive/v2/organizations/:orgId/messages', ok: [200, 201, 202], body: (p) => ({ messages: [{ externalId: p.id, timestamp: new Date(p.at ?? Date.now()).toISOString(), channel: p.channel, participants: p.participants ?? [], body: { contentType: 'text/plain', content: p.text }, retentionPolicy: p.retention ?? 'default' }] }) },
      fetch: { method: 'GET', path: '/archive/v2/organizations/:orgId/messages/:id', ok: [200] },
      search: { method: 'POST', path: '/archive/v2/organizations/:orgId/search', ok: [200], body: (p) => ({ query: p.query, from: p.from, to: p.to, pageSize: p.limit ?? 50, pageToken: p.cursor ?? undefined }), page: { cursorIn: 'pageToken', cursorOut: 'nextPageToken', items: 'messages', done: (r) => !r.nextPageToken } }
    }
  },
  global_relay: {
    module: 'archive', name: 'Global Relay', baseUrl: 'https://api.globalrelay.com',
    docs: 'https://www.globalrelay.com/services/archive/', docsVersion: 'v1',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password'], scopes: [], steps: ['Global Relay Support → request Message Delivery API credentials for your archive.', 'Credentials are per-archive, not per-user.'] },
    ops: {
      push: { method: 'POST', path: '/v1/messages', ok: [200, 201, 202], body: (p) => ({ messageId: p.id, sentTime: new Date(p.at ?? Date.now()).toISOString(), channelType: p.channel, participants: p.participants ?? [], content: p.text }) },
      fetch: { method: 'GET', path: '/v1/messages/:id', ok: [200] },
      search: { method: 'POST', path: '/v1/search', ok: [200], body: (p) => ({ query: p.query, startDate: p.from, endDate: p.to, limit: p.limit ?? 50, offset: p.offset ?? 0 }), page: { offsetIn: 'offset', items: 'messages', done: (r, sent) => (r.messages?.length ?? 0) < (sent.limit ?? 50) } }
    }
  },
  theta_lake: {
    module: 'archive', name: 'Theta Lake', baseUrl: 'https://api.thetalake.com',
    docs: 'https://thetalake.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Theta Lake admin → Integrations → API tokens.'] },
    ops: {
      push: { method: 'POST', path: '/api/v1/content', ok: [200, 201, 202], body: (p) => ({ externalId: p.id, capturedAt: new Date(p.at ?? Date.now()).toISOString(), source: p.channel, participants: p.participants ?? [], transcript: p.text }) },
      fetch: { method: 'GET', path: '/api/v1/content/:id', ok: [200] },
      search: { method: 'POST', path: '/api/v1/search', ok: [200], body: (p) => ({ q: p.query, limit: p.limit ?? 50, cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: 'nextCursor', items: 'items', done: (r) => !r.nextCursor } }
    }
  },
  proofpoint_archive: {
    module: 'archive', name: 'Proofpoint Archive', baseUrl: 'https://api.proofpoint.com',
    docs: 'https://help.proofpoint.com/', docsVersion: 'v2',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password'], scopes: [], steps: ['Proofpoint Admin → Settings → API keys → create a service principal.', 'username is the principal, password is the secret.'] },
    ops: {
      push: { method: 'POST', path: '/v2/archive/messages', ok: [200, 201, 202], body: (p) => ({ id: p.id, date: new Date(p.at ?? Date.now()).toISOString(), channel: p.channel, body: p.text }) },
      fetch: { method: 'GET', path: '/v2/archive/messages/:id', ok: [200] },
      search: { method: 'GET', path: '/v2/archive/search', ok: [200], query: (p) => ({ q: p.query, limit: String(p.limit ?? 50), offset: String(p.offset ?? 0) }), page: { offsetIn: 'offset', items: 'results', done: (r, sent) => (r.results?.length ?? 0) < Number(sent.limit ?? 50) } }
    }
  },
  purview_archive: {
    module: 'archive', name: 'Microsoft Purview', baseUrl: 'https://graph.microsoft.com',
    docs: 'https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview', docsVersion: 'v1.0',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['eDiscovery.ReadWrite.All', 'Files.ReadWrite.All'], steps: ['Entra ID → App registrations → New registration.', 'API permissions → Microsoft Graph → application permissions → the scopes above → grant admin consent.', 'Exchange the client secret for a token at https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token.'] },
    ops: {
      push: { method: 'POST', path: '/v1.0/security/cases/ediscoveryCases/:caseId/custodians', ok: [200, 201], body: (p) => ({ email: p.participants?.[0] ?? 'unknown@vault.local', applyHoldToSources: true }) },
      fetch: { method: 'GET', path: '/v1.0/security/cases/ediscoveryCases/:caseId', ok: [200] },
      search: { method: 'POST', path: '/v1.0/security/cases/ediscoveryCases/:caseId/searches', ok: [200, 201], body: (p) => ({ displayName: `vault-${p.id ?? 'search'}`, contentQuery: p.query }) }
    }
  },
  veritas: {
    module: 'archive', name: 'Veritas Enterprise Vault', baseUrl: 'https://{host}/EnterpriseVault',
    docs: 'https://www.veritas.com/support/en_US/doc/ev_api', docsVersion: '14.x',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password', 'baseUrl'], scopes: [], steps: ['Enterprise Vault admin console → create a service account with Archive Explorer rights.', 'baseUrl is https://<ev-server>/EnterpriseVault.'] },
    ops: {
      push: { method: 'POST', path: '/api/archives/:archiveId/items', ok: [200, 201], body: (p) => ({ externalId: p.id, subject: p.title ?? p.id, content: p.text, receivedDate: new Date(p.at ?? Date.now()).toISOString() }) },
      fetch: { method: 'GET', path: '/api/archives/:archiveId/items/:id', ok: [200] },
      search: { method: 'GET', path: '/api/archives/:archiveId/search', ok: [200], query: (p) => ({ query: p.query, pageSize: String(p.limit ?? 50), pageNumber: String(p.page ?? 1) }), page: { pageIn: 'pageNumber', items: 'items', done: (r, sent) => (r.items?.length ?? 0) < Number(sent.pageSize ?? 50) } }
    }
  },
  jatheon: {
    module: 'archive', name: 'Jatheon', baseUrl: 'https://api.jatheon.com',
    docs: 'https://jatheon.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Jatheon Cloud → Settings → API access.'] },
    ops: {
      push: { method: 'POST', path: '/v1/messages', ok: [200, 201], body: (p) => ({ id: p.id, timestamp: new Date(p.at ?? Date.now()).toISOString(), channel: p.channel, body: p.text }) },
      fetch: { method: 'GET', path: '/v1/messages/:id', ok: [200] },
      search: { method: 'GET', path: '/v1/search', ok: [200], query: (p) => ({ q: p.query, limit: String(p.limit ?? 50), offset: String(p.offset ?? 0) }), page: { offsetIn: 'offset', items: 'results', done: (r, sent) => (r.results?.length ?? 0) < Number(sent.limit ?? 50) } }
    }
  },
  mimecast: {
    module: 'archive', name: 'Mimecast', baseUrl: 'https://api.services.mimecast.com',
    docs: 'https://integrations.mimecast.com/documentation/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Mimecast Administration → Services → API and Platform Integrations → create a 2.0 app.', 'Exchange client id/secret at /oauth/token for a bearer token.'] },
    ops: {
      push: { method: 'POST', path: '/api/archive/put-file', ok: [200], body: (p) => ({ data: [{ id: p.id, content: p.text, timestamp: new Date(p.at ?? Date.now()).toISOString() }] }) },
      fetch: { method: 'POST', path: '/api/archive/get-file', ok: [200], body: (p) => ({ data: [{ id: p.id }] }) },
      search: { method: 'POST', path: '/api/archive/search', ok: [200], body: (p) => ({ data: [{ query: p.query, pageSize: p.limit ?? 50, pageToken: p.cursor ?? undefined }] }), page: { cursorIn: 'pageToken', cursorOut: 'meta.pagination.next', items: 'data[0].items', done: (r) => !r?.meta?.pagination?.next } }
    }
  },
  shield: {
    module: 'archive', name: 'Shield', baseUrl: 'https://api.shieldfc.com',
    docs: 'https://www.shieldfc.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Shield platform → Admin → API credentials.'] },
    ops: {
      push: { method: 'POST', path: '/v1/communications', ok: [200, 201], body: (p) => ({ externalId: p.id, capturedAt: new Date(p.at ?? Date.now()).toISOString(), channel: p.channel, participants: p.participants ?? [], content: p.text }) },
      fetch: { method: 'GET', path: '/v1/communications/:id', ok: [200] },
      search: { method: 'POST', path: '/v1/communications/search', ok: [200], body: (p) => ({ query: p.query, limit: p.limit ?? 50, cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: 'nextCursor', items: 'results', done: (r) => !r.nextCursor } }
    }
  },
  generic_archive: {
    module: 'archive', name: 'Generic SFTP/S3/webhook', baseUrl: null,
    docs: 'docs/FORMATS.md', docsVersion: 'vault-1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['Point baseUrl at any endpoint that accepts the Vault archive schema in docs/FORMATS.md.', 'This is the escape hatch for an archive vendor with no bespoke adapter.'] },
    ops: {
      push: { method: 'POST', path: '/archive', ok: [200, 201, 202], body: (p) => ({ id: p.id, at: p.at, channel: p.channel, participants: p.participants, text: p.text }) },
      fetch: { method: 'GET', path: '/archive/:id', ok: [200] },
      search: { method: 'POST', path: '/archive/search', ok: [200], body: (p) => ({ query: p.query, limit: p.limit ?? 50 }) }
    }
  },

  // ── §17 Registry / Agent identity ───────────────────────────────────────
  entra_agent_id: {
    module: 'registry', name: 'Microsoft Agent 365 / Entra Agent ID', baseUrl: 'https://graph.microsoft.com',
    docs: 'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal', docsVersion: 'v1.0',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['Application.ReadWrite.All', 'Directory.Read.All'], steps: ['Entra ID → App registrations → New registration.', 'API permissions → Microsoft Graph → application permissions → the scopes above → grant admin consent.', 'Exchange the client secret at https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token.'] },
    ops: {
      push: { method: 'POST', path: '/v1.0/applications', ok: [200, 201], body: (p) => ({ displayName: p.name, description: p.purpose, tags: [`vault:agent`, `owner:${p.businessOwner ?? 'unknown'}`, `mode:${p.mode ?? 'inline'}`] }) },
      fetch: { method: 'GET', path: '/v1.0/servicePrincipals', ok: [200], query: (p) => ({ $filter: `tags/any(t:t eq 'vault:agent')`, $top: String(p.limit ?? 100), $skiptoken: p.cursor ?? undefined }), page: { cursorIn: '$skiptoken', cursorOut: '@odata.nextLink', items: 'value', done: (r) => !r['@odata.nextLink'] } }
    }
  },
  servicenow_registry: {
    module: 'registry', name: 'ServiceNow AI Control Tower', baseUrl: 'https://{instance}.service-now.com',
    docs: 'https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI', docsVersion: 'Table API',
    auth: 'basic_user_pass',
    credential: { needs: ['username', 'password', 'baseUrl'], scopes: ['sn_ai_ctrl.admin'], steps: ['ServiceNow → create an integration user with the AI Control Tower role.'] },
    ops: {
      push: { method: 'POST', path: '/api/now/table/sn_ai_agent', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owned_by: p.businessOwner, u_mode: p.mode, u_model_pin: p.pinnedModel ?? '' }) },
      fetch: { method: 'GET', path: '/api/now/table/sn_ai_agent', ok: [200], query: (p) => ({ sysparm_limit: String(p.limit ?? 100), sysparm_offset: String(p.offset ?? 0) }), page: { offsetIn: 'sysparm_offset', items: 'result', done: (r, sent) => (r.result?.length ?? 0) < Number(sent.sysparm_limit ?? 100) } }
    }
  },
  okta_registry: {
    module: 'registry', name: 'Okta', baseUrl: 'https://{org}.okta.com',
    docs: 'https://developer.okta.com/docs/reference/api/apps/', docsVersion: 'v1',
    auth: 'sso_token',
    credential: { needs: ['token', 'baseUrl'], scopes: ['okta.apps.manage', 'okta.apps.read'], steps: ['Okta Admin → Security → API → Tokens → Create Token.', 'The header format is "SSWS <token>", not Bearer — a Bearer header is rejected.', 'baseUrl is https://<your-org>.okta.com.'] },
    ops: {
      push: { method: 'POST', path: '/api/v1/apps', ok: [200, 201], body: (p) => ({ name: 'oidc_client', label: p.name, signOnMode: 'OPENID_CONNECT', credentials: { oauthClient: { token_endpoint_auth_method: 'client_secret_basic' } }, settings: { oauthClient: { grant_types: ['client_credentials'], application_type: 'service' } } }) },
      fetch: { method: 'GET', path: '/api/v1/apps', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), after: p.cursor ?? undefined }), page: { cursorIn: 'after', linkHeader: true, items: null, done: (r, sent, headers) => !/rel="next"/.test(headers?.get?.('link') ?? '') } }
    }
  },
  ping: {
    module: 'registry', name: 'Ping Identity', baseUrl: 'https://api.pingone.com',
    docs: 'https://apidocs.pingidentity.com/pingone/platform/v1/api/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'envId'], scopes: ['p1:create:application', 'p1:read:application'], steps: ['PingOne → Applications → create a Worker app.', 'Exchange client credentials at https://auth.pingone.com/<envId>/as/token.', 'envId is the PingOne environment id.'] },
    ops: {
      push: { method: 'POST', path: '/v1/environments/:envId/applications', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, enabled: true, type: 'WORKER', protocol: 'OPENID_CONNECT', grantTypes: ['CLIENT_CREDENTIALS'] }) },
      fetch: { method: 'GET', path: '/v1/environments/:envId/applications', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: '_links.next.href', items: '_embedded.applications', done: (r) => !r?._links?.next } }
    }
  },
  cyberark: {
    module: 'registry', name: 'CyberArk', baseUrl: 'https://{tenant}.cyberark.cloud',
    docs: 'https://docs.cyberark.com/identity/latest/en/content/developer/api-index.htm', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['CyberArk Identity → Settings → API services → create an OAuth2 confidential client.', 'Exchange at /oauth2/token/<app> for a bearer token.'] },
    ops: {
      push: { method: 'POST', path: '/api/identities', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, type: 'service' }) },
      fetch: { method: 'GET', path: '/api/identities', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), offset: String(p.offset ?? 0) }), page: { offsetIn: 'offset', items: 'Result.Results', done: (r, sent) => (r?.Result?.Results?.length ?? 0) < Number(sent.limit ?? 100) } }
    }
  },
  palo_alto: {
    module: 'registry', name: 'Palo Alto Networks', baseUrl: 'https://api.strata.paloaltonetworks.com',
    docs: 'https://pan.dev/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Strata Cloud Manager → Settings → Identity & Access → Service Accounts.', 'Exchange client credentials at https://auth.apps.paloaltonetworks.com/am/oauth2/access_token.'] },
    ops: {
      push: { method: 'POST', path: '/v1/agents', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.businessOwner }) },
      fetch: { method: 'GET', path: '/v1/agents', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), offset: String(p.offset ?? 0) }), page: { offsetIn: 'offset', items: 'data', done: (r, sent) => (r.data?.length ?? 0) < Number(sent.limit ?? 100) } }
    }
  },
  astrix: {
    module: 'registry', name: 'Astrix Security', baseUrl: 'https://api.astrix.security',
    docs: 'https://astrix.security/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Astrix console → Settings → API tokens.'] },
    ops: {
      push: { method: 'POST', path: '/v1/service-accounts', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.businessOwner }) },
      fetch: { method: 'GET', path: '/v1/service-accounts', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: 'nextCursor', items: 'items', done: (r) => !r.nextCursor } }
    }
  },
  cisco: {
    module: 'registry', name: 'Cisco', baseUrl: 'https://api.cisco.com',
    docs: 'https://developer.cisco.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Cisco API Console → register an app → obtain client credentials.', 'Exchange at https://id.cisco.com/oauth2/default/v1/token.'] },
    ops: {
      push: { method: 'POST', path: '/v1/identities', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose }) },
      fetch: { method: 'GET', path: '/v1/identities', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100) }) }
    }
  },
  oasis: {
    module: 'registry', name: 'Oasis Security', baseUrl: 'https://api.oasis.security',
    docs: 'https://www.oasis.security/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Oasis console → Settings → API keys.'] },
    ops: {
      push: { method: 'POST', path: '/v1/identities', ok: [200, 201], body: (p) => ({ name: p.name, type: 'non-human', owner: p.businessOwner, description: p.purpose }) },
      fetch: { method: 'GET', path: '/v1/identities', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), cursor: p.cursor ?? undefined }), page: { cursorIn: 'cursor', cursorOut: 'nextCursor', items: 'identities', done: (r) => !r.nextCursor } }
    }
  },
  entro: {
    module: 'registry', name: 'Entro Security', baseUrl: 'https://api.entro.security',
    docs: 'https://entro.security/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Entro platform → Settings → API access tokens.'] },
    ops: {
      push: { method: 'POST', path: '/v1/secrets/identities', ok: [200, 201], body: (p) => ({ name: p.name, owner: p.businessOwner, purpose: p.purpose }) },
      fetch: { method: 'GET', path: '/v1/secrets/identities', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100) }) }
    }
  },
  linx: {
    module: 'registry', name: 'Linx Security', baseUrl: 'https://api.linx.security',
    docs: 'https://www.linx.security/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: [], steps: ['Linx console → Settings → API tokens.'] },
    ops: {
      push: { method: 'POST', path: '/v1/identities', ok: [200, 201], body: (p) => ({ name: p.name, description: p.purpose, owner: p.businessOwner }) },
      fetch: { method: 'GET', path: '/v1/identities', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100) }) }
    }
  },
  jumpcloud: {
    module: 'registry', name: 'JumpCloud', baseUrl: 'https://console.jumpcloud.com',
    docs: 'https://docs.jumpcloud.com/api/1.0/index.html', docsVersion: 'v1',
    auth: 'api_key_header', headerName: 'x-api-key',
    credential: { needs: ['apiKey'], scopes: [], steps: ['JumpCloud Admin Console → your user icon → API Settings → generate key.', 'JumpCloud has a free tier up to 10 users, so this can be verified live without a purchase.'] },
    ops: {
      push: { method: 'POST', path: '/api/systemusers', ok: [200, 201], body: (p) => ({ username: slug(p.name), email: `${slug(p.name)}@vault.local`, description: p.purpose, account_locked: false }) },
      fetch: { method: 'GET', path: '/api/systemusers', ok: [200], query: (p) => ({ limit: String(p.limit ?? 100), skip: String(p.offset ?? 0) }), page: { offsetIn: 'skip', items: 'results', done: (r, sent) => (r.results?.length ?? 0) < Number(sent.limit ?? 100) } }
    }
  },
  keycloak: {
    module: 'registry', name: 'Keycloak', selfHostable: true, baseUrl: 'http://localhost:8080',
    docs: 'https://www.keycloak.org/docs-api/latest/rest-api/index.html', docsVersion: '26.x',
    auth: 'bearer',
    credential: { needs: ['token', 'realm'], scopes: ['manage-clients', 'view-clients'], steps: ['Run Keycloak: `docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak start-dev`.', 'Get a token: POST /realms/master/protocol/openid-connect/token with grant_type=password&client_id=admin-cli.', 'Keycloak is free and self-hostable — verify this one live.'] },
    ops: {
      push: { method: 'POST', path: '/admin/realms/:realm/clients', ok: [200, 201, 204], body: (p) => ({ clientId: slug(p.name), name: p.name, description: p.purpose, serviceAccountsEnabled: true, publicClient: false, standardFlowEnabled: false }) },
      fetch: { method: 'GET', path: '/admin/realms/:realm/clients', ok: [200], query: (p) => ({ max: String(p.limit ?? 100), first: String(p.offset ?? 0) }), page: { offsetIn: 'first', items: null, done: (r, sent) => (Array.isArray(r) ? r.length : 0) < Number(sent.max ?? 100) } }
    }
  },

  // ── §5 Check 4 — DLP ────────────────────────────────────────────────────
  purview_dlp: {
    module: 'dlp', name: 'Microsoft Purview DLP', baseUrl: 'https://graph.microsoft.com',
    docs: 'https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview', docsVersion: 'v1.0',
    auth: 'bearer',
    credential: { needs: ['token'], scopes: ['InformationProtectionPolicy.Read.All', 'SensitivityLabel.Read.All'], steps: ['Entra ID → App registrations → API permissions → Microsoft Graph → the scopes above → grant admin consent.'] },
    ops: { scan: { method: 'POST', path: '/v1.0/security/informationProtection/sensitivityLabels/evaluateClassificationResults', ok: [200], body: (p) => ({ contentInfo: { '@odata.type': 'microsoft.graph.contentInfo', format: 'default', identifier: p.id ?? null }, classificationResults: [{ sensitiveTypeId: p.sensitiveTypeId ?? null, count: 1 }], text: p.text }) } }
  },
  symantec_dlp: {
    module: 'dlp', name: 'Symantec/Broadcom DLP', baseUrl: 'https://{host}',
    docs: 'https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention.html', docsVersion: 'v2',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['DLP Enforce Server → System → Settings → create an API user.', 'baseUrl is https://<enforce-server>.'] },
    ops: { scan: { method: 'POST', path: '/ProtectManager/webservices/v2/detection/scan', ok: [200], body: (p) => ({ content: p.text, contentType: 'text/plain', requestId: p.id }) } }
  },
  forcepoint: {
    module: 'dlp', name: 'Forcepoint DLP', baseUrl: 'https://{host}',
    docs: 'https://www.websense.com/content/support/library/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['Forcepoint Security Manager → Settings → API access.'] },
    ops: { scan: { method: 'POST', path: '/api/dlp/v1/scan', ok: [200], body: (p) => ({ content: p.text, id: p.id }) } }
  },
  netskope: {
    module: 'dlp', name: 'Netskope', baseUrl: 'https://{tenant}.goskope.com',
    docs: 'https://docs.netskope.com/en/netskope-help/admin-console/rest-api/', docsVersion: 'v2',
    auth: 'api_key_header', headerName: 'Netskope-Api-Token',
    credential: { needs: ['apiKey', 'baseUrl'], scopes: ['/api/v2/policy/dlp:read'], steps: ['Netskope tenant → Settings → Tools → REST API v2 → New Token.', 'Grant read on /api/v2/policy/dlp.', 'baseUrl is https://<tenant>.goskope.com.'] },
    ops: { scan: { method: 'POST', path: '/api/v2/policy/dlp/scan', ok: [200], body: (p) => ({ content: p.text, filename: p.id }) } }
  },
  nightfall: {
    module: 'dlp', name: 'Nightfall AI', baseUrl: 'https://api.nightfall.ai',
    docs: 'https://docs.nightfall.ai/reference/scanpayloadv3', docsVersion: 'v3',
    auth: 'bearer',
    credential: { needs: ['token', 'detectionRuleUUID'], scopes: [], steps: ['nightfall.ai → Dashboard → API Keys → create.', 'Create a Detection Rule and copy its UUID.', 'Nightfall has a free tier, so this can be verified live.'] },
    ops: { scan: { method: 'POST', path: '/v3/scan', ok: [200], body: (p) => ({ payload: [p.text], config: { detectionRuleUUIDs: [p.detectionRuleUUID] } }) } }
  },
  bigid: {
    module: 'dlp', name: 'BigID', baseUrl: 'https://{host}',
    docs: 'https://api.bigid.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['BigID → Administration → Access Management → create a service user.', 'POST /api/v1/sessions to exchange credentials for a token.'] },
    ops: { scan: { method: 'POST', path: '/api/v1/classify', ok: [200], body: (p) => ({ text: p.text, id: p.id }) } }
  },
  varonis: {
    module: 'dlp', name: 'Varonis', baseUrl: 'https://{host}',
    docs: 'https://www.varonis.com/', docsVersion: 'v1',
    auth: 'bearer',
    credential: { needs: ['token', 'baseUrl'], scopes: [], steps: ['Varonis Web UI → Configuration → API keys.'] },
    ops: { scan: { method: 'POST', path: '/api/classification/v1/scan', ok: [200], body: (p) => ({ content: p.text, identifier: p.id }) } }
  }
};

// ── helpers ───────────────────────────────────────────────────────────────

const slug = (s) => String(s ?? 'agent').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function otelAttrs(p) {
  return [
    { key: 'gen_ai.prompt', value: { stringValue: String(p.input ?? '') } },
    { key: 'gen_ai.completion', value: { stringValue: String(p.output ?? '') } },
    { key: 'vault.span.kind', value: { stringValue: String(p.kind ?? 'llm') } }
  ];
}

function flat(obj, prefix = '') {
  const out = {};
  for (const [k, v] of Object.entries(obj ?? {})) {
    if (v && typeof v === 'object' && !Array.isArray(v)) Object.assign(out, flat(v, `${prefix}${k}.`));
    else out[`${prefix}${k}`] = v;
  }
  return out;
}

/** Substitute `:name` path segments from the payload or the config. */
function fillPath(path, payload, config) {
  return path.replace(/:([A-Za-z_]+)/g, (_, key) => {
    const v = payload?.[key] ?? config?.[key];
    if (v == null) throw new VaultError('validation', `this operation needs "${key}" in the payload or the vendor config`);
    return encodeURIComponent(String(v));
  });
}

function resolveBase(spec, config) {
  const base = config?.baseUrl ?? spec.baseUrl;
  if (!base) throw new VaultError('validation', `${spec.name} needs baseUrl in its config`);
  if (/\{[a-z]+\}/i.test(base)) {
    throw new VaultError('validation',
      `${spec.name}'s default host is a template (${base}) — supply the real one as config.baseUrl`);
  }
  return base;
}

/**
 * The exact request an operation would send, WITHOUT sending it.
 *
 * This is what the contract tests assert against the vendor's published docs,
 * and it is the only way to verify 70-odd vendors from a machine that cannot
 * reach any of them. The secret is redacted so a contract fixture can be
 * committed and read without leaking a credential.
 */
export function contractFor(vendorId, op, payload = {}, config = {}) {
  const spec = VENDOR_ADAPTERS[vendorId];
  if (!spec) throw new VaultError('not_found', `no adapter for vendor "${vendorId}"`);
  const opSpec = spec.ops[op];
  if (!opSpec) {
    throw new VaultError('unsupported', `${spec.name} has no "${op}" operation`, {
      supported: Object.keys(spec.ops),
      declaredByModule: MODULES[spec.module]?.ops ?? []
    });
  }
  const base = resolveBase(spec, config);
  const url = new URL(fillPath(opSpec.path, payload, config), base);
  for (const [k, v] of Object.entries(opSpec.query?.(payload) ?? {})) {
    if (v !== undefined) url.searchParams.set(k, v);
  }
  const authHeaders = VENDOR_AUTH[spec.auth](config, spec);
  return {
    vendor: vendorId,
    vendorName: spec.name,
    module: spec.module,
    op,
    method: opSpec.method,
    url: url.toString(),
    path: url.pathname,
    headers: {
      ...(opSpec.method === 'GET' ? {} : { 'Content-Type': opSpec.contentType ?? 'application/json' }),
      ...authHeaders,
      ...(opSpec.extraHeaders ?? {})
    },
    // The header VALUE is what a contract test checks the shape of; the secret
    // inside it is not, so it is masked here and never in the live path.
    authHeaderName: Object.keys(authHeaders)[0] ?? null,
    authScheme: spec.auth,
    body: opSpec.body ? opSpec.body(payload) : null,
    expectStatus: opSpec.ok ?? [200],
    pagination: opSpec.page ?? null,
    docs: spec.docs,
    docsVersion: spec.docsVersion
  };
}

/**
 * A live adapter for one vendor, shaped for `ModuleRegistry.set(module,
 * 'connected', { adapter })`.
 */
export function buildVendorAdapter(vendorId, config = {}) {
  const spec = VENDOR_ADAPTERS[vendorId];
  if (!spec) throw new VaultError('not_found', `no adapter for vendor "${vendorId}"`);
  const declared = MODULES[spec.module]?.ops ?? Object.keys(spec.ops);
  const adapter = {
    _kind: 'vendor',
    _vendor: vendorId,
    _module: spec.module,
    _url: resolveBase(spec, config)
  };
  for (const op of Object.keys(spec.ops)) {
    adapter[op] = async (payload = {}) => {
      const c = contractFor(vendorId, op, payload, config);
      const res = await fetch(c.url, {
        method: c.method,
        headers: c.headers,
        body: c.body == null ? undefined : JSON.stringify(c.body),
        signal: AbortSignal.timeout(config.timeoutMs ?? 10_000)
      });
      if (!c.expectStatus.includes(res.status)) {
        // Never echo the response body: a vendor error page can contain the
        // request, and the request contains the credential.
        // Deliberately `vendorStatus`, not `status`: VaultError lifts a `status`
        // key out of meta and uses it as the HTTP status VAULT returns to its
        // own caller, so a vendor's 429 would silently become Vault's 429 to a
        // customer whose request was fine.
        throw new VaultError('connector', `${spec.name} returned ${res.status} for ${op}`, {
          vendor: vendorId, op, vendorStatus: res.status,
          retryAfter: res.headers.get('retry-after') ?? null,
          rateLimitRemaining: res.headers.get('x-ratelimit-remaining') ?? res.headers.get('ratelimit-remaining') ?? null
        });
      }
      return res.json().catch(() => ({}));
    };
  }
  adapter._missingOps = declared.filter((op) => typeof adapter[op] !== 'function');
  return adapter;
}

/**
 * What a reader needs in order to finish the job: the exact credential, the
 * exact scopes, and the exact steps. No guessing.
 */
export function vendorStatus(vendorId, { liveVerified = new Set() } = {}) {
  const spec = VENDOR_ADAPTERS[vendorId];
  if (!spec) throw new VaultError('not_found', `no adapter for vendor "${vendorId}"`);
  const declared = MODULES[spec.module]?.ops ?? [];
  const implemented = Object.keys(spec.ops);
  return {
    vendor: vendorId,
    name: spec.name,
    module: spec.module,
    verification: liveVerified.has(vendorId) ? 'live-verified' : 'contract-verified against published docs, NOT verified against a live account',
    docs: spec.docs,
    docsVersion: spec.docsVersion,
    selfHostable: Boolean(spec.selfHostable),
    host: spec.baseUrl,
    hostIsTemplate: Boolean(spec.baseUrl && /\{[a-z]+\}/i.test(spec.baseUrl)),
    authScheme: spec.auth,
    credentialRequired: spec.credential.needs,
    scopesRequired: spec.credential.scopes,
    howToObtain: spec.credential.steps,
    opsImplemented: implemented,
    opsDeclaredByModule: declared,
    missingOps: declared.filter((o) => !implemented.includes(o)),
    complete: declared.every((o) => implemented.includes(o))
  };
}

/** Every vendor, grouped by module. Drives the toggle screen and the report. */
export function vendorCatalogue({ liveVerified = new Set() } = {}) {
  const byModule = {};
  for (const id of Object.keys(VENDOR_ADAPTERS)) {
    const s = vendorStatus(id, { liveVerified });
    (byModule[s.module] ??= []).push(s);
  }
  return {
    totalVendors: Object.keys(VENDOR_ADAPTERS).length,
    modules: byModule,
    complete: Object.values(byModule).flat().filter((v) => v.complete).length,
    liveVerified: Object.values(byModule).flat().filter((v) => v.verification === 'live-verified').length
  };
}
