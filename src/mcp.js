const PROTOCOL = '2025-11-25';
const JSON_HEADERS = { 'content-type': 'application/json; charset=UTF-8', 'cache-control': 'no-store' };
const now = () => new Date().toISOString();
const uid = () => crypto.randomUUID();
const rpc = (id, result, extraHeaders = {}) => new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), { status: 200, headers: { ...JSON_HEADERS, ...extraHeaders } });
const rpcError = (id, code, message, status = 200) => new Response(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }), { status, headers: JSON_HEADERS });

function authorized(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (!env.CRM_ADMIN_TOKEN || !auth.startsWith('Bearer ')) return false;
  const supplied = auth.slice(7).trim();
  return supplied && supplied === env.CRM_ADMIN_TOKEN;
}

async function ensureSchema(env) {
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_contacts(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT NOT NULL,email TEXT,phone TEXT,company TEXT,status TEXT NOT NULL DEFAULT 'lead',notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_projects(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT NOT NULL,category TEXT,status TEXT NOT NULL DEFAULT 'active',summary TEXT,next_action TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_tasks(id TEXT PRIMARY KEY,tenant_id TEXT,project_id TEXT,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',priority TEXT NOT NULL DEFAULT 'normal',due_at TEXT,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_activity(id TEXT PRIMARY KEY,tenant_id TEXT,entity_type TEXT,entity_id TEXT,action TEXT NOT NULL,detail TEXT,created_at TEXT NOT NULL)`)
  ]);
}

const tenant = env => env.CRM_ADMIN_TENANT || 'zorvian';

async function activity(env, entityType, entityId, action, detail = '') {
  await env.DB.prepare('INSERT INTO crm_activity(id,tenant_id,entity_type,entity_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)')
    .bind(uid(), tenant(env), entityType, entityId, action, detail, now()).run();
}

const toolResult = (text, data = {}) => ({
  content: [{ type: 'text', text }],
  structuredContent: data,
  isError: false
});

const tools = [
  {
    name: 'crm_status',
    title: 'CRM status',
    description: 'Use this when you need to confirm that the Zorvian CRM connection is live and writable.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'list_projects',
    title: 'List CRM projects',
    description: 'Use this when you need to see the user’s current Zorvian projects, briefs, statuses, and next actions.',
    inputSchema: { type: 'object', properties: { status: { type: 'string', enum: ['active', 'waiting', 'complete'] } }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'create_project',
    title: 'Create CRM project',
    description: 'Use this when the user asks to create a new project in Zorvian CRM.',
    inputSchema: { type: 'object', required: ['name'], properties: { name: { type: 'string', minLength: 1 }, category: { type: 'string' }, summary: { type: 'string' }, next_action: { type: 'string' }, status: { type: 'string', enum: ['active', 'waiting', 'complete'] } }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false }
  },
  {
    name: 'update_project',
    title: 'Update CRM project',
    description: 'Use this when the user asks to change a project brief, status, category, or next action in Zorvian CRM.',
    inputSchema: { type: 'object', required: ['id'], properties: { id: { type: 'string' }, name: { type: 'string' }, category: { type: 'string' }, summary: { type: 'string' }, next_action: { type: 'string' }, status: { type: 'string', enum: ['active', 'waiting', 'complete'] } }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'list_tasks',
    title: 'List CRM tasks',
    description: 'Use this when you need to see outstanding or completed Zorvian CRM tasks.',
    inputSchema: { type: 'object', properties: { status: { type: 'string', enum: ['open', 'done'] }, project_id: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'create_task',
    title: 'Create CRM task',
    description: 'Use this when the user asks to add a concrete task to Zorvian CRM.',
    inputSchema: { type: 'object', required: ['title'], properties: { title: { type: 'string', minLength: 1 }, project_id: { type: 'string' }, priority: { type: 'string', enum: ['low', 'normal', 'high', 'urgent'] }, due_at: { type: ['string', 'null'] }, notes: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false }
  },
  {
    name: 'update_task',
    title: 'Update CRM task',
    description: 'Use this when the user asks to update, complete, reprioritise, or add results/notes to a Zorvian CRM task.',
    inputSchema: { type: 'object', required: ['id'], properties: { id: { type: 'string' }, title: { type: 'string' }, project_id: { type: 'string' }, status: { type: 'string', enum: ['open', 'done'] }, priority: { type: 'string', enum: ['low', 'normal', 'high', 'urgent'] }, due_at: { type: ['string', 'null'] }, notes: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'list_contacts',
    title: 'List CRM contacts',
    description: 'Use this when you need to see leads, clients, suppliers, or partners stored in Zorvian CRM.',
    inputSchema: { type: 'object', properties: { status: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  },
  {
    name: 'create_contact',
    title: 'Create CRM contact',
    description: 'Use this when the user asks to add a lead, client, supplier, or partner to Zorvian CRM.',
    inputSchema: { type: 'object', required: ['name'], properties: { name: { type: 'string', minLength: 1 }, email: { type: 'string' }, phone: { type: 'string' }, company: { type: 'string' }, status: { type: 'string' }, notes: { type: 'string' } }, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: false }
  },
  {
    name: 'list_activity',
    title: 'List CRM activity',
    description: 'Use this when you need the latest Zorvian CRM history so you can continue work without losing the thread.',
    inputSchema: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, maximum: 100 } }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  }
];

async function callTool(name, args, env) {
  const t = tenant(env);
  if (name === 'crm_status') {
    const p = await env.DB.prepare('SELECT COUNT(*) AS n FROM crm_projects WHERE tenant_id=?').bind(t).first();
    const q = await env.DB.prepare("SELECT COUNT(*) AS n FROM crm_tasks WHERE tenant_id=? AND status='open'").bind(t).first();
    return toolResult('Zorvian CRM is connected and writable.', { ok: true, tenant: t, projects: Number(p?.n || 0), open_tasks: Number(q?.n || 0) });
  }
  if (name === 'list_projects') {
    const r = args.status
      ? await env.DB.prepare('SELECT * FROM crm_projects WHERE tenant_id=? AND status=? ORDER BY updated_at DESC').bind(t, args.status).all()
      : await env.DB.prepare('SELECT * FROM crm_projects WHERE tenant_id=? ORDER BY updated_at DESC').bind(t).all();
    return toolResult(`Found ${r.results.length} CRM project(s).`, { projects: r.results });
  }
  if (name === 'create_project') {
    const id = uid(), ts = now();
    await env.DB.prepare('INSERT INTO crm_projects(id,tenant_id,name,category,status,summary,next_action,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .bind(id, t, String(args.name).trim(), args.category || '', args.status || 'active', args.summary || '', args.next_action || '', ts, ts).run();
    await activity(env, 'projects', id, 'created_by_chatgpt', args.name);
    return toolResult(`Created project “${args.name}” in Zorvian CRM.`, { id, created: true });
  }
  if (name === 'update_project') {
    const allowed = ['name', 'category', 'status', 'summary', 'next_action'];
    const keys = allowed.filter(k => Object.prototype.hasOwnProperty.call(args, k));
    if (!keys.length) return { content: [{ type: 'text', text: 'No project fields were supplied to update.' }], isError: true };
    await env.DB.prepare(`UPDATE crm_projects SET ${keys.map(k => `${k}=?`).join(',')},updated_at=? WHERE id=? AND tenant_id=?`)
      .bind(...keys.map(k => args[k]), now(), args.id, t).run();
    await activity(env, 'projects', args.id, 'updated_by_chatgpt', keys.join(', '));
    return toolResult('Updated the CRM project.', { id: args.id, updated_fields: keys });
  }
  if (name === 'list_tasks') {
    const clauses = ['tenant_id=?']; const vals = [t];
    if (args.status) { clauses.push('status=?'); vals.push(args.status); }
    if (args.project_id) { clauses.push('project_id=?'); vals.push(args.project_id); }
    const r = await env.DB.prepare(`SELECT * FROM crm_tasks WHERE ${clauses.join(' AND ')} ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, updated_at DESC`).bind(...vals).all();
    return toolResult(`Found ${r.results.length} CRM task(s).`, { tasks: r.results });
  }
  if (name === 'create_task') {
    const id = uid(), ts = now();
    await env.DB.prepare('INSERT INTO crm_tasks(id,tenant_id,project_id,title,status,priority,due_at,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, args.project_id || '', String(args.title).trim(), 'open', args.priority || 'normal', args.due_at || null, args.notes || '', ts, ts).run();
    await activity(env, 'tasks', id, 'created_by_chatgpt', args.title);
    return toolResult(`Created task “${args.title}” in Zorvian CRM.`, { id, created: true });
  }
  if (name === 'update_task') {
    const allowed = ['project_id', 'title', 'status', 'priority', 'due_at', 'notes'];
    const keys = allowed.filter(k => Object.prototype.hasOwnProperty.call(args, k));
    if (!keys.length) return { content: [{ type: 'text', text: 'No task fields were supplied to update.' }], isError: true };
    await env.DB.prepare(`UPDATE crm_tasks SET ${keys.map(k => `${k}=?`).join(',')},updated_at=? WHERE id=? AND tenant_id=?`)
      .bind(...keys.map(k => args[k]), now(), args.id, t).run();
    await activity(env, 'tasks', args.id, 'updated_by_chatgpt', keys.join(', '));
    return toolResult('Updated the CRM task.', { id: args.id, updated_fields: keys });
  }
  if (name === 'list_contacts') {
    const r = args.status
      ? await env.DB.prepare('SELECT * FROM crm_contacts WHERE tenant_id=? AND status=? ORDER BY updated_at DESC').bind(t, args.status).all()
      : await env.DB.prepare('SELECT * FROM crm_contacts WHERE tenant_id=? ORDER BY updated_at DESC').bind(t).all();
    return toolResult(`Found ${r.results.length} CRM contact(s).`, { contacts: r.results });
  }
  if (name === 'create_contact') {
    const id = uid(), ts = now();
    await env.DB.prepare('INSERT INTO crm_contacts(id,tenant_id,name,email,phone,company,status,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, String(args.name).trim(), args.email || '', args.phone || '', args.company || '', args.status || 'lead', args.notes || '', ts, ts).run();
    await activity(env, 'contacts', id, 'created_by_chatgpt', args.name);
    return toolResult(`Created contact “${args.name}” in Zorvian CRM.`, { id, created: true });
  }
  if (name === 'list_activity') {
    const limit = Math.min(Math.max(Number(args.limit || 30), 1), 100);
    const r = await env.DB.prepare('SELECT * FROM crm_activity WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?').bind(t, limit).all();
    return toolResult(`Loaded ${r.results.length} CRM activity record(s).`, { activity: r.results });
  }
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

export async function handleMCP(request, env) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization,content-type,mcp-session-id,mcp-protocol-version,mcp-method,mcp-name', 'access-control-allow-methods': 'POST,GET,DELETE,OPTIONS' } });
  if (!authorized(request, env)) return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: { ...JSON_HEADERS, 'www-authenticate': 'Bearer realm="zorvian-crm-mcp"' } });
  if (!env.DB) return rpcError(null, -32000, 'CRM database unavailable', 503);
  if (request.method === 'DELETE') return new Response(null, { status: 204 });
  if (request.method === 'GET') return new Response(JSON.stringify({ name: 'Zorvian CRM MCP', status: 'ready', endpoint: '/mcp' }), { status: 200, headers: JSON_HEADERS });
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: { allow: 'POST, GET, DELETE, OPTIONS' } });

  let msg;
  try { msg = await request.json(); } catch { return rpcError(null, -32700, 'Parse error', 400); }
  if (!msg || msg.jsonrpc !== '2.0' || !msg.method) return rpcError(msg?.id, -32600, 'Invalid Request', 400);
  await ensureSchema(env);

  if (msg.method === 'initialize') {
    const requested = msg.params?.protocolVersion;
    const protocolVersion = ['2025-11-25', '2025-06-18', '2025-03-26'].includes(requested) ? requested : PROTOCOL;
    return rpc(msg.id, {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'zorvian-crm', title: 'Zorvian CRM', version: '1.0.0' },
      instructions: 'Use Zorvian CRM tools to preserve project context, create and complete tasks, and update project records when the user asks. Do not invent CRM records; read current records before modifying ambiguous items.'
    }, { 'Mcp-Session-Id': uid() });
  }
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') return new Response(null, { status: 202 });
  if (msg.method === 'ping') return rpc(msg.id, {});
  if (msg.method === 'tools/list') return rpc(msg.id, { tools });
  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    const args = msg.params?.arguments || {};
    if (!name) return rpcError(msg.id, -32602, 'Tool name is required');
    try { return rpc(msg.id, await callTool(name, args, env)); }
    catch (e) { return rpc(msg.id, { content: [{ type: 'text', text: `CRM tool failed: ${e?.message || 'unknown error'}` }], isError: true }); }
  }
  return rpcError(msg.id, -32601, `Method not found: ${msg.method}`);
}
