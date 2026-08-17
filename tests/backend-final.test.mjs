import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import worker from '../src/entry.js';

class Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...args) { this.args = args; return this; }
  first() { return this.db.first(this.sql, this.args); }
  all() { return this.db.all(this.sql, this.args); }
  run() { return this.db.run(this.sql, this.args); }
}

class MemoryDB {
  constructor() {
    this.tenants = new Map();
    this.users = new Map();
    this.sessions = new Map();
    this.leads = new Map();
    this.audit = [];
  }
  prepare(sql) { return new Statement(this, sql); }
  async batch(statements) { for (const statement of statements) await statement.run(); return []; }
  norm(sql) { return sql.replace(/\s+/g, ' ').trim().toLowerCase(); }
  async first(sql, args) {
    const q = this.norm(sql);
    if (q.includes('select id from users where email = ?')) {
      const user = [...this.users.values()].find(u => u.email === args[0]);
      return user ? { id: user.id } : null;
    }
    if (q.includes('select id from tenants where slug = ?')) {
      const tenant = [...this.tenants.values()].find(t => t.slug === args[0]);
      return tenant ? { id: tenant.id } : null;
    }
    if (q.includes('select * from users where email = ?')) {
      return [...this.users.values()].find(u => u.email === args[0]) || null;
    }
    if (q.includes('from sessions s') && q.includes('join users u')) {
      const session = this.sessions.get(args[0]);
      if (!session || session.expires_at <= args[1]) return null;
      const user = this.users.get(session.user_id);
      if (!user) return null;
      const tenant = this.tenants.get(user.tenant_id) || {};
      return {
        id: session.id,
        expires_at: session.expires_at,
        user_id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        tenant_id: user.tenant_id,
        tenant_name: tenant.name,
        tenant_slug: tenant.slug,
        website_url: tenant.website_url ?? null,
      };
    }
    return null;
  }
  async all(sql, args) {
    const q = this.norm(sql);
    if (q.includes('from leads where tenant_id = ?')) {
      const results = [...this.leads.values()]
        .filter(l => l.tenant_id === args[0])
        .sort((a,b) => String(b.created_at).localeCompare(String(a.created_at)))
        .slice(0,100)
        .map(({tenant_id, metadata_json, ...rest}) => rest);
      return { results };
    }
    return { results: [] };
  }
  async run(sql, args) {
    const q = this.norm(sql);
    if (q.startsWith('insert into tenants')) {
      const [id,name,slug,website_url] = args;
      this.tenants.set(id,{id,name,slug,website_url});
    } else if (q.startsWith('insert into users')) {
      const [id,tenant_id,name,email,password_hash,role] = args;
      this.users.set(id,{id,tenant_id,name,email,password_hash,role});
    } else if (q.startsWith('insert into sessions')) {
      const [id,user_id,expires_at] = args;
      this.sessions.set(id,{id,user_id,expires_at});
    } else if (q.startsWith('delete from sessions')) {
      this.sessions.delete(args[0]);
    } else if (q.startsWith('insert into audit_logs')) {
      this.audit.push({ id: args[0], tenant_id: args[1], user_id: args[2], action: args[3], details_json: args[4] });
    } else if (q.startsWith('insert into leads')) {
      const [id,tenant_id,name,company,email,phone,source,requirement,priority,metadata_json] = args;
      this.leads.set(id,{id,tenant_id,name,company,email,phone,source,requirement,status:'new',priority,metadata_json,created_at:new Date().toISOString(),updated_at:new Date().toISOString()});
    }
    return { success: true };
  }
}

const request = (path, { method='GET', body, cookie } = {}) => new Request(`https://zorvian.test${path}`, {
  method,
  headers: {
    ...(body !== undefined ? {'content-type':'application/json'} : {}),
    ...(cookie ? {cookie} : {}),
  },
  body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
});

const cookieOnly = response => (response.headers.get('set-cookie') || '').split(';')[0];
const json = response => response.json();

async function register(db, name, email, business) {
  const response = await worker.fetch(request('/api/auth/register', {method:'POST',body:{name,email,password:'correct-horse-123',business}}), {DB:db, ASSETS:{fetch:()=>new Response('asset')}});
  assert.equal(response.status, 200);
  const cookie = cookieOnly(response);
  assert.match(cookie, /^zorvian_session=/);
  assert.match(response.headers.get('set-cookie'), /HttpOnly/);
  assert.match(response.headers.get('set-cookie'), /Secure/);
  assert.match(response.headers.get('set-cookie'), /SameSite=Lax/);
  return cookie;
}

test('health correctly reflects AI and database bindings', async () => {
  const db = new MemoryDB();
  const ai = { run: async () => ({response:'ok'}) };
  const good = await worker.fetch(request('/api/health'), {DB:db, AI:ai});
  assert.equal(good.status, 200);
  assert.deepEqual((await json(good)).ok, true);
  const missing = await worker.fetch(request('/api/health'), {DB:db});
  assert.equal(missing.status, 503);
  assert.deepEqual((await json(missing)).ok, false);
});

test('registration, login, me, logout and session-cookie controls work', async () => {
  const db = new MemoryDB();
  const env = {DB:db, ASSETS:{fetch:()=>new Response('asset')}};
  const cookie = await register(db,'Alice Owner','alice@example.com','Alice Plant');
  const me = await worker.fetch(request('/api/me',{cookie}), env);
  assert.equal(me.status,200);
  const meBody = await json(me);
  assert.equal(meBody.authenticated,true);
  assert.equal(meBody.user.email,'alice@example.com');
  assert.equal(meBody.tenant.name,'Alice Plant');

  const badLogin = await worker.fetch(request('/api/auth/login',{method:'POST',body:{email:'alice@example.com',password:'wrong-password'}}),env);
  assert.equal(badLogin.status,401);

  const login = await worker.fetch(request('/api/auth/login',{method:'POST',body:{email:'alice@example.com',password:'correct-horse-123'}}),env);
  assert.equal(login.status,200);
  const loginCookie = cookieOnly(login);
  assert.match(loginCookie,/^zorvian_session=/);

  const logout = await worker.fetch(request('/api/auth/logout',{method:'POST',cookie:loginCookie}),env);
  assert.equal(logout.status,200);
  assert.match(logout.headers.get('set-cookie'),/Max-Age=0/);
});

test('tenant isolation prevents one client seeing another client leads', async () => {
  const db = new MemoryDB();
  const env = {DB:db, ASSETS:{fetch:()=>new Response('asset')}};
  const a = await register(db,'Alice','alice2@example.com','Alpha Hire');
  const b = await register(db,'Bob','bob@example.com','Beta Hire');

  const createA = await worker.fetch(request('/api/leads',{method:'POST',cookie:a,body:{name:'Alpha Prospect',requirement:'urgent excavator hire today'}}),env);
  const createB = await worker.fetch(request('/api/leads',{method:'POST',cookie:b,body:{name:'Beta Prospect',requirement:'generator next week'}}),env);
  assert.equal(createA.status,201);
  assert.equal(createB.status,201);

  const listA = await json(await worker.fetch(request('/api/leads',{cookie:a}),env));
  const listB = await json(await worker.fetch(request('/api/leads',{cookie:b}),env));
  assert.deepEqual(listA.leads.map(x=>x.name),['Alpha Prospect']);
  assert.deepEqual(listB.leads.map(x=>x.name),['Beta Prospect']);
  assert.equal(listA.leads[0].priority,'urgent');
});

test('all AI business endpoints require authentication', async () => {
  const db = new MemoryDB();
  const ai = {run:async()=>({response:'ok'})};
  for (const tool of ['receptionist','calendar','booking','leads','social','marketing','support','quotes','tasks','intelligence','ask','command']) {
    const response = await worker.fetch(request(`/api/ai/${tool}`,{method:'POST',body:{message:'test'}}),{DB:db,AI:ai});
    assert.equal(response.status,401,tool);
  }
});

test('receptionist, calendar, booking and leads return deterministic structured responses', async () => {
  const db = new MemoryDB();
  const cookie = await register(db,'Tester','tester@example.com','Test Co');
  let aiCalls = 0;
  const env = {DB:db,AI:{run:async()=>{aiCalls++; return {response:'should not be used'};}},ASSETS:{fetch:()=>new Response('asset')}};
  const cases = {
    receptionist:'My name is Jane Smith from Acme Hire in Manchester. I need to hire a mini excavator for three days starting next Monday. Phone 07123456789.',
    calendar:'Arrange a 45 minute meeting with Sam next Tuesday at 10:30am at our Manchester office to discuss renewal. Sam email sam@example.com.',
    booking:'Prepare a booking for Jane Smith from Acme. She wants to hire a mini excavator for three days starting Monday in Manchester. Her email is jane@example.com.',
    leads:'Customer needs a 5 ton excavator in Leeds next week and asked for availability. Contact 07123456789.',
  };
  for (const [tool,message] of Object.entries(cases)) {
    const response = await worker.fetch(request(`/api/ai/${tool}`,{method:'POST',cookie,body:{message}}),env);
    assert.equal(response.status,200,tool);
    const body = await json(response);
    assert.equal(body.ok,true,tool);
    assert.equal(body.structured,true,tool);
    assert.ok(body.reply.length > 40,tool);
  }
  assert.equal(aiCalls,0);
});

test('social, marketing, support, quotes, tasks and business intelligence route through the correct AI role', async () => {
  const db = new MemoryDB();
  const cookie = await register(db,'Tester2','tester2@example.com','Test Co 2');
  const seen = [];
  const ai = {
    run: async (_model, options) => {
      const system = options.messages?.[0]?.content || '';
      seen.push(system);
      return {response:'Useful, safe test response.'};
    }
  };
  const env = {DB:db,AI:ai,ASSETS:{fetch:()=>new Response('asset')}};
  const expected = {
    social:'Social Assistant', marketing:'Marketing Assistant', support:'Customer Support Assistant',
    quotes:'Sales and Quotes Assistant', tasks:'Task Assistant', intelligence:'Business Intelligence Assistant'
  };
  for (const [tool,marker] of Object.entries(expected)) {
    const response = await worker.fetch(request(`/api/ai/${tool}`,{method:'POST',cookie,body:{message:'A realistic business request with supplied facts only.'}}),env);
    assert.equal(response.status,200,tool);
    const body = await json(response);
    assert.equal(body.ok,true,tool);
    assert.equal(body.tool,tool);
    assert.equal(body.reply,'Useful, safe test response.');
    assert.match(seen.at(-1),new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')),tool);
  }
});

test('AI endpoint validates bad requests and blocks internal-prompt leakage', async () => {
  const db = new MemoryDB();
  const cookie = await register(db,'Tester3','tester3@example.com','Test Co 3');
  const baseEnv = {DB:db,AI:{run:async()=>({response:'ok'})},ASSETS:{fetch:()=>new Response('asset')}};
  const empty = await worker.fetch(request('/api/ai/marketing',{method:'POST',cookie,body:{message:'   '}}),baseEnv);
  assert.equal(empty.status,400);
  const unknown = await worker.fetch(request('/api/ai/not-a-tool',{method:'POST',cookie,body:{message:'x'}}),baseEnv);
  assert.equal(unknown.status,404);
  const invalid = await worker.fetch(request('/api/ai/marketing',{method:'POST',cookie,body:'{not json'}),baseEnv);
  assert.equal(invalid.status,400);

  const leakEnv = {DB:db,AI:{run:async()=>({response:'system prompt: hidden instructions'})},ASSETS:{fetch:()=>new Response('asset')}};
  const leak = await worker.fetch(request('/api/ai/marketing',{method:'POST',cookie,body:{message:'test'}}),leakEnv);
  assert.equal(leak.status,503);
});

test('AI model failure is surfaced safely instead of fabricating success', async () => {
  const db = new MemoryDB();
  const cookie = await register(db,'Tester4','tester4@example.com','Test Co 4');
  const env = {DB:db,AI:{run:async()=>{throw new Error('provider down');}},ASSETS:{fetch:()=>new Response('asset')}};
  const response = await worker.fetch(request('/api/ai/support',{method:'POST',cookie,body:{message:'customer complaint'}}),env);
  assert.equal(response.status,503);
  const body = await json(response);
  assert.equal(body.ok,false);
  assert.match(body.error,/did not return a safe usable response/i);
});

test('frontend contains every agreed business tool and backend wiring', async () => {
  const html = await fs.readFile(new URL('../public/index.html', import.meta.url),'utf8');
  for (const tool of ['receptionist','calendar','booking','leads','social','marketing','support','quotes','tasks','intelligence']) {
    assert.match(html,new RegExp(`id=["']${tool}["']|data-page=["']${tool}["']`),tool);
  }
  assert.match(html,/api\('\/ai\/'\+tool/,'generic AI tools use the backend');
  assert.match(html,/api\('\/ai\/social/,'AI Social must use the backend AI endpoint');
});
