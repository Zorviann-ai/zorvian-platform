const JSON_HEADERS={"content-type":"application/json; charset=UTF-8","cache-control":"no-store"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});
const now=()=>new Date().toISOString();
const uid=()=>crypto.randomUUID();
const PIPELINE=['NEW','CONTACTED','QUALIFIED','PROPOSAL','WON','LOST'];

function getCookie(request,name){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function sessionUser(request,env){const id=getCookie(request,'zorvian_session');if(!id||!env.DB)return null;return env.DB.prepare(`SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`).bind(id,now()).first();}
function serviceUser(request,env){const auth=request.headers.get('Authorization')||'';if(!env.CRM_ADMIN_TOKEN||!auth.startsWith('Bearer '))return null;const token=auth.slice(7).trim();if(token!==env.CRM_ADMIN_TOKEN)return null;return{id:'crm-service',name:'Caelomere CRM Service',email:'service@caelomere.internal',role:'admin',tenant_id:env.CRM_ADMIN_TENANT||'zorvian',service:true};}
async function authenticatedUser(request,env){return serviceUser(request,env)||await sessionUser(request,env);}
const tenant=u=>u.tenant_id||'zorvian';

async function columns(env,table){const r=await env.DB.prepare(`PRAGMA table_info(${table})`).all();return new Set((r.results||[]).map(x=>x.name));}
async function addMissingColumns(env,table,defs){const existing=await columns(env,table);for(const [name,def] of defs){if(!existing.has(name)){await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`).run();}}}
async function ensureSchema(env){
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_contacts(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT NOT NULL,email TEXT,phone TEXT,company TEXT,status TEXT NOT NULL DEFAULT 'lead',notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_tasks(id TEXT PRIMARY KEY,tenant_id TEXT,project_id TEXT,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',priority TEXT NOT NULL DEFAULT 'normal',due_at TEXT,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_activity(id TEXT PRIMARY KEY,tenant_id TEXT,entity_type TEXT,entity_id TEXT,action TEXT NOT NULL,detail TEXT,created_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_leads(id TEXT PRIMARY KEY,tenant_id TEXT,contact_id TEXT,name TEXT NOT NULL,company TEXT,source TEXT,status TEXT NOT NULL DEFAULT 'NEW',value REAL,owner TEXT,next_action TEXT,follow_up_at TEXT,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`)
  ]);
  await addMissingColumns(env,'crm_contacts',[["source","TEXT"],["owner","TEXT"]]);
  await addMissingColumns(env,'crm_tasks',[["contact_id","TEXT"],["lead_id","TEXT"]]);
  await env.DB.batch([
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_crm_contacts_tenant ON crm_contacts(tenant_id,updated_at)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_crm_leads_tenant ON crm_leads(tenant_id,status,updated_at)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_crm_tasks_tenant ON crm_tasks(tenant_id,status,due_at)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_crm_activity_tenant ON crm_activity(tenant_id,created_at)')
  ]);
}
async function activity(env,u,entityType,entityId,action,detail=''){await env.DB.prepare('INSERT INTO crm_activity(id,tenant_id,entity_type,entity_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)').bind(uid(),tenant(u),entityType,entityId,action,detail,now()).run();}
function safeSearch(q){return `%${String(q||'').trim().replaceAll('%','')}%`;}

async function listContacts(env,u,url){const t=tenant(u),q=url.searchParams.get('q');if(q){const like=safeSearch(q);return env.DB.prepare('SELECT * FROM crm_contacts WHERE tenant_id=? AND (name LIKE ? OR company LIKE ? OR email LIKE ? OR phone LIKE ?) ORDER BY updated_at DESC LIMIT 250').bind(t,like,like,like,like).all();}return env.DB.prepare('SELECT * FROM crm_contacts WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 250').bind(t).all();}
async function createContact(env,u,b){const name=String(b.name||'').trim();if(!name)return json({error:'name_required'},400);const id=uid(),ts=now();await env.DB.prepare('INSERT INTO crm_contacts(id,tenant_id,name,email,phone,company,status,notes,created_at,updated_at,source,owner) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,tenant(u),name,b.email||'',b.phone||'',b.company||'',b.status||'lead',b.notes||'',ts,ts,b.source||'',b.owner||'').run();await activity(env,u,'contact',id,'created',name);return json({ok:true,id},201);}
async function updateContact(env,u,id,b){const allowed=['name','email','phone','company','status','notes','source','owner'];const keys=allowed.filter(k=>Object.prototype.hasOwnProperty.call(b,k));if(!keys.length)return json({error:'nothing_to_update'},400);await env.DB.prepare(`UPDATE crm_contacts SET ${keys.map(k=>k+'=?').join(',')},updated_at=? WHERE id=? AND tenant_id=?`).bind(...keys.map(k=>b[k]),now(),id,tenant(u)).run();await activity(env,u,'contact',id,'updated',keys.join(', '));return json({ok:true});}

async function listLeads(env,u,url){const t=tenant(u),status=url.searchParams.get('status'),q=url.searchParams.get('q');let sql='SELECT * FROM crm_leads WHERE tenant_id=?',args=[t];if(status){sql+=' AND status=?';args.push(status);}if(q){const like=safeSearch(q);sql+=' AND (name LIKE ? OR company LIKE ? OR source LIKE ? OR notes LIKE ?)';args.push(like,like,like,like);}sql+=' ORDER BY updated_at DESC LIMIT 250';return env.DB.prepare(sql).bind(...args).all();}
async function createLead(env,u,b){const name=String(b.name||'').trim();if(!name)return json({error:'name_required'},400);const status=PIPELINE.includes(String(b.status||'NEW').toUpperCase())?String(b.status||'NEW').toUpperCase():'NEW';const id=uid(),ts=now(),value=(b.value===''||b.value==null)?null:Number(b.value);await env.DB.prepare('INSERT INTO crm_leads(id,tenant_id,contact_id,name,company,source,status,value,owner,next_action,follow_up_at,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,tenant(u),b.contact_id||null,name,b.company||'',b.source||'',status,Number.isFinite(value)?value:null,b.owner||'',b.next_action||'',b.follow_up_at||null,b.notes||'',ts,ts).run();await activity(env,u,'lead',id,'created',`${name} — ${status}`);return json({ok:true,id,status},201);}
async function updateLead(env,u,id,b){const allowed=['contact_id','name','company','source','value','owner','next_action','follow_up_at','notes'];const keys=allowed.filter(k=>Object.prototype.hasOwnProperty.call(b,k));if(Object.prototype.hasOwnProperty.call(b,'status')){const status=String(b.status||'').toUpperCase();if(!PIPELINE.includes(status))return json({error:'invalid_pipeline_status'},400);keys.push('status');b.status=status;}if(!keys.length)return json({error:'nothing_to_update'},400);await env.DB.prepare(`UPDATE crm_leads SET ${keys.map(k=>k+'=?').join(',')},updated_at=? WHERE id=? AND tenant_id=?`).bind(...keys.map(k=>b[k]),now(),id,tenant(u)).run();await activity(env,u,'lead',id,'updated',keys.join(', '));return json({ok:true});}

async function listTasks(env,u){return env.DB.prepare("SELECT * FROM crm_tasks WHERE tenant_id=? ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, due_at IS NULL, due_at, updated_at DESC LIMIT 250").bind(tenant(u)).all();}
async function createTask(env,u,b){const title=String(b.title||'').trim();if(!title)return json({error:'title_required'},400);const id=uid(),ts=now();await env.DB.prepare('INSERT INTO crm_tasks(id,tenant_id,project_id,title,status,priority,due_at,notes,created_at,updated_at,contact_id,lead_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,tenant(u),b.project_id||'',title,b.status||'open',b.priority||'normal',b.due_at||null,b.notes||'',ts,ts,b.contact_id||null,b.lead_id||null).run();await activity(env,u,'task',id,'created',title);return json({ok:true,id},201);}
async function updateTask(env,u,id,b){const allowed=['project_id','title','status','priority','due_at','notes','contact_id','lead_id'];const keys=allowed.filter(k=>Object.prototype.hasOwnProperty.call(b,k));if(!keys.length)return json({error:'nothing_to_update'},400);await env.DB.prepare(`UPDATE crm_tasks SET ${keys.map(k=>k+'=?').join(',')},updated_at=? WHERE id=? AND tenant_id=?`).bind(...keys.map(k=>b[k]),now(),id,tenant(u)).run();await activity(env,u,'task',id,'updated',keys.join(', '));return json({ok:true});}

async function dashboard(env,u){const t=tenant(u),today=now();const [contacts,newLeads,actionLeads,overdue,pipeline,recent]=await Promise.all([
  env.DB.prepare('SELECT COUNT(*) AS n FROM crm_contacts WHERE tenant_id=?').bind(t).first(),
  env.DB.prepare("SELECT COUNT(*) AS n FROM crm_leads WHERE tenant_id=? AND status='NEW'").bind(t).first(),
  env.DB.prepare("SELECT COUNT(*) AS n FROM crm_leads WHERE tenant_id=? AND status NOT IN ('WON','LOST') AND (next_action<>'' OR follow_up_at IS NOT NULL)").bind(t).first(),
  env.DB.prepare("SELECT COUNT(*) AS n FROM crm_tasks WHERE tenant_id=? AND status='open' AND due_at IS NOT NULL AND due_at<?").bind(t,today).first(),
  env.DB.prepare('SELECT status,COUNT(*) AS count,COALESCE(SUM(value),0) AS value FROM crm_leads WHERE tenant_id=? GROUP BY status').bind(t).all(),
  env.DB.prepare('SELECT * FROM crm_activity WHERE tenant_id=? ORDER BY created_at DESC LIMIT 20').bind(t).all()
]);return {ok:true,total_contacts:Number(contacts?.n||0),new_leads:Number(newLeads?.n||0),leads_requiring_action:Number(actionLeads?.n||0),overdue_tasks:Number(overdue?.n||0),pipeline:PIPELINE.map(status=>{const x=(pipeline.results||[]).find(r=>r.status===status);return{status,count:Number(x?.count||0),value:Number(x?.value||0)}}),recent_activity:recent.results||[]};}

export async function handleOperationalCRM(request,env){if(!env.DB)return null;const url=new URL(request.url);if(!url.pathname.startsWith('/api/crm/'))return null;const parts=url.pathname.split('/').filter(Boolean),type=parts[2],id=parts[3];const handled=['dashboard','contacts','leads','tasks','activity','pipeline'];if(!handled.includes(type))return null;const u=await authenticatedUser(request,env);if(!u)return json({error:'unauthorized'},401);await ensureSchema(env);
  if(type==='dashboard'&&request.method==='GET')return json(await dashboard(env,u));
  if(type==='pipeline'&&request.method==='GET')return json({ok:true,statuses:PIPELINE});
  if(type==='activity'&&request.method==='GET'){const r=await env.DB.prepare('SELECT * FROM crm_activity WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(tenant(u)).all();return json({ok:true,items:r.results||[]});}
  if(type==='contacts'){if(request.method==='GET'){const r=await listContacts(env,u,url);return json({ok:true,items:r.results||[]});}if(request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return createContact(env,u,b);}if(request.method==='PATCH'&&id){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return updateContact(env,u,id,b);}}
  if(type==='leads'){if(request.method==='GET'){const r=await listLeads(env,u,url);return json({ok:true,items:r.results||[]});}if(request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return createLead(env,u,b);}if(request.method==='PATCH'&&id){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return updateLead(env,u,id,b);}}
  if(type==='tasks'){if(request.method==='GET'){const r=await listTasks(env,u);return json({ok:true,items:r.results||[]});}if(request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return createTask(env,u,b);}if(request.method==='PATCH'&&id){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)}return updateTask(env,u,id,b);}}
  return json({error:'not_found'},404);
}
