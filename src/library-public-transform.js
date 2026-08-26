import { generateAI } from './ai-router.js';

const ALLOWED_RIGHTS=new Set(['PUBLIC_DOMAIN_VERIFIED','AUTHOR_PERMISSION_VERIFIED','PUBLISHER_PERMISSION_VERIFIED','LICENSE_VERIFIED']);
const ORIGINS=new Set(['https://caelomerestudio.com','https://www.caelomerestudio.com']);
const H={'content-type':'application/json; charset=UTF-8','cache-control':'no-store'};
const uid=()=>crypto.randomUUID();
const now=()=>new Date().toISOString();
const CAPABILITIES={
  bookclub:{job:'SUMMARY',permission:'create_summary',label:'AI Book Club',instruction:'Create an engaging AI book-club experience with a concise story orientation, 8 discussion questions, 5 themes with explanations, 5 character prompts, and 3 interactive reader activities.'},
  character:{job:'SUMMARY',permission:'create_summary',label:'Character Exploration',instruction:'Create a character exploration. Identify the major characters, their role, motivations, conflicts, relationships, arc, visual direction and 3 reader questions for each major character.'},
  scene:{job:'SCENE_PLAN',permission:'create_video',label:'Scene Visualisation',instruction:'Create a cinematic scene plan for 6 important moments. For each include source basis, setting, action, camera/visual direction, atmosphere, narration idea and sound direction. Do not claim anything was rendered.'},
  trailer:{job:'LONG_VIDEO',permission:'create_video',label:'Cinematic Trailer',instruction:'Create a 60-90 second cinematic trailer treatment with hook, beat-by-beat structure, visual direction, text cards, narration direction, sound direction and closing beat. Do not claim video was rendered.'},
  screenplay:{job:'SUMMARY',permission:'create_summary',label:'Screenplay Development',instruction:'Create a screen-adaptation pathway: logline, central dramatic question, act structure, 8 key sequences, adaptation challenges, what to preserve from the source, and next screenplay-development steps.'},
  audio:{job:'AUDIO_NARRATION',permission:'create_audio',label:'Audio Narration',instruction:'Create an audio adaptation brief: narrator profile, voice direction, pacing, pronunciation/character notes, soundscape approach, chapter/scene audio structure and a short sample narration direction. Do not claim audio was rendered.'}
};
function cors(request){const origin=request.headers.get('Origin')||'';return ORIGINS.has(origin)?{'access-control-allow-origin':origin,'access-control-allow-methods':'POST, GET, OPTIONS','access-control-allow-headers':'content-type','access-control-max-age':'86400','vary':'Origin'}:{};}
function json(request,data,status=200){return new Response(JSON.stringify(data),{status,headers:{...H,...cors(request)}});}
async function ensure(env){await env.DB.batch([
 env.DB.prepare("CREATE TABLE IF NOT EXISTS library_public_outputs(job_id TEXT PRIMARY KEY,book_id TEXT NOT NULL,capability TEXT NOT NULL,output_text TEXT NOT NULL,created_at TEXT NOT NULL)"),
 env.DB.prepare("CREATE TABLE IF NOT EXISTS library_jobs(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,job_type TEXT NOT NULL,status TEXT NOT NULL,source_asset_id TEXT,output_asset_id TEXT,provider TEXT,model TEXT,prompt_version TEXT,cost_minor INTEGER,currency TEXT,error_text TEXT,created_at TEXT NOT NULL,started_at TEXT,completed_at TEXT)"),
 env.DB.prepare("CREATE TABLE IF NOT EXISTS library_publish_requests(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,destination TEXT NOT NULL,monetise INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'PENDING',requested_by TEXT,approved_by TEXT,approved_at TEXT,remote_id TEXT,remote_url TEXT,created_at TEXT NOT NULL)")
]);}
async function bookRecord(env,id){return env.DB.prepare("SELECT b.id,b.title,b.publication_year,b.status,a.name author,e.identifier,e.source_reference,r.rights_status,r.permissions_json FROM library_books b LEFT JOIN library_authors a ON a.id=b.author_id LEFT JOIN library_editions e ON e.book_id=b.id LEFT JOIN library_rights r ON r.book_id=b.id WHERE b.id=? LIMIT 1").bind(id).first();}
function parsePerms(v){try{return JSON.parse(v||'{}');}catch{return {};}}
function gutenbergNumber(identifier,source){const m=String(identifier||'').match(/g?(\d+)/)||String(source||'').match(/ebooks\/(\d+)/);return m?m[1]:null;}
async function sourceText(book){
 const n=gutenbergNumber(book.identifier,book.source_reference);if(!n)throw new Error('source_identifier_missing');
 const urls=[`https://www.gutenberg.org/cache/epub/${n}/pg${n}.txt`,`https://www.gutenberg.org/files/${n}/${n}-8.txt`,`https://www.gutenberg.org/files/${n}/${n}.txt`];
 for(const u of urls){try{const r=await fetch(u,{headers:{'user-agent':'Caelomere-Library/1.0'}});if(r.ok){const t=(await r.text()).trim();if(t.length>1000)return {text:t.slice(0,50000),url:u};}}catch{}}
 throw new Error('source_text_unavailable');
}
function stripCodeFence(s){return String(s||'').replace(/^```(?:json|text)?\s*/i,'').replace(/```$/,'').trim();}
export async function handleLibraryPublicTransform(request,env){
 const url=new URL(request.url),p=url.pathname;
 if(!p.startsWith('/api/library/transform'))return null;
 if(request.method==='OPTIONS'){const origin=request.headers.get('Origin')||'';if(origin&& !ORIGINS.has(origin))return new Response(null,{status:403,headers:H});return new Response(null,{status:204,headers:{...H,...cors(request)}});}
 if(!env.DB)return json(request,{error:'database_unavailable'},503);
 await ensure(env);
 if(p.startsWith('/api/library/transform/jobs/')&&request.method==='GET'){
  const id=p.split('/').pop();const job=await env.DB.prepare('SELECT id,book_id,job_type,status,provider,model,error_text,created_at,started_at,completed_at FROM library_jobs WHERE id=?').bind(id).first();if(!job)return json(request,{error:'not_found'},404);const out=await env.DB.prepare('SELECT capability,output_text FROM library_public_outputs WHERE job_id=?').bind(id).first();return json(request,{ok:true,job,output:out||null});
 }
 if(p==='/api/library/transform/publish-request'&&request.method==='POST'){
  let b={};try{b=await request.json();}catch{return json(request,{error:'invalid_json'},400);}const job=await env.DB.prepare("SELECT j.id,j.book_id,j.status,o.capability FROM library_jobs j JOIN library_public_outputs o ON o.job_id=j.id WHERE j.id=?").bind(String(b.job_id||'')).first();if(!job||job.status!=='COMPLETED')return json(request,{error:'completed_job_required'},400);const book=await bookRecord(env,job.book_id);if(!book||!ALLOWED_RIGHTS.has(book.rights_status))return json(request,{error:'rights_gate_blocked'},403);const perms=parsePerms(book.permissions_json);if(b.monetise===true&&perms.monetise!==true)return json(request,{error:'monetisation_not_permitted'},403);const id=uid();await env.DB.prepare("INSERT INTO library_publish_requests(id,book_id,destination,monetise,status,requested_by,created_at) VALUES(?,?,?,?,?,?,?)").bind(id,book.id,String(b.destination||'Caelomere Library'),b.monetise===true?1:0,'PENDING','studio-public',now()).run();return json(request,{ok:true,id,status:'PENDING',message:'Publish request created. Human approval is required before release.'},201);
 }
 if(p!=='/api/library/transform'||request.method!=='POST')return json(request,{error:'not_found'},404);
 let b={};try{b=await request.json();}catch{return json(request,{error:'invalid_json'},400);}const capability=String(b.capability||'').toLowerCase(),cfg=CAPABILITIES[capability];if(!cfg)return json(request,{error:'invalid_capability',allowed:Object.keys(CAPABILITIES)},400);const book=await bookRecord(env,String(b.book_id||''));if(!book)return json(request,{error:'book_not_found'},404);if(!ALLOWED_RIGHTS.has(book.rights_status))return json(request,{error:'rights_gate_blocked',rights_status:book.rights_status},403);const perms=parsePerms(book.permissions_json);if(perms[cfg.permission]!==true)return json(request,{error:'capability_not_permitted',required_permission:cfg.permission},403);
 const jobId=uid(),ts=now();await env.DB.prepare("INSERT INTO library_jobs(id,book_id,job_type,status,provider,prompt_version,created_at,started_at) VALUES(?,?,?,?,?,?,?,?)").bind(jobId,book.id,cfg.job,'PROCESSING','Caelomere Celestial Core','library-public-v1',ts,ts).run();
 try{
  const src=await sourceText(book);
  const prompt=`You are Caelomere Studio working from a rights-verified source edition.\nTITLE: ${book.title}\nAUTHOR: ${book.author||''}\nRIGHTS STATUS: ${book.rights_status}\nSOURCE PROVENANCE: ${src.url}\n\nTASK: ${cfg.instruction}\n\nRules: use only the supplied source text; distinguish source facts from adaptation proposals; never invent quotations, rights, sales, reviews or biographical facts; keep direct quotations very short; use clear British English; make the result client-ready.\n\nSOURCE TEXT:\n${src.text}`;
  const r=await generateAI(env,{system:'You are the Caelomere Studio transformation engine powered by Caelomere Celestial Core.',input:prompt,maxOutputTokens:3500,temperature:.25});const output=stripCodeFence(r.text);if(!output)throw new Error('empty_ai_result');const done=now();await env.DB.prepare('INSERT OR REPLACE INTO library_public_outputs(job_id,book_id,capability,output_text,created_at) VALUES(?,?,?,?,?)').bind(jobId,book.id,capability,output,done).run();await env.DB.prepare("UPDATE library_jobs SET status='COMPLETED',provider=?,model=?,completed_at=? WHERE id=?").bind(r.provider||'Caelomere Celestial Core',r.model||'',done,jobId).run();return json(request,{ok:true,job_id:jobId,status:'COMPLETED',book:{id:book.id,title:book.title,author:book.author,rights_status:book.rights_status},capability,label:cfg.label,source_provenance:src.url,output,publish_gate:'HUMAN_APPROVAL_REQUIRED'},201);
 }catch(e){await env.DB.prepare("UPDATE library_jobs SET status='FAILED',error_text=?,completed_at=? WHERE id=?").bind(String(e?.message||'transform_failed'),now(),jobId).run();return json(request,{error:'transform_failed',job_id:jobId,detail:String(e?.message||'unknown')},503);}
}
