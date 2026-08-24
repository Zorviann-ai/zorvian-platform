const JSON_HEADERS={"content-type":"application/json; charset=UTF-8","cache-control":"no-store"};
const AI_MODEL='@cf/zai-org/glm-4.7-flash';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});
const now=()=>new Date().toISOString();
const uid=()=>crypto.randomUUID();

function cookie(request,name){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function user(request,env){const sid=cookie(request,'zorvian_session');if(!sid||!env.DB)return null;return env.DB.prepare(`SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`).bind(sid,now()).first();}
const tenant=u=>u.tenant_id||'zorvian';

async function schema(env){await env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_social_content(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT,
  platform TEXT NOT NULL,
  format TEXT NOT NULL,
  objective TEXT,
  audience TEXT,
  brief TEXT,
  caption TEXT,
  hashtags TEXT,
  script TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  video_provider TEXT,
  video_job_id TEXT,
  video_url TEXT,
  provider_status TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)`).run();}

function extractText(result){const c=result?.choices?.[0];return String(result?.response||result?.result?.response||result?.output_text||result?.result?.output_text||result?.text||result?.result?.text||c?.message?.content||c?.text||'').trim();}
function parseAI(text){let s=String(text||'').trim();s=s.replace(/^```(?:json)?\s*/i,'').replace(/```$/,'').trim();try{return JSON.parse(s)}catch{return {caption:s,hashtags:'',script:s};}}

async function generateAI(env,b){if(!env.AI)throw new Error('ai_unavailable');const prompt=`You are Zorvian Social & Video Studio. Create production-ready social media content from the supplied confirmed brief. Return ONLY valid JSON with exactly these string keys: caption, hashtags, script.\n\nPlatform: ${b.platform}\nFormat: ${b.format}\nObjective: ${b.objective||''}\nAudience: ${b.audience||''}\nBrief: ${b.brief||''}\n\nRules:\n- caption: platform-appropriate finished copy with a clear CTA when suitable.\n- hashtags: a concise space-separated set; do not invent branded claims.\n- script: spoken/visual script suitable for the requested format. For short-form video, make the opening hook immediate and keep pacing tight.\n- Use only facts provided in the brief. Do not invent prices, testimonials, statistics, accreditations or guarantees.\n- For child or education audiences, keep the tone age-appropriate and avoid manipulative pressure.`;
const result=await env.AI.run(AI_MODEL,{messages:[{role:'system',content:'Return valid JSON only. No markdown fences.'},{role:'user',content:prompt}],max_tokens:1800,temperature:0.45});return parseAI(extractText(result));}

async function activity(env,u,id,action,detail){try{await env.DB.prepare('INSERT INTO crm_activity(id,tenant_id,entity_type,entity_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)').bind(uid(),tenant(u),'social',id,action,detail||'',now()).run();}catch{}}

async function list(env,u){const r=await env.DB.prepare('SELECT * FROM crm_social_content WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 100').bind(tenant(u)).all();return r.results||[];}
async function one(env,u,id){return env.DB.prepare('SELECT * FROM crm_social_content WHERE id=? AND tenant_id=?').bind(id,tenant(u)).first();}

async function createDraft(env,u,b){const generated=await generateAI(env,b);const id=uid(),ts=now();await env.DB.prepare(`INSERT INTO crm_social_content(id,tenant_id,project_id,platform,format,objective,audience,brief,caption,hashtags,script,status,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,tenant(u),b.project_id||'',b.platform,b.format,b.objective||'',b.audience||'',b.brief||'',generated.caption||'',generated.hashtags||'',generated.script||'','draft',ts,ts).run();await activity(env,u,id,'generated',`${b.platform} ${b.format}`);return{id,...generated,status:'draft'};}

async function patch(env,u,id,b){const allowed=['caption','hashtags','script','status','platform','format','objective','audience','brief','project_id'];const keys=allowed.filter(k=>Object.prototype.hasOwnProperty.call(b,k));if(!keys.length)return false;const sql=`UPDATE crm_social_content SET ${keys.map(k=>k+'=?').join(',')},updated_at=? WHERE id=? AND tenant_id=?`;await env.DB.prepare(sql).bind(...keys.map(k=>b[k]),now(),id,tenant(u)).run();await activity(env,u,id,'updated',keys.join(', '));return true;}

function heygenReady(env){return Boolean(env.HEYGEN_API_KEY&&env.HEYGEN_AVATAR_ID&&env.HEYGEN_VOICE_ID);}
async function renderHeyGen(env,u,item){if(!heygenReady(env))return {error:'heygen_not_configured',status:503,needs:['HEYGEN_API_KEY','HEYGEN_AVATAR_ID','HEYGEN_VOICE_ID']};if(!item.script?.trim())return {error:'video_script_required',status:400};const vertical=/tiktok|instagram|reel|short/i.test(`${item.platform} ${item.format}`);const payload={video_inputs:[{character:{type:'avatar',avatar_id:env.HEYGEN_AVATAR_ID,avatar_style:'normal'},voice:{type:'text',input_text:item.script,voice_id:env.HEYGEN_VOICE_ID}}],dimension:vertical?{width:720,height:1280}:{width:1280,height:720}};const r=await fetch('https://api.heygen.com/v2/video/generate',{method:'POST',headers:{'X-Api-Key':env.HEYGEN_API_KEY,'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(payload)});let d={};try{d=await r.json()}catch{}if(!r.ok)return {error:'heygen_request_failed',status:502,detail:d};const videoId=d?.data?.video_id||d?.video_id;if(!videoId)return {error:'heygen_video_id_missing',status:502,detail:d};await env.DB.prepare(`UPDATE crm_social_content SET video_provider='heygen',video_job_id=?,provider_status='processing',status='rendering',updated_at=? WHERE id=? AND tenant_id=?`).bind(videoId,now(),item.id,tenant(u)).run();await activity(env,u,item.id,'video_render_started',videoId);return {ok:true,video_id:videoId,status:'rendering'};}

async function refreshHeyGen(env,u,item){if(!env.HEYGEN_API_KEY)return {error:'heygen_not_configured',status:503};if(!item.video_job_id)return {error:'video_job_missing',status:400};const url='https://api.heygen.com/v1/video_status.get?video_id='+encodeURIComponent(item.video_job_id);const r=await fetch(url,{headers:{'X-Api-Key':env.HEYGEN_API_KEY,'Accept':'application/json'}});let d={};try{d=await r.json()}catch{}if(!r.ok)return {error:'heygen_status_failed',status:502,detail:d};const data=d?.data||d;const providerStatus=String(data?.status||'unknown');const videoUrl=data?.video_url||data?.url||'';const mapped=providerStatus==='completed'?'ready':providerStatus==='failed'?'failed':'rendering';await env.DB.prepare('UPDATE crm_social_content SET provider_status=?,video_url=?,status=?,updated_at=? WHERE id=? AND tenant_id=?').bind(providerStatus,videoUrl,mapped,now(),item.id,tenant(u)).run();if(mapped==='ready')await activity(env,u,item.id,'video_ready',item.video_job_id);return {ok:true,status:mapped,provider_status:providerStatus,video_url:videoUrl};}

export async function handleSocial(request,env){if(!env.DB)return json({error:'database_unavailable'},503);const u=await user(request,env);if(!u)return json({error:'unauthorized'},401);await schema(env);const url=new URL(request.url);const p=url.pathname.split('/').filter(Boolean);if(p[0]!=='api'||p[1]!=='social')return json({error:'not_found'},404);

if(p[2]==='status'&&request.method==='GET')return json({ok:true,ai_configured:Boolean(env.AI),heygen_configured:heygenReady(env),provider:'heygen',required_video_secrets:['HEYGEN_API_KEY','HEYGEN_AVATAR_ID','HEYGEN_VOICE_ID']});
if(p[2]==='items'&&!p[3]&&request.method==='GET')return json({ok:true,items:await list(env,u)});
if(p[2]==='generate'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};b.platform=String(b.platform||'').trim();b.format=String(b.format||'').trim();b.brief=String(b.brief||'').trim();if(!b.platform||!b.format||!b.brief)return json({error:'platform_format_brief_required'},400);try{return json({ok:true,...await createDraft(env,u,b)},201)}catch(e){return json({error:e?.message||'generation_failed'},502)}}
if(p[2]==='items'&&p[3]&&request.method==='PATCH'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};return (await patch(env,u,p[3],b))?json({ok:true}):json({error:'nothing_to_update'},400);}
if(p[2]==='items'&&p[3]&&p[4]==='render'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await renderHeyGen(env,u,item);return r.error?json(r,r.status||500):json(r);}
if(p[2]==='items'&&p[3]&&p[4]==='refresh'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await refreshHeyGen(env,u,item);return r.error?json(r,r.status||500):json(r);}
return json({error:'not_found'},404);}
