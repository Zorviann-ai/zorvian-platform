const JSON_HEADERS={"content-type":"application/json; charset=UTF-8","cache-control":"no-store"};
const AI_MODEL='@cf/zai-org/glm-4.7-flash';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});
const now=()=>new Date().toISOString();
const uid=()=>crypto.randomUUID();
const CHANNELS={
instagram:{name:'Instagram',credential:'META_SOCIAL_CONFIGURED',formats:[{key:'reel',label:'Reel',width:1080,height:1920,ratio:'9:16',container:'mp4',video:'H.264',audio:'AAC'},{key:'feed-portrait',label:'Feed portrait',width:1080,height:1350,ratio:'4:5',container:'mp4',video:'H.264',audio:'AAC'},{key:'square',label:'Square',width:1080,height:1080,ratio:'1:1',container:'mp4',video:'H.264',audio:'AAC'}]},
facebook:{name:'Facebook',credential:'META_SOCIAL_CONFIGURED',formats:[{key:'reel',label:'Reel',width:1080,height:1920,ratio:'9:16',container:'mp4',video:'H.264',audio:'AAC'},{key:'feed',label:'Feed',width:1080,height:1350,ratio:'4:5',container:'mp4',video:'H.264',audio:'AAC'}]},
linkedin:{name:'LinkedIn',credential:'LINKEDIN_SOCIAL_CONFIGURED',formats:[{key:'landscape',label:'Landscape',width:1920,height:1080,ratio:'16:9',container:'mp4',video:'H.264',audio:'AAC'},{key:'portrait',label:'Portrait',width:1080,height:1350,ratio:'4:5',container:'mp4',video:'H.264',audio:'AAC'}]},
tiktok:{name:'TikTok',credential:'TIKTOK_SOCIAL_CONFIGURED',formats:[{key:'vertical',label:'Vertical video',width:1080,height:1920,ratio:'9:16',container:'mp4',video:'H.264',audio:'AAC'}]},
youtube:{name:'YouTube',credential:'YOUTUBE_SOCIAL_CONFIGURED',formats:[{key:'short',label:'Short',width:1080,height:1920,ratio:'9:16',container:'mp4',video:'H.264',audio:'AAC'},{key:'video',label:'Video',width:1920,height:1080,ratio:'16:9',container:'mp4',video:'H.264',audio:'AAC'}]},
x:{name:'X',credential:'X_SOCIAL_CONFIGURED',formats:[{key:'landscape',label:'Landscape',width:1920,height:1080,ratio:'16:9',container:'mp4',video:'H.264',audio:'AAC'},{key:'square',label:'Square',width:1080,height:1080,ratio:'1:1',container:'mp4',video:'H.264',audio:'AAC'}]}
};
const channels=env=>Object.entries(CHANNELS).map(([key,value])=>({key,name:value.name,connected:String(env[value.credential]||'').toLowerCase()==='true',formats:value.formats}));

function cookie(request,name){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function user(request,env){const sid=cookie(request,'zorvian_session');if(!sid||!env.DB)return null;return env.DB.prepare(`SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`).bind(sid,now()).first();}
const tenant=u=>u.tenant_id||'zorvian';

async function schema(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS crm_social_content(
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
    voice_provider TEXT,
    voice_job_id TEXT,
    voice_url TEXT,
    voice_status TEXT,
    voice_model TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`).run();
  const info=await env.DB.prepare('PRAGMA table_info(crm_social_content)').all();
  const names=new Set((info.results||[]).map(x=>x.name));
  const additions=[
    ['voice_provider','TEXT'],['voice_job_id','TEXT'],['voice_url','TEXT'],['voice_status','TEXT'],['voice_model','TEXT']
  ];
  for(const [name,type] of additions){if(!names.has(name)){try{await env.DB.prepare(`ALTER TABLE crm_social_content ADD COLUMN ${name} ${type}`).run();}catch{}}}
  for(const [name,type] of [['approved_by','TEXT'],['approved_at','TEXT'],['scheduled_for','TEXT'],['published_at','TEXT'],['publish_reference','TEXT']]){if(!names.has(name)){try{await env.DB.prepare(`ALTER TABLE crm_social_content ADD COLUMN ${name} ${type}`).run();}catch{}}}
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS social_campaigns(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,objective TEXT,audience TEXT,start_at TEXT,end_at TEXT,status TEXT NOT NULL DEFAULT 'draft',created_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS social_schedule(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,content_id TEXT NOT NULL,platform TEXT NOT NULL,scheduled_for TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'scheduled',approved_by TEXT NOT NULL,approved_at TEXT NOT NULL,publish_reference TEXT,error TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS social_analytics(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,content_id TEXT,platform TEXT NOT NULL,posted_at TEXT NOT NULL,impressions INTEGER NOT NULL DEFAULT 0,views INTEGER NOT NULL DEFAULT 0,engagements INTEGER NOT NULL DEFAULT 0,clicks INTEGER NOT NULL DEFAULT 0,watch_seconds REAL NOT NULL DEFAULT 0,source TEXT NOT NULL DEFAULT 'manual',created_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS social_approvals(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,content_id TEXT NOT NULL,decision TEXT NOT NULL,decided_by TEXT NOT NULL,note TEXT,created_at TEXT NOT NULL)`)
  ]);
}

function extractText(result){const c=result?.choices?.[0];return String(result?.response||result?.result?.response||result?.output_text||result?.result?.output_text||result?.text||result?.result?.text||c?.message?.content||c?.text||'').trim();}
function parseAI(text){let s=String(text||'').trim();s=s.replace(/^```(?:json)?\s*/i,'').replace(/```$/,'').trim();try{return JSON.parse(s)}catch{return {caption:s,hashtags:'',script:s};}}

async function generateAI(env,b){if(!env.AI)throw new Error('ai_unavailable');const prompt=`You are Caelomere Social & Video Studio. Create production-ready social media content from the supplied confirmed brief. Return ONLY valid JSON with exactly these string keys: caption, hashtags, script.\n\nPlatform: ${b.platform}\nFormat: ${b.format}\nObjective: ${b.objective||''}\nAudience: ${b.audience||''}\nBrief: ${b.brief||''}\n\nRules:\n- caption: platform-appropriate finished copy with a clear CTA when suitable.\n- hashtags: a concise space-separated set; do not invent branded claims.\n- script: spoken/visual script suitable for the requested format. For short-form video, make the opening hook immediate and keep pacing tight.\n- Use only facts provided in the brief. Do not invent prices, testimonials, statistics, accreditations or guarantees.\n- For child or education audiences, keep the tone age-appropriate and avoid manipulative pressure.`;
  const result=await env.AI.run(AI_MODEL,{messages:[{role:'system',content:'Return valid JSON only. No markdown fences.'},{role:'user',content:prompt}],max_tokens:1800,temperature:0.45});return parseAI(extractText(result));}

async function activity(env,u,id,action,detail){try{await env.DB.prepare('INSERT INTO crm_activity(id,tenant_id,entity_type,entity_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)').bind(uid(),tenant(u),'social',id,action,detail||'',now()).run();}catch{}}

async function list(env,u){const r=await env.DB.prepare('SELECT * FROM crm_social_content WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 100').bind(tenant(u)).all();return r.results||[];}
async function one(env,u,id){return env.DB.prepare('SELECT * FROM crm_social_content WHERE id=? AND tenant_id=?').bind(id,tenant(u)).first();}

async function createDraft(env,u,b){const generated=await generateAI(env,b);const id=uid(),ts=now();await env.DB.prepare(`INSERT INTO crm_social_content(id,tenant_id,project_id,platform,format,objective,audience,brief,caption,hashtags,script,status,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,tenant(u),b.project_id||'',b.platform,b.format,b.objective||'',b.audience||'',b.brief||'',generated.caption||'',generated.hashtags||'',generated.script||'','draft',ts,ts).run();await activity(env,u,id,'generated',`${b.platform} ${b.format}`);return{id,...generated,status:'draft'};}

async function patch(env,u,id,b){const allowed=['caption','hashtags','script','status','platform','format','objective','audience','brief','project_id'];const keys=allowed.filter(k=>Object.prototype.hasOwnProperty.call(b,k));if(!keys.length)return false;const sql=`UPDATE crm_social_content SET ${keys.map(k=>k+'=?').join(',')},updated_at=? WHERE id=? AND tenant_id=?`;await env.DB.prepare(sql).bind(...keys.map(k=>b[k]),now(),id,tenant(u)).run();await activity(env,u,id,'updated',keys.join(', '));return true;}

function elevenReady(env){return Boolean(env.ELEVENLABS_API_KEY&&env.ELEVENLABS_VOICE_ID);}
function elevenModel(env){return env.ELEVENLABS_MODEL_ID||'eleven_multilingual_v2';}
function elevenOutputUrl(d){return String(d?.output_url||d?.audio_url||d?.url||d?.output?.url||d?.output?.audio_url||d?.data?.url||d?.data?.audio_url||d?.result?.url||d?.result?.audio_url||'');}

async function startEleven(env,u,item){
  if(!elevenReady(env))return {error:'elevenlabs_not_configured',status:503,needs:['ELEVENLABS_API_KEY','ELEVENLABS_VOICE_ID']};
  if(!item.script?.trim())return {error:'video_script_required',status:400};
  const model=elevenModel(env);
  const r=await fetch('https://api.elevenlabs.io/v1/flows/text-to-speech',{method:'POST',headers:{'xi-api-key':env.ELEVENLABS_API_KEY,'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({model_id:model,text:item.script,voice:env.ELEVENLABS_VOICE_ID})});
  let d={};try{d=await r.json()}catch{}
  if(!r.ok)return {error:'elevenlabs_request_failed',status:502,detail:d};
  const generationId=d?.id||d?.generation_id;
  if(!generationId)return {error:'elevenlabs_generation_id_missing',status:502,detail:d};
  await env.DB.prepare(`UPDATE crm_social_content SET voice_provider='elevenlabs',voice_job_id=?,voice_status=?,voice_model=?,voice_url='',updated_at=? WHERE id=? AND tenant_id=?`).bind(generationId,String(d?.status||'pending'),model,now(),item.id,tenant(u)).run();
  await activity(env,u,item.id,'voice_generation_started',generationId);
  return {ok:true,voice_job_id:generationId,voice_status:String(d?.status||'pending')};
}

async function refreshEleven(env,u,item){
  if(!env.ELEVENLABS_API_KEY)return {error:'elevenlabs_not_configured',status:503};
  if(!item.voice_job_id)return {error:'voice_job_missing',status:400};
  const r=await fetch('https://api.elevenlabs.io/v1/flows/text-to-speech/'+encodeURIComponent(item.voice_job_id),{headers:{'xi-api-key':env.ELEVENLABS_API_KEY,'Accept':'application/json'}});
  let d={};try{d=await r.json()}catch{}
  if(!r.ok)return {error:'elevenlabs_status_failed',status:502,detail:d};
  const providerStatus=String(d?.status||'unknown');
  const voiceUrl=elevenOutputUrl(d);
  const mapped=providerStatus==='completed'?'ready':providerStatus==='failed'?'failed':'processing';
  await env.DB.prepare('UPDATE crm_social_content SET voice_status=?,voice_url=?,updated_at=? WHERE id=? AND tenant_id=?').bind(mapped,voiceUrl,now(),item.id,tenant(u)).run();
  if(mapped==='ready')await activity(env,u,item.id,'voice_ready',item.voice_job_id);
  return {ok:true,status:mapped,provider_status:providerStatus,voice_url:voiceUrl};
}

function heygenReady(env){return Boolean(env.HEYGEN_API_KEY&&env.HEYGEN_AVATAR_ID&&(env.HEYGEN_VOICE_ID||elevenReady(env)));}
async function renderHeyGen(env,u,item){
  if(!env.HEYGEN_API_KEY||!env.HEYGEN_AVATAR_ID)return {error:'heygen_not_configured',status:503,needs:['HEYGEN_API_KEY','HEYGEN_AVATAR_ID']};
  if(!item.script?.trim())return {error:'video_script_required',status:400};
  if(elevenReady(env)&&!item.voice_url)return {error:'elevenlabs_voice_required',status:409,message:'Generate and refresh the ElevenLabs voiceover before rendering the video.'};
  if(!item.voice_url&&!env.HEYGEN_VOICE_ID)return {error:'heygen_voice_not_configured',status:503,needs:['HEYGEN_VOICE_ID']};
  const vertical=/tiktok|instagram|reel|short/i.test(`${item.platform} ${item.format}`);
  const voice=item.voice_url?{type:'audio',audio_url:item.voice_url}:{type:'text',input_text:item.script,voice_id:env.HEYGEN_VOICE_ID};
  const payload={video_inputs:[{character:{type:'avatar',avatar_id:env.HEYGEN_AVATAR_ID,avatar_style:'normal'},voice}],dimension:vertical?{width:720,height:1280}:{width:1280,height:720}};
  const r=await fetch('https://api.heygen.com/v2/video/generate',{method:'POST',headers:{'X-Api-Key':env.HEYGEN_API_KEY,'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(payload)});
  let d={};try{d=await r.json()}catch{}
  if(!r.ok)return {error:'heygen_request_failed',status:502,detail:d};
  const videoId=d?.data?.video_id||d?.video_id;
  if(!videoId)return {error:'heygen_video_id_missing',status:502,detail:d};
  await env.DB.prepare(`UPDATE crm_social_content SET video_provider='heygen',video_job_id=?,provider_status='processing',status='rendering',updated_at=? WHERE id=? AND tenant_id=?`).bind(videoId,now(),item.id,tenant(u)).run();
  await activity(env,u,item.id,'video_render_started',videoId);
  return {ok:true,video_id:videoId,status:'rendering',voice_provider:item.voice_url?'elevenlabs':'heygen'};
}

async function refreshHeyGen(env,u,item){if(!env.HEYGEN_API_KEY)return {error:'heygen_not_configured',status:503};if(!item.video_job_id)return {error:'video_job_missing',status:400};const url='https://api.heygen.com/v1/video_status.get?video_id='+encodeURIComponent(item.video_job_id);const r=await fetch(url,{headers:{'X-Api-Key':env.HEYGEN_API_KEY,'Accept':'application/json'}});let d={};try{d=await r.json()}catch{}if(!r.ok)return {error:'heygen_status_failed',status:502,detail:d};const data=d?.data||d;const providerStatus=String(data?.status||'unknown');const videoUrl=data?.video_url||data?.url||'';const mapped=providerStatus==='completed'?'ready':providerStatus==='failed'?'failed':'rendering';await env.DB.prepare('UPDATE crm_social_content SET provider_status=?,video_url=?,status=?,updated_at=? WHERE id=? AND tenant_id=?').bind(providerStatus,videoUrl,mapped,now(),item.id,tenant(u)).run();if(mapped==='ready')await activity(env,u,item.id,'video_ready',item.video_job_id);return {ok:true,status:mapped,provider_status:providerStatus,video_url:videoUrl};}

function renditionPlan(platforms){const chosen=(platforms||[]).filter(x=>CHANNELS[x]);return chosen.flatMap(platform=>CHANNELS[platform].formats.map(format=>({platform,channel:CHANNELS[platform].name,...format,safe_area:{top_percent:10,bottom_percent:18,side_percent:8},captions:'burned-in and sidecar',audio_normalisation:true,thumbnail_required:['youtube','facebook','linkedin'].includes(platform)})));}
async function approve(env,u,id,b){const item=await one(env,u,id);if(!item)return json({error:'not_found'},404);if(b.confirm!==true)return json({error:'human_confirmation_required'},400);const ts=now(),decision=b.decision==='rejected'?'rejected':'approved';await env.DB.batch([env.DB.prepare('UPDATE crm_social_content SET status=?,approved_by=?,approved_at=?,updated_at=? WHERE id=? AND tenant_id=?').bind(decision,u.id,ts,ts,id,tenant(u)),env.DB.prepare('INSERT INTO social_approvals(id,tenant_id,content_id,decision,decided_by,note,created_at) VALUES(?,?,?,?,?,?,?)').bind(uid(),tenant(u),id,decision,u.id,String(b.note||''),ts)]);await activity(env,u,id,decision,String(b.note||''));return json({ok:true,status:decision,approved_by:u.id,approved_at:ts});}
async function scheduleItem(env,u,id,b){const item=await one(env,u,id);if(!item)return json({error:'not_found'},404);if(item.status!=='approved'||!item.approved_at)return json({error:'human_approval_required'},409);const when=String(b.scheduled_for||'');if(!when||Number.isNaN(Date.parse(when))||Date.parse(when)<=Date.now())return json({error:'future_schedule_required'},400);const platform=String(b.platform||item.platform||'').toLowerCase();if(!CHANNELS[platform])return json({error:'supported_platform_required'},400);const sid=uid(),ts=now();await env.DB.batch([env.DB.prepare('INSERT INTO social_schedule(id,tenant_id,content_id,platform,scheduled_for,status,approved_by,approved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(sid,tenant(u),id,platform,new Date(when).toISOString(),'scheduled',item.approved_by,item.approved_at,ts,ts),env.DB.prepare("UPDATE crm_social_content SET status='scheduled',scheduled_for=?,updated_at=? WHERE id=? AND tenant_id=?").bind(new Date(when).toISOString(),ts,id,tenant(u))]);await activity(env,u,id,'scheduled',new Date(when).toISOString());return json({ok:true,schedule_id:sid,status:'scheduled',scheduled_for:new Date(when).toISOString(),publishing_automatic:false,message:'Approved schedule saved. Direct publishing starts only when the channel connection is active.'});}
async function schedules(env,u){const r=await env.DB.prepare('SELECT s.*,c.caption,c.format FROM social_schedule s LEFT JOIN crm_social_content c ON c.id=s.content_id WHERE s.tenant_id=? ORDER BY s.scheduled_for').bind(tenant(u)).all();return r.results||[];}
async function addAnalytics(env,u,b){const platform=String(b.platform||'').toLowerCase();if(!CHANNELS[platform])return json({error:'supported_platform_required'},400);const posted=String(b.posted_at||'');if(!posted||Number.isNaN(Date.parse(posted)))return json({error:'valid_posted_at_required'},400);const n=k=>Math.max(0,Number(b[k]||0));const id=uid();await env.DB.prepare('INSERT INTO social_analytics(id,tenant_id,content_id,platform,posted_at,impressions,views,engagements,clicks,watch_seconds,source,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,tenant(u),String(b.content_id||''),platform,new Date(posted).toISOString(),n('impressions'),n('views'),n('engagements'),n('clicks'),n('watch_seconds'),String(b.source||'manual'),now()).run();return json({ok:true,id},201);}
async function analyticsSummary(env,u){const r=await env.DB.prepare('SELECT * FROM social_analytics WHERE tenant_id=? ORDER BY posted_at DESC LIMIT 1000').bind(tenant(u)).all(),items=r.results||[],buckets=new Map();for(const x of items){const d=new Date(x.posted_at),key=d.getUTCDay()+':'+d.getUTCHours(),score=Number(x.engagements)*3+Number(x.clicks)*4+Number(x.views)*.1+Number(x.watch_seconds)*.01,prior=buckets.get(key)||{samples:0,score:0};prior.samples++;prior.score+=score;buckets.set(key,prior);}const best=[...buckets.entries()].filter(([,v])=>v.samples>=2).sort((a,b)=>(b[1].score/b[1].samples)-(a[1].score/a[1].samples)).slice(0,5).map(([key,v])=>{const [day,hour]=key.split(':').map(Number);return{day:['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][day],hour_utc:hour,samples:v.samples,average_score:Number((v.score/v.samples).toFixed(2))};});const totals=items.reduce((a,x)=>{for(const k of ['impressions','views','engagements','clicks','watch_seconds'])a[k]+=Number(x[k]||0);return a;},{impressions:0,views:0,engagements:0,clicks:0,watch_seconds:0});return{ok:true,sample_count:items.length,totals,best_times:best,recommendation_status:best.length?'evidence_available':'insufficient_data',method:'Best times require at least two measured posts in the same UTC weekday/hour. Score weights engagements, clicks, views and watch time.'};}

export async function handleSocial(request,env){if(!env.DB)return json({error:'database_unavailable'},503);const u=await user(request,env);if(!u)return json({error:'unauthorized'},401);await schema(env);const url=new URL(request.url);const p=url.pathname.split('/').filter(Boolean);if(p[0]!=='api'||p[1]!=='social')return json({error:'not_found'},404);

if(p[2]==='channels'&&request.method==='GET')return json({ok:true,channels:channels(env),account_connections_visible:true,direct_publish_requires_official_credentials:true});
if(p[2]==='renditions'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};const plan=renditionPlan(Array.isArray(b.platforms)?b.platforms:[]);return plan.length?json({ok:true,master:{recommended_width:1920,recommended_height:1080,mezzanine:'high-quality landscape master'},renditions:plan}):json({error:'platforms_required'},400);}
if(p[2]==='schedules'&&request.method==='GET')return json({ok:true,items:await schedules(env,u)});
if(p[2]==='analytics'&&request.method==='GET')return json(await analyticsSummary(env,u));
if(p[2]==='analytics'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};return addAnalytics(env,u,b);}
if(p[2]==='items'&&p[3]&&p[4]==='approval'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};return approve(env,u,p[3],b);}
if(p[2]==='items'&&p[3]&&p[4]==='schedule'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};return scheduleItem(env,u,p[3],b);}
if(p[2]==='status'&&request.method==='GET')return json({ok:true,ai_configured:Boolean(env.AI),heygen_configured:heygenReady(env),heygen_voice_configured:Boolean(env.HEYGEN_VOICE_ID),elevenlabs_configured:elevenReady(env),voice_provider:elevenReady(env)?'elevenlabs':env.HEYGEN_VOICE_ID?'heygen':'none',required_elevenlabs_secrets:['ELEVENLABS_API_KEY','ELEVENLABS_VOICE_ID'],required_video_secrets:['HEYGEN_API_KEY','HEYGEN_AVATAR_ID']});
if(p[2]==='items'&&!p[3]&&request.method==='GET')return json({ok:true,items:await list(env,u)});
if(p[2]==='generate'&&request.method==='POST'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};b.platform=String(b.platform||'').trim();b.format=String(b.format||'').trim();b.brief=String(b.brief||'').trim();if(!b.platform||!b.format||!b.brief)return json({error:'platform_format_brief_required'},400);try{return json({ok:true,...await createDraft(env,u,b)},201)}catch(e){return json({error:e?.message||'generation_failed'},502)}}
if(p[2]==='items'&&p[3]&&request.method==='PATCH'){let b={};try{b=await request.json()}catch{return json({error:'invalid_json'},400)};return (await patch(env,u,p[3],b))?json({ok:true}):json({error:'nothing_to_update'},400);}
if(p[2]==='items'&&p[3]&&p[4]==='voice'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await startEleven(env,u,item);return r.error?json(r,r.status||500):json(r);}
if(p[2]==='items'&&p[3]&&p[4]==='voice-refresh'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await refreshEleven(env,u,item);return r.error?json(r,r.status||500):json(r);}
if(p[2]==='items'&&p[3]&&p[4]==='render'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await renderHeyGen(env,u,item);return r.error?json(r,r.status||500):json(r);}
if(p[2]==='items'&&p[3]&&p[4]==='refresh'&&request.method==='POST'){const item=await one(env,u,p[3]);if(!item)return json({error:'not_found'},404);const r=await refreshHeyGen(env,u,item);return r.error?json(r,r.status||500):json(r);}
return json({error:'not_found'},404);}
