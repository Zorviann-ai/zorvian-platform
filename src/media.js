const JSON_HEADERS={"content-type":"application/json; charset=UTF-8","cache-control":"no-store"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});
const now=()=>new Date().toISOString();
const uid=()=>crypto.randomUUID();

function cookie(request,name){const h=request.headers.get("Cookie")||"";const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function user(request,env){const sid=cookie(request,"zorvian_session");if(!sid||!env.DB)return null;return env.DB.prepare(`SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`).bind(sid,now()).first();}
const tenant=u=>u.tenant_id||"zorvian";

async function schema(env){
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS media_profiles(
      id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,kind TEXT NOT NULL,
      provider TEXT NOT NULL,provider_id TEXT NOT NULL,description TEXT,status TEXT NOT NULL DEFAULT 'active',
      consent_confirmed INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS media_productions(
      id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,title TEXT NOT NULL,objective TEXT,audience TEXT,
      format TEXT NOT NULL,aspect_ratio TEXT NOT NULL,duration_minutes INTEGER NOT NULL DEFAULT 1,
      brief TEXT NOT NULL,script TEXT,status TEXT NOT NULL DEFAULT 'draft',provider TEXT,
      provider_job_id TEXT,output_url TEXT,error TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS media_scenes(
      id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,production_id TEXT NOT NULL,position INTEGER NOT NULL,
      title TEXT,narration TEXT,visual_prompt TEXT,avatar_profile_id TEXT,voice_profile_id TEXT,
      sound_prompt TEXT,caption TEXT,status TEXT NOT NULL DEFAULT 'planned',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS media_assets(
      id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,production_id TEXT,scene_id TEXT,kind TEXT NOT NULL,
      provider TEXT,provider_job_id TEXT,url TEXT,prompt TEXT,status TEXT NOT NULL DEFAULT 'planned',
      metadata_json TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`)
  ]);
}

function extractText(result){const c=result?.choices?.[0];return String(result?.response||result?.result?.response||result?.output_text||result?.result?.output_text||result?.text||result?.result?.text||c?.message?.content||c?.text||"").trim();}
function parsePlan(text){let value=String(text||"").trim().replace(/^\`\`\`(?:json)?\s*/i,"").replace(/\`\`\`$/,"").trim();try{return JSON.parse(value)}catch{return null;}}
function providerStatus(env){return{
  ai:Boolean(env.AI),
  heygen:Boolean(env.HEYGEN_API_KEY&&env.HEYGEN_AVATAR_ID),
  heygen_voice:Boolean(env.HEYGEN_VOICE_ID),
  elevenlabs:Boolean(env.ELEVENLABS_API_KEY&&env.ELEVENLABS_VOICE_ID),
  image_provider:Boolean(env.AI),
  long_video:Boolean(env.HEYGEN_API_KEY&&env.HEYGEN_AVATAR_ID&&(env.HEYGEN_VOICE_ID||env.ELEVENLABS_VOICE_ID)),
  required:["AI","HEYGEN_API_KEY","HEYGEN_AVATAR_ID","HEYGEN_VOICE_ID","ELEVENLABS_API_KEY","ELEVENLABS_VOICE_ID"]
};}

async function planProduction(env,b){
  if(!env.AI)throw new Error("ai_unavailable");
  const duration=Math.min(Math.max(Number(b.duration_minutes||1),1),60);
  const sceneCount=Math.min(Math.max(Math.ceil(duration*2),1),60);
  const prompt=`Create a production-ready social video plan using only confirmed facts. Return ONLY valid JSON:
{"script":"complete narration","scenes":[{"title":"scene title","narration":"spoken words","visual_prompt":"specific visual direction","sound_prompt":"music or sound design direction","caption":"on-screen caption"}]}
Title: ${b.title}
Objective: ${b.objective||""}
Audience: ${b.audience||""}
Format: ${b.format}
Aspect ratio: ${b.aspect_ratio}
Target duration: ${duration} minutes
Target scenes: ${sceneCount}
Brief: ${b.brief}
Rules: provide exactly ${sceneCount} scenes; do not invent prices, claims, testimonials, statistics, accreditations or rights; do not imitate a real person's voice or likeness without confirmed consent; keep captions concise; include opening hook, structured middle and clear ending.`;
  const result=await env.AI.run("@cf/zai-org/glm-4.7-flash",{messages:[{role:"system",content:"Return valid JSON only. No markdown."},{role:"user",content:prompt}],max_tokens:7000,temperature:.35});
  const plan=parsePlan(extractText(result));
  if(!plan||!Array.isArray(plan.scenes)||!plan.scenes.length)throw new Error("invalid_ai_plan");
  return{script:String(plan.script||""),scenes:plan.scenes.slice(0,60)};
}

async function createProfile(env,u,b){
  const kind=String(b.kind||"").trim();
  if(!["avatar","voice"].includes(kind))return json({error:"kind_must_be_avatar_or_voice"},400);
  const provider=String(b.provider||"").trim();
  const providerId=String(b.provider_id||"").trim();
  const name=String(b.name||"").trim();
  if(!name||!provider||!providerId)return json({error:"name_provider_and_provider_id_required"},400);
  if(!b.consent_confirmed)return json({error:"consent_confirmation_required"},400);
  const id=uid(),ts=now();
  await env.DB.prepare("INSERT INTO media_profiles(id,tenant_id,name,kind,provider,provider_id,description,status,consent_confirmed,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
    .bind(id,tenant(u),name,kind,provider,providerId,String(b.description||""),"active",1,ts,ts).run();
  return json({ok:true,id},201);
}

async function listProfiles(env,u){const r=await env.DB.prepare("SELECT * FROM media_profiles WHERE tenant_id=? ORDER BY kind,name").bind(tenant(u)).all();return json({ok:true,items:r.results||[]});}

async function createProduction(env,u,b){
  const title=String(b.title||"").trim(),brief=String(b.brief||"").trim();
  if(!title||!brief)return json({error:"title_and_brief_required"},400);
  const input={title,brief,objective:String(b.objective||""),audience:String(b.audience||""),format:String(b.format||"long-video"),aspect_ratio:String(b.aspect_ratio||"16:9"),duration_minutes:Math.min(Math.max(Number(b.duration_minutes||1),1),60)};
  let plan;try{plan=await planProduction(env,input)}catch(e){return json({error:e?.message||"planning_failed"},502);}
  const id=uid(),ts=now();
  await env.DB.prepare("INSERT INTO media_productions(id,tenant_id,title,objective,audience,format,aspect_ratio,duration_minutes,brief,script,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(id,tenant(u),input.title,input.objective,input.audience,input.format,input.aspect_ratio,input.duration_minutes,input.brief,plan.script,"planned",ts,ts).run();
  const avatar=String(b.avatar_profile_id||""),voice=String(b.voice_profile_id||"");
  const statements=plan.scenes.map((s,index)=>env.DB.prepare("INSERT INTO media_scenes(id,tenant_id,production_id,position,title,narration,visual_prompt,avatar_profile_id,voice_profile_id,sound_prompt,caption,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(uid(),tenant(u),id,index+1,String(s.title||`Scene ${index+1}`),String(s.narration||""),String(s.visual_prompt||""),avatar,voice,String(s.sound_prompt||""),String(s.caption||""),"planned",ts,ts));
  if(statements.length)await env.DB.batch(statements);
  return json({ok:true,id,scene_count:statements.length,script:plan.script},201);
}

async function listProductions(env,u){const r=await env.DB.prepare("SELECT * FROM media_productions WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 100").bind(tenant(u)).all();return json({ok:true,items:r.results||[]});}
async function getProduction(env,u,id){
  const item=await env.DB.prepare("SELECT * FROM media_productions WHERE id=? AND tenant_id=?").bind(id,tenant(u)).first();
  if(!item)return json({error:"not_found"},404);
  const scenes=await env.DB.prepare("SELECT * FROM media_scenes WHERE production_id=? AND tenant_id=? ORDER BY position").bind(id,tenant(u)).all();
  const assets=await env.DB.prepare("SELECT * FROM media_assets WHERE production_id=? AND tenant_id=? ORDER BY created_at").bind(id,tenant(u)).all();
  return json({ok:true,item,scenes:scenes.results||[],assets:assets.results||[]});
}

async function profile(env,u,id,kind){if(!id)return null;return env.DB.prepare("SELECT * FROM media_profiles WHERE id=? AND tenant_id=? AND kind=? AND status='active' AND consent_confirmed=1").bind(id,tenant(u),kind).first();}

async function renderProduction(env,u,id){
  const item=await env.DB.prepare("SELECT * FROM media_productions WHERE id=? AND tenant_id=?").bind(id,tenant(u)).first();
  if(!item)return json({error:"not_found"},404);
  if(!env.HEYGEN_API_KEY)return json({error:"heygen_not_configured",needs:["HEYGEN_API_KEY"]},503);
  const r=await env.DB.prepare("SELECT * FROM media_scenes WHERE production_id=? AND tenant_id=? ORDER BY position").bind(id,tenant(u)).all();
  const scenes=r.results||[];if(!scenes.length)return json({error:"scenes_required"},400);
  const inputs=[];
  for(const scene of scenes){
    const avatar=await profile(env,u,scene.avatar_profile_id,"avatar");
    const voice=await profile(env,u,scene.voice_profile_id,"voice");
    const avatarId=avatar?.provider_id||env.HEYGEN_AVATAR_ID;
    const voiceId=voice?.provider_id||env.HEYGEN_VOICE_ID;
    if(!avatarId||!voiceId)return json({error:"avatar_and_voice_required",scene_id:scene.id},400);
    inputs.push({character:{type:"avatar",avatar_id:avatarId,avatar_style:"normal"},voice:{type:"text",input_text:scene.narration,voice_id:voiceId}});
  }
  const vertical=/9:16/.test(item.aspect_ratio);const square=/1:1/.test(item.aspect_ratio);
  const dimension=vertical?{width:720,height:1280}:square?{width:1080,height:1080}:{width:1280,height:720};
  const response=await fetch("https://api.heygen.com/v2/video/generate",{method:"POST",headers:{"X-Api-Key":env.HEYGEN_API_KEY,"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({video_inputs:inputs,dimension})});
  let data={};try{data=await response.json()}catch{}
  if(!response.ok)return json({error:"heygen_request_failed",status:response.status},502);
  const jobId=data?.data?.video_id||data?.video_id;if(!jobId)return json({error:"heygen_video_id_missing"},502);
  const ts=now();
  await env.DB.prepare("UPDATE media_productions SET provider='heygen',provider_job_id=?,status='rendering',error='',updated_at=? WHERE id=? AND tenant_id=?").bind(jobId,ts,id,tenant(u)).run();
  await env.DB.prepare("INSERT INTO media_assets(id,tenant_id,production_id,scene_id,kind,provider,provider_job_id,url,prompt,status,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(uid(),tenant(u),id,"","video","heygen",jobId,"",item.brief,"rendering",JSON.stringify({scene_count:inputs.length,dimension}),ts,ts).run();
  return json({ok:true,job_id:jobId,status:"rendering"});
}

async function refreshProduction(env,u,id){
  const item=await env.DB.prepare("SELECT * FROM media_productions WHERE id=? AND tenant_id=?").bind(id,tenant(u)).first();
  if(!item)return json({error:"not_found"},404);
  if(!item.provider_job_id||!env.HEYGEN_API_KEY)return json({error:"video_job_or_provider_missing"},400);
  const response=await fetch("https://api.heygen.com/v1/video_status.get?video_id="+encodeURIComponent(item.provider_job_id),{headers:{"X-Api-Key":env.HEYGEN_API_KEY,"Accept":"application/json"}});
  let body={};try{body=await response.json()}catch{}
  if(!response.ok)return json({error:"heygen_status_failed"},502);
  const data=body?.data||body,providerStatus=String(data?.status||"unknown"),url=String(data?.video_url||data?.url||"");
  const status=providerStatus==="completed"?"ready":providerStatus==="failed"?"failed":"rendering";
  await env.DB.batch([
    env.DB.prepare("UPDATE media_productions SET status=?,output_url=?,error=?,updated_at=? WHERE id=? AND tenant_id=?").bind(status,url,status==="failed"?String(data?.error||"render_failed"):"",now(),id,tenant(u)),
    env.DB.prepare("UPDATE media_assets SET status=?,url=?,updated_at=? WHERE production_id=? AND tenant_id=? AND kind='video' AND provider_job_id=?").bind(status,url,now(),id,tenant(u),item.provider_job_id)
  ]);
  return json({ok:true,status,provider_status:providerStatus,output_url:url});
}

async function generateSound(request,env,u){
  if(!env.ELEVENLABS_API_KEY)return json({error:"elevenlabs_not_configured"},503);
  let b={};try{b=await request.json()}catch{return json({error:"invalid_json"},400);}
  const prompt=String(b.prompt||"").trim();if(!prompt)return json({error:"sound_prompt_required"},400);
  const duration=Math.min(Math.max(Number(b.duration_seconds||5),.5),22);
  const response=await fetch("https://api.elevenlabs.io/v1/sound-generation",{method:"POST",headers:{"xi-api-key":env.ELEVENLABS_API_KEY,"Content-Type":"application/json","Accept":"audio/mpeg"},body:JSON.stringify({text:prompt,duration_seconds:duration,prompt_influence:.4})});
  if(!response.ok)return json({error:"sound_generation_failed",status:response.status},502);
  return new Response(response.body,{status:200,headers:{"content-type":response.headers.get("content-type")||"audio/mpeg","cache-control":"no-store","content-disposition":'attachment; filename="caelomere-ai-sound.mp3"'}});
}

export async function handleMedia(request,env){
  if(!env.DB)return json({error:"database_unavailable"},503);
  const u=await user(request,env);if(!u)return json({error:"unauthorized"},401);
  await schema(env);
  const p=new URL(request.url).pathname.split("/").filter(Boolean);
  if(p[0]!=="api"||p[1]!=="media")return json({error:"not_found"},404);
  if(p[2]==="status"&&request.method==="GET")return json({ok:true,...providerStatus(env),capabilities:["ai-planning","avatar-profiles","voice-profiles","sound-generation","multi-scene-video","long-video","short-video","captions","asset-history"]});
  if(p[2]==="profiles"&&request.method==="GET")return listProfiles(env,u);
  if(p[2]==="profiles"&&request.method==="POST"){let b={};try{b=await request.json()}catch{return json({error:"invalid_json"},400);}return createProfile(env,u,b);}
  if(p[2]==="productions"&&!p[3]&&request.method==="GET")return listProductions(env,u);
  if(p[2]==="productions"&&!p[3]&&request.method==="POST"){let b={};try{b=await request.json()}catch{return json({error:"invalid_json"},400);}return createProduction(env,u,b);}
  if(p[2]==="productions"&&p[3]&&!p[4]&&request.method==="GET")return getProduction(env,u,p[3]);
  if(p[2]==="productions"&&p[3]&&p[4]==="render"&&request.method==="POST")return renderProduction(env,u,p[3]);
  if(p[2]==="productions"&&p[3]&&p[4]==="refresh"&&request.method==="POST")return refreshProduction(env,u,p[3]);
  if(p[2]==="sound"&&request.method==="POST")return generateSound(request,env,u);
  return json({error:"not_found"},404);
}
