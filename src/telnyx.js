const API='https://api.telnyx.com/v2';
const JSON_HEADERS={'content-type':'application/json; charset=UTF-8','cache-control':'no-store'};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});

function bytes64(value){
  const clean=String(value||'').replace(/-/g,'+').replace(/_/g,'/');
  const raw=atob(clean);
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
export async function verifyTelnyxWebhook(request,publicKey){
  if(!publicKey)return false;
  const signature=request.headers.get('telnyx-signature-ed25519')||'';
  const timestamp=request.headers.get('telnyx-timestamp')||'';
  if(!signature||!timestamp)return false;
  const seconds=Number(timestamp);
  if(!Number.isFinite(seconds)||Math.abs(Date.now()/1000-seconds)>300)return false;
  const payload=await request.clone().text();
  try{
    const key=await crypto.subtle.importKey('raw',bytes64(publicKey),{name:'Ed25519'},false,['verify']);
    return crypto.subtle.verify({name:'Ed25519'},key,bytes64(signature),new TextEncoder().encode(timestamp+'|'+payload));
  }catch{return false;}
}
async function telnyx(env,path,{method='GET',body}={}){
  if(!env.TELNYX_API_KEY)throw new Error('telnyx_not_configured');
  const response=await fetch(API+path,{method,headers:{authorization:'Bearer '+env.TELNYX_API_KEY,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
  let data={};try{data=await response.json();}catch{}
  if(!response.ok)throw new Error(data?.errors?.[0]?.detail||data?.errors?.[0]?.title||'telnyx_request_failed');
  return data;
}
export const answerCall=(env,id)=>telnyx(env,`/calls/${encodeURIComponent(id)}/actions/answer`,{method:'POST',body:{}});
export const speakCall=(env,id,text,voice='female')=>telnyx(env,`/calls/${encodeURIComponent(id)}/actions/speak`,{method:'POST',body:{payload:String(text).slice(0,3000),voice,language:'en-GB'}});
export const transferCall=(env,id,to)=>telnyx(env,`/calls/${encodeURIComponent(id)}/actions/transfer`,{method:'POST',body:{to}});
export const startTranscription=(env,id)=>telnyx(env,`/calls/${encodeURIComponent(id)}/actions/transcription_start`,{method:'POST',body:{language:'en',transcription_engine:'Telnyx'}});
export const startRecording=(env,id)=>telnyx(env,`/calls/${encodeURIComponent(id)}/actions/record_start`,{method:'POST',body:{format:'mp3',channels:'single'}});
export const sendMessage=(env,{to,text,media_urls})=>telnyx(env,'/messages',{method:'POST',body:{from:env.TELNYX_FROM_NUMBER,messaging_profile_id:env.TELNYX_MESSAGING_PROFILE_ID,to,text,media_urls}});
export const lookupNumber=(env,number)=>telnyx(env,`/number_lookup/${encodeURIComponent(number)}?type=carrier&type=caller-name`);
export const sendVerification=(env,{phone,channel='sms'})=>telnyx(env,`/verify_profiles/${encodeURIComponent(env.TELNYX_VERIFY_PROFILE_ID)}/verifications`,{method:'POST',body:{phone_number:phone,type:channel}});
export const checkVerification=(env,{phone,code})=>telnyx(env,`/verify_profiles/${encodeURIComponent(env.TELNYX_VERIFY_PROFILE_ID)}/verifications/by_phone_number/${encodeURIComponent(phone)}/actions/verify`,{method:'POST',body:{code}});

async function user(request,env){
  const match=(request.headers.get('Cookie')||'').match(/(?:^|; )zorvian_session=([^;]+)/);
  if(!match||!env.DB)return null;
  return env.DB.prepare('SELECT u.id,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?').bind(match[1],new Date().toISOString()).first();
}
function readiness(env){
  return{
    configured:Boolean(env.TELNYX_API_KEY&&env.TELNYX_PUBLIC_KEY),
    voice:Boolean(env.TELNYX_API_KEY&&env.TELNYX_PUBLIC_KEY&&env.TELNYX_CONNECTION_ID&&env.TELNYX_FROM_NUMBER),
    messaging:Boolean(env.TELNYX_API_KEY&&env.TELNYX_MESSAGING_PROFILE_ID&&env.TELNYX_FROM_NUMBER),
    verification:Boolean(env.TELNYX_API_KEY&&env.TELNYX_VERIFY_PROFILE_ID),
    capabilities:['uk_numbers','inbound_voice','outbound_voice','call_transfer','voicemail','recording','transcription','sms','mms','whatsapp_ready','otp','number_lookup','delivery_events']
  };
}
export async function handleTelnyx(request,env){
  const url=new URL(request.url);
  if(!url.pathname.startsWith('/api/telnyx/'))return null;
  const current=await user(request,env);
  if(!current)return json({error:'unauthorized'},401);
  if(url.pathname==='/api/telnyx/status'&&request.method==='GET')return json({ok:true,provider:'telnyx',...readiness(env)});
  if(url.pathname==='/api/telnyx/messages'&&request.method==='POST'){
    let body={};try{body=await request.json();}catch{return json({error:'invalid_json'},400);}
    if(!body.to||!body.text)return json({error:'to_and_text_required'},400);
    try{const result=await sendMessage(env,body);return json({ok:true,id:result?.data?.id,status:result?.data?.to?.[0]?.status||'accepted'});}
    catch(error){return json({error:String(error.message||error)},503);}
  }
  if(url.pathname==='/api/telnyx/lookup'&&request.method==='POST'){
    let body={};try{body=await request.json();}catch{return json({error:'invalid_json'},400);}
    try{const result=await lookupNumber(env,body.phone);return json({ok:true,data:result.data});}
    catch(error){return json({error:String(error.message||error)},503);}
  }
  return json({error:'not_found'},404);
}
