import { generateAI } from './ai-router.js';

const ORIGINS=new Set(['https://caelomerestudio.com','https://www.caelomerestudio.com']);
const base={'content-type':'application/json; charset=UTF-8','cache-control':'no-store'};
function cors(request){const origin=request.headers.get('Origin')||'';return ORIGINS.has(origin)?{'access-control-allow-origin':origin,'access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'content-type','access-control-max-age':'86400','vary':'Origin'}:{};}
function reply(request,data,status=200){return new Response(JSON.stringify(data),{status,headers:{...base,...cors(request)}});}
function parseJson(text){const cleaned=String(text||'').replace(/^```(?:json)?\s*/i,'').replace(/```$/,'').trim();try{return JSON.parse(cleaned);}catch{return null;}}

export async function handleStudioPublic(request,env){
  const url=new URL(request.url);
  if(url.pathname!=='/api/studio/analyse')return null;
  if(request.method==='OPTIONS'){
    const origin=request.headers.get('Origin')||'';
    if(!ORIGINS.has(origin))return new Response(null,{status:403,headers:{'cache-control':'no-store'}});
    return new Response(null,{status:204,headers:cors(request)});
  }
  if(request.method!=='POST')return reply(request,{error:'method_not_allowed'},405);
  let body={};try{body=await request.json();}catch{return reply(request,{error:'invalid_json'},400);}
  const title=String(body.title||'').trim().slice(0,240);
  const author=String(body.author||'').trim().slice(0,160);
  const genre=String(body.genre||'').trim().slice(0,120);
  const source=String(body.source_text||'').trim().slice(0,50000);
  if(!title||source.length<200)return reply(request,{error:'title_and_manuscript_required'},400);
  if(body.rights_confirmed!==true&&body.public_domain!==true)return reply(request,{error:'rights_confirmation_required'},400);
  const rights=body.public_domain===true?'public_domain':'authorised';
  const prompt=`Create a Caelomere Studio story-development blueprint from the authorised manuscript below. Return valid JSON only with these keys: summary, proofreading_notes, themes, characters, scene_map, reader_experience, trailer_treatment, adaptation_pathway, rights_and_evidence. Characters must contain name, role, motivation, visual_direction. Scene_map must contain position, title, source_basis, visual_direction, narration, sound_direction. Use only the supplied manuscript. Do not invent quotations, rights, sales, reviews or biographical facts. Keep quotations very short. Do not claim that images, audio or video were rendered.\n\nTITLE: ${title}\nAUTHOR: ${author}\nGENRE: ${genre}\nRIGHTS: ${rights}\nMANUSCRIPT:\n${source}`;
  try{
    const result=await generateAI(env,{system:'Return valid JSON only. Use clear British English.',input:prompt,maxOutputTokens:5000,temperature:.2});
    const plan=parseJson(result.text);
    if(!plan)return reply(request,{error:'invalid_ai_result'},503);
    return reply(request,{ok:true,status:'analysed',title,rights_basis:rights,visualisation:plan,ai_provider:result.provider,ai_model:result.model});
  }catch(error){console.error('studio_public_analysis_failed',error);return reply(request,{error:'analysis_failed'},503);}
}
