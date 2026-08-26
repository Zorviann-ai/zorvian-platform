import { generateAI } from './ai-router.js';
import { APPROVED_TEMPLATES, buildValidatedSTL } from './maker-geometry.js';
const H={'content-type':'application/json; charset=UTF-8','cache-control':'no-store'};
const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:H});
const now=()=>new Date().toISOString();
function cookie(request,name){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function user(request,env){const sid=cookie(request,'zorvian_session');if(!sid||!env.DB)return null;return env.DB.prepare('SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?').bind(sid,now()).first();}
async function schema(env){await env.DB.prepare(`CREATE TABLE IF NOT EXISTS maker_designs(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,title TEXT NOT NULL,prompt TEXT,template TEXT NOT NULL,parameters_json TEXT NOT NULL,status TEXT NOT NULL,validation_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`).run();}
function cleanParams(x={}){const out={};for(const k of ['width','height','depth','tip','lip'])if(Number.isFinite(Number(x[k])))out[k]=Number(x[k]);return out;}
function templateFromPrompt(prompt){const p=prompt.toLowerCase();if(/plant|garden|seed|herb|label|marker/.test(p))return 'plant_label';if(/phone|desk|wedge|stand|rest/.test(p))return 'desk_wedge';if(/plaque|sign|nameplate|badge/.test(p))return 'wall_plaque';return null;}
export async function handleMaker(request,env){
  if(!env.DB)return json({error:'database_unavailable'},503);const u=await user(request,env);if(!u)return json({error:'unauthorized'},401);await schema(env);const url=new URL(request.url);
  if(url.pathname==='/api/maker/status'&&request.method==='GET')return json({ok:true,pipeline:'validated-parametric-v1',templates:APPROVED_TEMPLATES,print_ready_gate:{requires:['approved_template','successful_mesh_generation','finite_coordinates','no_degenerate_triangles','closed_manifold_edges','dimensions_within_limits','non_zero_volume'],unsupported_freeform_status:'needs_validation'}});
  if(url.pathname==='/api/maker/designs'&&request.method==='GET'){const r=await env.DB.prepare('SELECT id,title,prompt,template,parameters_json,status,validation_json,created_at,updated_at FROM maker_designs WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 100').bind(u.tenant_id||'zorvian').all();return json({ok:true,designs:r.results||[]});}
  if(url.pathname==='/api/maker/designs'&&request.method==='POST'){
    let b={};try{b=await request.json();}catch{return json({error:'invalid_json'},400);}const prompt=String(b.prompt||'').trim().slice(0,4000);let template=String(b.template||'').trim();let params=cleanParams(b.parameters);let ai=null;
    if(!template&&prompt)template=templateFromPrompt(prompt)||'';
    if(!template){
      try{ai=await generateAI(env,{system:'You are CAELOMERE Maker Studio. Classify a requested 3D printable object into exactly one approved template: wall_plaque, plant_label, desk_wedge, or unsupported. Return only the template token. Never claim print readiness.',input:prompt,maxOutputTokens:30,temperature:0});template=['wall_plaque','plant_label','desk_wedge'].includes(ai.text.trim())?ai.text.trim():'';}catch{}
    }
    if(!template||!APPROVED_TEMPLATES[template])return json({ok:true,status:'needs_validation',print_ready:false,message:'The concept is retained as a design draft. It is not eligible for automatic Print Ready status because no approved geometry template safely represents it.',supported_templates:Object.keys(APPROVED_TEMPLATES)},202);
    let built;try{built=buildValidatedSTL(template,params,b.title||template);}catch(e){return json({error:'geometry_generation_failed',detail:String(e?.message||e)},422);}
    const id=crypto.randomUUID(),ts=now(),title=String(b.title||APPROVED_TEMPLATES[template].label).slice(0,160);await env.DB.prepare('INSERT INTO maker_designs(id,tenant_id,user_id,title,prompt,template,parameters_json,status,validation_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(id,u.tenant_id||'zorvian',u.id,title,prompt,template,JSON.stringify(params),built.status,JSON.stringify(built.validation),ts,ts).run();
    return json({ok:true,id,title,template,parameters:params,status:built.status,print_ready:built.status==='print_ready',validation:built.validation,download_url:built.status==='print_ready'?`/api/maker/designs/${id}/stl`:null,ai_provider:ai?.provider||null},201);
  }
  const m=url.pathname.match(/^\/api\/maker\/designs\/([^/]+)\/stl$/);if(m&&request.method==='GET'){
    const d=await env.DB.prepare('SELECT * FROM maker_designs WHERE id=? AND tenant_id=?').bind(m[1],u.tenant_id||'zorvian').first();if(!d)return json({error:'design_not_found'},404);if(d.status!=='print_ready')return json({error:'design_not_print_ready'},409);let built;try{built=buildValidatedSTL(d.template,JSON.parse(d.parameters_json||'{}'),d.title);}catch(e){return json({error:'geometry_regeneration_failed'},422);}if(built.status!=='print_ready')return json({error:'validation_failed_on_regeneration',validation:built.validation},409);return new Response(built.stl,{headers:{'content-type':'model/stl; charset=UTF-8','content-disposition':`attachment; filename="${d.id}.stl"`,'cache-control':'private, no-store','x-caelomere-validation':'print-ready'}});
  }
  return json({error:'maker_route_not_found'},404);
}
