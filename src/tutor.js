import { generateAI, providerStatus } from './ai-router.js';
import { getCurriculumContext, curriculumRegistry } from './curriculum.js';

const JSON_HEADERS={
  'content-type':'application/json; charset=UTF-8',
  'cache-control':'no-store',
  'access-control-allow-origin':'*',
  'access-control-allow-methods':'GET,POST,OPTIONS',
  'access-control-allow-headers':'content-type'
};
function json(data,status=200){return new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});}
function stripFences(value){return String(value||'').replace(/^```(?:json)?\s*/i,'').replace(/\s*```$/i,'').trim();}
function parseTutorPayload(text,fallback){try{const p=JSON.parse(stripFences(text));return {question:p.question||fallback.question,answer:p.answer||'Let us work through this together.',explanation:p.explanation||'',learning_path:Array.isArray(p.learning_path)?p.learning_path.slice(0,6):[],method:p.method||'',conclusion:p.conclusion||'',remember:p.remember||'',visual:p.visual||{type:'none',title:'',description:'',data:[]},practice:p.practice||'',check_understanding:p.check_understanding||'',references:Array.isArray(p.references)?p.references.slice(0,8):[],integrity_note:p.integrity_note||''};}catch{return {question:fallback.question,answer:text,explanation:'',learning_path:[],method:'',conclusion:'',remember:'',visual:{type:'none',title:'',description:'',data:[]},practice:'',check_understanding:'',references:[],integrity_note:''};}}

function tutorSystem({level,subject,mode,visualPreference,board,qualification,curriculum}){return `You are CAELOMERE Tutor, a warm, accurate UK education tutor. Your goal is to help students understand, remember, enjoy learning and pass exams.
Student context: level=${level}; qualification=${qualification}; exam board=${board||'not selected'}; subject=${subject}; mode=${mode}; preferred visual style=${visualPreference}.
${curriculum?.matched?`OFFICIAL CURRICULUM SOURCE: ${curriculum.source.board} ${curriculum.source.qualification} ${curriculum.source.subject} ${curriculum.source.code}. Source URL: ${curriculum.source.url}.`:'No exact official exam-board source is currently registered for this selection.'}
${curriculum?.context?`OFFICIAL SOURCE EXTRACT:\n${curriculum.context}`:''}
Teaching rules:
- Answer the actual question accurately and prioritise the supplied official curriculum extract when it is relevant.
- Never claim a syllabus requirement unless supported by the supplied official source or you clearly label it as general teaching knowledge.
- Never reveal hidden chain-of-thought. Provide a concise STUDENT-FACING LEARNING PATH: useful working, method, evidence and checks a student can learn.
- Adapt vocabulary and depth to the stated UK level.
- Maths/science: show useful working and method. English/humanities: show evidence, structure and reasoning.
- Assessed work: coach, structure, give feedback/examples/questions, but do not impersonate the student's submitted work.
- Suggest a visual when useful from simple_shapes, number_line, bar_chart, line_graph, pie_chart, timeline, labelled_diagram, table, none. Do not invent factual statistics.
- References must be honest. Include the official curriculum URL above when it materially supports the answer. Never invent citations.
- End with a short practice question or comprehension check when appropriate.
Return ONLY valid JSON: {"question":"","answer":"","explanation":"","learning_path":[""],"method":"","conclusion":"","remember":"","visual":{"type":"none","title":"","description":"","data":[]},"practice":"","check_understanding":"","references":[{"title":"","url":"","note":""}],"integrity_note":""}`;}

export async function handleTutor(request,env){
 const url=new URL(request.url);
 if(request.method==='OPTIONS'&&url.pathname.startsWith('/api/tutor'))return new Response(null,{status:204,headers:JSON_HEADERS});
 if(request.method==='GET'&&url.pathname==='/api/tutor/status')return json({ok:true,service:'caelomere_tutor',ai:providerStatus(env),curriculum_sources:curriculumRegistry().length});
 if(request.method==='GET'&&url.pathname==='/api/tutor/curriculum')return json({ok:true,sources:curriculumRegistry()});
 if(request.method!=='POST'||url.pathname!=='/api/tutor')return null;
 let body;try{body=await request.json();}catch{return json({error:'invalid_json'},400);}
 const question=String(body?.question||'').trim();if(!question)return json({error:'question_required'},400);if(question.length>12000)return json({error:'question_too_long'},413);
 const level=String(body?.level||'GCSE').slice(0,80),qualification=String(body?.qualification||level||'GCSE').slice(0,80),board=String(body?.board||body?.exam_board||'').slice(0,80),subject=String(body?.subject||'General').slice(0,80),code=String(body?.specification_code||'').slice(0,40),mode=String(body?.mode||'learn').slice(0,40),visualPreference=String(body?.visual_preference||body?.visual||'best_way').slice(0,80);
 const curriculum=await getCurriculumContext({board,qualification,subject,code,question});
 const system=tutorSystem({level,qualification,board,subject,mode,visualPreference,curriculum});
 const input=`Student question:\n${question}`;
 try{const result=await generateAI(env,{system,input,maxOutputTokens:1900,temperature:0.2});const lesson=parseTutorPayload(result.text,{question});
   if(curriculum?.matched&&curriculum.source&&!lesson.references.some(r=>r?.url===curriculum.source.url))lesson.references.unshift({title:`${curriculum.source.board} ${curriculum.source.qualification} ${curriculum.source.subject} specification`,url:curriculum.source.url,note:`Official source; specification code ${curriculum.source.code}`});
   return json({ok:true,...lesson,meta:{provider:result.provider,model:result.model,level,qualification,board,subject,mode,visual_preference:visualPreference,curriculum:{matched:curriculum.matched,source:curriculum.source,warning:curriculum.warning||null}}});
 }catch(error){console.error(JSON.stringify({event:'tutor_ai_failed',error:String(error?.message||error)}));return json({error:'tutor_ai_unavailable',detail:String(error?.message||error),curriculum:{matched:curriculum?.matched||false,source:curriculum?.source||null}},503);}
}
