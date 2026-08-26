const SOURCES = [
  {board:'AQA',qualification:'GCSE',subject:'English Language',code:'8700',url:'https://www.aqa.org.uk/subjects/english/gcse/english-8700/specification/subject-content'},
  {board:'AQA',qualification:'GCSE',subject:'Mathematics',code:'8300',url:'https://www.aqa.org.uk/subjects/mathematics/gcse/mathematics-8300/specification'},
  {board:'AQA',qualification:'GCSE',subject:'Biology',code:'8461',url:'https://www.aqa.org.uk/subjects/science/gcse/biology-8461/specification'},
  {board:'AQA',qualification:'GCSE',subject:'Chemistry',code:'8462',url:'https://www.aqa.org.uk/subjects/science/gcse/chemistry-8462/specification'},
  {board:'AQA',qualification:'GCSE',subject:'Physics',code:'8463',url:'https://www.aqa.org.uk/subjects/science/gcse/physics-8463/specification'},
  {board:'AQA',qualification:'GCSE',subject:'Combined Science',code:'8464',url:'https://www.aqa.org.uk/subjects/science/gcse/science-8464/specification'},
  {board:'AQA',qualification:'GCSE',subject:'Computer Science',code:'8525',url:'https://www.aqa.org.uk/subjects/computer-science/gcse/computer-science-8525/specification'},

  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Mathematics',code:'1MA1',url:'https://qualifications.pearson.com/en/subjects/mathematics.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'English Language',code:'1EN0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/english-language-2015.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Biology',code:'1BI0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/sciences-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Chemistry',code:'1CH0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/sciences-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Physics',code:'1PH0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/sciences-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Combined Science',code:'1SC0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/sciences-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'History',code:'1HI0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/history-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Geography A',code:'1GA0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/geography-a-2016.html'},
  {board:'Pearson Edexcel',qualification:'GCSE',subject:'Business',code:'1BS0',url:'https://qualifications.pearson.com/en/qualifications/edexcel-gcses/business-2017.html'},

  {board:'OCR',qualification:'GCSE',subject:'Mathematics',code:'J560',url:'https://www.ocr.org.uk/qualifications/gcse/mathematics-j560-from-2015/'},
  {board:'OCR',qualification:'GCSE',subject:'Computer Science',code:'J277',url:'https://www.ocr.org.uk/qualifications/gcse/computer-science-j277-from-2020/specification-at-a-glance/'},

  {board:'Eduqas',qualification:'GCSE',subject:'English Language',code:'C700QS',url:'https://www.eduqas.co.uk/qualifications/english-language-gcse/'},
  {board:'Eduqas',qualification:'GCSE',subject:'Mathematics',code:'C300QS',url:'https://www.wjec.co.uk/ed/qualifications/mathematics-gcse/'},

  {board:'WJEC',qualification:'GCSE',subject:'Mathematics',code:'3300QS',url:'https://www.wjec.co.uk/qualifications/mathematics-gcse/'},

  {board:'DfE',qualification:'GCSE',subject:'English Language',code:'DFE-00232-2013',url:'https://www.gov.uk/government/publications/gcse-english-language-and-gcse-english-literature-new-content'}
];

function normalise(value){return String(value||'').trim().toLowerCase().replace(/[^a-z0-9]+/g,' ');}
function scoreSource(source,{board,qualification,subject,code}){
  let score=0;
  const b=normalise(board),q=normalise(qualification),s=normalise(subject),c=normalise(code);
  if(c&&normalise(source.code)===c)score+=20;
  if(b&&normalise(source.board)===b)score+=10;
  if(q&&normalise(source.qualification)===q)score+=6;
  const ss=normalise(source.subject);
  if(s&&ss===s)score+=12;
  else if(s&&(ss.includes(s)||s.includes(ss)))score+=7;
  return score;
}

export function listCurriculumSources(filters={}){
  const ranked=SOURCES.map(source=>({source,score:scoreSource(source,filters)})).filter(x=>x.score>0).sort((a,b)=>b.score-a.score);
  return ranked.map(x=>x.source);
}

function htmlToText(html){
  return String(html||'')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi,' ')
    .replace(/<[^>]+>/g,' ')
    .replace(/&nbsp;/gi,' ')
    .replace(/&amp;/gi,'&')
    .replace(/&lt;/gi,'<')
    .replace(/&gt;/gi,'>')
    .replace(/&#39;/g,"'")
    .replace(/&quot;/gi,'"')
    .replace(/\s+/g,' ')
    .trim();
}

function selectRelevant(text,question,limit=12000){
  if(!text)return '';
  const terms=[...new Set(normalise(question).split(' ').filter(x=>x.length>3))].slice(0,10);
  const chunks=text.match(/.{1,900}(?:\.|$)/g)||[text];
  const scored=chunks.map((chunk,index)=>{
    const low=normalise(chunk);let score=0;
    for(const term of terms)if(low.includes(term))score+=2;
    if(/subject content|assessment|specification|paper|topic|knowledge|skills|students|learners/i.test(chunk))score+=1;
    return {chunk,index,score};
  }).sort((a,b)=>b.score-a.score||a.index-b.index);
  const selected=[];let length=0;
  for(const item of scored){
    if(length+item.chunk.length>limit)continue;
    selected.push(item);length+=item.chunk.length;
    if(length>limit*0.8)break;
  }
  return selected.sort((a,b)=>a.index-b.index).map(x=>x.chunk).join('\n');
}

export async function getCurriculumContext({board,qualification,subject,code,question}){
  const matches=listCurriculumSources({board,qualification,subject,code});
  const source=matches[0];
  if(!source)return {matched:false,source:null,context:'',warning:'No exact official curriculum source is registered for this selection yet.'};
  try{
    const response=await fetch(source.url,{headers:{'user-agent':'CAELOMERE-Tutor/1.0 curriculum grounding'}});
    if(!response.ok)throw new Error(`http_${response.status}`);
    const type=response.headers.get('content-type')||'';
    if(!type.includes('text/html')&&!type.includes('text/plain')){
      return {matched:true,source,context:'',warning:'Official source is registered but is not directly text-readable by the live tutor. Use source metadata only.'};
    }
    const raw=await response.text();
    const text=htmlToText(raw);
    const context=selectRelevant(text,question||subject||'',12000);
    return {matched:true,source,context,warning:context?'':'Official source returned no usable text.'};
  }catch(error){
    return {matched:true,source,context:'',warning:`Official source could not be fetched live: ${String(error?.message||error)}`};
  }
}

export function curriculumRegistry(){return SOURCES;}
