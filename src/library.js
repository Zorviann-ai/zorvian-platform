const H={'content-type':'application/json; charset=UTF-8','cache-control':'no-store'};
const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:H});
const uid=()=>crypto.randomUUID();
const now=()=>new Date().toISOString();
const ALLOWED_RIGHTS=new Set(['PUBLIC_DOMAIN_VERIFIED','AUTHOR_PERMISSION_VERIFIED','PUBLISHER_PERMISSION_VERIFIED','LICENSE_VERIFIED']);
const JOB_TYPES=new Set(['CLEAN_TEXT','CHAPTER_SPLIT','SUMMARY','AUDIO_NARRATION','COVER_GENERATION','SCENE_PLAN','ILLUSTRATION','LONG_VIDEO','SHORT_VIDEO','CAPTIONS','METADATA_PACK','SOCIAL_PACK','TRANSLATION','EPUB_EXPORT','PDF_EXPORT']);

const SEED=[
['g11','Alice’s Adventures in Wonderland','Lewis Carroll',1865,'https://www.gutenberg.org/ebooks/11'],
['g1342','Pride and Prejudice','Jane Austen',1813,'https://www.gutenberg.org/ebooks/1342'],
['g84','Frankenstein','Mary Shelley',1818,'https://www.gutenberg.org/ebooks/84'],
['g345','Dracula','Bram Stoker',1897,'https://www.gutenberg.org/ebooks/345'],
['g2701','Moby-Dick','Herman Melville',1851,'https://www.gutenberg.org/ebooks/2701'],
['g1260','Jane Eyre','Charlotte Brontë',1847,'https://www.gutenberg.org/ebooks/1260'],
['g768','Wuthering Heights','Emily Brontë',1847,'https://www.gutenberg.org/ebooks/768'],
['g1400','Great Expectations','Charles Dickens',1861,'https://www.gutenberg.org/ebooks/1400'],
['g98','A Tale of Two Cities','Charles Dickens',1859,'https://www.gutenberg.org/ebooks/98'],
['g730','Oliver Twist','Charles Dickens',1838,'https://www.gutenberg.org/ebooks/730'],
['g174','The Picture of Dorian Gray','Oscar Wilde',1890,'https://www.gutenberg.org/ebooks/174'],
['g35','The Time Machine','H. G. Wells',1895,'https://www.gutenberg.org/ebooks/35'],
['g36','The War of the Worlds','H. G. Wells',1898,'https://www.gutenberg.org/ebooks/36'],
['g55','The Wonderful Wizard of Oz','L. Frank Baum',1900,'https://www.gutenberg.org/ebooks/55'],
['g1661','The Adventures of Sherlock Holmes','Arthur Conan Doyle',1892,'https://www.gutenberg.org/ebooks/1661'],
['g120','Treasure Island','Robert Louis Stevenson',1883,'https://www.gutenberg.org/ebooks/120'],
['g17396','The Secret Garden','Frances Hodgson Burnett',1911,'https://www.gutenberg.org/ebooks/17396'],
['g16','Peter Pan','J. M. Barrie',1911,'https://www.gutenberg.org/ebooks/16'],
['g289','The Wind in the Willows','Kenneth Grahame',1908,'https://www.gutenberg.org/ebooks/289'],
['g514','Little Women','Louisa May Alcott',1868,'https://www.gutenberg.org/ebooks/514'],
['g45','Anne of Green Gables','L. M. Montgomery',1908,'https://www.gutenberg.org/ebooks/45'],
['g103','Around the World in Eighty Days','Jules Verne',1872,'https://www.gutenberg.org/ebooks/103'],
['g43','Strange Case of Dr Jekyll and Mr Hyde','Robert Louis Stevenson',1886,'https://www.gutenberg.org/ebooks/43'],
['g236','The Jungle Book','Rudyard Kipling',1894,'https://www.gutenberg.org/ebooks/236'],
['g215','The Call of the Wild','Jack London',1903,'https://www.gutenberg.org/ebooks/215']
];

function cookie(request,name){const h=request.headers.get('Cookie')||'';const m=h.match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?m[1]:null;}
async function currentUser(request,env){const sid=cookie(request,'zorvian_session');if(!sid||!env.DB)return null;return env.DB.prepare('SELECT u.id,u.name,u.email,u.role,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?').bind(sid,now()).first();}
async function body(request){try{return await request.json();}catch{return null;}}

async function schema(env){
 if(!env.DB)throw new Error('database_unavailable');
 await env.DB.batch([
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_authors(id TEXT PRIMARY KEY,name TEXT NOT NULL,pen_name TEXT,email TEXT,created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_books(id TEXT PRIMARY KEY,author_id TEXT,title TEXT NOT NULL,language TEXT,publication_year INTEGER,status TEXT NOT NULL DEFAULT \'DISCOVERED\',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_editions(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,source_name TEXT,source_reference TEXT,identifier TEXT,original_asset_key TEXT,canonical_text_asset_key TEXT,original_sha256 TEXT,created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_rights(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,edition_id TEXT,rights_status TEXT NOT NULL DEFAULT \'UNKNOWN\',jurisdiction TEXT,rights_owner TEXT,evidence_reference TEXT,evidence_note TEXT,verified_by TEXT,verified_at TEXT,expires_at TEXT,permissions_json TEXT NOT NULL DEFAULT \'{}\',restrictions_json TEXT NOT NULL DEFAULT \'{}\',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_assets(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,edition_id TEXT,asset_type TEXT NOT NULL,storage_key TEXT NOT NULL,mime_type TEXT,sha256 TEXT,provenance_json TEXT NOT NULL DEFAULT \'{}\',created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_jobs(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,job_type TEXT NOT NULL,status TEXT NOT NULL,source_asset_id TEXT,output_asset_id TEXT,provider TEXT,model TEXT,prompt_version TEXT,cost_minor INTEGER,currency TEXT,error_text TEXT,created_at TEXT NOT NULL,started_at TEXT,completed_at TEXT)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_publish_requests(id TEXT PRIMARY KEY,book_id TEXT NOT NULL,destination TEXT NOT NULL,monetise INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT \'PENDING\',requested_by TEXT,approved_by TEXT,approved_at TEXT,remote_id TEXT,remote_url TEXT,created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_author_leads(id TEXT PRIMARY KEY,author_name TEXT NOT NULL,pen_name TEXT,email TEXT,book_title TEXT,rights_owner_type TEXT,proof_reference TEXT,goals_json TEXT DEFAULT \'{}\',channels_json TEXT DEFAULT \'{}\',monetisation_preference TEXT,territory TEXT,consent INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT \'NEW\',created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_audit(id TEXT PRIMARY KEY,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,action TEXT NOT NULL,actor TEXT,data_json TEXT DEFAULT \'{}\',created_at TEXT NOT NULL)'),
  env.DB.prepare('CREATE TABLE IF NOT EXISTS library_events(id TEXT PRIMARY KEY,event_type TEXT NOT NULL,book_id TEXT,revenue_minor INTEGER DEFAULT 0,currency TEXT,metadata_json TEXT DEFAULT \'{}\',created_at TEXT NOT NULL)')
 ]);
 await seed(env);
}

async function seed(env){
 const existing=await env.DB.prepare('SELECT COUNT(*) c FROM library_books').first();
 if(Number(existing?.c||0)>=SEED.length)return;
 const ts=now();
 for(const [id,title,author,year,source] of SEED){
  const aid='a_'+id; const eid='e_'+id; const rid='r_'+id;
  await env.DB.prepare('INSERT OR IGNORE INTO library_authors(id,name,created_at) VALUES(?,?,?)').bind(aid,author,ts).run();
  await env.DB.prepare('INSERT OR IGNORE INTO library_books(id,author_id,title,language,publication_year,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').bind(id,aid,title,'en',year,'RIGHTS_REVIEW',ts,ts).run();
  await env.DB.prepare('INSERT OR IGNORE INTO library_editions(id,book_id,source_name,source_reference,identifier,created_at) VALUES(?,?,?,?,?,?)').bind(eid,id,'Project Gutenberg',source,id,ts).run();
  await env.DB.prepare('INSERT OR IGNORE INTO library_rights(id,book_id,edition_id,rights_status,jurisdiction,evidence_reference,evidence_note,permissions_json,restrictions_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(rid,id,eid,'PUBLIC_DOMAIN_CLAIMED','GB',source,'Seed candidate only. Reviewer must verify the edition and jurisdiction before transformation or publication.',JSON.stringify({ingest:false,store:true,display_text:false,create_audio:false,create_video:false,create_summary:false,create_translation:false,publish_youtube:false,publish_library:false,monetise:false,create_short_form:false,use_cover_art:false}),'{}',ts,ts).run();
 }
 // Alice is the existing public-domain demonstration already used by Caelomere Studio.
 await env.DB.prepare('UPDATE library_rights SET rights_status=?,verified_by=?,verified_at=?,evidence_note=?,permissions_json=?,updated_at=? WHERE book_id=?').bind('PUBLIC_DOMAIN_VERIFIED','Caelomere seed review',ts,'Public-domain demonstration title. Source text edition must remain provenance-linked.',JSON.stringify({ingest:true,store:true,display_text:true,create_audio:true,create_video:true,create_summary:true,create_translation:true,publish_youtube:true,publish_library:true,monetise:true,create_short_form:true,use_cover_art:false}),ts,'g11').run();
 await env.DB.prepare('UPDATE library_books SET status=?,updated_at=? WHERE id=?').bind('TRANSFORMATION_READY',ts,'g11').run();
}

async function rights(env,bookId){return env.DB.prepare('SELECT * FROM library_rights WHERE book_id=? ORDER BY updated_at DESC LIMIT 1').bind(bookId).first();}
async function audit(env,type,id,action,actor,data={}){await env.DB.prepare('INSERT INTO library_audit(id,entity_type,entity_id,action,actor,data_json,created_at) VALUES(?,?,?,?,?,?,?)').bind(uid(),type,id,action,actor||'system',JSON.stringify(data),now()).run();}
async function requireAdmin(request,env){const u=await currentUser(request,env);return u||null;}

async function listBooks(env,url){
 const q=(url.searchParams.get('q')||'').trim();
 let stmt='SELECT b.id,b.title,b.language,b.publication_year,b.status,a.name author,e.source_name,e.source_reference,r.rights_status,r.jurisdiction,r.permissions_json FROM library_books b LEFT JOIN library_authors a ON a.id=b.author_id LEFT JOIN library_editions e ON e.book_id=b.id LEFT JOIN library_rights r ON r.book_id=b.id';
 let result;
 if(q)result=await env.DB.prepare(stmt+' WHERE lower(b.title) LIKE ? OR lower(a.name) LIKE ? ORDER BY b.title').bind('%'+q.toLowerCase()+'%','%'+q.toLowerCase()+'%').all();else result=await env.DB.prepare(stmt+' ORDER BY b.title').all();
 return json({ok:true,count:(result.results||[]).length,items:(result.results||[]).map(x=>({...x,permissions:JSON.parse(x.permissions_json||'{}'),permissions_json:undefined}))});
}

export async function handleLibrary(request,env){
 const url=new URL(request.url),p=url.pathname;
 if(!p.startsWith('/api/library/'))return null;
 try{await schema(env);}catch{return json({error:'database_unavailable'},503);}
 if(p==='/api/library/health'&&request.method==='GET')return json({ok:true,rights_gate:true,seed_titles:SEED.length,states:['DISCOVERED','RIGHTS_REVIEW','RIGHTS_HOLD','APPROVED','INGESTED','TRANSFORMATION_READY','PROCESSING','QA_REVIEW','PUBLISH_APPROVAL','PUBLISHED','ARCHIVED','REVOKED']});
 if(p==='/api/library/books'&&request.method==='GET')return listBooks(env,url);
 if(p==='/api/library/authors/leads'&&request.method==='POST'){
  const b=await body(request);if(!b)return json({error:'invalid_json'},400);if(!b.author_name||!String(b.email||'').includes('@')||b.consent!==true)return json({error:'author_email_and_consent_required'},400);
  const id=uid();await env.DB.prepare('INSERT INTO library_author_leads(id,author_name,pen_name,email,book_title,rights_owner_type,proof_reference,goals_json,channels_json,monetisation_preference,territory,consent,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,String(b.author_name).slice(0,160),String(b.pen_name||'').slice(0,160),String(b.email).slice(0,254),String(b.book_title||'').slice(0,240),String(b.rights_owner_type||''),String(b.proof_reference||''),JSON.stringify(b.goals||{}),JSON.stringify(b.channels||{}),String(b.monetisation_preference||''),String(b.territory||''),1,'NEW',now()).run();return json({ok:true,id},201);
 }
 const u=await requireAdmin(request,env);if(!u)return json({error:'unauthorized'},401);
 const actor=u.email||u.id;
 if(p==='/api/library/discover'&&request.method==='POST'){
  const b=await body(request);if(!b?.title||!b?.source_reference)return json({error:'title_and_source_reference_required'},400);const id=uid(),aid=uid(),eid=uid(),rid=uid(),ts=now();
  await env.DB.prepare('INSERT INTO library_authors(id,name,created_at) VALUES(?,?,?)').bind(aid,String(b.author||'Unknown'),ts).run();await env.DB.prepare('INSERT INTO library_books(id,author_id,title,language,publication_year,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').bind(id,aid,String(b.title),String(b.language||'en'),Number(b.publication_year||0)||null,'RIGHTS_REVIEW',ts,ts).run();await env.DB.prepare('INSERT INTO library_editions(id,book_id,source_name,source_reference,identifier,created_at) VALUES(?,?,?,?,?,?)').bind(eid,id,String(b.source_name||'Manual'),String(b.source_reference),String(b.identifier||''),ts).run();await env.DB.prepare('INSERT INTO library_rights(id,book_id,edition_id,rights_status,jurisdiction,evidence_reference,evidence_note,permissions_json,restrictions_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(rid,id,eid,'UNKNOWN',String(b.jurisdiction||'GB'),String(b.evidence_reference||''),String(b.evidence_note||''),'{}','{}',ts,ts).run();await audit(env,'book',id,'DISCOVERED',actor,b);return json({ok:true,id,status:'RIGHTS_REVIEW'},201);
 }
 if(p==='/api/library/rights/verify'&&request.method==='POST'){
  const b=await body(request),status=String(b?.rights_status||'');if(!b?.book_id||!['PUBLIC_DOMAIN_VERIFIED','AUTHOR_PERMISSION_VERIFIED','PUBLISHER_PERMISSION_VERIFIED','LICENSE_VERIFIED','RESTRICTED','REVOKED'].includes(status))return json({error:'book_id_and_valid_rights_status_required'},400);if(!b.evidence_reference||!b.jurisdiction)return json({error:'evidence_reference_and_jurisdiction_required'},400);
  const ts=now(),perms=b.permissions||{};await env.DB.prepare('UPDATE library_rights SET rights_status=?,jurisdiction=?,rights_owner=?,evidence_reference=?,evidence_note=?,verified_by=?,verified_at=?,expires_at=?,permissions_json=?,restrictions_json=?,updated_at=? WHERE book_id=?').bind(status,String(b.jurisdiction),String(b.rights_owner||''),String(b.evidence_reference),String(b.evidence_note||''),actor,ts,b.expires_at||null,JSON.stringify(perms),JSON.stringify(b.restrictions||{}),ts,String(b.book_id)).run();await env.DB.prepare('UPDATE library_books SET status=?,updated_at=? WHERE id=?').bind(ALLOWED_RIGHTS.has(status)?'APPROVED':'RIGHTS_HOLD',ts,String(b.book_id)).run();await audit(env,'rights',String(b.book_id),'RIGHTS_VERIFIED',actor,{status,permissions:perms});return json({ok:true,book_id:b.book_id,rights_status:status});
 }
 if(p==='/api/library/ingest'&&request.method==='POST'){
  const b=await body(request);if(!b?.book_id)return json({error:'book_id_required'},400);const r=await rights(env,String(b.book_id));if(!r||!ALLOWED_RIGHTS.has(r.rights_status))return json({error:'rights_gate_blocked'},403);const perms=JSON.parse(r.permissions_json||'{}');if(perms.ingest!==true)return json({error:'ingest_not_permitted'},403);const ts=now();await env.DB.prepare('UPDATE library_books SET status=?,updated_at=? WHERE id=?').bind('INGESTED',ts,String(b.book_id)).run();await audit(env,'book',String(b.book_id),'INGESTED',actor,{source_asset:b.source_asset||null});return json({ok:true,book_id:b.book_id,status:'INGESTED'});
 }
 if(p==='/api/library/jobs'&&request.method==='POST'){
  const b=await body(request),jt=String(b?.job_type||'');if(!b?.book_id||!JOB_TYPES.has(jt))return json({error:'book_id_and_valid_job_type_required'},400);const r=await rights(env,String(b.book_id));if(!r||!ALLOWED_RIGHTS.has(r.rights_status))return json({error:'rights_gate_blocked'},403);const id=uid();await env.DB.prepare('INSERT INTO library_jobs(id,book_id,job_type,status,source_asset_id,provider,model,prompt_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)').bind(id,String(b.book_id),jt,'QUEUED',b.source_asset_id||null,String(b.provider||'Caelomere Celestial Core'),String(b.model||''),String(b.prompt_version||'v1'),now()).run();await audit(env,'job',id,'QUEUED',actor,{book_id:b.book_id,job_type:jt});return json({ok:true,id,status:'QUEUED'},201);
 }
 if(p.startsWith('/api/library/jobs/')&&request.method==='GET'){const id=p.split('/').pop();const x=await env.DB.prepare('SELECT * FROM library_jobs WHERE id=?').bind(id).first();return x?json({ok:true,item:x}):json({error:'not_found'},404);}
 if(p==='/api/library/publish/request'&&request.method==='POST'){
  const b=await body(request);if(!b?.book_id||!b?.destination)return json({error:'book_id_and_destination_required'},400);const r=await rights(env,String(b.book_id));if(!r||!ALLOWED_RIGHTS.has(r.rights_status))return json({error:'rights_gate_blocked'},403);const perms=JSON.parse(r.permissions_json||'{}');if(b.monetise===true&&perms.monetise!==true)return json({error:'monetisation_not_permitted'},403);const id=uid();await env.DB.prepare('INSERT INTO library_publish_requests(id,book_id,destination,monetise,status,requested_by,created_at) VALUES(?,?,?,?,?,?,?)').bind(id,String(b.book_id),String(b.destination),b.monetise===true?1:0,'PENDING',actor,now()).run();await audit(env,'publish',id,'REQUESTED',actor,b);return json({ok:true,id,status:'PENDING'},201);
 }
 if(p==='/api/library/publish/approve'&&request.method==='POST'){
  const b=await body(request);if(!b?.request_id)return json({error:'request_id_required'},400);const req=await env.DB.prepare('SELECT * FROM library_publish_requests WHERE id=?').bind(String(b.request_id)).first();if(!req)return json({error:'not_found'},404);const r=await rights(env,req.book_id);if(!r||!ALLOWED_RIGHTS.has(r.rights_status))return json({error:'rights_gate_blocked'},403);await env.DB.prepare('UPDATE library_publish_requests SET status=?,approved_by=?,approved_at=? WHERE id=?').bind('APPROVED',actor,now(),String(b.request_id)).run();await audit(env,'publish',String(b.request_id),'APPROVED',actor,{});return json({ok:true,status:'APPROVED'});
 }
 if(p==='/api/library/analytics/summary'&&request.method==='GET'){
  const books=await env.DB.prepare('SELECT COUNT(*) c FROM library_books').first(),ready=await env.DB.prepare("SELECT COUNT(*) c FROM library_rights WHERE rights_status IN ('PUBLIC_DOMAIN_VERIFIED','AUTHOR_PERMISSION_VERIFIED','PUBLISHER_PERMISSION_VERIFIED','LICENSE_VERIFIED')").first(),jobs=await env.DB.prepare('SELECT COUNT(*) c FROM library_jobs').first(),pub=await env.DB.prepare("SELECT COUNT(*) c FROM library_publish_requests WHERE status='APPROVED'").first(),rev=await env.DB.prepare('SELECT COALESCE(SUM(revenue_minor),0) v FROM library_events').first();return json({ok:true,books:Number(books?.c||0),rights_ready:Number(ready?.c||0),jobs:Number(jobs?.c||0),approved_publish:Number(pub?.c||0),revenue_minor:Number(rev?.v||0)});
 }
 return json({error:'not_found'},404);
}
