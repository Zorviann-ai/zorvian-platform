from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Any
import os, sqlite3, uuid, datetime, json
import httpx

APP_VERSION='2.0.0'
DB=os.getenv('SQLITE_PATH','zorvian_v2.db')
ALLOWED_ORIGINS=[x.strip() for x in os.getenv('ALLOWED_ORIGINS','https://zorvian.co.uk,https://www.zorvian.co.uk,http://localhost:3000').split(',') if x.strip()]
app=FastAPI(title='Zorvian Provider Mesh API',version=APP_VERSION)
app.add_middleware(CORSMiddleware,allow_origins=ALLOWED_ORIGINS,allow_methods=['*'],allow_headers=['*'])

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, tenant_id TEXT, action TEXT, payload TEXT, status TEXT, requested_at TEXT, approved_at TEXT, approved_by TEXT);
    CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY, tenant_id TEXT, event TEXT, detail TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, tenant_id TEXT, service TEXT, provider TEXT, status TEXT, request TEXT, response TEXT, created_at TEXT, updated_at TEXT);
    '''); c.commit(); c.close()
init_db()

def tenant(x_tenant_id: Optional[str]=Header(None)):
    return x_tenant_id or 'demo-tenant'

def audit(tenant_id,event,detail):
    c=db(); c.execute('INSERT INTO audit VALUES(?,?,?,?,?)',(str(uuid.uuid4()),tenant_id,event,json.dumps(detail)[:5000],now())); c.commit(); c.close()

class Action(BaseModel):
    service:str
    operation:str
    payload:dict[str,Any]=Field(default_factory=dict)
    approval_id:Optional[str]=None
class ApprovalIn(BaseModel):
    action:str
    payload:dict[str,Any]=Field(default_factory=dict)
class ApprovalDecision(BaseModel):
    approved_by:str='principal'

PROVIDERS={
 'ai': {'primary':'openai','fallback':'anthropic','env':['OPENAI_API_KEY'],'why':'Orchestration, structured outputs, realtime voice and multimodal intelligence.'},
 'voice': {'primary':'twilio','fallback':'telnyx','env':['TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN'],'why':'Programmable voice, call routing, conferencing, recording and messaging.'},
 'messaging': {'primary':'twilio','fallback':'meta_whatsapp','env':['TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN'],'why':'SMS + WhatsApp in one channel layer, with Meta-native option for scale.'},
 'email': {'primary':'resend','fallback':'smtp','env':['RESEND_API_KEY'],'why':'Transactional email with simple API, delivery events and domain controls.'},
 'travel_flights': {'primary':'duffel','fallback':'amadeus','env':['DUFFEL_ACCESS_TOKEN'],'why':'Modern flight shopping/booking API; Amadeus fallback for broader travel data.'},
 'travel_stays': {'primary':'duffel','fallback':'expedia_rapid','env':['DUFFEL_ACCESS_TOKEN'],'why':'Search, quote and book stays; Expedia Rapid is ideal as a high-supply secondary source.'},
 'routing': {'primary':'here','fallback':'tomtom','env':['HERE_API_KEY'],'why':'Enterprise routing, traffic and geocoding with TomTom resilience.'},
 'video': {'primary':'heygen','fallback':'openai_video','env':['HEYGEN_API_KEY'],'why':'Presenter/avatar video and multilingual production; generative video fallback.'},
 'audio': {'primary':'elevenlabs','fallback':'openai_audio','env':['ELEVENLABS_API_KEY'],'why':'High-quality branded voices, dubbing and narration with realtime AI fallback.'},
 'social': {'primary':'native_platform_apis','fallback':'buffer','env':[],'why':'Publish via official Meta/LinkedIn/TikTok/X APIs, with aggregator fallback where appropriate.'},
 'calendar': {'primary':'zorvian_calendar','fallback':'microsoft_graph','env':[],'why':'Zorvian-owned scheduling first; optional external calendar sync.'},
 'documents': {'primary':'openai','fallback':'anthropic','env':['OPENAI_API_KEY'],'why':'Structured drafting, extraction, tender analysis and business document generation.'},
 'guardian': {'primary':'zorvian_guardian','fallback':'cloudflare','env':[],'why':'Internal policy/audit layer with edge security and bot/WAF protection.'}
}

MUTATING_OPS={'book','purchase','send','publish','call','reserve','cancel','submit','create_order','create_booking','render','generate_final'}
def needs_approval(operation:str)->bool: return operation.lower() in MUTATING_OPS

def approval_ok(tenant_id,approval_id,action):
    if not approval_id: return False
    c=db(); r=c.execute('SELECT * FROM approvals WHERE id=? AND tenant_id=?',(approval_id,tenant_id)).fetchone(); c.close()
    return bool(r and r['status']=='approved' and r['action']==action)

@app.get('/')
def root(): return {'service':'Zorvian Provider Mesh','version':APP_VERSION,'status':'online','approval_enforcement':'server-side'}
@app.get('/health')
def health(): return {'status':'ok','version':APP_VERSION,'providers':{k:{'primary':v['primary'],'configured':all(os.getenv(e) for e in v['env']) if v['env'] else True} for k,v in PROVIDERS.items()}}
@app.get('/v2/providers')
def providers(): return {k:{**v,'configured':all(os.getenv(e) for e in v['env']) if v['env'] else True} for k,v in PROVIDERS.items()}

@app.post('/v2/approvals')
def request_approval(body:ApprovalIn,tenant_id:str=Depends(tenant)):
    aid=str(uuid.uuid4()); c=db(); c.execute('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)',(aid,tenant_id,body.action,json.dumps(body.payload),'pending',now(),None,None)); c.commit(); c.close(); audit(tenant_id,'approval.requested',{'id':aid,'action':body.action}); return {'approval_id':aid,'status':'pending'}
@app.post('/v2/approvals/{approval_id}/approve')
def approve(approval_id:str,body:ApprovalDecision,tenant_id:str=Depends(tenant)):
    c=db(); r=c.execute('SELECT * FROM approvals WHERE id=? AND tenant_id=?',(approval_id,tenant_id)).fetchone()
    if not r: c.close(); raise HTTPException(404,'Approval not found')
    c.execute('UPDATE approvals SET status=?,approved_at=?,approved_by=? WHERE id=?',('approved',now(),body.approved_by,approval_id)); c.commit(); c.close(); audit(tenant_id,'approval.approved',{'id':approval_id,'by':body.approved_by}); return {'approval_id':approval_id,'status':'approved'}

async def call_provider(service:str,operation:str,payload:dict):
    if service in ('travel_flights','travel_stays') and os.getenv('DUFFEL_ACCESS_TOKEN'):
        headers={'Authorization':f"Bearer {os.getenv('DUFFEL_ACCESS_TOKEN')}",'Duffel-Version':'v2','Accept':'application/json','Content-Type':'application/json'}
        async with httpx.AsyncClient(timeout=40) as client:
            if service=='travel_flights' and operation=='search':
                r=await client.post('https://api.duffel.com/air/offer_requests',headers=headers,json={'data':payload}); r.raise_for_status(); return r.json()
            if service=='travel_stays' and operation=='search':
                r=await client.post('https://api.duffel.com/stays/search',headers=headers,json={'data':payload}); r.raise_for_status(); return r.json()
    if service=='routing' and os.getenv('HERE_API_KEY') and operation=='route':
        params={**payload,'apikey':os.getenv('HERE_API_KEY')}
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.get('https://router.hereapi.com/v8/routes',params=params); r.raise_for_status(); return r.json()
    if service=='email' and os.getenv('RESEND_API_KEY') and operation=='send':
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.post('https://api.resend.com/emails',headers={'Authorization':f"Bearer {os.getenv('RESEND_API_KEY')}",'Content-Type':'application/json'},json=payload); r.raise_for_status(); return r.json()
    if service=='video' and os.getenv('HEYGEN_API_KEY') and operation in ('render','generate_final'):
        async with httpx.AsyncClient(timeout=60) as client:
            r=await client.post('https://api.heygen.com/v2/video/generate',headers={'X-Api-Key':os.getenv('HEYGEN_API_KEY'),'Content-Type':'application/json'},json=payload); r.raise_for_status(); return r.json()
    return {'status':'connector_ready','live_call_made':False,'service':service,'operation':operation,'provider':PROVIDERS.get(service,{}).get('primary'),'reason':'Provider credential or mapped operation not configured yet','payload_received':payload}

@app.post('/v2/execute')
async def execute(body:Action,tenant_id:str=Depends(tenant)):
    if body.service not in PROVIDERS: raise HTTPException(404,'Unknown service')
    action=f'{body.service}:{body.operation}'
    if needs_approval(body.operation) and not approval_ok(tenant_id,body.approval_id,action):
        raise HTTPException(409,{'code':'APPROVAL_REQUIRED','message':'Principal/client approval is required before this external action','action':action})
    jid=str(uuid.uuid4()); c=db(); c.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',(jid,tenant_id,body.service,PROVIDERS[body.service]['primary'],'running',json.dumps(body.payload),None,now(),now())); c.commit(); c.close()
    try:
        result=await call_provider(body.service,body.operation,body.payload)
        c=db(); c.execute('UPDATE jobs SET status=?,response=?,updated_at=? WHERE id=?',('completed',json.dumps(result)[:500000],now(),jid)); c.commit(); c.close(); audit(tenant_id,'service.executed',{'job_id':jid,'service':body.service,'operation':body.operation}); return {'job_id':jid,'provider':PROVIDERS[body.service]['primary'],'result':result}
    except httpx.HTTPStatusError as e:
        detail=e.response.text[:2000]; c=db(); c.execute('UPDATE jobs SET status=?,response=?,updated_at=? WHERE id=?',('failed',detail,now(),jid)); c.commit(); c.close(); audit(tenant_id,'provider.error',{'job_id':jid,'status':e.response.status_code,'detail':detail}); raise HTTPException(502,'Provider request failed')

@app.get('/v2/jobs/{job_id}')
def get_job(job_id:str,tenant_id:str=Depends(tenant)):
    c=db(); r=c.execute('SELECT * FROM jobs WHERE id=? AND tenant_id=?',(job_id,tenant_id)).fetchone(); c.close()
    if not r: raise HTTPException(404,'Job not found')
    return dict(r)
