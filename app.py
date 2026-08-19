from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, uuid, hashlib, secrets, datetime, os

DB=os.path.join(os.path.dirname(__file__),"zorvian.db")
app=FastAPI(title="Zorvian Core API",version="0.8.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z")
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db(); cur=c.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,tenant_id TEXT,email TEXT UNIQUE,password_hash TEXT,role TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT,expires_at TEXT);
    CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT,contact TEXT,need TEXT,source TEXT,score INTEGER,created_at TEXT);
    CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,tenant_id TEXT,title TEXT,owner TEXT,due TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS bookings(id TEXT PRIMARY KEY,tenant_id TEXT,contact_id TEXT,type TEXT,date TEXT,time TEXT,reminder TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,tenant_id TEXT,type TEXT,recipient TEXT,body TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY,tenant_id TEXT,channel TEXT,goal TEXT,audience TEXT,content TEXT,mode TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS routes(id TEXT PRIMARY KEY,tenant_id TEXT,start TEXT,end TEXT,mode TEXT,notes TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS freight_jobs(id TEXT PRIMARY KEY,tenant_id TEXT,ref TEXT,collection TEXT,delivery TEXT,vehicle TEXT,notes TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS video_projects(id TEXT PRIMARY KEY,tenant_id TEXT,project TEXT,source TEXT,output TEXT,brief TEXT,plan TEXT,status TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS freshx_opportunities(
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, product TEXT, owner TEXT,
      market TEXT, stage TEXT, notes TEXT, readiness INTEGER, status TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tenders(
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT, ref TEXT,
      deadline TEXT, value TEXT, requirements TEXT, analysis TEXT, draft TEXT,
      readiness INTEGER, status TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,tenant_id TEXT,user_id TEXT,event TEXT,detail TEXT,severity TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,tenant_id TEXT,provider TEXT,status TEXT,config_json TEXT,created_at TEXT);
    """)
    if cur.execute("SELECT COUNT(*) c FROM tenants").fetchone()["c"]==0:
        tid="tenant_demo"; uid="user_admin"
        cur.execute("INSERT INTO tenants VALUES (?,?,?)",(tid,"Zorvian Demo Tenant",now()))
        cur.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",(uid,tid,"admin@zorvian.local",hashlib.sha256("zorvian-demo".encode()).hexdigest(),"admin",now()))
        for p in ["telephony","sms","email","calendar","social","maps","payments","travel","vehicle_data","video_render","tender_feeds","freshx_commercial_data"]:
            cur.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),tid,p,"not_connected","{}",now()))
    c.commit(); c.close()
init_db()

class LoginIn(BaseModel): email:str; password:str
class ContactIn(BaseModel): name:str; contact:str; need:str=""; source:str="manual"
class ReceptionIn(BaseModel): name:str; contact:str; text:str; language:str="English"
class BookingIn(BaseModel): contact_id:str; type:str="Appointment"; date:str; time:str; reminder:str="24 hours before"
class TaskIn(BaseModel): title:str; owner:str="Team"; due:str=""
class DocumentIn(BaseModel): type:str; recipient:str; facts:str
class CampaignIn(BaseModel): channel:str; goal:str; audience:str=""; message:str; mode:str="Approval required"
class RouteIn(BaseModel): start:str; end:str; mode:str; notes:str=""
class FreightIn(BaseModel): ref:str; collection:str; delivery:str; vehicle:str; notes:str=""
class VideoIn(BaseModel): project:str; source:str; output:str; brief:str
class FreshXIn(BaseModel):
    product:str
    owner:str
    market:str
    stage:str="Qualification"
    notes:str=""
class TenderIn(BaseModel):
    title:str
    ref:str
    deadline:str
    value:str=""
    requirements:str

def current_user(authorization:Optional[str]=Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Missing bearer token")
    token=authorization.split(" ",1)[1]; c=db()
    r=c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?",(token,now())).fetchone(); c.close()
    if not r: raise HTTPException(401,"Invalid or expired session")
    return dict(r)
def require(u,a):
    rights={"admin":{"write","approve","export","admin"},"principal":{"write","approve","export"},"staff":{"write"},"viewer":set()}
    if a not in rights.get(u["role"],set()): raise HTTPException(403,"Role does not permit this action")
def audit(u,e,d="",sev="info"):
    c=db(); c.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],u["id"],e,d,sev,now())); c.commit(); c.close()
def score(t):
    s=30; x=t.lower()
    for k in ["urgent","today","tomorrow","quote","price","book","appointment","need","buy","lease","demo","loan","money","funding","finance","purchase","reserve"]:
        if k in x: s+=5
    return min(99,s)

@app.get("/")
def root(): return {"service":"Zorvian Core API","version":"0.8.0","status":"online"}
@app.get("/health")
def health(): return {"status":"ok","database":"sqlite","external_integrations":"gated"}

@app.post("/auth/login")
def login(d:LoginIn):
    c=db(); r=c.execute("SELECT * FROM users WHERE email=? AND password_hash=?",(d.email.lower(),hashlib.sha256(d.password.encode()).hexdigest())).fetchone()
    if not r: c.close(); raise HTTPException(401,"Invalid login")
    token=secrets.token_urlsafe(32); exp=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=12)).isoformat().replace("+00:00","Z")
    c.execute("INSERT INTO sessions VALUES (?,?,?)",(token,r["id"],exp)); c.commit(); c.close()
    return {"token":token,"role":r["role"],"tenant_id":r["tenant_id"]}

@app.get("/integrations")
def integrations(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT provider,status FROM integrations WHERE tenant_id=? ORDER BY provider",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]

@app.get("/contacts")
def contacts(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM contacts WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/contacts")
def add_contact(d:ContactIn,u=Depends(current_user)):
    require(u,"write"); item=(str(uuid.uuid4()),u["tenant_id"],d.name,d.contact,d.need,d.source,score(d.need),now())
    c=db(); c.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)",item); c.commit(); c.close(); audit(u,"contact_created",d.name)
    return {"id":item[0],"score":item[6]}

@app.post("/reception/process")
def reception(d:ReceptionIn,u=Depends(current_user)):
    require(u,"write"); t=d.text.lower()
    if any(x in t for x in ["loan","money","finance","funding","credit","borrow","mortgage","capital"]):
        intent,route,reply="finance_funding","Finance Enquiries",f"Thanks, {d.name}. Are you looking for personal or business funding, roughly how much do you need, and what is it for?"
    elif any(x in t for x in ["book","appointment","reserve","availability","calendar","meeting"]):
        intent,route,reply="booking","Bookings Team",f"Thanks, {d.name}. What date and time would you prefer, and what are you looking to book?"
    elif any(x in t for x in ["quote","price","cost","buy","purchase","lease","sales"]):
        intent,route,reply="sales","Sales Team",f"Thanks, {d.name}. Tell me what you need, your timing and any budget or specification you have."
    else:
        intent,route,reply="general","Reception Team",f"Thanks, {d.name}. What outcome are you looking for so I can route this correctly?"
    cid,tid=str(uuid.uuid4()),str(uuid.uuid4()); c=db()
    c.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)",(cid,u["tenant_id"],d.name,d.contact,d.text,"Receptionist",score(d.text),now()))
    c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(tid,u["tenant_id"],f"{route}: follow up {d.name}",route,datetime.date.today().isoformat(),"Open",now()))
    c.commit(); c.close(); audit(u,"reception_processed",f"{d.name} · {intent}")
    return {"reply":reply,"intent":intent,"route":route,"contact_id":cid,"task_id":tid,"lead_score":score(d.text)}

@app.get("/bookings")
def bookings(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM bookings WHERE tenant_id=? ORDER BY date,time",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/bookings")
def add_booking(d:BookingIn,u=Depends(current_user)):
    require(u,"write"); c=db()
    contact=c.execute("SELECT * FROM contacts WHERE id=? AND tenant_id=?",(d.contact_id,u["tenant_id"])).fetchone()
    if not contact: c.close(); raise HTTPException(404,"Contact not found")
    dup=c.execute("SELECT id FROM bookings WHERE tenant_id=? AND contact_id=? AND date=? AND time=? AND status!='Cancelled'",(u["tenant_id"],d.contact_id,d.date,d.time)).fetchone()
    if dup: c.close(); raise HTTPException(409,"Duplicate booking")
    bid=str(uuid.uuid4())
    c.execute("INSERT INTO bookings VALUES (?,?,?,?,?,?,?,?,?)",(bid,u["tenant_id"],d.contact_id,d.type,d.date,d.time,d.reminder,"Confirmed",now()))
    c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],f"Send booking confirmation to {contact['name']}","Automation",d.date,"Open",now()))
    c.commit(); c.close(); audit(u,"booking_created",f"{contact['name']} · {d.date} {d.time}")
    return {"id":bid,"status":"Confirmed","notification":"queued_internal"}

@app.get("/tasks")
def tasks(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM tasks WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/tasks")
def add_task(d:TaskIn,u=Depends(current_user)):
    require(u,"write"); tid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(tid,u["tenant_id"],d.title,d.owner,d.due,"Open",now())); c.commit(); c.close(); audit(u,"task_created",d.title); return {"id":tid,"status":"Open"}

@app.post("/documents")
def add_document(d:DocumentIn,u=Depends(current_user)):
    require(u,"write"); body=f"{d.type.upper()}\n\nPrepared for: {d.recipient}\n\nCONFIRMED SOURCE INFORMATION\n{d.facts}\n\nCONTROL STATUS\nDRAFT — principal approval required before external use."
    did=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?)",(did,u["tenant_id"],d.type,d.recipient,body,"Draft",now())); c.commit(); c.close(); audit(u,"document_created",d.recipient); return {"id":did,"body":body,"status":"Draft"}
@app.post("/documents/{doc_id}/approve")
def approve_document(doc_id:str,u=Depends(current_user)):
    require(u,"approve"); c=db(); r=c.execute("SELECT id FROM documents WHERE id=? AND tenant_id=?",(doc_id,u["tenant_id"])).fetchone()
    if not r: c.close(); raise HTTPException(404,"Document not found")
    c.execute("UPDATE documents SET status='Principal Approved' WHERE id=?",(doc_id,)); c.commit(); c.close(); audit(u,"document_approved",doc_id); return {"id":doc_id,"status":"Principal Approved"}

@app.post("/campaigns")
def add_campaign(d:CampaignIn,u=Depends(current_user)):
    require(u,"write"); content=f"CAMPAIGN: {d.goal}\n\nCHANNEL\n{d.channel}\n\nAUDIENCE\n{d.audience}\n\nMESSAGE\n{d.message}\n\nCALL TO ACTION\nBook, enquire or contact us."
    cid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?)",(cid,u["tenant_id"],d.channel,d.goal,d.audience,content,d.mode,"Draft",now())); c.commit(); c.close(); audit(u,"campaign_created",d.goal); return {"id":cid,"content":content,"status":"Draft"}

@app.post("/routes")
def add_route(d:RouteIn,u=Depends(current_user)):
    require(u,"write"); rid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO routes VALUES (?,?,?,?,?,?,?,?)",(rid,u["tenant_id"],d.start,d.end,d.mode,d.notes,"Planned locally",now())); c.commit(); c.close(); audit(u,"route_created",f"{d.start} → {d.end}"); return {"id":rid,"status":"Planned locally","live_mapping":"not_connected"}

@app.post("/freight")
def add_freight(d:FreightIn,u=Depends(current_user)):
    require(u,"write"); fid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO freight_jobs VALUES (?,?,?,?,?,?,?,?,?)",(fid,u["tenant_id"],d.ref,d.collection,d.delivery,d.vehicle,d.notes,"Unassigned",now())); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],f"Assign vehicle/driver for {d.ref}","Fleet Operations",datetime.date.today().isoformat(),"Open",now())); c.commit(); c.close(); audit(u,"freight_created",d.ref); return {"id":fid,"status":"Unassigned"}

@app.post("/video")
def add_video(d:VideoIn,u=Depends(current_user)):
    require(u,"write"); plan=f"PROJECT\n{d.project}\n\nSOURCE\n{d.source}\n\nTARGET OUTPUT\n{d.output}\n\nOBJECTIVE\n{d.brief}\n\nPRODUCTION PLAN\n1. Ingest and index source.\n2. Select strongest scenes.\n3. Build structured edit.\n4. Create captions/title cards.\n5. Produce platform variants.\n6. Apply brand package.\n7. Human review before export."
    vid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO video_projects VALUES (?,?,?,?,?,?,?,?,?)",(vid,u["tenant_id"],d.project,d.source,d.output,d.brief,plan,"Draft",now())); c.commit(); c.close(); audit(u,"video_plan_created",d.project); return {"id":vid,"plan":plan,"status":"Draft"}

@app.get("/freshx")
def freshx_list(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM freshx_opportunities WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close()
    return [dict(x) for x in rows]

@app.post("/freshx")
def freshx_create(d:FreshXIn,u=Depends(current_user)):
    require(u,"write")
    low=d.notes.lower(); readiness=20
    for k in ["rights","supply","grower","specification","freight","compliance","price","retailer","certification"]:
        if k in low: readiness+=7
    readiness=min(90,readiness)
    fid=str(uuid.uuid4())
    c=db(); c.execute("INSERT INTO freshx_opportunities VALUES (?,?,?,?,?,?,?,?,?,?)",(fid,u["tenant_id"],d.product,d.owner,d.market,d.stage,d.notes,readiness,"Working",now()))
    c.commit(); c.close(); audit(u,"freshx_opportunity_created",f"{d.product} · {d.stage}")
    return {"id":fid,"readiness":readiness,"status":"Working"}

@app.post("/freshx/{freshx_id}/approve")
def freshx_approve(freshx_id:str,u=Depends(current_user)):
    require(u,"approve")
    c=db(); row=c.execute("SELECT id FROM freshx_opportunities WHERE id=? AND tenant_id=?",(freshx_id,u["tenant_id"])).fetchone()
    if not row: c.close(); raise HTTPException(404,"FreshX opportunity not found")
    c.execute("UPDATE freshx_opportunities SET status='Stage Approved' WHERE id=?",(freshx_id,)); c.commit(); c.close(); audit(u,"freshx_stage_approved",freshx_id)
    return {"id":freshx_id,"status":"Stage Approved"}

@app.get("/tenders")
def tender_list(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM tenders WHERE tenant_id=? ORDER BY deadline,created_at DESC",(u["tenant_id"],)).fetchall(); c.close()
    return [dict(x) for x in rows]

@app.post("/tenders/analyse")
def tender_analyse(d:TenderIn,u=Depends(current_user)):
    require(u,"write")
    text=d.requirements.lower()
    signals=["insurance","turnover","experience","references","policy","certificate","method statement","social value","pricing","gdpr","security","quality","environment","health and safety"]
    found=[k for k in signals if k in text]; gaps=[k for k in signals if k not in text][:6]
    readiness=min(85,25+len(found)*4)
    analysis=f"""TENDER ANALYSIS\n\nTENDER\n{d.title}\n\nREFERENCE\n{d.ref}\n\nDEADLINE\n{d.deadline}\n\nESTIMATED VALUE\n{d.value or 'Not supplied'}\n\nREQUIREMENT SIGNALS DETECTED\n{', '.join(found) if found else 'No standard evidence signals detected automatically.'}\n\nPOTENTIAL EVIDENCE / REVIEW GAPS\n{chr(10).join('• Check '+x for x in gaps)}\n\nCONTROL WORKFLOW\n1. Confirm eligibility and go/no-go.\n2. Build requirement/question matrix.\n3. Map requirements to verified company evidence.\n4. Flag missing evidence or professional confirmations.\n5. Draft using confirmed facts only.\n6. Commercial/legal/regulatory review.\n7. Principal approval.\n8. Submit only through an authorised channel.\n"""
    tid=str(uuid.uuid4())
    c=db(); c.execute("INSERT INTO tenders VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(tid,u["tenant_id"],d.title,d.ref,d.deadline,d.value,d.requirements,analysis,"",readiness,"Analysed",now()))
    c.commit(); c.close(); audit(u,"tender_analysed",f"{d.title} · {d.ref}")
    return {"id":tid,"analysis":analysis,"readiness":readiness,"status":"Analysed"}

@app.post("/tenders/{tender_id}/draft")
def tender_draft(tender_id:str,u=Depends(current_user)):
    require(u,"write")
    c=db(); t=c.execute("SELECT * FROM tenders WHERE id=? AND tenant_id=?",(tender_id,u["tenant_id"])).fetchone()
    if not t: c.close(); raise HTTPException(404,"Tender not found")
    draft=f"""EXECUTIVE RESPONSE — WORKING DRAFT\n\nBuyer / Tender: {t['title']}\nReference: {t['ref']}\n\n1. UNDERSTANDING OF REQUIREMENT\nWe have reviewed the supplied requirements and will respond against the buyer's stated outcomes and evidence requirements.\n\n2. DELIVERY APPROACH\n[Insert verified delivery method, resources, timescales and governance.]\n\n3. EXPERIENCE AND EVIDENCE\n[Insert verified case studies, references, accreditations and supporting documents.]\n\n4. QUALITY / RISK / COMPLIANCE\n[Insert only confirmed policies, certifications, insurance and compliance statements.]\n\n5. COMMERCIAL RESPONSE\n[Insert authorised pricing, assumptions and exclusions.]\n\nCONTROL STATUS\nWORKING DRAFT — NOT FOR SUBMISSION.\n"""
    readiness=min(92,int(t["readiness"] or 0)+10)
    c.execute("UPDATE tenders SET draft=?,readiness=?,status='Draft' WHERE id=?",(draft,readiness,tender_id)); c.commit(); c.close(); audit(u,"tender_response_drafted",tender_id)
    return {"id":tender_id,"draft":draft,"readiness":readiness,"status":"Draft"}

@app.post("/tenders/{tender_id}/approve")
def tender_approve(tender_id:str,u=Depends(current_user)):
    require(u,"approve")
    c=db(); t=c.execute("SELECT * FROM tenders WHERE id=? AND tenant_id=?",(tender_id,u["tenant_id"])).fetchone()
    if not t: c.close(); raise HTTPException(404,"Tender not found")
    if not t["draft"]: c.close(); raise HTTPException(409,"Create tender draft before approval")
    c.execute("UPDATE tenders SET readiness=100,status='Principal Approved' WHERE id=?",(tender_id,)); c.commit(); c.close(); audit(u,"tender_principal_approved",tender_id)
    return {"id":tender_id,"readiness":100,"status":"Principal Approved"}

@app.get("/audit")
def audit_log(u=Depends(current_user)):
    c=db(); rows=c.execute("SELECT * FROM audit WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
