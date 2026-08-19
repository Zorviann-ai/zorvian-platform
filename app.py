from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import sqlite3, uuid, hashlib, secrets, datetime, os, re, smtplib, ssl, base64, hmac, struct, time
from email.message import EmailMessage

APP_VERSION="0.9.0"
ENV=os.getenv("ZORVIAN_ENV","production").lower()
DB=os.getenv("SQLITE_PATH",os.path.join(os.path.dirname(__file__),"zorvian.db"))
SESSION_HOURS=int(os.getenv("SESSION_HOURS","12")); LOCKOUT_MINUTES=int(os.getenv("LOCKOUT_MINUTES","15")); MAX_FAILED_LOGINS=int(os.getenv("MAX_FAILED_LOGINS","5"))
ALLOWED_ORIGINS=[x.strip() for x in os.getenv("ALLOWED_ORIGINS","https://zorvian.co.uk,https://www.zorvian.co.uk").split(",") if x.strip()]
ph=PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1)
app=FastAPI(title="Zorvian Core API",version=APP_VERSION,docs_url=None if ENV=="production" else "/docs",redoc_url=None if ENV=="production" else "/redoc")
app.add_middleware(CORSMiddleware,allow_origins=ALLOWED_ORIGINS,allow_credentials=False,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","X-Request-ID"])

def now_dt(): return datetime.datetime.now(datetime.timezone.utc)
def now(): return now_dt().isoformat().replace("+00:00","Z")
def future(minutes=0,hours=0,days=0): return (now_dt()+datetime.timedelta(minutes=minutes,hours=hours,days=days)).isoformat().replace("+00:00","Z")
def db():
 c=sqlite3.connect(DB,timeout=20); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL"); return c
def columns(c,t): return {r["name"] for r in c.execute(f"PRAGMA table_info({t})").fetchall()}
def add_column(c,t,d):
 n=d.split()[0]
 if n not in columns(c,t): c.execute(f"ALTER TABLE {t} ADD COLUMN {d}")
def init_db():
 c=db(); cur=c.cursor(); cur.executescript("""
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
 CREATE TABLE IF NOT EXISTS freshx_opportunities(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,product TEXT,owner TEXT,market TEXT,stage TEXT,notes TEXT,readiness INTEGER,status TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS tenders(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,title TEXT,ref TEXT,deadline TEXT,value TEXT,requirements TEXT,analysis TEXT,draft TEXT,readiness INTEGER,status TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,tenant_id TEXT,user_id TEXT,event TEXT,detail TEXT,severity TEXT,created_at TEXT);
 CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,tenant_id TEXT,provider TEXT,status TEXT,config_json TEXT,created_at TEXT);
 CREATE TABLE IF NOT EXISTS secure_sessions(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,user_id TEXT NOT NULL,tenant_id TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,ip_hash TEXT,user_agent_hash TEXT,revoked_at TEXT);
 CREATE TABLE IF NOT EXISTS email_verifications(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,used_at TEXT,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS password_resets(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,used_at TEXT,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,email TEXT NOT NULL,role TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,accepted_at TEXT,created_by TEXT,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS security_events(id TEXT PRIMARY KEY,tenant_id TEXT,user_id TEXT,event TEXT,severity TEXT,ip_hash TEXT,detail TEXT,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS rate_limits(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,window_start TEXT NOT NULL);
 """)
 for d in ["display_name TEXT","email_verified INTEGER NOT NULL DEFAULT 0","mfa_secret TEXT","mfa_enabled INTEGER NOT NULL DEFAULT 0","status TEXT NOT NULL DEFAULT 'active'","failed_attempts INTEGER NOT NULL DEFAULT 0","locked_until TEXT","last_login_at TEXT","password_changed_at TEXT"]: add_column(c,"users",d)
 for d in ["slug TEXT","status TEXT NOT NULL DEFAULT 'active'","plan TEXT NOT NULL DEFAULT 'gate2'","owner_user_id TEXT"]: add_column(c,"tenants",d)
 if ENV=="production": cur.execute("UPDATE users SET status='disabled' WHERE email='admin@zorvian.local'")
 c.commit(); c.close()
init_db()

def norm_email(v):
 e=v.strip().lower()
 if len(e)>254 or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$",e): raise HTTPException(422,"Enter a valid email address")
 return e
def validate_password(p):
 if len(p)<12: raise HTTPException(422,"Password must be at least 12 characters")
 if len(p)>128: raise HTTPException(422,"Password is too long")
 if p.lower() in {"password1234","zorvian-demo","letmein123456"}: raise HTTPException(422,"Choose a stronger password")
 return p
def hash_password(p): return ph.hash(p)
def verify_password(stored,supplied):
 try: return ph.verify(stored,supplied)
 except (VerifyMismatchError,InvalidHashError,Exception): return False
def hash_token(t): return hashlib.sha256(t.encode()).hexdigest()
def totp_code(secret,for_time=None):
 t=int(for_time if for_time is not None else time.time())//30; padded=secret+'='*((8-len(secret)%8)%8); key=base64.b32decode(padded,casefold=True); digest=hmac.new(key,struct.pack('>Q',t),hashlib.sha1).digest(); off=digest[-1]&0x0f; n=(struct.unpack('>I',digest[off:off+4])[0]&0x7fffffff)%1000000; return f"{n:06d}"
def verify_totp(secret,code):
 if not code or not re.fullmatch(r"\d{6}",str(code)): return False
 ts=int(time.time()); return any(hmac.compare_digest(totp_code(secret,ts+x*30),str(code)) for x in (-1,0,1))
def privacy_hash(v):
 if not v:return None
 return hashlib.sha256((os.getenv("GUARDIAN_HASH_PEPPER","change-me-in-railway")+v).encode()).hexdigest()
def request_fingerprint(req):
 ip=req.client.host if req.client else "unknown"; ua=req.headers.get("user-agent","")[:500]; return privacy_hash(ip),privacy_hash(ua)
def security_event(event,severity="info",tenant_id=None,user_id=None,detail="",request=None):
 ip=request_fingerprint(request)[0] if request else None; c=db(); c.execute("INSERT INTO security_events VALUES (?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),tenant_id,user_id,event,severity,ip,detail[:1000],now())); c.commit(); c.close()
def audit(u,e,d="",sev="info"):
 c=db(); c.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],u["id"],e,d[:1000],sev,now())); c.commit(); c.close()
def rate_limit(bucket,limit=10,window_seconds=300):
 c=db(); r=c.execute("SELECT * FROM rate_limits WHERE bucket=?",(bucket,)).fetchone(); n=now_dt()
 if not r: c.execute("INSERT INTO rate_limits VALUES (?,?,?)",(bucket,1,now())); c.commit(); c.close(); return
 start=datetime.datetime.fromisoformat(r["window_start"].replace("Z","+00:00"))
 if (n-start).total_seconds()>=window_seconds: c.execute("UPDATE rate_limits SET count=1,window_start=? WHERE bucket=?",(now(),bucket)); c.commit(); c.close(); return
 if r["count"]>=limit: c.close(); raise HTTPException(429,"Too many attempts. Try again later.")
 c.execute("UPDATE rate_limits SET count=count+1 WHERE bucket=?",(bucket,)); c.commit(); c.close()
def smtp_ready(): return all(os.getenv(x) for x in ["SMTP_HOST","SMTP_USERNAME","SMTP_PASSWORD","SMTP_FROM"])
def send_email(to,subject,text):
 if not smtp_ready(): return False
 msg=EmailMessage(); msg["From"]=os.getenv("SMTP_FROM"); msg["To"]=to; msg["Subject"]=subject; msg.set_content(text); host=os.getenv("SMTP_HOST"); port=int(os.getenv("SMTP_PORT","465")); user=os.getenv("SMTP_USERNAME"); pwd=os.getenv("SMTP_PASSWORD")
 if os.getenv("SMTP_TLS_MODE","ssl").lower()=="starttls":
  with smtplib.SMTP(host,port,timeout=15) as s: s.starttls(context=ssl.create_default_context()); s.login(user,pwd); s.send_message(msg)
 else:
  with smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=15) as s: s.login(user,pwd); s.send_message(msg)
 return True
def issue_email_verification(uid,email):
 raw=secrets.token_urlsafe(32); c=db(); c.execute("INSERT INTO email_verifications VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),uid,hash_token(raw),future(hours=24),None,now())); c.commit(); c.close(); delivered=send_email(email,"Verify your Zorvian account",f"Verify your Zorvian account:\n\nhttps://zorvian.co.uk/?verify={raw}\n\nThis link expires in 24 hours."); return raw,delivered
def issue_session(user,request):
 raw=secrets.token_urlsafe(48); ip,ua=request_fingerprint(request); c=db(); c.execute("INSERT INTO secure_sessions VALUES (?,?,?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),hash_token(raw),user["id"],user["tenant_id"],now(),future(hours=SESSION_HOURS),now(),ip,ua,None)); c.commit(); c.close(); return raw
def current_user(request:Request,authorization:Optional[str]=Header(None)):
 if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Missing bearer token")
 th=hash_token(authorization.split(" ",1)[1]); c=db(); r=c.execute("SELECT u.* FROM secure_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'",(th,now())).fetchone()
 if not r: c.close(); raise HTTPException(401,"Invalid or expired session")
 c.execute("UPDATE secure_sessions SET last_seen_at=? WHERE token_hash=?",(now(),th)); c.commit(); c.close(); return dict(r)
def require(u,a):
 rights={"owner":{"write","approve","export","admin","invite"},"admin":{"write","approve","export","admin","invite"},"principal":{"write","approve","export"},"staff":{"write"},"viewer":set()}
 if a not in rights.get(u["role"],set()): raise HTTPException(403,"Role does not permit this action")
def score(t):
 s=30; x=t.lower()
 for k in ["urgent","today","tomorrow","quote","price","book","appointment","need","buy","lease","demo","loan","money","funding","finance","purchase","reserve"]:
  if k in x:s+=5
 return min(99,s)

class RegisterIn(BaseModel): company_name:str=Field(min_length=2,max_length=120); name:str=Field(min_length=2,max_length=120); email:str; password:str
class VerifyEmailIn(BaseModel): token:str
class LoginIn(BaseModel): email:str; password:str; otp:Optional[str]=None
class ForgotIn(BaseModel): email:str
class ResetIn(BaseModel): token:str; password:str
class MFAEnableIn(BaseModel): code:str
class InviteIn(BaseModel): email:str; role:str="staff"
class AcceptInviteIn(BaseModel): token:str; name:str; password:str
class ContactIn(BaseModel): name:str; contact:str; need:str=""; source:str="manual"
class ReceptionIn(BaseModel): name:str; contact:str; text:str; language:str="English"
class BookingIn(BaseModel): contact_id:str; type:str="Appointment"; date:str; time:str; reminder:str="24 hours before"
class TaskIn(BaseModel): title:str; owner:str="Team"; due:str=""
class DocumentIn(BaseModel): type:str; recipient:str; facts:str
class CampaignIn(BaseModel): channel:str; goal:str; audience:str=""; message:str; mode:str="Approval required"
class RouteIn(BaseModel): start:str; end:str; mode:str; notes:str=""
class FreightIn(BaseModel): ref:str; collection:str; delivery:str; vehicle:str; notes:str=""
class VideoIn(BaseModel): project:str; source:str; output:str; brief:str
class FreshXIn(BaseModel): product:str; owner:str; market:str; stage:str="Qualification"; notes:str=""
class TenderIn(BaseModel): title:str; ref:str; deadline:str; value:str=""; requirements:str

@app.middleware("http")
async def guardian_headers(request,call_next):
 response=await call_next(request); response.headers["X-Content-Type-Options"]="nosniff"; response.headers["X-Frame-Options"]="DENY"; response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"; response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"; response.headers["Cache-Control"]="no-store" if request.url.path.startswith("/auth") else "no-cache"; response.headers["Content-Security-Policy"]="default-src 'none'; frame-ancestors 'none'; base-uri 'none'"; return response
@app.get("/")
def root(): return {"service":"Zorvian Core API","version":APP_VERSION,"status":"online","guardian":"active"}
@app.get("/health")
def health(): return {"status":"ok","database":"sqlite","external_integrations":"gated","guardian":"active","version":APP_VERSION}
@app.post("/auth/register",status_code=201)
def register(d:RegisterIn,request:Request):
 ip,_=request_fingerprint(request); rate_limit("register:"+str(ip),10,3600); email=norm_email(d.email); validate_password(d.password); c=db()
 if c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone(): c.close(); raise HTTPException(409,"An account already exists for this email")
 tid=str(uuid.uuid4()); uid=str(uuid.uuid4()); slug=re.sub(r"[^a-z0-9]+","-",d.company_name.lower()).strip("-")[:50] or "workspace"; base=slug; n=1
 while c.execute("SELECT id FROM tenants WHERE slug=?",(slug,)).fetchone(): n+=1; slug=f"{base}-{n}"
 c.execute("INSERT INTO tenants(id,name,created_at,slug,status,plan,owner_user_id) VALUES (?,?,?,?,?,?,?)",(tid,d.company_name.strip(),now(),slug,"active","gate2",uid)); c.execute("INSERT INTO users(id,tenant_id,email,password_hash,role,created_at,display_name,email_verified,mfa_enabled,status,failed_attempts,password_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(uid,tid,email,hash_password(d.password),"owner",now(),d.name.strip(),0,0,"active",0,now()))
 for p in ["telephony","sms","email","calendar","social","maps","payments","travel","vehicle_data","video_render","tender_feeds","freshx_commercial_data"]: c.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),tid,p,"not_connected","{}",now()))
 c.commit(); c.close(); raw,delivered=issue_email_verification(uid,email); security_event("account_registered","info",tid,uid,"owner account created",request); body={"status":"verification_required","email_delivery":"sent" if delivered else "not_configured","workspace":slug}
 if ENV!="production" and os.getenv("DEV_EXPOSE_TOKENS")=="1": body["verification_token"]=raw
 return body
@app.post("/auth/verify-email")
def verify_email(d:VerifyEmailIn,request:Request):
 c=db(); r=c.execute("SELECT * FROM email_verifications WHERE token_hash=? AND used_at IS NULL AND expires_at>?",(hash_token(d.token),now())).fetchone()
 if not r: c.close(); raise HTTPException(400,"Verification link is invalid or expired")
 u=c.execute("SELECT * FROM users WHERE id=?",(r["user_id"],)).fetchone(); c.execute("UPDATE users SET email_verified=1 WHERE id=?",(r["user_id"],)); c.execute("UPDATE email_verifications SET used_at=? WHERE id=?",(now(),r["id"])); c.commit(); c.close(); security_event("email_verified","info",u["tenant_id"],u["id"],"email verified",request); return {"status":"verified"}
@app.post("/auth/login")
def login(d:LoginIn,request:Request):
 email=norm_email(d.email); ip,_=request_fingerprint(request); rate_limit("login:"+str(ip),30,300); rate_limit("login-email:"+privacy_hash(email),15,300); c=db(); r=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
 if not r or r["status"]!="active": c.close(); security_event("login_failed","warning",None,None,"unknown/disabled account",request); raise HTTPException(401,"Invalid login")
 if r["locked_until"] and r["locked_until"]>now(): c.close(); raise HTTPException(423,"Account temporarily locked")
 if not verify_password(r["password_hash"],d.password):
  attempts=int(r["failed_attempts"] or 0)+1; locked=future(minutes=LOCKOUT_MINUTES) if attempts>=MAX_FAILED_LOGINS else None; c.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",(attempts,locked,r["id"])); c.commit(); c.close(); security_event("login_failed","warning",r["tenant_id"],r["id"],f"failed_attempts={attempts}",request); raise HTTPException(401,"Invalid login")
 if not r["email_verified"]: c.close(); raise HTTPException(403,"Verify your email before signing in")
 if r["mfa_enabled"] and (not d.otp or not verify_totp(r["mfa_secret"],d.otp)): c.close(); security_event("mfa_failed","warning",r["tenant_id"],r["id"],"invalid otp",request); raise HTTPException(401,"MFA code required or invalid")
 c.execute("UPDATE users SET failed_attempts=0,locked_until=NULL,last_login_at=? WHERE id=?",(now(),r["id"])); c.commit(); c.close(); token=issue_session(r,request); security_event("login_success","info",r["tenant_id"],r["id"],"session issued",request); return {"token":token,"role":r["role"],"tenant_id":r["tenant_id"],"name":r["display_name"],"mfa_enabled":bool(r["mfa_enabled"])}
@app.post("/auth/logout")
def logout(request:Request,authorization:Optional[str]=Header(None),u=Depends(current_user)):
 th=hash_token(authorization.split(" ",1)[1]); c=db(); c.execute("UPDATE secure_sessions SET revoked_at=? WHERE token_hash=?",(now(),th)); c.commit(); c.close(); security_event("logout","info",u["tenant_id"],u["id"],"session revoked",request); return {"status":"logged_out"}
@app.get("/auth/me")
def me(u=Depends(current_user)):
 c=db(); t=c.execute("SELECT * FROM tenants WHERE id=?",(u["tenant_id"],)).fetchone(); c.close(); return {"id":u["id"],"name":u["display_name"],"email":u["email"],"role":u["role"],"mfa_enabled":bool(u["mfa_enabled"]),"workspace":{"id":u["tenant_id"],"name":t["name"],"slug":t["slug"],"plan":t["plan"]}}
@app.post("/auth/mfa/setup")
def mfa_setup(u=Depends(current_user)):
 secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="); c=db(); c.execute("UPDATE users SET mfa_secret=?,mfa_enabled=0 WHERE id=?",(secret,u["id"])); c.commit(); c.close(); uri=f"otpauth://totp/Zorvian%20Guardian:{u['email']}?secret={secret}&issuer=Zorvian%20Guardian&digits=6&period=30"; audit(u,"mfa_setup_started"); return {"secret":secret,"otpauth_uri":uri}
@app.post("/auth/mfa/enable")
def mfa_enable(d:MFAEnableIn,request:Request,u=Depends(current_user)):
 c=db(); r=c.execute("SELECT mfa_secret FROM users WHERE id=?",(u["id"],)).fetchone()
 if not r or not r["mfa_secret"] or not verify_totp(r["mfa_secret"],d.code): c.close(); raise HTTPException(400,"Invalid authenticator code")
 c.execute("UPDATE users SET mfa_enabled=1 WHERE id=?",(u["id"],)); c.commit(); c.close(); security_event("mfa_enabled","info",u["tenant_id"],u["id"],"TOTP enabled",request); return {"status":"mfa_enabled"}
@app.post("/auth/forgot-password")
def forgot(d:ForgotIn,request:Request):
 email=norm_email(d.email); rate_limit("forgot:"+privacy_hash(email),5,3600); c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND status='active'",(email,)).fetchone()
 if u:
  raw=secrets.token_urlsafe(32); c.execute("INSERT INTO password_resets VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),u["id"],hash_token(raw),future(hours=1),None,now())); c.commit(); send_email(email,"Reset your Zorvian password",f"Reset your password:\n\nhttps://zorvian.co.uk/?reset={raw}\n\nThis link expires in one hour.")
 c.close(); return {"status":"If the account exists, reset instructions have been sent."}
@app.post("/auth/reset-password")
def reset_password(d:ResetIn,request:Request):
 validate_password(d.password); c=db(); r=c.execute("SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?",(hash_token(d.token),now())).fetchone()
 if not r: c.close(); raise HTTPException(400,"Reset link is invalid or expired")
 u=c.execute("SELECT * FROM users WHERE id=?",(r["user_id"],)).fetchone(); c.execute("UPDATE users SET password_hash=?,password_changed_at=?,failed_attempts=0,locked_until=NULL WHERE id=?",(hash_password(d.password),now(),u["id"])); c.execute("UPDATE password_resets SET used_at=? WHERE id=?",(now(),r["id"])); c.execute("UPDATE secure_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",(now(),u["id"])); c.commit(); c.close(); security_event("password_reset_completed","warning",u["tenant_id"],u["id"],"all sessions revoked",request); return {"status":"password_reset"}
@app.post("/auth/invitations")
def invite(d:InviteIn,u=Depends(current_user)):
 require(u,"invite"); email=norm_email(d.email); role=d.role.lower()
 if role not in {"admin","principal","staff","viewer"}: raise HTTPException(422,"Invalid role")
 raw=secrets.token_urlsafe(32); c=db(); c.execute("INSERT INTO invitations VALUES (?,?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],email,role,hash_token(raw),future(days=7),None,u["id"],now())); c.commit(); c.close(); delivered=send_email(email,"You've been invited to Zorvian",f"Accept your invitation:\n\nhttps://zorvian.co.uk/?invite={raw}\n\nThis invitation expires in 7 days."); audit(u,"user_invited",f"{email} · {role}"); return {"status":"invited","email_delivery":"sent" if delivered else "not_configured"}
@app.post("/auth/invitations/accept")
def accept_invite(d:AcceptInviteIn,request:Request):
 validate_password(d.password); c=db(); inv=c.execute("SELECT * FROM invitations WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?",(hash_token(d.token),now())).fetchone()
 if not inv: c.close(); raise HTTPException(400,"Invitation is invalid or expired")
 if c.execute("SELECT id FROM users WHERE email=?",(inv["email"],)).fetchone(): c.close(); raise HTTPException(409,"Account already exists")
 uid=str(uuid.uuid4()); c.execute("INSERT INTO users(id,tenant_id,email,password_hash,role,created_at,display_name,email_verified,mfa_enabled,status,failed_attempts,password_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(uid,inv["tenant_id"],inv["email"],hash_password(d.password),inv["role"],now(),d.name.strip(),1,0,"active",0,now())); c.execute("UPDATE invitations SET accepted_at=? WHERE id=?",(now(),inv["id"])); c.commit(); c.close(); return {"status":"account_created"}
@app.get("/guardian/status")
def guardian_status(u=Depends(current_user)):
 c=db(); active=c.execute("SELECT COUNT(*) c FROM secure_sessions WHERE tenant_id=? AND revoked_at IS NULL AND expires_at>?",(u["tenant_id"],now())).fetchone()["c"]; verified=c.execute("SELECT COUNT(*) c FROM users WHERE tenant_id=? AND email_verified=1 AND status='active'",(u["tenant_id"],)).fetchone()["c"]; mfa=c.execute("SELECT COUNT(*) c FROM users WHERE tenant_id=? AND mfa_enabled=1 AND status='active'",(u["tenant_id"],)).fetchone()["c"]; total=c.execute("SELECT COUNT(*) c FROM users WHERE tenant_id=? AND status='active'",(u["tenant_id"],)).fetchone()["c"]; c.close(); return {"guardian":"active","active_sessions":active,"verified_users":verified,"mfa_users":mfa,"users":total,"tenant_isolation":"enforced","password_hashing":"argon2id","session_tokens":"hashed_at_rest"}
@app.get("/guardian/events")
def guardian_events(u=Depends(current_user)):
 require(u,"admin"); c=db(); rows=c.execute("SELECT event,severity,detail,created_at FROM security_events WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.get("/integrations")
def integrations(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT provider,status FROM integrations WHERE tenant_id=? ORDER BY provider",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.get("/contacts")
def contacts(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT * FROM contacts WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/contacts")
def add_contact(d:ContactIn,u=Depends(current_user)):
 require(u,"write"); item=(str(uuid.uuid4()),u["tenant_id"],d.name,d.contact,d.need,d.source,score(d.need),now()); c=db(); c.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)",item); c.commit(); c.close(); audit(u,"contact_created",d.name); return {"id":item[0],"score":item[6]}
@app.post("/reception/process")
def reception(d:ReceptionIn,u=Depends(current_user)):
 require(u,"write"); t=d.text.lower()
 if any(x in t for x in ["loan","money","finance","funding","credit","borrow","mortgage","capital"]): intent,route,reply="finance_funding","Finance Enquiries",f"Thanks, {d.name}. Are you looking for personal or business funding, roughly how much do you need, and what is it for?"
 elif any(x in t for x in ["book","appointment","reserve","availability","calendar","meeting"]): intent,route,reply="booking","Bookings Team",f"Thanks, {d.name}. What date and time would you prefer, and what are you looking to book?"
 elif any(x in t for x in ["quote","price","cost","buy","purchase","lease","sales"]): intent,route,reply="sales","Sales Team",f"Thanks, {d.name}. Tell me what you need, your timing and any budget or specification you have."
 else: intent,route,reply="general","Reception Team",f"Thanks, {d.name}. What outcome are you looking for so I can route this correctly?"
 cid,tid=str(uuid.uuid4()),str(uuid.uuid4()); c=db(); c.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)",(cid,u["tenant_id"],d.name,d.contact,d.text,"Receptionist",score(d.text),now())); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(tid,u["tenant_id"],f"{route}: follow up {d.name}",route,datetime.date.today().isoformat(),"Open",now())); c.commit(); c.close(); audit(u,"reception_processed",f"{d.name} · {intent}"); return {"reply":reply,"intent":intent,"route":route,"contact_id":cid,"task_id":tid,"lead_score":score(d.text)}
@app.get("/bookings")
def bookings(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT * FROM bookings WHERE tenant_id=? ORDER BY date,time",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/bookings")
def add_booking(d:BookingIn,u=Depends(current_user)):
 require(u,"write"); c=db(); contact=c.execute("SELECT * FROM contacts WHERE id=? AND tenant_id=?",(d.contact_id,u["tenant_id"])).fetchone()
 if not contact: c.close(); raise HTTPException(404,"Contact not found")
 dup=c.execute("SELECT id FROM bookings WHERE tenant_id=? AND contact_id=? AND date=? AND time=? AND status!='Cancelled'",(u["tenant_id"],d.contact_id,d.date,d.time)).fetchone()
 if dup: c.close(); raise HTTPException(409,"Duplicate booking")
 bid=str(uuid.uuid4()); c.execute("INSERT INTO bookings VALUES (?,?,?,?,?,?,?,?,?)",(bid,u["tenant_id"],d.contact_id,d.type,d.date,d.time,d.reminder,"Confirmed",now())); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],f"Send booking confirmation to {contact['name']}","Automation",d.date,"Open",now())); c.commit(); c.close(); audit(u,"booking_created",f"{contact['name']} · {d.date} {d.time}"); return {"id":bid,"status":"Confirmed","notification":"queued_internal"}
@app.get("/tasks")
def tasks(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT * FROM tasks WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/tasks")
def add_task(d:TaskIn,u=Depends(current_user)):
 require(u,"write"); tid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(tid,u["tenant_id"],d.title,d.owner,d.due,"Open",now())); c.commit(); c.close(); audit(u,"task_created",d.title); return {"id":tid,"status":"Open"}
@app.post("/documents")
def add_document(d:DocumentIn,u=Depends(current_user)):
 require(u,"write"); body=f"{d.type.upper()}\n\nPrepared for: {d.recipient}\n\nCONFIRMED SOURCE INFORMATION\n{d.facts}\n\nCONTROL STATUS\nDRAFT — principal approval required before external use."; did=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?)",(did,u["tenant_id"],d.type,d.recipient,body,"Draft",now())); c.commit(); c.close(); audit(u,"document_created",d.recipient); return {"id":did,"body":body,"status":"Draft"}
@app.post("/documents/{doc_id}/approve")
def approve_document(doc_id:str,u=Depends(current_user)):
 require(u,"approve"); c=db(); r=c.execute("SELECT id FROM documents WHERE id=? AND tenant_id=?",(doc_id,u["tenant_id"])).fetchone()
 if not r: c.close(); raise HTTPException(404,"Document not found")
 c.execute("UPDATE documents SET status='Principal Approved' WHERE id=?",(doc_id,)); c.commit(); c.close(); audit(u,"document_approved",doc_id); return {"id":doc_id,"status":"Principal Approved"}
@app.post("/campaigns")
def add_campaign(d:CampaignIn,u=Depends(current_user)):
 require(u,"write"); content=f"CAMPAIGN: {d.goal}\n\nCHANNEL\n{d.channel}\n\nAUDIENCE\n{d.audience}\n\nMESSAGE\n{d.message}\n\nCALL TO ACTION\nBook, enquire or contact us."; cid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?)",(cid,u["tenant_id"],d.channel,d.goal,d.audience,content,d.mode,"Draft",now())); c.commit(); c.close(); audit(u,"campaign_created",d.goal); return {"id":cid,"content":content,"status":"Draft"}
@app.post("/routes")
def add_route(d:RouteIn,u=Depends(current_user)):
 require(u,"write"); rid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO routes VALUES (?,?,?,?,?,?,?,?)",(rid,u["tenant_id"],d.start,d.end,d.mode,d.notes,"Planned locally",now())); c.commit(); c.close(); audit(u,"route_created",f"{d.start} → {d.end}"); return {"id":rid,"status":"Planned locally","live_mapping":"not_connected"}
@app.post("/freight")
def add_freight(d:FreightIn,u=Depends(current_user)):
 require(u,"write"); fid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO freight_jobs VALUES (?,?,?,?,?,?,?,?,?)",(fid,u["tenant_id"],d.ref,d.collection,d.delivery,d.vehicle,d.notes,"Unassigned",now())); c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",(str(uuid.uuid4()),u["tenant_id"],f"Assign vehicle/driver for {d.ref}","Fleet Operations",datetime.date.today().isoformat(),"Open",now())); c.commit(); c.close(); audit(u,"freight_created",d.ref); return {"id":fid,"status":"Unassigned"}
@app.post("/video")
def add_video(d:VideoIn,u=Depends(current_user)):
 require(u,"write"); plan=f"PROJECT\n{d.project}\n\nSOURCE\n{d.source}\n\nTARGET OUTPUT\n{d.output}\n\nOBJECTIVE\n{d.brief}\n\nPRODUCTION PLAN\n1. Ingest and index source.\n2. Select strongest scenes.\n3. Build structured edit.\n4. Create captions/title cards.\n5. Produce platform variants.\n6. Apply brand package.\n7. Human review before export."; vid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO video_projects VALUES (?,?,?,?,?,?,?,?,?)",(vid,u["tenant_id"],d.project,d.source,d.output,d.brief,plan,"Planned",now())); c.commit(); c.close(); audit(u,"video_plan_created",d.project); return {"id":vid,"plan":plan,"rendering":"not_connected"}
@app.get("/freshx")
def freshx_list(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT * FROM freshx_opportunities WHERE tenant_id=? ORDER BY created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/freshx")
def freshx_create(d:FreshXIn,u=Depends(current_user)):
 require(u,"write"); low=d.notes.lower(); readiness=20
 for k in ["rights","supply","grower","specification","freight","compliance","price","retailer","certification"]:
  if k in low: readiness+=7
 readiness=min(90,readiness); fid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO freshx_opportunities VALUES (?,?,?,?,?,?,?,?,?,?)",(fid,u["tenant_id"],d.product,d.owner,d.market,d.stage,d.notes,readiness,"Working",now())); c.commit(); c.close(); audit(u,"freshx_opportunity_created",f"{d.product} · {d.stage}"); return {"id":fid,"readiness":readiness,"status":"Working"}
@app.post("/freshx/{freshx_id}/approve")
def freshx_approve(freshx_id:str,u=Depends(current_user)):
 require(u,"approve"); c=db(); row=c.execute("SELECT id FROM freshx_opportunities WHERE id=? AND tenant_id=?",(freshx_id,u["tenant_id"])).fetchone()
 if not row: c.close(); raise HTTPException(404,"FreshX opportunity not found")
 c.execute("UPDATE freshx_opportunities SET status='Stage Approved' WHERE id=?",(freshx_id,)); c.commit(); c.close(); audit(u,"freshx_stage_approved",freshx_id); return {"id":freshx_id,"status":"Stage Approved"}
@app.get("/tenders")
def tender_list(u=Depends(current_user)):
 c=db(); rows=c.execute("SELECT * FROM tenders WHERE tenant_id=? ORDER BY deadline,created_at DESC",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
@app.post("/tenders/analyse")
def tender_analyse(d:TenderIn,u=Depends(current_user)):
 require(u,"write"); text=d.requirements.lower(); signals=["insurance","turnover","experience","references","policy","certificate","method statement","social value","pricing","gdpr","security","quality","environment","health and safety"]; found=[k for k in signals if k in text]; gaps=[k for k in signals if k not in text][:6]; readiness=min(85,25+len(found)*4); analysis=f"TENDER ANALYSIS\n\nTENDER\n{d.title}\n\nREFERENCE\n{d.ref}\n\nDEADLINE\n{d.deadline}\n\nESTIMATED VALUE\n{d.value or 'Not supplied'}\n\nREQUIREMENT SIGNALS DETECTED\n{', '.join(found) if found else 'No standard evidence signals detected automatically.'}\n\nPOTENTIAL EVIDENCE / REVIEW GAPS\n"+"\n".join('• Check '+x for x in gaps)+"\n\nCONTROL WORKFLOW\n1. Confirm eligibility and go/no-go.\n2. Build requirement/question matrix.\n3. Map requirements to verified company evidence.\n4. Flag missing evidence or professional confirmations.\n5. Draft using confirmed facts only.\n6. Commercial/legal/regulatory review.\n7. Principal approval.\n8. Submit only through an authorised channel.\n"; tid=str(uuid.uuid4()); c=db(); c.execute("INSERT INTO tenders VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(tid,u["tenant_id"],d.title,d.ref,d.deadline,d.value,d.requirements,analysis,"",readiness,"Analysed",now())); c.commit(); c.close(); audit(u,"tender_analysed",f"{d.title} · {d.ref}"); return {"id":tid,"analysis":analysis,"readiness":readiness,"status":"Analysed"}
@app.post("/tenders/{tender_id}/draft")
def tender_draft(tender_id:str,u=Depends(current_user)):
 require(u,"write"); c=db(); t=c.execute("SELECT * FROM tenders WHERE id=? AND tenant_id=?",(tender_id,u["tenant_id"])).fetchone()
 if not t: c.close(); raise HTTPException(404,"Tender not found")
 draft=f"EXECUTIVE RESPONSE — WORKING DRAFT\n\nBuyer / Tender: {t['title']}\nReference: {t['ref']}\n\n1. UNDERSTANDING OF REQUIREMENT\nWe have reviewed the supplied requirements and will respond against the buyer's stated outcomes and evidence requirements.\n\n2. DELIVERY APPROACH\n[Insert verified delivery method, resources, timescales and governance.]\n\n3. EXPERIENCE AND EVIDENCE\n[Insert verified case studies, references, accreditations and supporting documents.]\n\n4. QUALITY / RISK / COMPLIANCE\n[Insert only confirmed policies, certifications, insurance and compliance statements.]\n\n5. COMMERCIAL RESPONSE\n[Insert authorised pricing, assumptions and exclusions.]\n\nCONTROL STATUS\nWORKING DRAFT — NOT FOR SUBMISSION.\n"; readiness=min(92,int(t["readiness"] or 0)+10); c.execute("UPDATE tenders SET draft=?,readiness=?,status='Draft' WHERE id=?",(draft,readiness,tender_id)); c.commit(); c.close(); audit(u,"tender_response_drafted",tender_id); return {"id":tender_id,"draft":draft,"readiness":readiness,"status":"Draft"}
@app.post("/tenders/{tender_id}/approve")
def tender_approve(tender_id:str,u=Depends(current_user)):
 require(u,"approve"); c=db(); t=c.execute("SELECT * FROM tenders WHERE id=? AND tenant_id=?",(tender_id,u["tenant_id"])).fetchone()
 if not t: c.close(); raise HTTPException(404,"Tender not found")
 if not t["draft"]: c.close(); raise HTTPException(409,"Create tender draft before approval")
 c.execute("UPDATE tenders SET readiness=100,status='Principal Approved' WHERE id=?",(tender_id,)); c.commit(); c.close(); audit(u,"tender_principal_approved",tender_id); return {"id":tender_id,"readiness":100,"status":"Principal Approved"}
@app.get("/audit")
def audit_log(u=Depends(current_user)):
 require(u,"admin"); c=db(); rows=c.execute("SELECT event,detail,severity,created_at FROM audit WHERE tenant_id=? ORDER BY created_at DESC LIMIT 200",(u["tenant_id"],)).fetchall(); c.close(); return [dict(x) for x in rows]
