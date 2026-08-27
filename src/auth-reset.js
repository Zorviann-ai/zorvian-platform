import app from "./entry.js";

const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" };
const RESET_TTL_MS = 30 * 60 * 1000;
const PASSWORD_HASH_ITERATIONS = 210000;

const OWNER_EMAIL = "hello@caelomere.com";
const OWNER_ACTIVATION_TOKEN_HASH = "41fa7fcec9ba1aad47faeabe3a78f90f2d7d299dd46f879cfb7b7993fe5062a9";

function constantTimeTextEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function activateOwner(request, env) {
  if (!env.DB) return json({ error: "database_unavailable" }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
  const token = String(body?.token || "").trim();
  const name = String(body?.name || "Mo").trim().slice(0, 100);
  const password = String(body?.password || "");
  if (!token) return json({ error: "activation_token_required" }, 400);
  if (password.length < 12) return json({ error: "password_too_short", message: "Use at least 12 characters." }, 400);
  if (!constantTimeTextEqual(await sha256(token), OWNER_ACTIVATION_TOKEN_HASH)) return json({ error: "invalid_activation" }, 403);

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS owner_activations (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    used_at TEXT NOT NULL
  )`).run();
  const usedActivation = await env.DB.prepare("SELECT token_hash FROM owner_activations WHERE token_hash=? LIMIT 1").bind(OWNER_ACTIVATION_TOKEN_HASH).first();
  if (usedActivation) return json({ error: "owner_already_activated" }, 409);

  const administrator = await env.DB.prepare("SELECT id,email FROM users WHERE role='admin' LIMIT 1").first();
  if (administrator && String(administrator.email || "").toLowerCase() !== OWNER_EMAIL) {
    return json({ error: "different_administrator_exists" }, 409);
  }

  const existingUser = await env.DB.prepare("SELECT id,tenant_id FROM users WHERE lower(email)=? LIMIT 1").bind(OWNER_EMAIL).first();
  const sessionId = uid();
  let userId;
  if (existingUser) {
    userId = existingUser.id;
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET name=?,password_hash=?,role='admin' WHERE id=?").bind(name || "Mo", await hashPassword(password), userId),
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(userId),
      env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)").bind(sessionId, userId, new Date(Date.now() + 604800000).toISOString())
    ]);
  } else {
    const tenantId = uid();
    userId = uid();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO tenants (id,name,slug,website_url) VALUES (?,?,?,?)").bind(tenantId, "Caelomere Ltd", "caelomere", "https://caelomere.com"),
      env.DB.prepare("INSERT INTO users (id,tenant_id,name,email,password_hash,role) VALUES (?,?,?,?,?,?)").bind(userId, tenantId, name || "Mo", OWNER_EMAIL, await hashPassword(password), "admin"),
      env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)").bind(sessionId, userId, new Date(Date.now() + 604800000).toISOString())
    ]);
  }
  await env.DB.prepare("INSERT INTO owner_activations (token_hash,user_id,used_at) VALUES (?,?,?)")
    .bind(OWNER_ACTIVATION_TOKEN_HASH, userId, nowIso()).run();
  return json({ ok: true, email: OWNER_EMAIL, role: "admin" }, 201, {
    "Set-Cookie": `zorvian_session=${sessionId}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax`
  });
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}

function uid() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }

async function hashPassword(password, salt = crypto.randomUUID()) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: PASSWORD_HASH_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return `pbkdf2_sha256$${PASSWORD_HASH_ITERATIONS}$${salt}$${btoa(String.fromCharCode(...new Uint8Array(bits)))}`;
}

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function ensureResetTable(env) {
  if (!env.DB) throw new Error("database_unavailable");
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash, expires_at)").run();
}

async function sendResetEmail(env, to, resetUrl) {
  if (!env.RESEND_API_KEY) throw new Error("resend_not_configured");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "Caelomere Security <support@caelomere.com>",
      to: [to],
      subject: "Reset your Caelomere password",
      html: `
        <div style="font-family:Arial,sans-serif;background:#070707;color:#f5f0e7;padding:32px;line-height:1.55">
          <div style="max-width:620px;margin:0 auto;border:1px solid #7f6118;border-radius:12px;padding:30px;background:#0d0d0d">
            <div style="color:#d6a82d;font-size:13px;font-weight:700;letter-spacing:.12em">CAELOMERE SECURITY</div>
            <h1 style="font-size:30px;margin:12px 0 16px;color:#fff">Reset your password</h1>
            <p>We received a request to reset the password for your Caelomere account.</p>
            <p><a href="${resetUrl}" style="display:inline-block;background:#d6a82d;color:#070707;text-decoration:none;font-weight:800;padding:13px 20px;border-radius:7px">RESET PASSWORD</a></p>
            <p style="color:#aaa">This link expires in 30 minutes and can only be used once.</p>
            <p style="color:#aaa">If you did not request this reset, you can ignore this email.</p>
          </div>
        </div>`
    })
  });
  if (!response.ok) {
    const body = await response.text();
    console.error("Resend password reset failed", response.status, body);
    throw new Error("email_send_failed");
  }
}

async function forgotPassword(request, env) {
  if (!env.DB) return json({ error: "database_unavailable" }, 503);
  await ensureResetTable(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
  const email = String(body?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return json({ error: "email_required" }, 400);

  const user = await env.DB.prepare("SELECT id,email FROM users WHERE lower(email)=?").bind(email).first();
  if (!user) return json({ ok: true, message: "If that account exists, a reset email has been sent." });

  const token = `${uid()}${uid()}`.replaceAll("-", "");
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + RESET_TTL_MS).toISOString();

  await env.DB.prepare("DELETE FROM password_resets WHERE user_id=? OR expires_at<=?").bind(user.id, nowIso()).run();
  await env.DB.prepare("INSERT INTO password_resets (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)")
    .bind(uid(), user.id, tokenHash, expiresAt).run();

  const origin = new URL(request.url).origin;
  const resetUrl = `${origin}/reset-password.html?token=${encodeURIComponent(token)}`;
  await sendResetEmail(env, user.email, resetUrl);
  return json({ ok: true, message: "If that account exists, a reset email has been sent." });
}

async function resetPassword(request, env) {
  if (!env.DB) return json({ error: "database_unavailable" }, 503);
  await ensureResetTable(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
  const token = String(body?.token || "").trim();
  const password = String(body?.password || "");
  if (!token) return json({ error: "token_required" }, 400);
  if (password.length < 12) return json({ error: "password_too_short", message: "Use at least 12 characters." }, 400);

  const tokenHash = await sha256(token);
  const reset = await env.DB.prepare(`SELECT id,user_id,expires_at,used_at FROM password_resets
    WHERE token_hash=? LIMIT 1`).bind(tokenHash).first();
  if (!reset || reset.used_at || reset.expires_at <= nowIso()) {
    return json({ error: "invalid_or_expired_token" }, 400);
  }

  const passwordHash = await hashPassword(password);
  const usedAt = nowIso();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(passwordHash, reset.user_id),
    env.DB.prepare("UPDATE password_resets SET used_at=? WHERE id=?").bind(usedAt, reset.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(reset.user_id)
  ]);
  return json({ ok: true, message: "Password updated. You can now sign in." });
}

async function injectForgotPassword(response) {
  const type = response.headers.get("content-type") || "";
  if (!type.includes("text/html") || !response.ok) return response;
  let html = await response.text();
  if (!html.includes('id="loginForm"') || html.includes('id="forgotPasswordButton"')) {
    return new Response(html, { status: response.status, statusText: response.statusText, headers: response.headers });
  }

  html = html.replace(
    '</form><div class="auth-help">',
    '</form><button id="forgotPasswordButton" class="secondary" type="button" style="width:100%;margin-top:10px;min-height:44px">FORGOT PASSWORD</button><div id="forgotPasswordStatus" class="auth-status" role="status"></div><div class="auth-help">'
  );

  html = html.replace(
    'async function signOut(){',
    `async function requestPasswordReset(){
      const email=$('loginEmail').value.trim();
      const status=$('forgotPasswordStatus');
      const button=$('forgotPasswordButton');
      if(!email){status.textContent='Enter your email address first.';return $('loginEmail').focus()}
      button.disabled=true;status.textContent='Sending reset link...';
      try{
        const data=await api('/auth/forgot-password',{method:'POST',body:JSON.stringify({email})});
        status.style.color='var(--success)';
        status.textContent=data.message||'If that account exists, a reset email has been sent.';
      }catch(error){
        status.style.color='var(--danger)';
        status.textContent='Password reset could not be sent. Please try again.';
      }finally{button.disabled=false}
    }
    async function signOut(){`
  );

  html = html.replace(
    "renderTools();$('loginForm').addEventListener('submit',submitLogin);",
    "renderTools();$('loginForm').addEventListener('submit',submitLogin);$('forgotPasswordButton')?.addEventListener('click',requestPasswordReset);"
  );

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.set("cache-control", "no-store");
  return new Response(html, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/auth/activate-owner" && request.method === "POST") return activateOwner(request, env);
    if (url.pathname === "/api/auth/forgot-password" && request.method === "POST") return forgotPassword(request, env);
    if (url.pathname === "/api/auth/reset-password" && request.method === "POST") return resetPassword(request, env);
    const response = await app.fetch(request, env, ctx);
    if (request.method === "GET") return injectForgotPassword(response);
    return response;
  }
};
