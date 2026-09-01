import app from "./entry.js";

const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" };
const RESET_TTL_MS = 30 * 60 * 1000;
const PASSWORD_HASH_ITERATIONS = 210000;

const OWNER_EMAIL = "hello@caelomere.com";
const OWNER_ACTIVATION_TOKEN_HASH = "0902aec778b70053ed45be58b14c9d8a1748a5351d9e3c7280a64968e6c2529f";

function constantTimeTextEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
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
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Caelomere Security <support@caelomere.com>",
      to: [to],
      subject: "Reset your Caelomere password",
      html: `<div style="font-family:Arial,sans-serif"><h1>Reset your Caelomere password</h1><p><a href="${resetUrl}">Reset password</a></p><p>This link expires in 30 minutes and can only be used once.</p></div>`
    })
  });
  if (!response.ok) {
    console.error("Resend password reset failed", response.status);
    throw new Error("email_send_failed");
  }
}

async function activateOwner(request, env) {
  let stage = "request";
  try {
    if (!env.DB) return json({ error: "database_unavailable" }, 503);
    let body;
    try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
    const token = String(body?.token || "").trim();
    const name = String(body?.name || "Mo").trim().slice(0, 100);
    const password = String(body?.password || "");
    if (!token) return json({ error: "activation_token_required" }, 400);
    if (password.length < 12) return json({ error: "password_too_short", message: "Use at least 12 characters." }, 400);
    if (!constantTimeTextEqual(await sha256(token), OWNER_ACTIVATION_TOKEN_HASH)) return json({ error: "invalid_activation" }, 403);

    stage = "activation_check";
    const used = await env.DB.prepare("SELECT id FROM audit_logs WHERE action=? LIMIT 1")
      .bind("owner.activated").first();
    if (used) return json({ error: "owner_already_activated" }, 409);

    stage = "legacy_owner_lookup";
    const legacy = await env.DB.prepare("SELECT id,tenant_id FROM users WHERE lower(email)=? LIMIT 1")
      .bind("hello@zorvian.co.uk").first();
    stage = "caelomere_owner_lookup";
    const target = await env.DB.prepare("SELECT id,tenant_id FROM users WHERE lower(email)=? LIMIT 1")
      .bind(OWNER_EMAIL).first();
    if (!legacy && !target) return json({ error: "owner_record_missing" }, 409);
    if (legacy && target && legacy.id !== target.id) return json({ error: "duplicate_owner_records" }, 409);

    const owner = target || legacy;
    const sessionId = uid();
    stage = "password_hash";
    const passwordHash = await hashPassword(password);
    const activationDetails = JSON.stringify({ token_hash: OWNER_ACTIVATION_TOKEN_HASH, email: OWNER_EMAIL });

    stage = "atomic_owner_migration";
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions"),
      env.DB.prepare("UPDATE users SET name=?,email=?,password_hash=?,role='admin' WHERE id=?")
        .bind(name || "Mo", OWNER_EMAIL, passwordHash, owner.id),
      env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)")
        .bind(sessionId, owner.id, new Date(Date.now() + 604800000).toISOString()),
      env.DB.prepare("INSERT INTO audit_logs (id,tenant_id,user_id,action,details_json) VALUES (?,?,?,?,?)")
        .bind(uid(), owner.tenant_id || null, owner.id, "owner.activated", activationDetails)
    ]);

    return json({ ok: true, email: OWNER_EMAIL, role: "admin" }, 201, {
      "Set-Cookie": `zorvian_session=${sessionId}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax`
    });
  } catch (error) {
    console.error("Owner activation failed", stage, error);
    return json({
      error: "owner_activation_failed",
      message: "The secure owner migration could not be completed. No success has been recorded."
    }, 500);
  }
}

async function forgotPassword(request, env) {
  try {
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
  } catch (error) {
    console.error("Password reset request failed", error);
    return json({ error: "password_reset_unavailable", message: "Password reset is temporarily unavailable. Please try again." }, 503);
  }
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
        status.textContent=error.message||'Password reset could not be sent. Please try again.';
      }finally{button.disabled=false}
    }
    async function signOut(){`
  );

  html = html.replace(
    "renderTools();prepareHubDictation();$('loginForm').addEventListener('submit',submitLogin);",
    "renderTools();prepareHubDictation();$('loginForm').addEventListener('submit',submitLogin);$('forgotPasswordButton')?.addEventListener('click',requestPasswordReset);"
  );

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.set("cache-control", "no-store");
  return new Response(html, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/auth/activate-owner" && request.method === "POST") {
      try {
        return await activateOwner(request, env);
      } catch (error) {
        console.error("Owner activation failed", error);
        return json({ error: "owner_activation_failed", message: "The secure owner migration could not be completed. No success has been recorded." }, 500);
      }
    }
    if (url.pathname === "/api/auth/forgot-password" && request.method === "POST") return forgotPassword(request, env);
    if (url.pathname === "/api/auth/reset-password" && request.method === "POST") return resetPassword(request, env);
    const response = await app.fetch(request, env, ctx);
    if (request.method === "GET") return injectForgotPassword(response);
    return response;
  }
};
