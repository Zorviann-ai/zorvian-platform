import app from "./entry.js";

const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" };
const RESET_TTL_MS = 30 * 60 * 1000;

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
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 10000, hash: "SHA-256" },
    key,
    256
  );
  return salt + "$" + btoa(String.fromCharCode(...new Uint8Array(bits)));
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
      from: "Zorvian Security <security@zorvian.co.uk>",
      to: [to],
      subject: "Reset your Zorvian password",
      html: `
        <div style="font-family:Arial,sans-serif;background:#070707;color:#f5f0e7;padding:32px;line-height:1.55">
          <div style="max-width:620px;margin:0 auto;border:1px solid #7f6118;border-radius:12px;padding:30px;background:#0d0d0d">
            <div style="color:#d6a82d;font-size:13px;font-weight:700;letter-spacing:.12em">ZORVIAN SECURITY</div>
            <h1 style="font-size:30px;margin:12px 0 16px;color:#fff">Reset your password</h1>
            <p>We received a request to reset the password for your Zorvian account.</p>
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
  // Always return the same public response so account existence is not disclosed.
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/auth/forgot-password" && request.method === "POST") return forgotPassword(request, env);
    if (url.pathname === "/api/auth/reset-password" && request.method === "POST") return resetPassword(request, env);
    return app.fetch(request, env, ctx);
  }
};
