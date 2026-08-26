import app from './auth-reset.js';
import { handleCRM } from './crm.js';
import { handleMCP } from './mcp.js';
import { handleSocial } from './social.js';
import { handleMedia } from './media.js';
import { handleAuthors } from './authors.js';
import { handleCore } from './core.js';

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'cross-origin-resource-policy': 'same-origin'
};

function secure(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function blocksCrossSiteCookieWrite(request) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return false;
  if (!request.headers.get('Cookie')) return false;
  const origin = request.headers.get('Origin');
  return Boolean(origin && origin !== new URL(request.url).origin);
}

async function enhanceCRM(response) {
  const type = response.headers.get('content-type') || '';
  if (!response.ok || !type.includes('text/html')) return response;
  let html = await response.text();
  const patch = `
<script>
(() => {
  const byId = id => document.getElementById(id);
  const ensureStatus = () => {
    if (byId('crmSaveStatus')) return byId('crmSaveStatus');
    const box = document.createElement('div');
    box.id = 'crmSaveStatus';
    box.style.cssText = 'position:fixed;right:22px;bottom:22px;z-index:9999;display:none;max-width:420px;padding:12px 16px;border-radius:10px;background:#111820;color:white;box-shadow:0 12px 35px rgba(0,0,0,.2);font:700 12px Arial';
    document.body.appendChild(box);
    return box;
  };
  const show = (message, ok=true) => {
    const box = ensureStatus();
    box.textContent = message;
    box.style.background = ok ? '#238653' : '#b33b3b';
    box.style.display = 'block';
    clearTimeout(window.__crmStatusTimer);
    window.__crmStatusTimer = setTimeout(() => box.style.display='none', 3500);
  };
  const pName = byId('pName');
  const pCategory = byId('pCategory');
  if (pName && !pName.value) pName.value = 'Your Total Tutor';
  if (pCategory && !pCategory.value) pCategory.value = 'Education / Client build';

  const studioButton = document.querySelector('button[data-page="studio"]');
  if (studioButton && !byId('socialVideoStudioLink')) {
    const socialButton = document.createElement('button');
    socialButton.id = 'socialVideoStudioLink';
    socialButton.textContent = 'AI Media Studio';
    socialButton.onclick = () => { location.href = '/media-studio.html'; };
    studioButton.insertAdjacentElement('afterend', socialButton);
  }

  const originalAddProject = window.addProject;
  if (typeof originalAddProject === 'function') {
    window.addProject = async function() {
      const name = (byId('pName')?.value || '').trim();
      if (!name) { show('Enter a project name before saving.', false); byId('pName')?.focus(); return; }
      try { await originalAddProject(); show('Project saved to CRM.'); }
      catch (e) { console.error(e); show('Project could not be saved: ' + (e?.message || 'unknown error'), false); }
    };
  }
  const originalAddContact = window.addContact;
  if (typeof originalAddContact === 'function') {
    window.addContact = async function() {
      const name = (byId('cName')?.value || '').trim();
      if (!name) { show('Enter a contact name before saving.', false); byId('cName')?.focus(); return; }
      try { await originalAddContact(); show('Contact saved to CRM.'); }
      catch (e) { console.error(e); show('Contact could not be saved: ' + (e?.message || 'unknown error'), false); }
    };
  }
  const originalAddTask = window.addTask;
  if (typeof originalAddTask === 'function') {
    window.addTask = async function() {
      const title = (byId('tTitle')?.value || '').trim();
      if (!title) { show('Enter a task before saving.', false); byId('tTitle')?.focus(); return; }
      try { await originalAddTask(); show('Task saved to CRM.'); }
      catch (e) { console.error(e); show('Task could not be saved: ' + (e?.message || 'unknown error'), false); }
    };
  }
})();
</script>`;
  html = html.replace('</body>', patch + '</body>');
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.set('cache-control', 'no-store');
  return new Response(html, { status: response.status, statusText: response.statusText, headers });
}

async function serveAssetFallback(request, env, response) {
  if (response.status !== 404) return response;
  if (!['GET', 'HEAD'].includes(request.method)) return response;
  if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') return response;
  const url = new URL(request.url);
  if (url.pathname.startsWith('/api/') || url.pathname === '/mcp' || url.pathname === '/mcp/') return response;
  const assetResponse = await env.ASSETS.fetch(request);
  return assetResponse.status === 404 ? response : assetResponse;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/') && blocksCrossSiteCookieWrite(request)) {
      return secure(new Response(JSON.stringify({ error: 'cross_site_request_blocked' }), { status: 403, headers: { 'content-type': 'application/json; charset=UTF-8', 'cache-control': 'no-store' } }));
    }
    if (url.pathname === '/mcp' || url.pathname === '/mcp/') return secure(await handleMCP(request, env));
    if (url.pathname.startsWith('/api/crm/')) return secure(await handleCRM(request, env));
    if (url.pathname.startsWith('/api/social/')) return secure(await handleSocial(request, env));
    if (url.pathname.startsWith('/api/media/')) return secure(await handleMedia(request, env));
    if (url.pathname.startsWith('/api/authors/')) return secure(await handleAuthors(request, env));
    if (url.pathname.startsWith('/api/core/')) return secure(await handleCore(request, env));
    let response = await app.fetch(request, env, ctx);
    response = await serveAssetFallback(request, env, response);
    if (request.method === 'GET' && (url.pathname === '/crm' || url.pathname === '/crm.html')) {
      return secure(await enhanceCRM(response));
    }
    return secure(response);
  }
};
