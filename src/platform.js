import app from './auth-reset.js';
import { handleCRM } from './crm.js';
import { handleMCP } from './mcp.js';
import { handleSocial } from './social.js';

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
    socialButton.textContent = 'Social & Video Studio';
    socialButton.onclick = () => { location.href = '/social-studio.html'; };
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/mcp' || url.pathname === '/mcp/') return handleMCP(request, env);
    if (url.pathname.startsWith('/api/crm/')) return handleCRM(request, env);
    if (url.pathname.startsWith('/api/social/')) return handleSocial(request, env);
    const response = await app.fetch(request, env, ctx);
    if (request.method === 'GET' && (url.pathname === '/crm' || url.pathname === '/crm.html')) {
      return enhanceCRM(response);
    }
    return response;
  }
};
