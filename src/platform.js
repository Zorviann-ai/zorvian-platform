import app from './auth-reset.js';
import { handleCRM } from './crm.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/crm/')) return handleCRM(request, env);
    return app.fetch(request, env, ctx);
  }
};
