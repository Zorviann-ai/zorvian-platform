import platformWorker from "./entry.js";
import { handleVideoApi } from "./video/api.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/video/")) {
      return handleVideoApi(request, env);
    }

    return platformWorker.fetch(request, env, ctx);
  },
};
