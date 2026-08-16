import platformWorker from "./entry.js";
import { handleVideoApi } from "./video/api.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/video/")) {
      return handleVideoApi(request, env);
    }

    if (url.pathname === "/video" || url.pathname === "/video/") {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = "/video.html";
      return env.ASSETS.fetch(new Request(assetUrl.toString(), request));
    }

    return platformWorker.fetch(request, env, ctx);
  },
};
