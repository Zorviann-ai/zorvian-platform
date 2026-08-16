import {
  VIDEO_CAPABILITIES,
  buildStoryboardPrompt,
  createVideoId,
  estimateProjectCostMicros,
  normalizeProjectInput,
  parseStoryboard,
  selectProvider,
} from "./core.js";
import { generateMockScene, mockVideoProvider } from "./providers/mock.js";

const AI_MODEL = "@cf/zai-org/glm-4.7-flash";
const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function getUser(request, env) {
  const sessionId = cookieValue(request, "zorvian_session");
  if (!sessionId || !env.DB) return null;
  return env.DB.prepare(
    `SELECT u.id AS user_id,u.tenant_id,u.name,u.email,u.role
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.id=? AND s.expires_at>?`
  ).bind(sessionId, new Date().toISOString()).first();
}

function extractText(result) {
  return String(
    result?.response || result?.result?.response || result?.output_text ||
    result?.result?.output_text || result?.text || result?.result?.text ||
    result?.choices?.[0]?.message?.content || result?.choices?.[0]?.text || ""
  ).trim();
}

async function planStoryboard(env, project) {
  if (!env.AI || typeof env.AI.run !== "function") {
    return parseStoryboard("", project);
  }
  try {
    const result = await env.AI.run(AI_MODEL, {
      messages: [
        { role: "system", content: "You are Zorvian Video Director. Return only valid JSON." },
        { role: "user", content: buildStoryboardPrompt(project) },
      ],
      max_completion_tokens: 1800,
      temperature: 0.25,
    });
    return parseStoryboard(extractText(result), project);
  } catch (error) {
    console.error("Video storyboard planning failed; using deterministic fallback", error);
    return parseStoryboard("", project);
  }
}

async function audit(env, user, action, details = {}) {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_logs (id,tenant_id,user_id,action,details_json) VALUES (?,?,?,?,?)"
    ).bind(createVideoId(), user.tenant_id, user.user_id, action, JSON.stringify(details)).run();
  } catch (error) {
    console.error("Video audit failed", error);
  }
}

function dbError(error) {
  const message = String(error?.message || error || "");
  if (/no such table: video_/i.test(message)) {
    return json({ error: "video_schema_required", migration: "0002_video_foundation.sql" }, 503);
  }
  console.error("Zorvian Video API failed", error);
  return json({ error: "video_server_error" }, 500);
}

async function listProjects(env, user) {
  const result = await env.DB.prepare(
    `SELECT p.id,p.title,p.prompt,p.status,p.aspect_ratio,p.target_duration_seconds,p.created_at,p.updated_at,
      COUNT(DISTINCT s.id) AS scene_count,
      COALESCE(SUM(DISTINCT j.actual_cost_micros),0) AS actual_cost_micros
     FROM video_projects p
     LEFT JOIN video_scenes s ON s.project_id=p.id
     LEFT JOIN video_jobs j ON j.project_id=p.id
     WHERE p.tenant_id=?
     GROUP BY p.id
     ORDER BY datetime(p.created_at) DESC LIMIT 50`
  ).bind(user.tenant_id).all();
  return json({ ok: true, projects: result.results || [] });
}

async function projectDetail(env, user, projectId) {
  const project = await env.DB.prepare(
    `SELECT id,title,prompt,status,aspect_ratio,target_duration_seconds,settings_json,created_at,updated_at
     FROM video_projects WHERE id=? AND tenant_id=?`
  ).bind(projectId, user.tenant_id).first();
  if (!project) return null;

  const scenes = await env.DB.prepare(
    `SELECT s.id,s.scene_index,s.title,s.narration,s.visual_prompt,s.duration_seconds,s.status,s.provider_key,s.provider_job_id,
      s.output_asset_id,a.source_url AS output_url,a.mime_type AS output_mime_type,a.metadata_json AS asset_metadata_json
     FROM video_scenes s LEFT JOIN video_assets a ON a.id=s.output_asset_id
     WHERE s.project_id=? ORDER BY s.scene_index ASC`
  ).bind(projectId).all();
  const jobs = await env.DB.prepare(
    `SELECT id,scene_id,job_type,provider_key,provider_job_id,status,attempt,estimated_cost_micros,actual_cost_micros,error_code,error_message,created_at,started_at,completed_at
     FROM video_jobs WHERE project_id=? ORDER BY datetime(created_at) ASC`
  ).bind(projectId).all();
  const renders = await env.DB.prepare(
    `SELECT id,status,resolution,format,duration_seconds,actual_cost_micros,error_message,created_at,completed_at
     FROM video_renders WHERE project_id=? ORDER BY datetime(created_at) DESC`
  ).bind(projectId).all();

  const jobRows = jobs.results || [];
  return {
    ...project,
    settings: safeJson(project.settings_json, {}),
    scenes: (scenes.results || []).map((scene) => ({ ...scene, asset_metadata: safeJson(scene.asset_metadata_json, {}) })),
    jobs: jobRows,
    renders: renders.results || [],
    costs: {
      estimated_micros: jobRows.reduce((sum, job) => sum + Number(job.estimated_cost_micros || 0), 0),
      actual_micros: jobRows.reduce((sum, job) => sum + Number(job.actual_cost_micros || 0), 0),
    },
  };
}

function safeJson(value, fallback) {
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

async function createProject(request, env, user) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
  let input;
  try { input = normalizeProjectInput(body); } catch (error) {
    return json({ error: error.message === "prompt_required" ? "prompt_required" : "invalid_project" }, 400);
  }

  const id = createVideoId();
  const project = { ...input, id };
  await env.DB.prepare(
    `INSERT INTO video_projects (id,tenant_id,user_id,title,prompt,status,aspect_ratio,target_duration_seconds,settings_json)
     VALUES (?,?,?,?,?,'planning',?,?,?)`
  ).bind(id, user.tenant_id, user.user_id, input.title, input.prompt, input.aspectRatio, input.targetDurationSeconds, JSON.stringify(input.settings)).run();

  const storyboard = await planStoryboard(env, project);
  const sceneStatements = storyboard.scenes.map((scene) => env.DB.prepare(
    `INSERT INTO video_scenes (id,project_id,scene_index,title,narration,visual_prompt,duration_seconds,status,metadata_json)
     VALUES (?,?,?,?,?,?,?,'planned',?)`
  ).bind(createVideoId(), id, scene.sceneIndex, scene.title, scene.narration, scene.visualPrompt, scene.durationSeconds, JSON.stringify({ planner_degraded: storyboard.degraded })));

  await env.DB.batch([
    env.DB.prepare("UPDATE video_projects SET title=?,status='planned',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(storyboard.title, id),
    ...sceneStatements,
  ]);
  await audit(env, user, "video.project.created", { projectId: id, sceneCount: storyboard.scenes.length, plannerDegraded: storyboard.degraded });
  const detail = await projectDetail(env, user, id);
  return json({ ok: true, project: detail, planner_degraded: storyboard.degraded }, 201);
}

async function generateProject(env, user, projectId) {
  const detail = await projectDetail(env, user, projectId);
  if (!detail) return json({ error: "video_project_not_found" }, 404);

  const provider = selectProvider({
    capability: VIDEO_CAPABILITIES.textToVideo,
    providers: [mockVideoProvider],
    preference: detail.settings?.routing_preference || "balanced",
  });
  if (!provider) return json({ error: "no_video_provider_available" }, 503);

  const pendingScenes = detail.scenes.filter((scene) => scene.status !== "completed");
  const estimatedProjectCost = estimateProjectCostMicros(
    pendingScenes.map((scene) => ({ durationSeconds: Number(scene.duration_seconds) })),
    provider
  );

  await env.DB.prepare("UPDATE video_projects SET status='generating',updated_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?")
    .bind(projectId, user.tenant_id).run();

  for (const scene of pendingScenes) {
    const jobId = createVideoId();
    const estimatedCost = Math.round(Number(scene.duration_seconds || 0) * Number(provider.pricePerSecondMicros || 0));
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO video_jobs (id,project_id,scene_id,job_type,provider_key,status,estimated_cost_micros,request_json,started_at)
         VALUES (?,?,?,'text_to_video',?,'running',?,?,CURRENT_TIMESTAMP)`
      ).bind(jobId, projectId, scene.id, provider.key, estimatedCost, JSON.stringify({ prompt: scene.visual_prompt, duration_seconds: scene.duration_seconds, simulation: true })),
      env.DB.prepare("UPDATE video_scenes SET status='generating',provider_key=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(provider.key, scene.id),
    ]);

    try {
      const generated = await generateMockScene({ project: detail, scene });
      const assetId = createVideoId();
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO video_assets (id,project_id,scene_id,kind,source_url,mime_type,width,height,duration_seconds,metadata_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)`
        ).bind(assetId, projectId, scene.id, generated.asset.kind, generated.asset.sourceUrl, generated.asset.mimeType, generated.asset.width, generated.asset.height, generated.asset.durationSeconds, JSON.stringify(generated.asset.metadata)),
        env.DB.prepare(
          `UPDATE video_jobs SET provider_job_id=?,status='completed',actual_cost_micros=?,response_json=?,completed_at=CURRENT_TIMESTAMP WHERE id=?`
        ).bind(generated.providerJobId, generated.actualCostMicros, JSON.stringify({ simulation: true, asset_id: assetId }), jobId),
        env.DB.prepare(
          `UPDATE video_scenes SET status='completed',provider_key=?,provider_job_id=?,output_asset_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`
        ).bind(provider.key, generated.providerJobId, assetId, scene.id),
      ]);
    } catch (error) {
      await env.DB.batch([
        env.DB.prepare("UPDATE video_jobs SET status='failed',error_code='mock_generation_failed',error_message=?,completed_at=CURRENT_TIMESTAMP WHERE id=?").bind(String(error?.message || error).slice(0, 1000), jobId),
        env.DB.prepare("UPDATE video_scenes SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(scene.id),
      ]);
      await env.DB.prepare("UPDATE video_projects SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(projectId).run();
      return json({ error: "video_generation_failed", project_id: projectId }, 500);
    }
  }

  const renderId = createVideoId();
  const totalDuration = detail.scenes.reduce((sum, scene) => sum + Number(scene.duration_seconds || 0), 0);
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO video_renders (id,project_id,status,resolution,format,duration_seconds,actual_cost_micros,completed_at)
       VALUES (?,?,'simulated','preview','mock',?,0,CURRENT_TIMESTAMP)`
    ).bind(renderId, projectId, totalDuration),
    env.DB.prepare("UPDATE video_projects SET status='simulated',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(projectId),
  ]);
  await audit(env, user, "video.project.simulated", { projectId, provider: provider.key, estimatedCostMicros: estimatedProjectCost, actualCostMicros: 0 });

  return json({ ok: true, project: await projectDetail(env, user, projectId), simulation: true });
}

export async function handleVideoApi(request, env) {
  if (!env.DB) return json({ error: "database_unavailable" }, 503);
  const user = await getUser(request, env);
  if (!user) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, "");

  try {
    if (path === "/api/video/providers" && request.method === "GET") {
      return json({ ok: true, providers: [{ ...mockVideoProvider }], mode: "simulation" });
    }
    if (path === "/api/video/projects" && request.method === "GET") return listProjects(env, user);
    if (path === "/api/video/projects" && request.method === "POST") return createProject(request, env, user);

    const match = path.match(/^\/api\/video\/projects\/([^/]+)(?:\/(generate))?$/);
    if (!match) return json({ error: "video_route_not_found" }, 404);
    const projectId = decodeURIComponent(match[1]);
    if (!match[2] && request.method === "GET") {
      const detail = await projectDetail(env, user, projectId);
      return detail ? json({ ok: true, project: detail }) : json({ error: "video_project_not_found" }, 404);
    }
    if (match[2] === "generate" && request.method === "POST") return generateProject(env, user, projectId);
    return json({ error: "method_not_allowed" }, 405);
  } catch (error) {
    return dbError(error);
  }
}
