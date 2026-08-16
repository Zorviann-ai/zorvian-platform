const DEFAULT_SCENE_SECONDS = 5;

export const VIDEO_CAPABILITIES = Object.freeze({
  textToVideo: "text_to_video",
  imageToVideo: "image_to_video",
  presenter: "presenter",
  render: "render",
});

export function createVideoId() {
  return crypto.randomUUID();
}

export function normalizeAspectRatio(value) {
  const allowed = new Set(["16:9", "9:16", "1:1"]);
  return allowed.has(value) ? value : "16:9";
}

export function normalizeProjectInput(body = {}) {
  const prompt = String(body.prompt || "").trim().slice(0, 12000);
  if (!prompt) throw new Error("prompt_required");

  const requestedDuration = Number(body.target_duration_seconds || body.duration_seconds || 0);
  const targetDurationSeconds = Number.isFinite(requestedDuration) && requestedDuration > 0
    ? Math.min(Math.max(Math.round(requestedDuration), 5), 600)
    : 20;

  const title = String(body.title || prompt.slice(0, 72) || "Untitled video").trim().slice(0, 120);

  return {
    title,
    prompt,
    aspectRatio: normalizeAspectRatio(body.aspect_ratio),
    targetDurationSeconds,
    settings: body.settings && typeof body.settings === "object" ? body.settings : {},
  };
}

export function fallbackStoryboard(project) {
  const sceneCount = Math.max(1, Math.min(12, Math.ceil(project.targetDurationSeconds / DEFAULT_SCENE_SECONDS)));
  const duration = project.targetDurationSeconds / sceneCount;

  return Array.from({ length: sceneCount }, (_, index) => ({
    sceneIndex: index,
    title: `Scene ${index + 1}`,
    narration: "",
    visualPrompt: `${project.prompt}\n\nCreate shot ${index + 1} of ${sceneCount}. Keep visual continuity with the other shots.`,
    durationSeconds: Number(duration.toFixed(2)),
  }));
}

export function buildStoryboardPrompt(project) {
  return `You are Zorvian Video Director. Convert the user's request into a production-ready storyboard.\n\nReturn JSON only in this shape:\n{\n  "title": "short project title",\n  "scenes": [\n    {\n      "title": "scene title",\n      "narration": "optional spoken words",\n      "visual_prompt": "specific generation prompt for one coherent shot",\n      "duration_seconds": 5\n    }\n  ]\n}\n\nRules:\n- Total scene duration should be close to ${project.targetDurationSeconds} seconds.\n- Use 1 to 12 scenes.\n- Each visual prompt must stand alone while preserving continuity.\n- Do not mention a provider or model name.\n- Aspect ratio: ${project.aspectRatio}.\n- Do not invent trademarked characters or copyrighted styles that the user did not request.\n\nUser request:\n${project.prompt}`;
}

export function parseStoryboard(raw, project) {
  const text = String(raw || "").trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { title: project.title, scenes: fallbackStoryboard(project), degraded: true };
  }

  const scenes = Array.isArray(parsed?.scenes) ? parsed.scenes.slice(0, 12) : [];
  const normalized = scenes.map((scene, index) => ({
    sceneIndex: index,
    title: String(scene?.title || `Scene ${index + 1}`).slice(0, 120),
    narration: String(scene?.narration || "").slice(0, 4000),
    visualPrompt: String(scene?.visual_prompt || scene?.prompt || project.prompt).trim().slice(0, 12000),
    durationSeconds: Math.min(Math.max(Number(scene?.duration_seconds) || DEFAULT_SCENE_SECONDS, 1), 20),
  })).filter((scene) => scene.visualPrompt);

  if (!normalized.length) {
    return { title: project.title, scenes: fallbackStoryboard(project), degraded: true };
  }

  return {
    title: String(parsed?.title || project.title).slice(0, 120),
    scenes: normalized,
    degraded: false,
  };
}

export function selectProvider({ capability, providers = [], preference = "balanced" }) {
  const eligible = providers.filter((provider) => provider.enabled !== false && provider.capabilities?.includes(capability));
  if (!eligible.length) return null;

  const scored = eligible.map((provider) => {
    const quality = Number(provider.qualityScore ?? 0.7);
    const reliability = Number(provider.reliabilityScore ?? 0.9);
    const cost = Math.max(Number(provider.costScore ?? 0.5), 0.01);
    const latency = Math.max(Number(provider.latencyScore ?? 0.5), 0.01);

    let score;
    if (preference === "quality") score = quality * 0.65 + reliability * 0.25 + (1 / cost) * 0.1;
    else if (preference === "cost") score = (1 / cost) * 0.55 + reliability * 0.3 + quality * 0.15;
    else if (preference === "speed") score = (1 / latency) * 0.55 + reliability * 0.3 + quality * 0.15;
    else score = quality * 0.35 + reliability * 0.35 + (1 / cost) * 0.15 + (1 / latency) * 0.15;

    return { provider, score };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored[0].provider;
}

export function estimateProjectCostMicros(scenes, provider) {
  const perSecondMicros = Number(provider?.pricePerSecondMicros || 0);
  return scenes.reduce((total, scene) => total + Math.round(scene.durationSeconds * perSecondMicros), 0);
}
