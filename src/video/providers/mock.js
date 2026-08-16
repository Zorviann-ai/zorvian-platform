import { VIDEO_CAPABILITIES } from "../core.js";

export const mockVideoProvider = Object.freeze({
  key: "mock",
  name: "Zorvian Mock Video",
  enabled: true,
  capabilities: [VIDEO_CAPABILITIES.textToVideo],
  qualityScore: 0.2,
  reliabilityScore: 1,
  costScore: 0.01,
  latencyScore: 0.01,
  pricePerSecondMicros: 0,
  simulation: true,
});

function escapeXml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function wrap(text, width = 54, lines = 5) {
  const words = String(text || "").split(/\s+/).filter(Boolean);
  const output = [];
  let current = "";
  for (const word of words) {
    if ((current + " " + word).trim().length > width) {
      if (current) output.push(current);
      current = word;
      if (output.length >= lines) break;
    } else {
      current = (current + " " + word).trim();
    }
  }
  if (current && output.length < lines) output.push(current);
  return output;
}

export async function generateMockScene({ project, scene }) {
  const lines = wrap(scene.visual_prompt || scene.visualPrompt || project.prompt);
  const copy = lines.map((line, index) =>
    `<text x="64" y="${205 + index * 34}" font-family="system-ui, sans-serif" font-size="22" fill="#d8def0">${escapeXml(line)}</text>`
  ).join("");
  const title = escapeXml(scene.title || `Scene ${Number(scene.scene_index ?? scene.sceneIndex ?? 0) + 1}`);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#111827"/><stop offset="1" stop-color="#261c45"/></linearGradient></defs><rect width="1280" height="720" fill="url(#g)"/><circle cx="1120" cy="120" r="210" fill="#7c3aed" opacity=".16"/><text x="64" y="82" font-family="system-ui, sans-serif" font-size="22" font-weight="700" fill="#a78bfa">ZORVIAN VIDEO · SIMULATION</text><text x="64" y="152" font-family="system-ui, sans-serif" font-size="42" font-weight="700" fill="white">${title}</text>${copy}<text x="64" y="650" font-family="system-ui, sans-serif" font-size="18" fill="#8f9bb3">${Number(scene.duration_seconds ?? scene.durationSeconds ?? 5).toFixed(1)}s · provider-neutral pipeline test · £0 generation spend</text></svg>`;
  const sourceUrl = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;

  return {
    providerKey: mockVideoProvider.key,
    providerJobId: `mock_${crypto.randomUUID()}`,
    status: "completed",
    actualCostMicros: 0,
    asset: {
      kind: "mock_scene_preview",
      sourceUrl,
      mimeType: "image/svg+xml",
      width: 1280,
      height: 720,
      durationSeconds: Number(scene.duration_seconds ?? scene.durationSeconds ?? 5),
      metadata: { simulation: true, provider: mockVideoProvider.key },
    },
  };
}
