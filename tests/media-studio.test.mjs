import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('AI Media Studio backend exposes the complete protected production surface', async () => {
  const source=await fs.readFile(new URL('../src/media.js',import.meta.url),'utf8');
  for(const table of ['media_profiles','media_productions','media_scenes','media_assets']) assert.ok(source.includes('CREATE TABLE IF NOT EXISTS '+table),table);
  for(const route of ['status','profiles','productions','render','refresh','sound']) assert.ok(source.includes('"'+route+'"'),route);
  assert.ok(source.includes('consent_confirmation_required'));
  assert.ok(source.includes('duration_minutes'));
  assert.ok(source.includes('https://api.heygen.com/v2/video/generate'));
  assert.ok(source.includes('https://api.elevenlabs.io/v1/sound-generation'));
  assert.ok(source.includes('cache-control'));
  assert.doesNotMatch(source,/sk-[A-Za-z0-9_-]{20}/);
});

test('customer portal includes a long-form television editing workspace', async () => {
  const html=await fs.readFile(new URL('../public/media-studio.html',import.meta.url),'utf8');
  for(const marker of [
    'AI Film & Television Editor',
    'PRODUCTION LIBRARY',
    'SCENE INSPECTOR',
    'TIMELINE',
    'V1 · PICTURE',
    'A1 · DIALOGUE',
    'A2 · MUSIC / SFX',
    'T1 · CAPTIONS',
    'Start a production',
    'Feature / long-form',
    'TV episode',
    'Documentary',
    '60 minutes',
    'Consented avatars & voices',
    'RENDER PRODUCTION',
    'EXPORT PLAN'
  ]) assert.ok(html.includes(marker),marker);
  assert.ok(html.includes('/api/media/sound'));
  assert.ok(html.includes('/media/productions'));
  assert.ok(html.includes("credentials:\"same-origin\""));
  assert.ok(html.includes('localStorage'));
});

test('production Worker routes media APIs and links the studio', async () => {
  const source=await fs.readFile(new URL('../src/platform.js',import.meta.url),'utf8');
  assert.ok(source.includes("import { handleMedia } from './media.js'"));
  assert.ok(source.includes("startsWith('/api/media/')"));
  assert.ok(source.includes("url.pathname==='/media-studio'"));
  assert.ok(source.includes("new URL('/media-studio.html',url)"));
});
