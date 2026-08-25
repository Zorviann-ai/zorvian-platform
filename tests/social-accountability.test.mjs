import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('social backend exposes channel presets and accountable workflow', async () => {
  const source=await fs.readFile(new URL('../src/social.js',import.meta.url),'utf8');
  for(const channel of ['instagram','facebook','linkedin','tiktok','youtube','x']) assert.match(source,new RegExp(channel+':\\{name:'),channel);
  for(const table of ['social_campaigns','social_schedule','social_analytics','social_approvals']) assert.ok(source.includes('CREATE TABLE IF NOT EXISTS '+table),table);
  for(const route of ['channels','renditions','schedules','analytics','approval','schedule']) assert.ok(source.includes("'"+route+"'"),route);
  assert.ok(source.includes('human_confirmation_required'));
  assert.ok(source.includes('human_approval_required'));
  assert.ok(source.includes('future_schedule_required'));
  assert.ok(source.includes('insufficient_data'));
  assert.ok(source.includes('publishing_automatic:false'));
  assert.doesNotMatch(source,/sk-[A-Za-z0-9_-]{20}/);
});

test('social format engine covers portrait, square and landscape outputs', async () => {
  const source=await fs.readFile(new URL('../src/social.js',import.meta.url),'utf8');
  for(const size of ['width:1080,height:1920','width:1080,height:1350','width:1080,height:1080','width:1920,height:1080']) assert.ok(source.includes(size),size);
  for(const control of ['safe_area','captions','audio_normalisation','thumbnail_required']) assert.ok(source.includes(control),control);
});

test('Social Studio visibly supports sound, vision, tone, approval and analytics', async () => {
  const html=await fs.readFile(new URL('../public/social-studio.html',import.meta.url),'utf8');
  for(const marker of ['CAELOMERE','Social account connections','Automatic format engine','Humorous','Serious and sensitive','HUMAN APPROVE','Approved schedule','Measured analytics & best times','SAVE VERIFIED METRICS']) assert.ok(html.includes(marker),marker);
  for(const endpoint of ['/api/social/channels','/api/social/renditions','/approval','/schedule','/api/social/analytics']) assert.ok(html.includes(endpoint),endpoint);
  assert.ok(html.includes("credentials:'same-origin'"));
});

test('CRM console exposes the Social Studio', async () => {
  const html=await fs.readFile(new URL('../public/crm.html',import.meta.url),'utf8');
  assert.ok(html.includes('/social-studio.html'));
  assert.ok(html.includes('Social Studio'));
});
