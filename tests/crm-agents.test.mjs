import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('CRM exposes exactly eight elite specialist agents with distinct mandates', async () => {
  const source=await fs.readFile(new URL('../src/crm.js',import.meta.url),'utf8');
  for(const key of ['executive','reception','sales','support','marketing','operations','finance','media']) {
    assert.match(source,new RegExp(key+':\\{name:'),key);
  }
  for(const title of ['Executive Strategist','Reception & Qualification Director','Sales & Proposal Director','Customer Success Director','Brand & Growth Director','Operations Director','Commercial Finance Director','Film & Media Production Director']) {
    assert.ok(source.includes(title),title);
  }
  assert.ok(source.includes("unknown_agent"));
  assert.ok(source.includes("external_actions_executed:false"));
});

test('elite assignments use a two-pass quality-controlled Workers AI process', async () => {
  const source=await fs.readFile(new URL('../src/crm.js',import.meta.url),'utf8');
  assert.equal((source.match(/env\.AI\.run\('@cf\/zai-org\/glm-4\.7-flash'/g)||[]).length,2);
  assert.ok(source.includes('independent quality director'));
  assert.ok(source.includes('factual fidelity'));
  assert.ok(source.includes('no claim that an external action occurred'));
  assert.ok(source.includes('quality_passes:2'));
  assert.doesNotMatch(source,/sk-[A-Za-z0-9_-]{20}/);
});

test('CRM presents readiness, specialist assignment and saved agent results', async () => {
  const html=await fs.readFile(new URL('../public/crm.html',import.meta.url),'utf8');
  for(const marker of ['CAELOMERE','Elite AI Team','Eight senior specialists','Assign work','Recent agent work','RUN SPECIALIST']) assert.ok(html.includes(marker),marker);
  assert.ok(html.includes('/api/crm/status'));
  assert.ok(html.includes('/api/crm/agent/run'));
  assert.ok(html.includes('/api/crm/agent-runs'));
  assert.ok(html.includes("credentials:'same-origin'"));
});
