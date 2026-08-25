import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('production Worker wires the unified Celestial Core',async()=>{
  const platform=await fs.readFile(new URL('../src/platform.js',import.meta.url),'utf8');
  assert.match(platform,/handleCore/);
  assert.match(platform,/\/api\/core\//);
});

test('Core exposes all requested AI services and approval controls',async()=>{
  const source=await fs.readFile(new URL('../src/core.js',import.meta.url),'utf8');
  for(const service of ['executive','sales','marketing','secretary','social','documents','proofreader','authors','sound','vision','economy']){
    assert.match(source,new RegExp(service+':\\{name:'),service);
  }
  for(const route of ['/api/core/status','/api/core/run','/api/core/runs','/api/core/workers']){
    assert.ok(source.includes(route),route);
  }
  assert.ok(source.includes("external_actions_executed:false"));
  assert.ok(source.includes("spending_limit:0"));
  assert.ok(source.includes("profit_only:true"));
  assert.ok(source.includes("loss_exposure:false"));
});

test('Authors flow requires rights and creates proof, story, sound and vision handoffs',async()=>{
  const source=await fs.readFile(new URL('../src/authors.js',import.meta.url),'utf8');
  for(const marker of ['public_domain_or_rights_confirmation_required','proofreading_notes','characters','scene_map','visual_direction','sound_direction','reader_experience','trailer_treatment','adaptation_pathway']){
    assert.ok(source.includes(marker),marker);
  }
  assert.ok(source.includes('/api/authors/visualise'));
  assert.ok(source.includes('/api/authors/projects'));
});

test('Core control workspace presents the joined services',async()=>{
  const html=await fs.readFile(new URL('../public/core.html',import.meta.url),'utf8');
  for(const marker of ['Sales AI','Marketing AI','Secretary AI','Social Media AI','Document Studio','Proofreader','Authors Visualisation','Sound Studio','Vision Studio','Profit Workers']){
    assert.ok(html.includes(marker),marker);
  }
  assert.ok(html.includes('/api/core/status'));
  assert.ok(html.includes('/api/core/run'));
  assert.ok(html.includes('/api/authors/visualise'));
});
