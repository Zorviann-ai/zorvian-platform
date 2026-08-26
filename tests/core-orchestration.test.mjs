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
  for(const service of ['executive','sales','marketing','secretary','social','documents','proofreader','authors','sound','vision','vehicle_sourcing']){
    assert.match(source,new RegExp(service+':\\{name:'),service);
  }
  for(const route of ['/api/core/status','/api/core/run','/api/core/runs']){
    assert.ok(source.includes(route),route);
  }
  assert.ok(source.includes("external_actions_executed:false"));
});

test('Club One vehicle sourcing AI is decision support only and requires approval',async()=>{
  const source=await fs.readFile(new URL('../src/core.js',import.meta.url),'utf8');
  for(const marker of ['Club One Vehicle Sourcing AI','DECISION: BUY / WATCH / REJECT','MAXIMUM BID','ESTIMATED LANDED COST','UK EXIT VALUE','PROJECTED GROSS MARGIN','HUMAN APPROVAL REQUIRED BEFORE ANY BID, PURCHASE, PAYMENT OR FINANCIAL COMMITMENT']){
    assert.ok(source.includes(marker),marker);
  }
  assert.ok(source.includes("'vehicle_sourcing'].includes(service)"));
  assert.ok(source.includes("'vehicle_bid'"));
  assert.ok(source.includes("'vehicle_purchase'"));
});

test('Authors flow requires rights and creates proof, story, sound and vision handoffs',async()=>{
  const source=await fs.readFile(new URL('../src/authors.js',import.meta.url),'utf8');
  for(const marker of ['public_domain_or_rights_confirmation_required','proofreading_notes','characters','scene_map','visual_direction','sound_direction','reader_experience','trailer_treatment','adaptation_pathway']){
    assert.ok(source.includes(marker),marker);
  }
  assert.ok(source.includes('/api/authors/visualise'));
  assert.ok(source.includes('/api/authors/projects'));
});

test('Core control workspace presents the joined client services',async()=>{
  const html=await fs.readFile(new URL('../public/core.html',import.meta.url),'utf8');
  for(const marker of ['CRM','AI Secretary','AI Assistant','Marketing & Social','Finance','Studio','Document & Letter Writer','Authors','My Workflow','GUARDIAN ACTIVE']){
    assert.ok(html.includes(marker),marker);
  }
  assert.ok(html.includes('/api/core/status'));
  assert.ok(html.includes('/crm.html'));
  assert.ok(html.includes('/social-studio.html'));
  assert.ok(html.includes('/media-studio.html'));
  assert.ok(html.includes('/authors/'));
});