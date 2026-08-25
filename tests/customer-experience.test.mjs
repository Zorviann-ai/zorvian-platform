import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const read=path=>fs.readFile(new URL('../'+path,import.meta.url),'utf8');

test('active customer surfaces use Caelomere branding', async () => {
  const files=['public/index.html','public/crm.html','public/social-studio.html','public/media-studio.html','public/website.html','public/progress.html','public/agent.html','public/life.html','public/reset-password.html'];
  for(const file of files){
    const source=await read(file);
    assert.doesNotMatch(source,/Zorvian/i,file);
    assert.match(source,/Caelomere/i,file);
  }
});

test('TV editor opens as a focus-first large screen with optional panels', async () => {
  const html=await read('public/media-studio.html');
  for(const marker of ["grid-template-columns:minmax(0,1fr)","LIBRARY","OPTIONS","FULL SCREEN","togglePanel('library')","togglePanel('inspector')","requestFullscreen","CAELOMERE DIRECTOR","I HAVE AN IDEA","ADD SOUND","FINISH & RENDER"]) assert.ok(html.includes(marker),marker);
  assert.ok(html.includes('speechSynthesis'));
  assert.ok(html.includes('directorVoiceOn=true'));
});

test('Social Studio offers simple living AI guidance', async () => {
  const html=await read('public/social-studio.html');
  for(const marker of ['CAELOMERE GUIDE','CREATE A POST','CREATE A VIDEO','ADD SOUND','CHOOSE CHANNELS','SCHEDULE','RESULTS','VOICE ON']) assert.ok(html.includes(marker),marker);
  assert.ok(html.includes('SpeechSynthesisUtterance'));
  assert.ok(html.includes('toggleGuideVoice'));
});

test('AI specialist identities no longer expose the legacy product brand', async () => {
  const source=await read('src/worker.js');
  assert.doesNotMatch(source,/Zorvian AI/);
  assert.match(source,/Caelomere AI Receptionist/);
});
