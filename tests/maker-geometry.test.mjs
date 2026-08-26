import test from 'node:test';
import assert from 'node:assert/strict';
import { generateTemplateMesh, validateMesh, buildValidatedSTL } from '../src/maker-geometry.js';

test('approved wall plaque produces closed print-ready STL',()=>{const r=buildValidatedSTL('wall_plaque',{width:100,height:50,depth:5},'test-plaque');assert.equal(r.status,'print_ready');assert.equal(r.validation.ok,true);assert.match(r.stl,/^solid test-plaque/);assert.equal(r.validation.triangle_count,12);});

test('approved plant label produces closed manifold geometry',()=>{const mesh=generateTemplateMesh('plant_label',{width:25,height:120,depth:3,tip:25});const v=validateMesh(mesh);assert.equal(v.ok,true);assert.equal(v.errors.length,0);assert.ok(v.volume_mm3>0);});

test('approved desk wedge produces closed manifold geometry',()=>{const mesh=generateTemplateMesh('desk_wedge',{width:100,height:50,depth:60,lip:20});const v=validateMesh(mesh);assert.equal(v.ok,true);assert.equal(v.errors.length,0);});

test('open mesh is blocked from print ready',()=>{const mesh=[[[0,0,0],[10,0,0],[0,10,0]]];const v=validateMesh(mesh);assert.equal(v.ok,false);assert.equal(v.status,'needs_validation');});

test('unsupported freeform template cannot generate STL',()=>{assert.throws(()=>buildValidatedSTL('dragon',{width:100},'x'),/unsupported_geometry_template/);});
