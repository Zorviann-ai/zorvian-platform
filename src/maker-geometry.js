const EPS=1e-7;
const n=v=>Number(v);
const clamp=(v,min,max)=>Math.min(max,Math.max(min,n(v)||min));
const vkey=v=>v.map(x=>Number(x).toFixed(6)).join(',');
const edgeKey=(a,b)=>{const x=vkey(a),y=vkey(b);return x<y?`${x}|${y}`:`${y}|${x}`;};
const sub=(a,b)=>[a[0]-b[0],a[1]-b[1],a[2]-b[2]];
const cross=(a,b)=>[a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]];
const dot=(a,b)=>a[0]*b[0]+a[1]*b[1]+a[2]*b[2];
const mag=a=>Math.sqrt(dot(a,a));

function tri(a,b,c){return [a,b,c];}

export function cuboidMesh(width,depth,height){
  const w=clamp(width,5,400),d=clamp(depth,2,400),h=clamp(height,2,400);
  const p=[[0,0,0],[w,0,0],[w,d,0],[0,d,0],[0,0,h],[w,0,h],[w,d,h],[0,d,h]];
  return [
    tri(p[0],p[2],p[1]),tri(p[0],p[3],p[2]),
    tri(p[4],p[5],p[6]),tri(p[4],p[6],p[7]),
    tri(p[0],p[1],p[5]),tri(p[0],p[5],p[4]),
    tri(p[1],p[2],p[6]),tri(p[1],p[6],p[5]),
    tri(p[2],p[3],p[7]),tri(p[2],p[7],p[6]),
    tri(p[3],p[0],p[4]),tri(p[3],p[4],p[7])
  ];
}

function polygonArea(poly){let s=0;for(let i=0;i<poly.length;i++){const a=poly[i],b=poly[(i+1)%poly.length];s+=a[0]*b[1]-b[0]*a[1];}return s/2;}

function pointInTri2(p,a,b,c){
  const s=(p1,p2,p3)=>(p1[0]-p3[0])*(p2[1]-p3[1])-(p2[0]-p3[0])*(p1[1]-p3[1]);
  const d1=s(p,a,b),d2=s(p,b,c),d3=s(p,c,a);const neg=d1<-EPS||d2<-EPS||d3<-EPS,pos=d1>EPS||d2>EPS||d3>EPS;return !(neg&&pos);
}
function earClip(poly){
  if(poly.length<3)throw new Error('polygon_too_small');
  const pts=polygonArea(poly)>0?poly:[...poly].reverse();
  const ids=pts.map((_,i)=>i),out=[];let guard=0;
  while(ids.length>3&&guard++<1000){let cut=false;
    for(let k=0;k<ids.length;k++){
      const ia=ids[(k-1+ids.length)%ids.length],ib=ids[k],ic=ids[(k+1)%ids.length];
      const a=pts[ia],b=pts[ib],c=pts[ic];
      const ab=[b[0]-a[0],b[1]-a[1]],bc=[c[0]-b[0],c[1]-b[1]];
      if(ab[0]*bc[1]-ab[1]*bc[0]<=EPS)continue;
      let inside=false;for(const id of ids){if(id===ia||id===ib||id===ic)continue;if(pointInTri2(pts[id],a,b,c)){inside=true;break;}}
      if(inside)continue;out.push([ia,ib,ic]);ids.splice(k,1);cut=true;break;
    }
    if(!cut)throw new Error('polygon_triangulation_failed');
  }
  if(ids.length===3)out.push([ids[0],ids[1],ids[2]]);
  return {pts,faces:out};
}

export function extrudePolygonMesh(poly,depth){
  const d=clamp(depth,2,100);const {pts,faces}=earClip(poly);const mesh=[];
  for(const [a,b,c] of faces){mesh.push(tri([pts[c][0],0,pts[c][1]],[pts[b][0],0,pts[b][1]],[pts[a][0],0,pts[a][1]]));mesh.push(tri([pts[a][0],d,pts[a][1]],[pts[b][0],d,pts[b][1]],[pts[c][0],d,pts[c][1]]));}
  for(let i=0;i<pts.length;i++){const a=pts[i],b=pts[(i+1)%pts.length];const a0=[a[0],0,a[1]],b0=[b[0],0,b[1]],a1=[a[0],d,a[1]],b1=[b[0],d,b[1]];mesh.push(tri(a0,b0,b1),tri(a0,b1,a1));}
  return mesh;
}

export const APPROVED_TEMPLATES={
  wall_plaque:{label:'Wall plaque',safe:true},
  plant_label:{label:'Plant label',safe:true},
  desk_wedge:{label:'Desk wedge / phone rest',safe:true}
};

export function generateTemplateMesh(template,params={}){
  if(template==='wall_plaque')return cuboidMesh(clamp(params.width,60,300),clamp(params.depth,3,18),clamp(params.height,25,160));
  if(template==='plant_label'){
    const w=clamp(params.width,18,60),h=clamp(params.height,80,240),tip=clamp(params.tip,15,Math.min(60,h*.4));
    return extrudePolygonMesh([[0,0],[w,0],[w,h-tip],[w/2,h],[0,h-tip]],clamp(params.depth,2,6));
  }
  if(template==='desk_wedge'){
    const w=clamp(params.width,60,220),h=clamp(params.height,25,120),lip=clamp(params.lip,12,Math.min(45,w*.3));
    return extrudePolygonMesh([[0,0],[w,0],[w-lip,h],[lip,h]],clamp(params.depth,35,120));
  }
  throw new Error('unsupported_geometry_template');
}

export function validateMesh(mesh,{maxDimension=400,minDimension=.8}={}){
  const errors=[];if(!Array.isArray(mesh)||mesh.length<4)return {ok:false,status:'needs_validation',errors:['mesh_missing_or_too_small']};
  const edges=new Map();let degenerate=0,finite=true;const mins=[Infinity,Infinity,Infinity],maxs=[-Infinity,-Infinity,-Infinity];let volume=0;
  for(const t of mesh){
    if(!Array.isArray(t)||t.length!==3){errors.push('invalid_triangle');continue;}
    for(const p of t){if(!Array.isArray(p)||p.length!==3||p.some(x=>!Number.isFinite(x)))finite=false;else for(let i=0;i<3;i++){mins[i]=Math.min(mins[i],p[i]);maxs[i]=Math.max(maxs[i],p[i]);}}
    if(!finite)continue;
    const normal=cross(sub(t[1],t[0]),sub(t[2],t[0]));if(mag(normal)<=EPS)degenerate++;
    for(const [a,b] of [[t[0],t[1]],[t[1],t[2]],[t[2],t[0]]]){const k=edgeKey(a,b);edges.set(k,(edges.get(k)||0)+1);}
    volume+=dot(t[0],cross(t[1],t[2]))/6;
  }
  if(!finite)errors.push('non_finite_coordinate');if(degenerate)errors.push(`degenerate_triangles:${degenerate}`);
  let boundary=0,nonManifold=0;for(const count of edges.values()){if(count===1)boundary++;else if(count!==2)nonManifold++;}
  if(boundary)errors.push(`open_boundary_edges:${boundary}`);if(nonManifold)errors.push(`non_manifold_edges:${nonManifold}`);
  const dims=maxs.map((x,i)=>x-mins[i]);if(dims.some(x=>!Number.isFinite(x)||x<minDimension))errors.push('dimension_below_minimum');if(dims.some(x=>x>maxDimension))errors.push('dimension_above_limit');
  if(Math.abs(volume)<=EPS)errors.push('zero_mesh_volume');
  return {ok:errors.length===0,status:errors.length===0?'print_ready':'needs_validation',errors,triangle_count:mesh.length,edge_count:edges.size,bounds_mm:{x:dims[0],y:dims[1],z:dims[2]},volume_mm3:Math.abs(volume)};
}

export function meshToAsciiSTL(mesh,name='caelomere-original'){
  const lines=[`solid ${String(name).replace(/[^a-z0-9_-]/gi,'-')}`];
  for(const t of mesh){const c=cross(sub(t[1],t[0]),sub(t[2],t[0])),m=mag(c)||1,norm=c.map(x=>x/m);lines.push(`  facet normal ${norm[0]} ${norm[1]} ${norm[2]}`,'    outer loop',...t.map(p=>`      vertex ${p[0]} ${p[1]} ${p[2]}`),'    endloop','  endfacet');}
  lines.push('endsolid');return lines.join('\n');
}

export function buildValidatedSTL(template,params,name){
  const mesh=generateTemplateMesh(template,params);const validation=validateMesh(mesh);if(!validation.ok)return {status:'needs_validation',validation,stl:null};
  return {status:'print_ready',validation,stl:meshToAsciiSTL(mesh,name)};
}
