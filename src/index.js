const COOKIE = "qearl_owner";
const MAX_AGE = 60 * 60 * 24 * 7;

const enc = new TextEncoder();

function bytesToB64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
}
function b64UrlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function hmac(data, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
function safeEqualString(a,b) {
  const aa=enc.encode(String(a||"")), bb=enc.encode(String(b||""));
  let diff=aa.length^bb.length;
  const n=Math.max(aa.length,bb.length);
  for(let i=0;i<n;i++) diff |= (aa[i%Math.max(1,aa.length)]||0) ^ (bb[i%Math.max(1,bb.length)]||0);
  return diff===0;
}
function parseCookies(request) {
  const raw=request.headers.get("Cookie")||"";
  const out={};
  raw.split(";").forEach(part=>{
    const i=part.indexOf("=");
    if(i>0) out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());
  });
  return out;
}
function json(data,status=200,headers={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...headers}
  });
}
function sameOrigin(request) {
  const origin=request.headers.get("Origin");
  return !origin || origin===new URL(request.url).origin;
}
async function makeSession(username, env) {
  const payload={sub:username,exp:Date.now()+MAX_AGE*1000,nonce:crypto.randomUUID()};
  const body=bytesToB64Url(enc.encode(JSON.stringify(payload)));
  const sig=bytesToB64Url(await hmac(body,env.SESSION_SECRET));
  return `${body}.${sig}`;
}
async function readSession(request, env) {
  try{
    const token=parseCookies(request)[COOKIE];
    if(!token)return null;
    const [body,sig]=token.split(".");
    if(!body||!sig)return null;
    const expected=await hmac(body,env.SESSION_SECRET);
    const key=await crypto.subtle.importKey("raw",enc.encode(env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const valid=await crypto.subtle.verify("HMAC",key,b64UrlToBytes(sig),enc.encode(body));
    if(!valid)return null;
    const payload=JSON.parse(new TextDecoder().decode(b64UrlToBytes(body)));
    if(!payload.exp || payload.exp<Date.now())return null;
    return payload;
  }catch{return null}
}
async function requireOwner(context) {
  const session=await readSession(context.request,context.env);
  if(!session) return {ok:false,response:json({error:"Unauthorized"},401)};
  return {ok:true,session};
}
function sessionCookie(token) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${MAX_AGE}`;
}
function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}



async function readJson(request){ return await request.json().catch(()=>({})); }
function validPage(x){return typeof x==="string" && /^[A-Za-z0-9_\-\u4e00-\u9fff]{1,80}$/.test(x)}

async function handleState(env){
  const [ov,add,pages]=await Promise.all([
    env.DB.prepare("SELECT page,block_index,text_override,image_key_override,deleted FROM content_overrides").all(),
    env.DB.prepare("SELECT id,page,sort_order,type,text_content,image_key,is_heading FROM additions ORDER BY page,sort_order,id").all(),
    env.DB.prepare("SELECT slug,title,sort_order FROM custom_pages WHERE published=1 ORDER BY sort_order,id").all()
  ]);
  const overrides={}, additions={};
  for(const r of ov.results||[]) (overrides[r.page] ||= {})[String(r.block_index)] = r;
  for(const r of add.results||[]) (additions[r.page] ||= []).push(r);
  return json({overrides,additions,pages:pages.results||[]});
}

async function handleBlock(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403);
  const b=await readJson(request);
  if(request.method==="POST"){
    if(!validPage(b.page)||!["text","image"].includes(b.type))return json({error:"Invalid data"},400);
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM additions WHERE page=?").bind(b.page).first();
    const result=await env.DB.prepare("INSERT INTO additions(page,sort_order,type,text_content,image_key,is_heading) VALUES(?,?,?,?,?,?) RETURNING id")
      .bind(b.page,row?.n||1,b.type,b.text||null,b.imageKey||null,b.isHeading?1:0).first();
    return json({ok:true,id:result.id});
  }
  if(request.method==="PUT"){
    if(b.additionId){
      const found=await env.DB.prepare("SELECT id FROM additions WHERE id=?").bind(b.additionId).first();
      if(!found)return json({error:"Not found"},404);
      if(b.text!==undefined)await env.DB.prepare("UPDATE additions SET text_content=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(b.text,b.additionId).run();
      if(b.imageKey)await env.DB.prepare("UPDATE additions SET image_key=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(b.imageKey,b.additionId).run();
      return json({ok:true});
    }
    if(!validPage(b.page)||!Number.isInteger(b.blockIndex))return json({error:"Invalid data"},400);
    await env.DB.prepare(`INSERT INTO content_overrides(page,block_index,text_override,image_key_override,deleted)
      VALUES(?,?,?,?,0) ON CONFLICT(page,block_index) DO UPDATE SET
      text_override=COALESCE(excluded.text_override,content_overrides.text_override),
      image_key_override=COALESCE(excluded.image_key_override,content_overrides.image_key_override),
      deleted=0,updated_at=CURRENT_TIMESTAMP`)
      .bind(b.page,b.blockIndex,b.text!==undefined?b.text:null,b.imageKey||null).run();
    return json({ok:true});
  }
  if(request.method==="DELETE"){
    if(b.additionId){ await env.DB.prepare("DELETE FROM additions WHERE id=?").bind(b.additionId).run(); return json({ok:true}); }
    if(!validPage(b.page)||!Number.isInteger(b.blockIndex))return json({error:"Invalid data"},400);
    await env.DB.prepare(`INSERT INTO content_overrides(page,block_index,deleted) VALUES(?,?,1)
      ON CONFLICT(page,block_index) DO UPDATE SET deleted=1,updated_at=CURRENT_TIMESTAMP`).bind(b.page,b.blockIndex).run();
    return json({ok:true});
  }
  return json({error:"Method not allowed"},405);
}


async function handlePublish(request,env){
  const a=await readSession(request,env);
  if(!a)return json({error:"Unauthorized"},401);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403);

  const form=await request.formData();
  const page=String(form.get("target")||"").trim();
  const title=String(form.get("title")||"").trim();
  const text=String(form.get("text")||"").trim();
  if(!validPage(page))return json({error:"Invalid page"},400);
  if(!title)return json({error:"Title required"},400);

  let next=(await env.DB.prepare(
    "SELECT COALESCE(MAX(sort_order),0)+1 n FROM additions WHERE page=?"
  ).bind(page).first())?.n||1;

  const stmts=[];
  stmts.push(
    env.DB.prepare(
      "INSERT INTO additions(page,sort_order,type,text_content,image_key,is_heading) VALUES(?,?,?,?,?,?)"
    ).bind(page,next++,"text",title,null,1)
  );

  if(text){
    for(const line of text.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){
      stmts.push(
        env.DB.prepare(
          "INSERT INTO additions(page,sort_order,type,text_content,image_key,is_heading) VALUES(?,?,?,?,?,?)"
        ).bind(page,next++,"text",line,null,0)
      );
    }
  }

  const files=form.getAll("images").filter(x=>x && typeof x.arrayBuffer==="function" && x.size>0);
  let total=0;
  for(const file of files){
    total+=file.size;
    if(file.size>950000)return json({error:"单张图片压缩后仍超过 950KB"},413);
    if(total>2800000)return json({error:"本次图片总大小超过 2.8MB"},413);

    const buf=new Uint8Array(await file.arrayBuffer());
    let binary="";
    const chunk=0x8000;
    for(let i=0;i<buf.length;i+=chunk){
      binary+=String.fromCharCode(...buf.subarray(i,i+chunk));
    }
    const dataUrl=`data:${file.type||"image/webp"};base64,${btoa(binary)}`;
    stmts.push(
      env.DB.prepare(
        "INSERT INTO additions(page,sort_order,type,text_content,image_key,is_heading) VALUES(?,?,?,?,?,?)"
      ).bind(page,next++,"image",null,dataUrl,0)
    );
  }

  if(stmts.length)await env.DB.batch(stmts);
  return json({ok:true,count:stmts.length});
}

async function handlePage(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403);
  const b=await readJson(request);
  if(request.method==="POST"){
    const title=String(b.title||"").trim();
    if(!title||title.length>100)return json({error:"Invalid title"},400);
    const slug="q-"+Date.now().toString(36)+"-"+crypto.randomUUID().slice(0,6);
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM custom_pages").first();
    await env.DB.prepare("INSERT INTO custom_pages(slug,title,sort_order,published) VALUES(?,?,?,1)").bind(slug,title,row?.n||1).run();
    return json({ok:true,slug,title});
  }
  if(request.method==="DELETE"){
    await env.DB.batch([
      env.DB.prepare("DELETE FROM additions WHERE page=?").bind(b.slug),
      env.DB.prepare("DELETE FROM custom_pages WHERE slug=?").bind(b.slug)
    ]);
    return json({ok:true});
  }
  return json({error:"Method not allowed"},405);
}


export default {
  async fetch(request,env){
    const url=new URL(request.url), p=url.pathname;
    try{
      if((p==="/api/session" || p==="/api/me") && request.method==="GET"){
        const s=await readSession(request,env); return json({authenticated:!!s,ok:!!s},s?200:401);
      }
      if(p==="/api/login" && request.method==="POST"){
        if(!sameOrigin(request))return json({error:"Invalid origin"},403);
        const b=await readJson(request);
        const loginName=b.username??b.id; const ok=safeEqualString(loginName,env.ADMIN_USERNAME)&&safeEqualString(b.password,env.ADMIN_PASSWORD);
        if(!ok)return json({error:"Invalid credentials"},401);
        const token=await makeSession(loginName,env);
        return json({ok:true},200,{"Set-Cookie":sessionCookie(token)});
      }
      if(p==="/api/logout" && request.method==="POST"){
        return json({ok:true},200,{"Set-Cookie":clearCookie()});
      }
      if(p==="/api/state" && request.method==="GET") return await handleState(env);
      if(p==="/api/publish" && request.method==="POST") return await handlePublish(request,env);
      if(p==="/api/block") return await handleBlock(request,env);
      if(p==="/api/page") return await handlePage(request,env);
      return env.ASSETS.fetch(request);
    }catch(e){
      console.error(e); return json({error:"Server error"},500);
    }
  }
};
