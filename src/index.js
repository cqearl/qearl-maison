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
function corsHeaders(request){
  const origin=request.headers.get("Origin")||"";
  const allowed=["https://qearlune.xyz","https://www.qearlune.xyz","https://api.qearlune.xyz"];
  return allowed.includes(origin)?{
    "Access-Control-Allow-Origin":origin,
    "Access-Control-Allow-Credentials":"true",
    "Vary":"Origin"
  }:{};
}
function json(data,status=200,headers={},request=null) {
  return new Response(JSON.stringify(data), {
    status,
    headers:{
      "Content-Type":"application/json; charset=utf-8",
      "Cache-Control":"no-store",
      ...(request?corsHeaders(request):{}),
      ...headers
    }
  });
}
function sameOrigin(request) {
  const origin=request.headers.get("Origin");
  if(!origin)return true;
  return ["https://qearlune.xyz","https://www.qearlune.xyz","https://api.qearlune.xyz",new URL(request.url).origin].includes(origin);
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
  return `${COOKIE}=${encodeURIComponent(token)}; Domain=.qearlune.xyz; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`;
}
function clearCookie() {
  return `${COOKIE}=; Domain=.qearlune.xyz; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
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
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
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
    return json({ok:true},200,{},request);
  }
  return json({error:"Method not allowed"},405,{},request);
}


async function handlePublish(request,env){
  const a=await readSession(request,env);
  if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);

  const form=await request.formData();
  const page=String(form.get("target")||"").trim();
  const title=String(form.get("title")||"").trim();
  const text=String(form.get("text")||"").trim();
  if(!validPage(page))return json({error:"Invalid page"},400,{},request);
  if(!title)return json({error:"Title required"},400,{},request);

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
    if(file.size>950000)return json({error:"单张图片压缩后仍超过 950KB"},413,{},request);
    if(total>2800000)return json({error:"本次图片总大小超过 2.8MB"},413,{},request);

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
  return json({ok:true,count:stmts.length},200,{},request);
}


async function ensureAdminSchema(env){
  const sqls=[
    `CREATE TABLE IF NOT EXISTS site_pages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, subtitle TEXT DEFAULT '',
      is_visible INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS site_sections (
      id INTEGER PRIMARY KEY AUTOINCREMENT, page_id INTEGER NOT NULL,
      title TEXT NOT NULL, subtitle TEXT DEFAULT '', layout_json TEXT DEFAULT '{}',
      is_visible INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS site_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT, section_id INTEGER NOT NULL,
      title TEXT NOT NULL, subtitle TEXT DEFAULT '', badge TEXT DEFAULT '', href TEXT DEFAULT '',
      content_text TEXT DEFAULT '', is_visible INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS site_media (
      id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
      url TEXT NOT NULL, public_id TEXT DEFAULT '', width INTEGER DEFAULT 0, height INTEGER DEFAULT 0,
      media_type TEXT DEFAULT 'image', alt TEXT DEFAULT '', sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`
  ];
  for(const q of sqls) await env.DB.prepare(q).run();
}
const toBool=v=>v?1:0;
const parseLayout=x=>{try{return JSON.parse(x||"{}")}catch{return {}}};


async function adminImportLegacy(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env);
  const payload=await readJson(request); let imported=0,skipped=0;
  for(const page of payload.pages||[]){
    const exists=await env.DB.prepare("SELECT id FROM site_pages WHERE slug=?").bind(page.slug).first();
    if(exists){skipped++;continue}
    const po=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM site_pages").first();
    const pr=await env.DB.prepare("INSERT INTO site_pages(title,slug,subtitle,is_visible,sort_order) VALUES(?,?,?,?,?) RETURNING id")
      .bind(page.title||page.slug,page.slug,page.subtitle||"",page.isVisible===false?0:1,po?.n||1).first();
    let so=1;
    for(const sec of page.sections||[]){
      const sr=await env.DB.prepare("INSERT INTO site_sections(page_id,title,subtitle,layout_json,is_visible,sort_order) VALUES(?,?,?,?,?,?) RETURNING id")
        .bind(pr.id,sec.title||"",sec.subtitle||"",JSON.stringify(sec.layout||{}),1,so++).first();
      let io=1;
      for(const item of sec.items||[]){
        const ir=await env.DB.prepare("INSERT INTO site_items(section_id,title,subtitle,badge,href,content_text,is_visible,sort_order) VALUES(?,?,?,?,?,?,?,?) RETURNING id")
          .bind(sr.id,item.title||"",item.subtitle||"",item.badge||"",item.href||"",item.content||"",1,io++).first();
        let mo=1;
        for(const media of item.media||[]){
          await env.DB.prepare("INSERT INTO site_media(item_id,url,public_id,width,height,media_type,alt,sort_order) VALUES(?,?,?,?,?,?,?,?)")
            .bind(ir.id,media.url||"",media.publicId||"",media.width||0,media.height||0,media.mediaType||"image",media.alt||"",mo++).run();
        }
      }
    }
    imported++;
  }
  return json({ok:true,imported,skipped},200,{},request);
}

async function adminBootstrap(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  await ensureAdminSchema(env);
  const [pr,sr,ir,mr]=await Promise.all([
    env.DB.prepare("SELECT * FROM site_pages ORDER BY sort_order,id").all(),
    env.DB.prepare("SELECT * FROM site_sections ORDER BY sort_order,id").all(),
    env.DB.prepare("SELECT * FROM site_items ORDER BY sort_order,id").all(),
    env.DB.prepare("SELECT * FROM site_media ORDER BY sort_order,id").all()
  ]);
  const pages=(pr.results||[]).map(p=>({...p,is_visible:!!p.is_visible,sections:[]}));
  const pmap=new Map(pages.map(p=>[String(p.id),p]));
  const smap=new Map();
  for(const r of sr.results||[]){
    const sec={...r,is_visible:!!r.is_visible,layout:parseLayout(r.layout_json),items:[]};
    smap.set(String(sec.id),sec); pmap.get(String(sec.page_id))?.sections.push(sec);
  }
  const imap=new Map();
  for(const r of ir.results||[]){
    const it={...r,is_visible:!!r.is_visible,media:[]}; imap.set(String(it.id),it);
    smap.get(String(it.section_id))?.items.push(it);
  }
  for(const r of mr.results||[]) imap.get(String(r.item_id))?.media.push(r);
  return json({ok:true,data:{pages}},200,{},request);
}
async function publicSite(request,env){
  await ensureAdminSchema(env);
  const url=new URL(request.url),slug=url.searchParams.get("page")||"";
  const p=await env.DB.prepare("SELECT * FROM site_pages WHERE slug=? AND is_visible=1").bind(slug).first();
  if(!p)return json({ok:true,page:null},200,{},request);
  const sr=await env.DB.prepare("SELECT * FROM site_sections WHERE page_id=? AND is_visible=1 ORDER BY sort_order,id").bind(p.id).all();
  const sections=[];
  for(const r of sr.results||[]){
    const ir=await env.DB.prepare("SELECT * FROM site_items WHERE section_id=? AND is_visible=1 ORDER BY sort_order,id").bind(r.id).all();
    const items=[];
    for(const it of ir.results||[]){
      const mr=await env.DB.prepare("SELECT * FROM site_media WHERE item_id=? ORDER BY sort_order,id").bind(it.id).all();
      items.push({...it,is_visible:!!it.is_visible,media:mr.results||[]});
    }
    sections.push({...r,is_visible:!!r.is_visible,layout:parseLayout(r.layout_json),items});
  }
  return json({ok:true,page:{...p,is_visible:true,sections}},200,{},request);
}
async function adminPages(request,env,p){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env); const b=await readJson(request);
  const m=p.match(/^\/api\/admin\/pages\/(\d+)$/),id=m?.[1];
  if(p==="/api/admin/pages"&&request.method==="POST"){
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM site_pages").first();
    const r=await env.DB.prepare("INSERT INTO site_pages(title,slug,subtitle,is_visible,sort_order) VALUES(?,?,?,?,?) RETURNING id")
      .bind(b.title||"Untitled page",b.slug||("page-"+Date.now()),b.subtitle||"",toBool(b.isVisible),row?.n||1).first();
    return json({ok:true,id:r.id},200,{},request);
  }
  if(id&&request.method==="PATCH"){
    await env.DB.prepare("UPDATE site_pages SET title=?,slug=?,subtitle=?,is_visible=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(b.title||"Untitled page",b.slug||("page-"+id),b.subtitle||"",toBool(b.isVisible),id).run();
    return json({ok:true},200,{},request);
  }
  if(id&&request.method==="DELETE"){
    const secs=await env.DB.prepare("SELECT id FROM site_sections WHERE page_id=?").bind(id).all();
    for(const sec of secs.results||[]){
      const its=await env.DB.prepare("SELECT id FROM site_items WHERE section_id=?").bind(sec.id).all();
      for(const it of its.results||[]) await env.DB.prepare("DELETE FROM site_media WHERE item_id=?").bind(it.id).run();
      await env.DB.prepare("DELETE FROM site_items WHERE section_id=?").bind(sec.id).run();
    }
    await env.DB.prepare("DELETE FROM site_sections WHERE page_id=?").bind(id).run();
    await env.DB.prepare("DELETE FROM site_pages WHERE id=?").bind(id).run();
    return json({ok:true},200,{},request);
  }
  return json({error:"Not Found"},404,{},request);
}
async function adminSections(request,env,p){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env); const b=await readJson(request);
  const m=p.match(/^\/api\/admin\/sections\/(\d+)$/),id=m?.[1];
  if(p==="/api/admin/sections"&&request.method==="POST"){
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM site_sections WHERE page_id=?").bind(b.pageId).first();
    const r=await env.DB.prepare("INSERT INTO site_sections(page_id,title,subtitle,layout_json,is_visible,sort_order) VALUES(?,?,?,?,?,?) RETURNING id")
      .bind(b.pageId,b.title||"Untitled section",b.subtitle||"",JSON.stringify(b.layout||{}),toBool(b.isVisible),row?.n||1).first();
    return json({ok:true,id:r.id},200,{},request);
  }
  if(id&&request.method==="PATCH"){
    await env.DB.prepare("UPDATE site_sections SET title=?,subtitle=?,layout_json=?,is_visible=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(b.title||"Untitled section",b.subtitle||"",JSON.stringify(b.layout||{}),toBool(b.isVisible),id).run();
    return json({ok:true},200,{},request);
  }
  if(id&&request.method==="DELETE"){
    const its=await env.DB.prepare("SELECT id FROM site_items WHERE section_id=?").bind(id).all();
    for(const it of its.results||[]) await env.DB.prepare("DELETE FROM site_media WHERE item_id=?").bind(it.id).run();
    await env.DB.prepare("DELETE FROM site_items WHERE section_id=?").bind(id).run();
    await env.DB.prepare("DELETE FROM site_sections WHERE id=?").bind(id).run();
    return json({ok:true},200,{},request);
  }
  return json({error:"Not Found"},404,{},request);
}
async function adminItems(request,env,p){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env); const b=await readJson(request);
  const m=p.match(/^\/api\/admin\/items\/(\d+)$/),id=m?.[1];
  if(p==="/api/admin/items"&&request.method==="POST"){
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM site_items WHERE section_id=?").bind(b.sectionId).first();
    const r=await env.DB.prepare("INSERT INTO site_items(section_id,title,subtitle,badge,href,content_text,is_visible,sort_order) VALUES(?,?,?,?,?,?,?,?) RETURNING id")
      .bind(b.sectionId,b.title||"Untitled item",b.subtitle||"",b.badge||"",b.href||"",b.content||"",toBool(b.isVisible),row?.n||1).first();
    return json({ok:true,id:r.id},200,{},request);
  }
  if(id&&request.method==="PATCH"){
    await env.DB.prepare("UPDATE site_items SET title=?,subtitle=?,badge=?,href=?,content_text=?,is_visible=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(b.title||"Untitled item",b.subtitle||"",b.badge||"",b.href||"",b.content||"",toBool(b.isVisible),id).run();
    return json({ok:true},200,{},request);
  }
  if(id&&request.method==="DELETE"){
    await env.DB.prepare("DELETE FROM site_media WHERE item_id=?").bind(id).run();
    await env.DB.prepare("DELETE FROM site_items WHERE id=?").bind(id).run();
    return json({ok:true},200,{},request);
  }
  return json({error:"Not Found"},404,{},request);
}
async function adminMedia(request,env,p){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env); const b=await readJson(request);
  const m=p.match(/^\/api\/admin\/media\/(\d+)$/),id=m?.[1];
  if(p==="/api/admin/media"&&request.method==="POST"){
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM site_media WHERE item_id=?").bind(b.itemId).first();
    const r=await env.DB.prepare("INSERT INTO site_media(item_id,url,public_id,width,height,media_type,alt,sort_order) VALUES(?,?,?,?,?,?,?,?) RETURNING id")
      .bind(b.itemId,b.url,b.publicId||"",b.width||0,b.height||0,b.mediaType||"image",b.alt||"",row?.n||1).first();
    return json({ok:true,id:r.id},200,{},request);
  }
  if(id&&request.method==="DELETE"){await env.DB.prepare("DELETE FROM site_media WHERE id=?").bind(id).run();return json({ok:true},200,{},request)}
  return json({error:"Not Found"},404,{},request);
}
async function adminReorder(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  await ensureAdminSchema(env); const b=await readJson(request),ids=(b.ids||[]).map(Number).filter(Boolean);
  const table={pages:"site_pages",sections:"site_sections",items:"site_items",media:"site_media"}[b.entity];
  if(!table)return json({error:"Invalid entity"},400,{},request);
  const stmts=ids.map((id,i)=>env.DB.prepare(`UPDATE ${table} SET sort_order=? WHERE id=?`).bind(i+1,id));
  if(stmts.length)await env.DB.batch(stmts);
  return json({ok:true},200,{},request);
}
async function uploadSignature(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  if(!env.CLOUDINARY_CLOUD_NAME||!env.CLOUDINARY_API_KEY||!env.CLOUDINARY_API_SECRET)
    return json({error:"Cloudinary secrets are not configured"},500,{},request);
  const timestamp=Math.floor(Date.now()/1000),folder="qearl-maison";
  const payload=`folder=${folder}&timestamp=${timestamp}${env.CLOUDINARY_API_SECRET}`;
  const digest=await crypto.subtle.digest("SHA-1",enc.encode(payload));
  const signature=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
  return json({
    apiKey:env.CLOUDINARY_API_KEY,timestamp,signature,folder,
    uploadPreset:"",uploadUrl:`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/image/upload`
  },200,{},request);
}

async function handlePage(request,env){
  const a=await readSession(request,env); if(!a)return json({error:"Unauthorized"},401,{},request);
  if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
  const b=await readJson(request);
  if(request.method==="POST"){
    const title=String(b.title||"").trim();
    if(!title||title.length>100)return json({error:"Invalid title"},400,{},request);
    const slug="q-"+Date.now().toString(36)+"-"+crypto.randomUUID().slice(0,6);
    const row=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0)+1 n FROM custom_pages").first();
    await env.DB.prepare("INSERT INTO custom_pages(slug,title,sort_order,published) VALUES(?,?,?,1)").bind(slug,title,row?.n||1).run();
    return json({ok:true,slug,title},200,{},request);
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

      if(request.method==="OPTIONS"){
        return new Response(null,{status:204,headers:{
          ...corsHeaders(request),
          "Access-Control-Allow-Methods":"GET,POST,PATCH,PUT,DELETE,OPTIONS",
          "Access-Control-Allow-Headers":"Content-Type"
        }});
      }
      if(p==="/api/admin/bootstrap"&&request.method==="GET") return await adminBootstrap(request,env);
      if(p==="/api/admin/import-legacy"&&request.method==="POST") return await adminImportLegacy(request,env);
      if(p==="/api/public/site"&&request.method==="GET") return await publicSite(request,env);
      if(p==="/api/admin/upload-signature"&&request.method==="POST") return await uploadSignature(request,env);
      if(p==="/api/admin/reorder"&&request.method==="POST") return await adminReorder(request,env);
      if(p==="/api/admin/pages"||p.startsWith("/api/admin/pages/")) return await adminPages(request,env,p);
      if(p==="/api/admin/sections"||p.startsWith("/api/admin/sections/")) return await adminSections(request,env,p);
      if(p==="/api/admin/items"||p.startsWith("/api/admin/items/")) return await adminItems(request,env,p);
      if(p==="/api/admin/media"||p.startsWith("/api/admin/media/")) return await adminMedia(request,env,p);

      if(p==="/api/health" && request.method==="GET") return json({ok:true,service:"qearl-maison",version:"V64.1"},200,{},request);
      if((p==="/api/session" || p==="/api/me") && request.method==="GET"){
        const s=await readSession(request,env); return json({authenticated:!!s,ok:!!s},s?200:401,{},request);
      }
      if(p==="/api/login" && request.method==="POST"){
        if(!sameOrigin(request))return json({error:"Invalid origin"},403,{},request);
        const b=await readJson(request);
        const loginName=b.username??b.id; const ok=safeEqualString(loginName,env.ADMIN_USERNAME)&&safeEqualString(b.password,env.ADMIN_PASSWORD);
        if(!ok)return json({error:"Invalid credentials"},401,{},request);
        const token=await makeSession(loginName,env);
        return json({ok:true},200,{"Set-Cookie":sessionCookie(token)},request);
      }
      if(p==="/api/logout" && request.method==="POST"){
        return json({ok:true},200,{"Set-Cookie":clearCookie()},request);
      }
      if(p==="/api/state" && request.method==="GET") return await handleState(env);
      if(p==="/api/publish" && request.method==="POST") return await handlePublish(request,env);
      if(p==="/api/block") return await handleBlock(request,env);
      if(p==="/api/page") return await handlePage(request,env);
      return env.ASSETS.fetch(request);
    }catch(e){
      console.error(e); return json({error:"Server error"},500,{},request);
    }
  }
};
