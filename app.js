/* ===== SUPABASE BACKEND (Firebase Realtime DB ki jagah) =====
   Sara data Supabase Postgres mein aik hi "app_data" table mein jsonb tree
   ki shakal mein rehta hai (users, settings, hotels, transport, quotations,
   lists, cities, branches). Path-based reads/writes (jo pehle Firebase mein
   "hotels/makkah" style hotay thay) ab Postgres RPC functions se hotay hain.
   SETUP: "supabase_setup.sql" file Supabase Dashboard > SQL Editor mein
   run karein — saari tables/functions khud ban jayengi. */
const SB_URL="https://dgwghwkrfiniaperoree.supabase.co";
const SB_KEY="sb_publishable_bPBx-dIrnlQZmLEGoxfgLQ_Wh7KWsJu";
async function sbRpc(fn,args){
  let res;
  try{
    res=await fetch(SB_URL+"/rest/v1/rpc/"+fn,{method:"POST",headers:{"apikey":SB_KEY,"Authorization":"Bearer "+SB_KEY,"Content-Type":"application/json"},body:JSON.stringify(args||{})});
  }catch(e){throw new Error("Network error — check your internet connection")}
  if(!res.ok){let msg="Supabase error "+res.status;try{const j=await res.json();msg=j.message||j.details||msg}catch(e){}if(res.status===404&&/function/i.test(msg))msg+=" — please run supabase_setup.sql in Supabase SQL Editor first";throw new Error(msg)}
  const txt=await res.text();
  return txt?JSON.parse(txt):null;
}

const S={user:null,settings:null,hotels:{makkah:[],madina:[]},cities:[{key:"makkah",label:"Makkah"},{key:"madina",label:"Madina"}],transport:[],airlines:[],classes:[],vehicles:[],rooms:[],sectors:[],quotations:{},users:{},branches:{},activeBranch:null};
const DEF_AIRLINES=["Emirates","AIRBLUE","FLYDUBAI","FLYNAS","ETIHAD","MALINDO","PIA","FLYADEAL","SAUDI AIRLINE","QATAR AIRWAYS","(ANY AIRLINE)","-","ETHIOPIAN AIRLINE"];
const DEF_CLASSES=["ECO","BUSINESS","FIRST","-"];
const DEF_VEHICLES=["SEDAN (2 TO 3 PERSON)","H1 (4 TO 7 PERSON)","STARIA (4 TO 7 PERSON)","GMC (4 TO 7 PERSON)","HIACE (7 TO 11 PERSON)","COASTER (11 TO 22 PERSON)","BUS (SHARING)"];
const DEF_ROOMS=["QUINT","QUAD","TRIPLE","DOUBLE","SHARING"];

const $=id=>document.getElementById(id);
const CE=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h)e.innerHTML=h;return e};

/* ===== SHA-256 PASSWORD HASHING ===== */
async function sha256(str){
  const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
/* Hash a password — returns hex string. Prefix "h:" marks hashed passwords in DB */
async function hashPw(plain){return 'h:'+await sha256(plain)}
/* Compare plain text against stored value (supports both plain and hashed) */
async function pwMatch(plain,stored){
  if(!stored)return false;
  if(stored.startsWith('h:'))return('h:'+await sha256(plain))===stored;
  return plain===stored; /* legacy plain-text — still works, migrated on next save */
}

/* Brute-force protection — IndexedDB mein persist hota hai (page refresh se bypass nahi hoga)
   Pehle yeh sirf in-memory tha — refresh marne par counter reset ho jata tha,
   attacker baar baar try kar sakta tha. Ab IndexedDB mein save hota hai. */
const BF_KEY='pgt_bf',BF_MAX=5,BF_WAIT=30000;
let _bfMem={}; /* Loaded from IndexedDB on boot — refresh se bypass nahi hoga */
function bfGet(){return _bfMem}
function bfSet(d){_bfMem=d;_idbSet(BF_KEY,JSON.stringify(d)).catch(()=>{})}
function bfCheck(u){const d=bfGet();const k=(u||'').toLowerCase();const r=d[k]||{c:0,t:0};if(r.c>=BF_MAX&&Date.now()-r.t<BF_WAIT){const s=Math.ceil((BF_WAIT-(Date.now()-r.t))/1000);return s}return 0}
function bfFail(u){const d=bfGet();const k=(u||'').toLowerCase();const r=d[k]||{c:0,t:0};r.c++;r.t=Date.now();d[k]=r;bfSet(d)}
function bfReset(u){const d=bfGet();delete d[(u||'').toLowerCase()];bfSet(d)}

/* ===== PERMISSION SYSTEM ===== */
const PERM_FEATURES=[
{key:"dash",label:"Dashboard",acts:["view"]},
{key:"pvt",label:"Private Costing",acts:["view","add","edit","delete"]},
{key:"grp",label:"Group Costing",acts:["view","add","edit","delete"]},
{key:"quot",label:"My Quotations",acts:["view","add","edit","delete"]},
{key:"allquot",label:"All Quotations (Admin Only)",acts:["view","add","edit","delete"]},
{key:"htl",label:"Hotels",acts:["view","add","edit","delete"]},
{key:"trn",label:"Transport",acts:["view","add","edit","delete"]},
{key:"lst",label:"Lists Manager",acts:["view","add","edit","delete"]},
{key:"usr",label:"Users",acts:["view","add","edit","delete"]},
{key:"branches",label:"Branch Management",acts:["view","add","edit","delete"]},
{key:"backup",label:"Backup Access (auto/manual backup from this PC)",acts:["view"]},
{key:"dup",label:"Duplicate Finder",acts:["view"]},
{key:"bin",label:"Recycle Bin (Recently Deleted)",acts:["view"]},
{key:"set",label:"Settings",acts:["view","edit"]}
];
/* Yeh permissions sirf SuperAdmin khud ko/admin ko de sakta hai — Admin apne
   user-permission grid mein inhe na dekh sake na hi kisi ko de sake */
const SUPERADMIN_ONLY_PERMS=["branches","backup"];
const ACT_LABELS={view:"View",add:"Add",edit:"Edit",delete:"Delete"};
function defaultPerms(role){
  const p={};
  PERM_FEATURES.forEach(f=>{p[f.key]={};f.acts.forEach(a=>p[f.key][a]=0)});
  if(role==="superadmin"||role==="admin"){PERM_FEATURES.forEach(f=>{f.acts.forEach(a=>p[f.key][a]=1)});
    /* Branch-add aur Backup: admin ko by-default NAHI milti — SuperAdmin ne
       khaas taur par grant karni hoti hai har admin ko alag se */
    if(role==="admin"){SUPERADMIN_ONLY_PERMS.forEach(k=>{if(p[k])Object.keys(p[k]).forEach(a=>p[k][a]=0)})}
    return p}
  if(role==="user"){
    p.dash.view=1;
    p.pvt.view=1;p.pvt.add=1;p.pvt.edit=1;p.pvt.delete=1;
    p.grp.view=1;p.grp.add=1;p.grp.edit=1;p.grp.delete=1;
    p.quot.view=1;p.quot.add=1;p.quot.edit=1;p.quot.delete=1;
    p.htl.view=1;p.trn.view=1;p.dup.view=1;p.bin.view=1;
    return p;
  }
  return p;
}
function getPerms(u){if(!u)return defaultPerms("user");if(u.r==="superadmin")return defaultPerms("admin");return u.perms||defaultPerms(u.r)}
function P(f,a){if(!S.user)return false;if(S.user.r==="superadmin")return true;const perms=getPerms(S.user);return !!(perms[f]&&perms[f][a])}
function permGridHtml(id,curPerms,role){
  const hide=role==="superadmin";
  /* Branch/Backup jaisi SuperAdmin-only permissions sirf tab dikhengi jab
     yeh grid khud SuperAdmin bana/dekh raha ho — Admin ko apne "Add User"
     ya "Edit User" form mein yeh rows bilkul show nahi hongi */
  const viewerIsSuper=!!(S.user&&S.user.r==="superadmin");
  const visibleFeatures=PERM_FEATURES.filter(f=>viewerIsSuper||!SUPERADMIN_ONLY_PERMS.includes(f.key));
  return `<div class="fg gf" id="${id}_wrap" style="${hide?"display:none":""}">
  <label>Feature Permissions</label>
  <div class="pg-wrap" style="max-height:280px;overflow-y:auto">
  <table id="${id}"><thead><tr><th class="label-cell">Feature</th><th>View</th><th>Add</th><th>Edit</th><th>Delete</th></tr></thead>
  <tbody>${visibleFeatures.map(f=>`<tr><td class="label-cell">${f.label}</td>${["view","add","edit","delete"].map(a=>f.acts.includes(a)?`<td><input type="checkbox" style="width:16px;height:16px" id="${id}_${f.key}_${a}" ${curPerms[f.key]&&curPerms[f.key][a]?"checked":""}></td>`:`<td style="color:var(--t2)">—</td>`).join("")}</tr>`).join("")}</tbody></table></div>
  <div style="display:flex;gap:6px;margin-top:6px"><button type="button" class="btn btn-sm btn-o" onclick="permGridSetAll('${id}',true)">Select All</button><button type="button" class="btn btn-sm btn-o" onclick="permGridSetAll('${id}',false)">Clear All</button></div>
  </div>`;
}
window.permGridSetAll=(id,val)=>{PERM_FEATURES.forEach(f=>f.acts.forEach(a=>{const el=$(`${id}_${f.key}_${a}`);if(el)el.checked=val}))};
function readPermGrid(id){const p={};PERM_FEATURES.forEach(f=>{p[f.key]={};f.acts.forEach(a=>{const el=$(`${id}_${f.key}_${a}`);p[f.key][a]=el&&el.checked?1:0})});return p}
function roleBadge(r){return r==="superadmin"?"sa":r==="admin"?"a":"u"}
function fullNameOf(u){if(!u)return"";const rec=Object.values(S.users||{}).find(x=>x.u===u);return rec?.full||u}
function canManageUserRow(u){
  if(!S.user)return false;
  if(S.user.r==="superadmin")return u.key!==S.user.key;
  if(S.user.r==="admin")return u.r==="user";
  return false;
}
function canSeeUserRow(u){
  if(S.user.r==="superadmin")return true;
  return u.r==="user"||u.key===S.user.key;
}

/* Session IndexedDB mein save hota hai (localStorage/sessionStorage nahi) —
   is liye browser band / system OFF ke baad bhi login 24 ghante tak rahta hai
   (Remember-me tick ho to 30 din). Refresh pe kabhi logout nahi hota. */
const SESSION_KEY="pgt_session",SESSION_TIMEOUT=24*60*60*1000,REMEMBER_TIMEOUT=30*24*60*60*1000;
let sessionCheckInterval=null;
function sessTimeout(s){return s&&s.remember?REMEMBER_TIMEOUT:SESSION_TIMEOUT}
async function _readSess(){try{return JSON.parse(await _idbGet(SESSION_KEY)||"null")}catch(e){return null}}
async function saveSession(remember){if(!S.user)return;let rem=remember;if(rem===undefined){rem=(await _readSess())?.remember||false}try{await _idbSet(SESSION_KEY,JSON.stringify({user:S.user,ts:Date.now(),remember:!!rem}))}catch(e){}}
async function loadSession(){try{const r=await _idbGet(SESSION_KEY);if(!r)return null;const s=JSON.parse(r);if(!s?.user||!s?.ts)return null;if(Date.now()-s.ts>sessTimeout(s)){clearSession();return null}return s.user}catch(e){return null}}
let _actT=0;
async function updateActivity(){if(!S.user)return;const now=Date.now();if(now-_actT<5000)return;_actT=now;try{const r=await _idbGet(SESSION_KEY);if(r){const s=JSON.parse(r);s.ts=Date.now();await _idbSet(SESSION_KEY,JSON.stringify(s))}}catch(e){}}
async function clearSession(){try{await _idbSet(SESSION_KEY,null)}catch(e){}}
function startSessionMonitor(){if(sessionCheckInterval)clearInterval(sessionCheckInterval);sessionCheckInterval=setInterval(async()=>{if(!S.user)return;try{const s=await _readSess();if(!s){doLogout();return}if(Date.now()-s.ts>sessTimeout(s)){toast("Session expired","warn");doLogout()}}catch(e){}},30000);["click","keydown","touchstart","scroll"].forEach(ev=>document.addEventListener(ev,updateActivity,{passive:true}))}

function toast(m,t="ok"){
  const tc=$("TC");
  const existing=tc.querySelectorAll(".tst");
  // Limit to 3 visible toasts — remove oldest if exceeded
  if(existing.length>=3)existing[0].remove();
  const d=CE("div","tst "+t,m);
  tc.appendChild(d);
  const dur=t==="err"?6000:2700; // errors stay longer so they're not missed
  setTimeout(()=>{d.style.transition="opacity .3s";d.style.opacity="0";setTimeout(()=>d.remove(),300)},dur);
}
function n(v){return parseFloat(v)||0}
function fmt(v){return Math.round(n(v)).toLocaleString("en-PK")}
function so(a,s=""){return(a||[]).map(x=>`<option ${x===s?"selected":""}>${x}</option>`).join("")}
function fmtDisplayDate(val){
  if(!val) return "";
  const str = String(val).trim();
  if(!str) return "";
  if(str.includes(" to ")){
    return str.split(" to ").map(s => fmtDisplayDate(s)).join(" to ");
  }
  // 1. Check for ISO timestamps (e.g. 2026-08-16T11:39:10.454Z or 2026-08-16 11:39)
  const isoMatch = str.match(/^(\d{4})[-/](\d{2})[-/](\d{2})[T\s](\d{2}):(\d{2})/);
  if(isoMatch){
    return `${isoMatch[3]}-${isoMatch[2]}-${isoMatch[1]}`;
  }
  // 2. Clean YYYY-MM-DD or YYYY/MM/DD
  const m = str.match(/^(\d{4})[-/](\d{2})[-/](\d{2})$/);
  if(m){
    return `${m[3]}-${m[2]}-${m[1]}`;
  }
  // 3. YYYY-MM-DD with arbitrary suffix
  const mSuffix = str.match(/^(\d{4})[-/](\d{2})[-/](\d{2})(.*)$/);
  if(mSuffix){
    const suffix = (mSuffix[4] || "").trim();
    if(!suffix || /^[T\s\d:.Z+-]+$/i.test(suffix)){
      return `${mSuffix[3]}-${mSuffix[2]}-${mSuffix[1]}`;
    }
    return `${mSuffix[3]}-${mSuffix[2]}-${mSuffix[1]} ${suffix}`;
  }
  return str;
}
function fmtDT(iso){
  if(!iso) return "";
  try{
    const d = new Date(iso);
    if(isNaN(d.getTime())) return fmtDisplayDate(iso);
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const ts = d.toLocaleTimeString("en-US", {hour:"numeric", minute:"2-digit", hour12:true});
    return `${day}-${month}-${year} ${ts}`;
  }catch(e){
    return fmtDisplayDate(iso);
  }
}
function cityLabel(key){const c=S.cities.find(c=>c.key===key);return c?c.label:(key?String(key).toUpperCase():"")}

/* ===== Flight transit / stay time calculation ===== */
function parseTimeToMin(str){if(!str)return null;const m=String(str).trim().match(/^(\d{1,2}):(\d{2})\s*([AaPp][Mm])$/);if(!m)return null;let h=parseInt(m[1],10);const mi=parseInt(m[2],10);const ap=m[3].toUpperCase();if(h===12)h=0;if(ap==="PM")h+=12;return h*60+mi}
function transitInfo(arr,dep2){const a=parseTimeToMin(arr),d=parseTimeToMin(dep2);if(a==null||d==null)return null;let diff=d-a,overnight=false;if(diff<=0){diff+=1440;overnight=true}const h=Math.floor(diff/60),m=diff%60;const label=(h>0?h+"h ":"")+((m>0||h===0)?m+"m":"");let badge;if(overnight)badge={t:"🌙 Overnight Transit",c:"badge-overnight"};else if(diff>=360)badge={t:"Long Transit",c:"badge-long"};else if(diff<120)badge={t:"Quick Transit",c:"badge-quick"};else badge={t:"Transit",c:"badge-neutral"};return{label,badge}}
function transitCellHtml(f){const ti=transitInfo(f.arr,f.dep2);if(!ti)return `<td class="transit-cell">-</td>`;return `<td class="transit-cell"><div class="tr-time">🕒 ${ti.label}</div><span class="badge ${ti.badge.c}">${ti.badge.t}</span></td>`}

/* ===== Shared print template helpers ===== */
function ppHeader(s,logo){
  // Split address: 70% top line, 30% bottom line
  const addr=s.address||"";
  let addrHtml="";
  if(addr){
    const splitIdx=Math.floor(addr.length*0.70);
    // Try to split at a comma/space near 70% mark
    let cutAt=splitIdx;
    for(let i=splitIdx;i>splitIdx-20&&i>0;i--){if(addr[i]===","||addr[i]===" "){cutAt=i;break}}
    const top=addr.slice(0,cutAt).trim().replace(/,$/,"");
    const bot=addr.slice(cutAt).trim().replace(/^,/,"").trim();
    addrHtml=`<div class="addr-top">${top}</div>${bot?`<div class="addr-bot">${bot}</div>`:""}`;
  }
  return `<div class="hdr">${logo}<div class="co-info"><h1>${s.company||"PAK GLOBE TRAVELS"}</h1><div class="lic">${s.license||""}</div>${addrHtml}</div><div class="contact-info">${s.phone?`<div class="ci-row"><span class="ci-ico">📞</span>${s.phone}</div>`:""}${s.website?`<div class="ci-row"><span class="ci-ico">🌐</span>${s.website.replace("https://","").replace(/\/$/,"")}</div>`:""}${s.email?`<div class="ci-row"><span class="ci-ico">✉</span>${s.email}</div>`:""}</div></div>`
}
function ppIcards(d,pkgType){return `<div class="icards"><div class="icard"><div class="ic-ico">📄</div><div class="ic-lbl">Invoice #</div><div class="ic-val">${d.invoiceNo||"-"}</div></div><div class="icard"><div class="ic-ico">📅</div><div class="ic-lbl">Date</div><div class="ic-val">${fmtDisplayDate(d.createdAt)||"-"}</div></div><div class="icard"><div class="ic-ico">👤</div><div class="ic-lbl">Prepared By</div><div class="ic-val">${fullNameOf(d.createdBy)||"-"}</div></div><div class="icard"><div class="ic-ico">🏷️</div><div class="ic-lbl">Package Type</div><div class="ic-val">${pkgType}</div></div></div>`}
function ppFlightTable(fl){
  if(!fl.length)return"";
  const cleanTime = (t) => (!t || t.trim() === "" || t.trim() === "--:--") ? "-" : t.trim();
  const cleanSec = (s) => (!s || s.trim() === "") ? "-" : s.trim().toUpperCase();
  const cleanVal = (v) => (!v || v.trim() === "") ? "-" : v.trim();

  return `<div class="sec"><span class="ic">✈</span> Flight Details</div><table class="ftbl"><thead><tr><th rowspan="2">Flt#</th><th rowspan="2">Date</th><th rowspan="2">Airline</th><th rowspan="2">Class</th><th colspan="3" class="grp1">Sector 1</th><th rowspan="2">Layover</th><th colspan="3" class="grp2">Sector 2</th><th rowspan="2">Lug</th><th rowspan="2">⏱ Stay/Transit Time</th></tr><tr><th class="grp1">Sector</th><th class="grp1">Dep</th><th class="grp1">Arr</th><th class="grp2">Sector</th><th class="grp2">Dep</th><th class="grp2">Arr</th></tr></thead><tbody>${fl.map((f,i)=>`<tr><td>${i+1}</td><td>${fmtDisplayDate(f.date) || "-"}</td><td>${cleanVal(f.airline)}</td><td>${cleanVal(f.cls)}</td><td class="sec-cell">${cleanSec(f.sec)}</td><td class="flt-time">${cleanTime(f.dep)}</td><td class="flt-time">${cleanTime(f.arr)}</td><td>${cleanVal(f.lay)}</td><td class="sec-cell">${cleanSec(f.sec2)}</td><td class="flt-time">${cleanTime(f.dep2)}</td><td class="flt-time">${cleanTime(f.arr2)}</td><td>${cleanVal(f.lug)}</td>${transitCellHtml(f)}</tr>`).join("")}</tbody></table>`;
}
function ppHotelBoxes(list,labelFn){
  // All hotels in ONE row — auto-fit regardless of count
  const valid=list.filter(h=>h&&h.name);
  if(!valid.length)return"";
  const boxes=valid.map(h=>`<div class="h-box">${h.img?`<div class="h-photo"><img src="${h.img}" alt="" style="width:100%;height:100%;object-fit:cover;display:block"></div>`:`<div class="h-photo h-photo-ph">🏨</div>`}<div class="h-info"><div class="h-lbl">${labelFn(h)}${h.loc?` <a href="${h.loc}" target="_blank" rel="noopener" class="h-pin">📍</a>`:""}</div><div class="h-nm">${h.name}</div><div class="h-dt"><b>Room:</b><span>${(h.type||h.cat||"-")}x${h.qty||0}</span><b>Nights:</b><span>${h.ngt||0}</span><b>Dist:</b><span>${h.dist||"-"}</span></div></div></div>`).join("");
  return `<div class="hotel-boxes">${boxes}</div>`;
}
function hotelImg(city,name){if(!S.hotels[city])ensureHotelsLoaded(city).catch(()=>{});return(S.hotels[city]||[]).find(h=>h.n===(name||"").toUpperCase().trim())?.img||""}
function ppTransportTable(list){if(!list.length)return"";return `<div class="sec"><span class="ic">🚗</span> Transport</div><table><thead><tr><th>Sector</th><th>Vehicle</th><th>Qty</th></tr></thead><tbody>${list.map(t=>`<tr><td><b>${(t.sec||"").toUpperCase()}</b></td><td>${t.veh}</td><td>${t.qty}</td></tr>`).join("")}</tbody></table>`}
/* VISA TABLE for client-facing print — shows Umrah visa + manual visas */
function ppVisaTable(o,roe){
  if(!o)return"";
  const v=o.visa||{};
  const mv=o.manualVisas||[];
  const cmv=o.childManualVisas||[];
  const imv=o.infantManualVisas||[];
  const cv=o.childVisa||{};
  const iv=o.infantVisa||{};
  const hasVisa=(v.r&&v.r>0)||(v.q&&v.q>0);
  /* Child/Infant ka DEFAULT visa bhi UMRAH VISA hi hota hai — alag row mein
     (CHILD)/(INFANT) label ke sath dikhao */
  const hasChildVisa=o.childPax>0&&((cv.r&&cv.r>0)||(cv.q&&cv.q>0));
  const hasInfantVisa=o.infantPax>0&&((iv.r&&iv.r>0)||(iv.q&&iv.q>0));
  const hasManual=mv.length>0||cmv.length>0||imv.length>0;
  if(!hasVisa&&!hasChildVisa&&!hasInfantVisa&&!hasManual)return"";
  let rows="";
  if(hasVisa){rows+=`<tr><td><b>UMRAH VISA</b></td><td>FT</td><td>${v.q||o.adultPax||0}</td></tr>`}
  if(mv.length>0){mv.forEach(m=>{rows+=`<tr><td><b>${_esc((m.name||"VISA").toUpperCase())}</b></td><td>—</td><td>${m.q||0}</td></tr>`})}
  if(hasChildVisa){rows+=`<tr><td><b>UMRAH VISA (CHILD)</b></td><td>FT</td><td>${cv.q||o.childPax||0}</td></tr>`}
  if(cmv.length>0){cmv.forEach(m=>{rows+=`<tr><td><b>${_esc((m.name||"VISA").toUpperCase())} (CHILD)</b></td><td>—</td><td>${m.q||0}</td></tr>`})}
  if(hasInfantVisa){rows+=`<tr><td><b>UMRAH VISA (INFANT)</b></td><td>FT</td><td>${iv.q||o.infantPax||0}</td></tr>`}
  if(imv.length>0){imv.forEach(m=>{rows+=`<tr><td><b>${_esc((m.name||"VISA").toUpperCase())} (INFANT)</b></td><td>—</td><td>${m.q||0}</td></tr>`})}
  return `<div class="sec"><span class="ic">🛂</span> Visa Details</div><table><thead><tr><th>Visa Type</th><th>Cat</th><th>Qty</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function ppFooter(s){return `<div class="pp-footer"><div class="ftr2"><div class="ftr2-note">ℹ️ Note: ${s.disclaimer||"All rates are subject to availability & may change without prior notice."}</div><div class="ftr2-dev">Developed by Shahzaman</div></div><div class="thankbar"><span class="ic">✈️</span> Thank you for choosing ${s.company||"Pak Globe Travels"} <span class="ic">✈️</span></div></div>`}
/* PHANTOM OPTION FILTER (saved quotations): agar option mein sirf default visa
   hai (koi hotel/ticket/transport/additional visa/child/infant nahi) to use
   print/view mein NA dikhao — user ne sirf Option A banaya ho to sirf A aaye,
   B/C khud ba khud na aayen jab tak un mein data na ho. Agar SAARE options
   visa-only hon (pure visa quotation) to phir sab dikhao. */
function _optHasRealData(o){return !!(o.hotels?.some(h=>h.name)||o.flights?.some(f=>f.airline&&f.airline!=="-"&&f.sec)||o.ticketPKR>0||o.transports?.some(t=>t.sec&&t.qty>0)||(o.manualVisas&&o.manualVisas.length)||(o.childManualVisas&&o.childManualVisas.length)||(o.infantManualVisas&&o.infantManualVisas.length)||o.childPax>0||o.infantPax>0)}
function _filterPrintOpts(opts){const real=opts.filter(([l,o])=>_optHasRealData(o));if(real.length)return real;return opts.filter(([l,o])=>(o.visa?.r>0&&o.visa?.q>0)||o.perAdult>0)}
function cityOptionsHtml(sel){return S.cities.map(c=>`<option value="${c.key}"${c.key===sel?" selected":""}>${c.label}</option>`).join("")+`<option value="__newcity__">+ Add New City...</option>`}
window.addNewCityInline=async(selectEl)=>{
  const name=prompt("Enter new city name:");
  if(!name||!name.trim()){selectEl.value=S.cities[0]?.key||"makkah";return}
  const label=name.trim().toUpperCase();
  let key=label.toLowerCase().replace(/[^a-z0-9]+/g,"_").replace(/^_+|_+$/g,"");
  if(!key)key="city"+Date.now();
  const existing=S.cities.find(c=>c.key===key||c.label.toUpperCase()===label);
  if(existing){selectEl.value=existing.key;selectEl.dispatchEvent(new Event("change"));return}
  S.cities.push({key,label});
  try{await bFS("cities",S.cities)}catch(e){toast("Failed to save city","err")}
  document.querySelectorAll('select[id^="hCity"],select[id^="gHCity"],select[id^="cHCity"]').forEach(sel=>{
    if(!Array.from(sel.options).some(o=>o.value===key)){
      const opt=document.createElement("option");opt.value=key;opt.textContent=label;
      sel.insertBefore(opt,sel.lastElementChild)
    }
  });
  selectEl.value=key;
  toast("City added: "+label);
  selectEl.dispatchEvent(new Event("change"))
};
function normalizeCityKey(t){return (t||"").toString().trim().toLowerCase().replace(/[^a-z0-9]+/g,"")||("city"+Date.now())}
function hotelLoc(city,name){if(!S.hotels[city])ensureHotelsLoaded(city).catch(()=>{});return(S.hotels[city]||[]).find(h=>h.n===(name||"").toUpperCase().trim())?.loc||""}
// Quotations store a snapshot of each hotel's name/rate/etc at save time —
// but location & photo should always reflect the CURRENT hotel master data,
// so editing a hotel later updates every quotation that uses it (old or new)
// without needing to re-save them.
function liveHotel(h){return{...h,loc:hotelLoc(h.city,h.name)||h.loc||"",img:hotelImg(h.city,h.name)||h.img||""}}
function vk(v){return{"SEDAN (2 TO 3 PERSON)":"SEDAN","H1 (4 TO 7 PERSON)":"H1","STARIA (4 TO 7 PERSON)":"STARIA","GMC (4 TO 7 PERSON)":"GMC","HIACE (7 TO 11 PERSON)":"HIACE","COASTER (11 TO 22 PERSON)":"COASTER","BUS (SHARING)":"BUS"}[v]||"SEDAN"}
function gtr(sec,veh){const r=S.transport.find(t=>t.s===sec);return r?n(r[vk(veh)]):0}

/* ===== TRANSPORT FREE-TYPE AUTOCOMPLETE ===== */
/* Creates an input that supports both lookup from master list AND free typing */
function trAcInput(id,val,kind){
  return `<div class="tr-ac-wrap"><input id="${id}" data-kind="${kind||"sector"}" value="${(val||"").replace(/"/g,"&quot;")}" autocomplete="off" placeholder="Type or select..." oninput="trAcShow('${id}')" onfocus="trAcShow('${id}')" onblur="setTimeout(()=>trAcHide('${id}'),200)"></div>`;
}
window.trAcShow=(id)=>{
  const inp=$(id);if(!inp)return;
  const v=(inp.value||"").trim().toUpperCase();
  let dd=document.getElementById("_trac_"+id);
  if(!dd){dd=document.createElement("div");dd.id="_trac_"+id;dd.className="tr-ac-dd";document.body.appendChild(dd)}
  // Vehicle column only shows vehicles from Lists Manager. Sector/Type column shows saved sectors + generic type options.
  const kind=inp.dataset.kind||"sector";
  const allOpts=kind==="vehicle"?[...S.vehicles]:[...S.sectors,"Private","Package","Sharing","VIP","Luxury","Airport Transfer","City Transfer"];
  const unique=dedupeCI(allOpts);
  const filtered=v?unique.filter(x=>x.toUpperCase().includes(v)):unique;
  if(!filtered.length){dd.classList.remove("show");return}
  dd.innerHTML=filtered.slice(0,18).map(x=>`<div onclick="trAcPick('${id}','${x.replace(/'/g,"\\'")}')">${x}</div>`).join("");
  const r=inp.getBoundingClientRect();
  dd.style.cssText=`left:${r.left}px;top:${r.bottom+2}px;width:${Math.max(r.width,180)}px`;
  dd.classList.add("show");
};
window.trAcHide=(id)=>{const dd=document.getElementById("_trac_"+id);if(dd)dd.classList.remove("show")};
window.trAcPick=(id,val)=>{const inp=$(id);if(inp){inp.value=val;inp.dispatchEvent(new Event("input"))}trAcHide(id);triggerCalc()};

const _esc=s=>String(s==null?"":s).replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
function fmtLug(inp){
  let v=inp.value.trim().toUpperCase().replace(/[^0-9]/g,"");
  if(v)inp.value=v+" Kg";
  else inp.value="";
}
window.fmtLug=fmtLug;

window.fmtTime=(inp)=>{let v=inp.value.trim().toUpperCase();if(!v){inp.value="";return}let ampm="",digits=v.replace(/[^0-9]/g,""),letters=v.replace(/[^APM]/g,"");if(letters.includes("A"))ampm="AM";else if(letters.includes("P"))ampm="PM";if(!digits){inp.value="";return}let h,m;if(digits.length<=2){h=parseInt(digits);m=0}else if(digits.length===3){h=parseInt(digits[0]);m=parseInt(digits.slice(1))}else{h=parseInt(digits.slice(0,2));m=parseInt(digits.slice(2,4))}if(m>59)m=59;if(h>=13&&h<=23){h=h-12;if(!ampm)ampm="PM"}else if(h===0){h=12;if(!ampm)ampm="AM"}else if(h===12){if(!ampm)ampm="PM"}else if(h>=1&&h<=11&&!ampm)ampm="AM";if(h>12)h=12;inp.value=String(h).padStart(2,"0")+":"+String(m).padStart(2,"0")+" "+ampm};

const wt=(p,ms=12e3)=>Promise.race([p,new Promise((_,r)=>setTimeout(()=>r(new Error("Timeout — check your internet connection")),ms))]);
const wtLong=(p,ms=120e3)=>Promise.race([p,new Promise((_,r)=>setTimeout(()=>r(new Error("Operation timed out — please check your internet and try again")),ms))]);
const FR_LONG=p=>wtLong(sbRpc("db_read",{p}));
const FS_LONG=(p,d)=>wtLong(sbRpc("db_write",{p,v:d===undefined?null:d}));
const FU_LONG=(p,d)=>wtLong(sbRpc("db_merge",{p,v:d}));
/* Firebase-style path helpers — ab Supabase RPC ke upar (same semantics) */
const FR=p=>wt(sbRpc("db_read",{p}));
const FS=(p,d)=>wt(sbRpc("db_write",{p,v:d===undefined?null:d}));
const FU=(p,d)=>wt(sbRpc("db_merge",{p,v:d}));
const FD=p=>wt(sbRpc("db_write",{p,v:null}));
const FP=(p,d)=>wt(sbRpc("db_push",{p,v:d}));
async function nextInvoiceNo(){
  const _myBr=myBranchForSave();
  const _isBr=!!(_myBr.id&&S.branches[_myBr.id]);
  /* Branch-wise invoice series: har branch ka apna alag invoice number */
  const _path=_isBr?"branches/"+_myBr.id+"/settings/invoiceNext":"settings/invoiceNext";
  const prefix=(_isBr?(S.branches[_myBr.id].settings?.invoicePrefix||null):null)||S.settings.invoicePrefix||"PGT";
  /* DUPLICATE-PROOF: is prefix ki SAARI mojooda invoices collect karo */
  const _used=new Set();let _maxUsed=0;
  Object.values(S.quotations||{}).forEach(q=>{const inv=q&&q.invoiceNo;if(!inv)return;_used.add(inv);if(inv.startsWith(prefix+"-")){const num=parseInt(inv.slice(prefix.length+1),10);if(!isNaN(num)&&num>_maxUsed)_maxUsed=num}});
  /* SEED: agar counter purani series se peeche hai (branch counter 1 se shuru
     aur PGT-0001..0097 global series mein pehle se used) to ek hi call mein
     counter ko sab se bare used number par le aao — warna har save par
     duplicates milte */
  let _cur=0;try{_cur=Math.round(n(await FR(_path)))||0}catch(e){}
  if(_maxUsed>=_cur){try{await wt(sbRpc("db_increment",{p:_path,delta:_maxUsed-_cur+1}))}catch(e){}}
  /* COLLISION LOOP: jo number mila woh pehle se used ho to aage barhao —
     duplicate invoice number KABHI nahi banega */
  let inv="",guard=0;
  do{
    const finalVal=Math.round(await wt(sbRpc("db_increment",{p:_path,delta:1})));
    const used=finalVal-1;
    inv=prefix+"-"+String(used).padStart(4,"0");
    if(_isBr){if(!S.branches[_myBr.id].settings)S.branches[_myBr.id].settings={};S.branches[_myBr.id].settings.invoiceNext=finalVal}
    else S.settings.invoiceNext=finalVal;
  }while(_used.has(inv)&&++guard<100);
  return inv;
}
/* MULTI-USER SAFETY: do log ek hi waqt app use karein to kisi ka kaam kisi aur
   ke save se overwrite/"ghayab" na ho — likhne se pehle server se FRESH copy
   nikalte hain, apni tabdeeli uspe apply kar ke phir poora likhte hain.
   Purani (stale) local array seedha overwrite karne se doosre user ki
   entries chupke se delete ho jati thin. */
async function _safeArrWrite(path,localArr,transform){
  let live=localArr;
  try{const a=_rawToHotelArr(await FR(path));if(a.length)live=a}catch(e){}
  return FS(path,transform(live));
}

async function boot(){
const _bootT0=performance.now();
try{$("LSt").textContent="Loading...";
/* Brute-force data IndexedDB se load karo — refresh se bypass na ho */
try{const bfRaw=await _idbGet(BF_KEY);if(bfRaw)_bfMem=JSON.parse(bfRaw)}catch(e){}
/* users + settings + branches — EK HI request mein (pehle 2-3 alag thin) */
const bootBundle=await wt(sbRpc("db_read_many",{paths:["users","settings","branches"]}),30000);
let u=bootBundle["users"],st=bootBundle["settings"];
/* branches pehle se mil gayi — loadBranchesAndApply mein dubara fetch nahi hogi */
S.branches=bootBundle["branches"]||{};
if(!u||!Object.keys(u).length){
const [hSuper,hAdmin,hUser]=await Promise.all([hashPw("super123"),hashPw("admin123"),hashPw("user123")]);
u={superadmin:{u:"superadmin",p:hSuper,r:"superadmin",full:"Super Admin"},admin:{u:"admin",p:hAdmin,r:"admin",full:"Admin",perms:defaultPerms("admin")},user1:{u:"user",p:hUser,r:"user",full:"Staff User",perms:defaultPerms("user")}};
await FS("users",u);
}S.users=u;
if(!st){st={company:"PAK GLOBE TRAVELS",license:"GL # 5807",address:"OFFICE # A/02, UPPER SIDE OF BROADWAY PIZZA MAIN AUTOBHAN ROAD HYDERABAD",website:"https://pakglobetravels.com/",phone:"03100376111",email:"info@pakglobetravels.com",disclaimer:"All Rates are Subject to availability & May change without Prior Notice",logo:"",instructions:"",invoicePrefix:"PGT",invoiceNext:1,visaAdultSAR:560,visaInfantSAR:0,defaultROE:78,defaultInfantROE:77};await FS("settings",st)}S.settings=st;
if(st.logo){["sbL","lLgo","lcLgo"].forEach(id=>{$(id).src=st.logo;$(id).style.display="block"});["sbLFb","lLgoFb","lcLgoFb"].forEach(id=>{$(id).style.display="none"})}
if(st.license)$("lLic").textContent=st.license+" • HYDERABAD";
const savedUser=await loadSession();
if(savedUser){
  S.user=savedUser;updateActivity();
  /* Boot bundle se fresh user data aaya hai — session user ko us se refresh karo
     taake permissions/branch changes turant reflect ho jayein */
  if(S.users&&S.users[savedUser.key]){S.user={...S.users[savedUser.key],key:savedUser.key};saveSession().catch(()=>{})}
  /* APP turant dikhao — skeleton dashboard render karo, data peeche se aata hai */
  $("LS").style.display="none";$("APP").style.display="block";
  $("TU").textContent=savedUser.full||savedUser.u;
  $("TR").textContent=savedUser.r;
  $("TR").className="bd bd-"+(savedUser.r==="superadmin"?"sa":savedUser.r==="admin"?"a":"u");
  applySidebarBranding();buildSB();
  /* Skeleton dashboard — turant kuch dikhao */
  const ct=$("CT");if(ct)ct.innerHTML=`<div style="padding:20px"><div style="text-align:center;padding:18px;color:var(--t2);font-size:.82rem;font-weight:600">⏳ Loading data from database...</div><div class="stats">${[1,2,3,4].map(()=>`<div class="st" style="animation:skPulse 1.2s ease-in-out infinite"><div style="height:14px;background:var(--bd);border-radius:4px;width:60%;margin-bottom:8px"></div><div style="height:28px;background:var(--bd);border-radius:4px;width:40%"></div></div>`).join("")}</div><div class="g2" style="margin-top:10px">${[1,2].map(()=>`<div class="cd" style="min-height:120px;animation:skPulse 1.2s ease-in-out infinite"><div style="height:14px;background:var(--bd);border-radius:4px;width:50%;margin-bottom:10px"></div><div style="height:10px;background:var(--bd);border-radius:4px;width:80%;margin-bottom:6px"></div><div style="height:10px;background:var(--bd);border-radius:4px;width:70%"></div></div>`).join("")}</div></div>`;
  if(innerWidth>=769)$("SB").classList.remove("closed");
  startSessionMonitor();
  /* Data aur branches parallel load karo */
  /* SPEED FIX: local cache se dashboard FORAN render karo (stale-while-revalidate).
     Fresh data background mein aata hai aur dashboard update kar deta hai —
     pehle yahan 5MB fetch ka poora intezar hota tha, slow internet par app
     atak jati thi aur "Loading slow / Timeout" errors aate the. */
  try{const cached=await cacheGet("coreData");
    if(cached&&cached.v&&typeof cached.v==="object"&&cached.v.quotations){
      S.quotations=cached.v.quotations;
      S.trash=cached.v.trash||{};
    }}catch(e){}
  buildSB();
  nav("dash");
  gSearchInit();
  console.log("[Boot] Dashboard ready in "+Math.round(performance.now()-_bootT0)+"ms");
  const _finishBoot=()=>{buildSB();if(curPage==="dash")nav("dash");setTimeout(_preloadAllHotels,1200);console.log("[Boot] Fresh data synced in "+Math.round(performance.now()-_bootT0)+"ms")};
  Promise.all([loadData(),loadBranchesAndApply()])
  .then(_finishBoot)
  .catch(e=>{
    toast("Data load failed: "+e.message+" — Retrying...","err");
    Promise.all([loadData(),loadBranchesAndApply()]).then(_finishBoot).catch(e2=>toast("Could not load data: "+e2.message,"err"));
  });
  if(P("backup","view")){_wrapBackupFunctions();_startHourlyBackup();}
  if(S.activeBranch&&S.activeBranch.name){
    toast("Welcome back, "+(savedUser.full||savedUser.u)+"! 🏢 "+S.activeBranch.name);
  }else{
    toast("Welcome back, "+(savedUser.full||savedUser.u)+"!");
  }
  setTimeout(()=>_showBranchBanner(),200);
  return
}
$("LS").style.display="none";$("LP").style.display="flex";
try{if(window.PasswordCredential&&navigator.credentials){const cred=await navigator.credentials.get({password:true,mediation:"optional"});if(cred&&cred.id){$("lgU").value=cred.id;if(cred.password)$("lgP").value=cred.password}}}catch(ce){}
$("lgU")?.focus();
}catch(e){
  $("LSt").style.display="none";
  const spin=document.querySelector("#LS .spin");if(spin)spin.style.display="none";
  $("LSe").innerHTML=`⚠ App failed to load: ${e.message}<br><small>Your data is safe — nothing was deleted or overwritten. Please check your internet connection and try again.</small><br><button class="btn btn-sm btn-p" style="margin-top:10px" onclick="location.reload()">🔄 Retry</button>`;
  console.error("Boot error:",e);
}}

/* Har hotel ko stable Firebase key (id) do — taake aage se ek hotel add/edit/delete
   karne par SIRF usi hotel ka node likha/mitaya jaye, poori list kabhi dobara
   upload na ho. (Pehle poori array city ke sath hi baar baar save hoti thi —
   20-30 hotel photos ke baad payload itna bara ho jata tha ke save fail/hang
   ho jati thi aur upar se agli save purani images ko bhi overwrite/khtam kar
   sakti thi. Ab yeh scene bilkul khatam.)
   NOTE: Yahan koi "migration write-back" nahi ki jati — sirf read time par
   purane array format ko interpret kiya jata hai (index hi id ban jata hai).
   Isse do log ek sath app khol lein tou bhi koi race/overwrite risk nahi
   rehta; jaisay hi koi hotel edit/add/delete hota hai, wohi node khud keyed
   ban jata hai Firebase mein — bilkul safe. */
function _newHotelId(){return "h_"+Date.now().toString(36)+"_"+Math.random().toString(36).slice(2,8)}
/* ===== SPEED CACHE (IndexedDB) =====
   Bari payloads — hotels (base64 images ~11MB) aur quotations (~5MB) — har
   session/page-refresh par dobara download na hon. Pehle local cache se
   FORAN dikhao, phir background mein fresh data lao (stale-while-revalidate).
   Slow internet par bhi app instantly khulti hai, "Loading slow/Timeout"
   errors khatam. */
function _cacheKey(k){return "pgt_cache_"+k}
async function cacheGet(k){try{const raw=await _idbGet(_cacheKey(k));return raw?JSON.parse(raw):null}catch(e){return null}}
async function cacheSet(k,v){try{await _idbSet(_cacheKey(k),JSON.stringify({t:Date.now(),v}))}catch(e){}}
function _rawToHotelArr(raw){
  if(!raw)return [];
  if(Array.isArray(raw))return raw.map((h,i)=>({...(h||{}),id:(h&&h.id)||String(i)}));
  return Object.entries(raw).map(([id,v])=>({...(v||{}),id}));
}
/* Hotels ab HAR login par eager load nahi hotay — sirf jis city ki zaroorat
   ho (Hotel Management kholna, ya quotation mein us city ka hotel field use
   karna) usi waqt fetch hoti hai, aur phir memory mein cache ho jati hai.
   Pehle har login par SAB cities ki SAARI hotel photos (chahe zaroorat ho ya
   na ho) download hoti thin — jitna zyada data (jitni zyada images) hoti,
   utna hi login/loading time barhta jata tha. Ab login turant hota hai,
   chahe hotels ki tadaad 20 ho ya 2000. */
const _hotelsLoading={};
async function ensureHotelsLoaded(cityKey){
  if(!cityKey)return[];
  if(S.hotels[cityKey])return S.hotels[cityKey];
  if(_hotelsLoading[cityKey])return _hotelsLoading[cityKey];
  const p=(async()=>{
    /* SPEED: pichli baar ki hotels IndexedDB se foran lao — 11MB images har
       session dobara download nahi hotin. Live fetch background mein update karti hai. */
    let cached=null;try{const c=await cacheGet("hotels/"+cityKey);if(c&&c.v)cached=c.v}catch(e){}
    let h;
    try{
      /* Hotels payload bohat bara hota hai (images) — is liye 12s ki jagah 45s timeout */
      h=await wt(sbRpc("db_read",{p:"hotels/"+cityKey}),45000); // yahan .catch() jaan bhoojh kar NAHI lagaya — fetch fail ho to neeche handle ho
    }catch(e){
      if(cached&&cached.length){
        /* Fetch fail — cached copy dikhao, background mein retry karte raho */
        console.warn("[Hotels]",cityKey,"live fetch failed — cached copy use ho rahi hai:",e.message);
        S.hotels[cityKey]=cached;delete _hotelsLoading[cityKey];
        setTimeout(()=>{delete S.hotels[cityKey];ensureHotelsLoaded(cityKey).catch(()=>{})},20000);
        return cached;
      }
      delete _hotelsLoading[cityKey];
      console.warn("[Hotels] load failed for",cityKey,"— city ko khali NAHI mana, dobara try hoga:",e.message);
      throw e; // KABHI bhi empty cache mat karo sirf isliye ke fetch fail hui — warna real data "gum" jaisa dikhega
    }
    let arr;
    if(h)arr=_rawToHotelArr(h);
    else if(cityKey==="makkah"){const d=[{n:"MAKKAH TOWER",d:"0m"},{n:"PULLMAN ZAMZAM",d:"0m"},{n:"SWISSOTEL MAKKAH",d:"0m"},{n:"HILTON SUITES",d:"0m"},{n:"HILTON CONVENTION",d:"50m"},{n:"HYATT REGENCY",d:"0m"},{n:"CONRAD MAKKAH",d:"100m"},{n:"JABAL OMAR MARRIOTT",d:"100m"},{n:"MILLENNIUM MAKKAH",d:"300m"},{n:"ELAF KINDA",d:"100m - 200m"},{n:"LE MERIDIEN MAKKAH",d:"SHUTTLE"},{n:"AL MASA GRAND AJYAD",d:"650m - 700m"},{n:"NAWAZI TOWER",d:"SHUTTLE"},{n:"EMAAR WORTH SUITE",d:"400m - 500m"},{n:"ABEER AL FADILAH",d:"SHUTTLE"},{n:"BURJ MUKHTARA",d:"250m - 300m"}];const keyed={};d.forEach(x=>{const id=_newHotelId();keyed[id]={...x,id}});await FS("hotels/makkah",keyed);arr=Object.values(keyed)}
    else if(cityKey==="madina"){const d=[{n:"DAR UL TAQWA",d:"0m"},{n:"OBEROI MADINA",d:"0m"},{n:"SHAZA MADINA",d:"100m"},{n:"PULLMAN MADINA",d:"200m"},{n:"MUKHTARA INTERNATIONAL",d:"250m - 300m"},{n:"MADINA HILTON",d:"200m"},{n:"DAR AL EIMAN GRAND",d:"SHUTTLE"},{n:"RUA AL KHAIR",d:"SHUTTLE"}];const keyed={};d.forEach(x=>{const id=_newHotelId();keyed[id]={...x,id}});await FS("hotels/madina",keyed);arr=Object.values(keyed)}
    else arr=[];
    /* Fresh copy mil gayi — cache update karo taake agli baar instantly load ho */
    if(arr&&arr.length)cacheSet("hotels/"+cityKey,arr);
    S.hotels[cityKey]=arr;
    delete _hotelsLoading[cityKey];
    return arr;
  })();
  _hotelsLoading[cityKey]=p;
  return p;
}
/* Login/boot ke turant baad SAARI cities ke hotels background mein load kar do —
   1000+ hotels bhi pehle se ready ho jate hain, tab kholne par wait nahi karna parta */
function _preloadAllHotels(){S.cities.forEach(c=>ensureHotelsLoaded(c.key).catch(()=>{}))}
async function loadData(){
/* BOHOT ZAROORI FIX: pehle agar internet mein zara si bhi rukawat aati aur
   koi ek fetch (cities/transport/lists) fail/timeout ho jati, to app is
   failure ko "yeh data pehli baar hai, khali hai" samajh kar DEFAULT data
   Firebase par LIKH deta tha — jo aapka REAL data (custom sectors, cities,
   lists) OVERWRITE/mita sakta tha. Yehi ghalat-fehmi baar baar data loss ki
   sabse badi wajah ho sakti hai. Ab agar koi bhi zaroori fetch fail ho, poora
   load rok diya jata hai aur SAAF error dikhaya jata hai — koi bhi default
   data kabhi nahi likha jata jab tak hum 100% confirm na kar lein ke woh
   jagah Firebase mein WAQAI khali hai (na ke sirf fetch fail hui hai). */
let cities0,tr,qt,air,cls,veh,rms,usr0;
let b=null,_loadErr=null;
try{
  /* Saara core data EK HI Supabase request mein + users bhi (taake refreshAll mein
     permissions/user changes reflect ho jayein — pehle users missing tha) */
  b=await wt(sbRpc("db_read_many",{paths:["users","cities","transport","quotations","lists/airlines","lists/classes","lists/vehicles","lists/rooms","trash"]}),60000);
}catch(e){
  _loadErr=e;
  /* Retry ek baar — network hiccup ho sakta hai */
  try{
    b=await wt(sbRpc("db_read_many",{paths:["users","cities","transport","quotations","lists/airlines","lists/classes","lists/vehicles","lists/rooms","trash"]}),60000);
    _loadErr=null;
  }catch(e2){
    _loadErr=e2;
  }
}
if(b&&typeof b==="object"){cacheSet("coreData",b)}
else{
  /* SPEED/OFFLINE FIX: fetch dono baar fail ho to pichla cached data dikha do —
     pehle app yahan poori tarah atak jati thi ("Loading slow / Timeout" error).
     Fresh data background mein retry hota rahega. */
  const cached=await cacheGet("coreData");
  if(cached&&cached.v&&typeof cached.v==="object"){
    b=cached.v;
    console.warn("[loadData] live fetch failed (",(_loadErr&&_loadErr.message),") — cached data use ho raha hai");
    toast("Slow/no internet — showing last synced data. Retrying...","warn");
    setTimeout(()=>{if(S.user)refreshAll&&refreshAll()},15000);
  }else{
    throw new Error("Data could not be loaded (please check your internet connection and try again): "+(_loadErr?_loadErr.message:"unknown"));
  }
}
usr0=b["users"];cities0=b["cities"];tr=b["transport"];qt=b["quotations"];air=b["lists/airlines"];cls=b["lists/classes"];veh=b["lists/vehicles"];rms=b["lists/rooms"];S.trash=b["trash"]||{};
/* Users refresh — yeh BOHOT ZAROORI hai: pehle loadData mein users nahi aate the,
   is liye refreshAll marne par bhi purane permissions/users dikhai dete the
   aur user ko logout/login karna parta tha. Ab har refresh par users bhi fresh honge. */
if(usr0&&typeof usr0==="object"&&Object.keys(usr0).length){S.users=usr0}
let cities=cities0;if(cities&&!Array.isArray(cities))cities=Object.values(cities).filter(Boolean);
if(!cities||!Array.isArray(cities)||!cities.length){cities=[{key:"makkah",label:"Makkah"},{key:"madina",label:"Madina"}];await FS("cities",cities)}
S.cities=cities;
S.hotels={};for(const k in _hotelsLoading)delete _hotelsLoading[k]; /* purana stale cache invalidate */
if(!tr){const d=[{s:"JED TO MAK TO MED TO JED APT",SEDAN:835,H1:1200,STARIA:1200,GMC:2250,HIACE:1450,COASTER:2250,BUS:0},{s:"JED TO MAK",SEDAN:200,H1:300,STARIA:300,GMC:450,HIACE:350,COASTER:550,BUS:0},{s:"MAK TO MED / MED TO MAK",SEDAN:325,H1:475,STARIA:475,GMC:950,HIACE:575,COASTER:875,BUS:35},{s:"MAK ZIYARAT",SEDAN:150,H1:250,STARIA:250,GMC:400,HIACE:350,COASTER:425,BUS:15},{s:"MED ZIYARAT",SEDAN:150,H1:250,STARIA:250,GMC:400,HIACE:350,COASTER:425,BUS:15},{s:"MED HTL TO JED APT",SEDAN:300,H1:425,STARIA:425,GMC:850,HIACE:525,COASTER:825,BUS:35}];const keyed={};d.forEach(x=>{const id=_newHotelId();keyed[id]={...x,id}});await FS("transport",keyed);S.transport=Object.values(keyed)}
else S.transport=_rawToHotelArr(tr);
S.airlines=air?(Array.isArray(air)?air:Object.values(air)):DEF_AIRLINES;if(!air)await FS("lists/airlines",DEF_AIRLINES);
S.classes=cls?(Array.isArray(cls)?cls:Object.values(cls)):DEF_CLASSES;if(!cls)await FS("lists/classes",DEF_CLASSES);
S.vehicles=veh?(Array.isArray(veh)?veh:Object.values(veh)):DEF_VEHICLES;if(!veh)await FS("lists/vehicles",DEF_VEHICLES);
S.rooms=rms?(Array.isArray(rms)?rms:Object.values(rms)):DEF_ROOMS;if(!rms)await FS("lists/rooms",DEF_ROOMS);
S.sectors=dedupeCI(S.transport.map(t=>t.s));S.quotations=qt||{};setTimeout(_purgeExpiredTrash,4000);
/* Session user ko server se refresh karo — agar admin ne permissions/branch change
   kiye hain to cached session stale nahi rahega. Yeh fix user ko baar baar
   logout/login se bachata hai jab admin unki settings change kare. */
if(S.user&&S.users){const freshUser=S.users[S.user.key];if(freshUser){S.user={...freshUser,key:S.user.key};saveSession().catch(()=>{})}}}
/* Case/space ke farq ke bawajood ek hi cheez ek hi baar — pehla-mila hua spelling rakhta hai */
function dedupeCI(arr){const seen=new Set();const out=[];(arr||[]).forEach(x=>{const t=(x||"").trim();if(!t)return;const k=t.toUpperCase();if(seen.has(k))return;seen.add(k);out.push(t)});return out}

window.toggleSB=()=>{const sb=$("SB"),ov=$("sbOv");if(sb.classList.contains("closed")||!sb.classList.contains("open")){sb.classList.remove("closed");sb.classList.add("open");if(innerWidth<769)ov.classList.add("show")}else{closeSB()}};
window.closeSB=()=>{$("SB").classList.remove("open");if(innerWidth<769){$("SB").classList.add("closed");$("sbOv").classList.remove("show")}};

window.handleLoginSubmit=(ev)=>{if(ev&&ev.preventDefault)ev.preventDefault();doLogin();return false};
window.doLogin=async()=>{const b=$("lgB"),u=$("lgU").value.trim(),p=$("lgP").value.trim(),e=$("lgE");e.classList.remove("show");if(!u||!p){e.textContent="Enter username & password";e.classList.add("show");return}
/* Brute force check */
const wait=bfCheck(u);if(wait>0){e.textContent="Too many attempts. Wait "+wait+" seconds.";e.classList.add("show");return}
b.disabled=true;b.textContent="SIGNING IN...";
try{const users=await FR("users");let f=null;
for(const k in users){const x=users[k];if(x?.u?.toLowerCase()===u.toLowerCase()){const ok=await pwMatch(p,x.p);if(ok){f={...x,key:k};break}}}
if(!f){bfFail(u);const rem=BF_MAX-((bfGet()[(u||'').toLowerCase()]||{c:0}).c);e.textContent=rem>0?"Invalid credentials. "+(rem)+" attempt(s) left.":"Account locked 30 seconds.";e.classList.add("show");b.disabled=false;b.textContent="SIGN IN";return}
bfReset(u);
/* Auto-migrate plain-text password to hashed on first successful login */
if(f.p&&!f.p.startsWith('h:')){const hashed=await hashPw(p);FU("users/"+f.key,{p:hashed}).catch(()=>{});f.p=hashed}
S.user=f;S.users=users;b.textContent="LOADING...";
/* loadData + loadBranchesAndApply parallel — login ~50% faster */
await Promise.all([loadData(),loadBranchesAndApply()]);
saveSession($("lgRem")?.checked!==false);startSessionMonitor();setTimeout(_preloadAllHotels,1200);
// Load branches and apply branch settings for this user — already done above in parallel
try{if(window.PasswordCredential){await navigator.credentials.store(new PasswordCredential({id:u,password:p,name:f.u}))}}catch(ce){}
$("LP").style.display="none";$("APP").style.display="block";$("TU").textContent=f.full||f.u;$("TR").textContent=f.r;$("TR").className="bd bd-"+(f.r==="superadmin"?"sa":f.r==="admin"?"a":"u");
applySidebarBranding();
buildSB();nav("dash");
if(P("backup","view")){_wrapBackupFunctions();_startHourlyBackup();}
// Branch notification: show which branch user is in
if(S.activeBranch&&S.activeBranch.name){
  toast("Welcome, "+(f.full||f.u)+"! 🏢 Branch: "+S.activeBranch.name);
}else{
  toast("Welcome, "+(f.full||f.u)+"!");
}
b.disabled=false;b.textContent="SIGN IN";if(innerWidth>=769)$("SB").classList.remove("closed");
// Show branch banner on dashboard if user has a branch assigned
setTimeout(()=>_showBranchBanner(),600);
}catch(ex){e.textContent="Error: "+ex.message;e.classList.add("show");b.disabled=false;b.textContent="SIGN IN"}};

window.doLogout=()=>{if(sessionCheckInterval){clearInterval(sessionCheckInterval);sessionCheckInterval=null}clearSession();S.user=null;S.activeBranch=null;$("APP").style.display="none";$("LP").style.display="flex";$("lgU").value="";$("lgP").value="";$("lgE").classList.remove("show")};

/* ============================================================
   BACKUP SYSTEM v2 (delta-aware Live Backup)
   - Live Backup: har 60 second check, ek hi rolling file
     (PGT_LiveBackup_LATEST.json) jab tak data barhta/same rehta hai.
   - Agar entries kam ho jayein (delete), LATEST.json overwrite nahi hota —
     us waqt ki state alag CHECKPOINT file mein jati hai, taake akhri
     mukammal backup hamesha recoverable rahe.
   - Hourly Full Backup: extra safety net, wahi delta-aware logic follow
     karta hai (PGT_HourlyBackup_LATEST.json / *_CHECKPOINT_*.json)
   ============================================================ */
let _backupTimer=null,_lastChangeBackupHash="",_hourlyBackupInterval=null;

/* ===== BACKUP FOLDER (File System Access API — Chrome/Edge only) =====
   Browser security ki wajah se koi bhi website apne aap kisi custom OS folder mein
   seedha likh nahi sakti. Ye Chrome/Edge ka officially supported tareeqa hai: user ek
   baar folder select karta hai (permission grant), uske baad backups seedha usi folder
   mein jaate hain — bina baar baar "Save As" dialog ke. Firefox/Safari mein ye API
   available nahi, wahan normal Downloads folder istemal hota hai (fallback). */
function _idbOpen(){
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open("pgt_backup_db",1);
    req.onupgradeneeded=()=>{req.result.createObjectStore("handles")};
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}
async function _idbSet(key,val){
  const db=await _idbOpen();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction("handles","readwrite");
    tx.objectStore("handles").put(val,key);
    tx.oncomplete=()=>resolve();
    tx.onerror=()=>reject(tx.error);
  });
}
async function _idbGet(key){
  const db=await _idbOpen();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction("handles","readonly");
    const req=tx.objectStore("handles").get(key);
    req.onsuccess=()=>resolve(req.result||null);
    req.onerror=()=>reject(req.error);
  });
}

window.pickBackupFolder=async function(){
  if(!window.showDirectoryPicker){toast("This feature only works in Chrome or Edge browser","err");return}
  try{
    const handle=await window.showDirectoryPicker({mode:"readwrite"});
    const perm=await handle.requestPermission({mode:"readwrite"});
    if(perm!=="granted"){toast("Folder permission was not granted","err");return}
    await _idbSet("backupDir",handle);
    await _idbSet("backupDirName",handle.name);
    _pgBackupName=handle.name;
    toast("✅ Backup folder set: "+handle.name);
    _refreshBackupFolderUI();
  }catch(e){if(e.name!=="AbortError")toast("Folder selection failed: "+e.message,"err")}
};
window.clearBackupFolder=async function(){
  try{await _idbSet("backupDir",null)}catch(e){}
  try{await _idbSet("backupDirName",null)}catch(e){}
  _pgBackupName=null;
  toast("Backup folder cleared — the normal Downloads folder will be used now");
  _refreshBackupFolderUI();
};
let _pgBackupName=null;
async function _refreshBackupFolderUI(){
  if(!_pgBackupName){try{_pgBackupName=await _idbGet("backupDirName")}catch(e){_pgBackupName=null}}
  const el=$("backupFolderStatus");if(!el)return;
  el.textContent=_pgBackupName?("📁 "+_pgBackupName):"Downloads (default — no folder set)";
}

async function _getBackupDirHandle(){
  if(!window.showDirectoryPicker)return null;
  try{
    const handle=await _idbGet("backupDir");
    if(!handle)return null;
    const perm=await handle.queryPermission({mode:"readwrite"});
    if(perm==="granted")return handle;
    return null; // dubara prompt karne ke liye user gesture chahiye, auto-backup mein nahi kar sakte
  }catch(e){return null}
}

/* Har backup (change/hourly/manual) yahi se save hota hai — pehle chosen folder try karta hai,
   agar available na ho to normal browser download par fallback karta hai */
async function _saveBackupFile(data,filename){
  try{
    const dir=await _getBackupDirHandle();
    if(dir){
      const fh=await dir.getFileHandle(filename,{create:true});
      const w=await fh.createWritable();
      await w.write(new Blob([JSON.stringify(data,null,2)],{type:"application/json"}));
      await w.close();
      console.log("[Backup] Saved to chosen folder:",filename);
      return true;
    }
  }catch(e){console.warn("[Backup] Folder save failed, falling back to download:",e.message)}
  _downloadJson(data,filename);
  return false;
}

function _downloadJson(data,filename){
  try{
    const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download=filename;
    document.body.appendChild(a);a.click();
    setTimeout(()=>{URL.revokeObjectURL(url);a.remove()},1000);
  }catch(e){console.warn("[Backup] Download failed:",e.message)}
}

async function _collectFullBackup(){
  const FR30=p=>wt(sbRpc("db_read",{p}),30000);
  try{
    const[users,settings,hotels_raw,transport,quotations,branches,lists,cities]=await Promise.all([
      FR30("users").catch(()=>null),
      FR30("settings").catch(()=>null),
      // hotels ke liye har city ka data
      Promise.all((S.cities||[{key:"makkah"},{key:"madina"}]).map(c=>FR30("hotels/"+c.key).catch(()=>null))).then(results=>{const obj={};(S.cities||[]).forEach((c,i)=>obj[c.key]=results[i]||[]);return obj}),
      FR30("transport").catch(()=>null),
      FR30("quotations").catch(()=>null),
      FR30("branches").catch(()=>null),
      FR30("lists").catch(()=>null),
      FR30("cities").catch(()=>null)
    ]);
    return{_backupMeta:{timestamp:new Date().toISOString(),version:"v7",createdBy:S.user?.u||"system",totalQuotations:Object.keys(quotations||{}).length,totalHotels:Object.values(hotels_raw||{}).reduce((a,l)=>a+(Array.isArray(l)?l.length:Object.keys(l||{}).length),0)},users,settings,hotels:hotels_raw,transport,quotations,branches,lists,cities};
  }catch(e){console.warn("[Backup] Collect failed:",e.message);return null}
}

/* Change Backup: Data change hone par "dirty" flag set hota hai,
   aur har 5 minute mein ek dafa check karke download hota hai (agar kuch change hua ho) */
let _backupDirty=false;
let _liveBackupDebounce=null;
window._triggerChangeBackup=function(label){
  if(!S.user)return;
  _backupDirty=true;
  _lastChangeLabel=label||"update";
  clearTimeout(_liveBackupDebounce);
  _liveBackupDebounce=setTimeout(_doLiveBackupIfDirty,1500);
};
let _lastChangeLabel="update";
let _changeBackupInterval=null;

/* ===== LIVE CONTINUOUS BACKUP =====
   Ek hi file ("PGT_LiveBackup_LATEST.json") har modification par update hoti rehti hai.
   Agar koi data delete/kam ho to LATEST.json overwrite nahi hoti — us reduced state
   ko ek alag NEW CHECKPOINT file (PGT_CHECKPOINT_<time>.json) mein save kiya jata hai
   taake last complete backup hamesha safe rahe. Hourly backups are removed. */
let _lastBackupCounts=null;
function _countData(data){
  const hotels=Object.values(data.hotels||{}).reduce((a,l)=>a+(Array.isArray(l)?l.length:Object.keys(l||{}).length),0);
  const transport=Array.isArray(data.transport)?data.transport.length:Object.keys(data.transport||{}).length;
  const quotations=Object.keys(data.quotations||{}).length;
  const users=Object.keys(data.users||{}).length;
  return{hotels,transport,quotations,users};
}
async function _doLiveBackupIfDirty(){
  if(!_backupDirty||!S.user)return;
  try{
    const data=await _collectFullBackup();
    if(!data)return;
    const hash=JSON.stringify(data.quotations||"")+JSON.stringify(Object.keys(data.hotels||{}).map(k=>[k,Array.isArray(data.hotels[k])?data.hotels[k].length:Object.keys(data.hotels[k]||{}).length]))+JSON.stringify(data.transport||"")+JSON.stringify(data.users||"");
    if(hash===_lastChangeBackupHash){_backupDirty=false;return}
    _lastChangeBackupHash=hash;_backupDirty=false;
    const counts=_countData(data);
    const shrank=_lastBackupCounts&&(counts.hotels<_lastBackupCounts.hotels||counts.transport<_lastBackupCounts.transport||counts.quotations<_lastBackupCounts.quotations||counts.users<_lastBackupCounts.users);
    if(shrank){
      const ts=new Date().toISOString().replace(/[:.]/g,"-").slice(0,19);
      await _saveBackupFile(data,`PGT_CHECKPOINT_${ts}.json`);
      console.log("[LiveBackup] Data shrank vs last snapshot — saved as NEW checkpoint file, LATEST.json untouched.",_lastBackupCounts,"->",counts);
    }else{
      await _saveBackupFile(data,"PGT_LiveBackup_LATEST.json");
    }
    _lastBackupCounts=counts;
  }catch(e){console.warn("[LiveBackup] Error:",e.message)}
}
function _startChangeBackupInterval(){
  if(_changeBackupInterval)clearInterval(_changeBackupInterval);
  _changeBackupInterval=setInterval(_doLiveBackupIfDirty,3000);
}

function _startHourlyBackup(){
  _startChangeBackupInterval();
}

/* Manual full backup button ke liye */
window.manualFullBackup=async function(){
  if(!P("backup","view"))return toast("Not allowed — backup permission required","err");
  toast("Downloading full backup...");
  const data=await _collectFullBackup();
  if(!data){toast("Backup failed","err");return}
  const ts=new Date().toISOString().replace(/[:.]/g,"-").slice(0,19);
  await _saveBackupFile(data,"PGT_Manual_Backup_"+ts+".json");
  toast("✅ Full backup downloaded!");
};

/* Badi restore writes ko chhote batches mein chalao — 50-100MB+ backups bhi
   aaram se ordered chaltein hain, browser/DB par ek saath bojh nahi parta */
async function _runBatched(tasks,atOnce=4){for(let i=0;i<tasks.length;i+=atOnce){await Promise.all(tasks.slice(i,i+atOnce).map(f=>f()))}}

/* Restore backup from JSON file */
window.restoreFromBackup=function(){
  if(S.user?.r!=="superadmin")return toast("Only SuperAdmin can restore","err");
  const input=document.createElement("input");input.type="file";input.accept=".json";
  input.onchange=async e=>{
    const file=e.target.files[0];if(!file)return;
    const mb=(file.size/1048576).toFixed(1);
    const reader=new FileReader();
    reader.onload=async ev=>{
      try{
        const data=JSON.parse(ev.target.result);
        if(!data._backupMeta)return toast("Invalid backup file","err");
        showModal("Restore Backup",`<div style="font-size:.82rem;line-height:1.6">
          <p>Backup date: <b>${data._backupMeta.timestamp}</b></p>
          <div class="fg"><label>Restore Mode</label>
            <select id="rsMode">
              <option value="merge" selected>🛡 Safe Merge — skip entries that already exist in the system, only add back what's missing/deleted (recommended)</option>
              <option value="replace">⚠ Full Replace — overwrite everything with this backup (any new work in the current data will be lost)</option>
            </select>
          </div>
          <p id="rsWarn" style="color:#065f46;background:#ecfdf5;border:1px solid #6ee7b7;border-radius:6px;padding:8px">In Merge mode, no existing data is ever deleted or overwritten — only what's in the backup but missing from the current system gets added back.</p>
        </div>`,()=>{
          const mode=$("rsMode").value;
          closeModal(); // close this modal first — otherwise the confirm dialog below would get wiped out immediately (this was the reason restore wasn't working before)
          confirmModal(mode==="replace"?"This will OVERWRITE ALL current data with the backup — any new work could be lost. Are you sure?":"Missing/deleted entries will be added back. Existing data stays safe. Continue?",async()=>{
            toast("Restoring "+mb+" MB backup — large files may take a moment, please do not close the page...");
            try{
              if(mode==="replace")await _restoreReplace(data);
              else await _restoreMerge(data);
              toast("✅ Restore complete! Reloading the page...");
              setTimeout(()=>location.reload(),1800);
            }catch(ex){toast("Restore failed: "+ex.message,"err")}
          },"Yes, Restore","btn-d");
          return false; // prevent showModal from also calling closeModal() — we already closed it, and the confirm dialog is now open
        });
      }catch(ex){toast("Backup file is invalid: "+ex.message,"err")}
    };
    reader.readAsText(file);
  };
  document.body.appendChild(input);input.click();input.remove();
};
/* Old behaviour — overwrite everything with the backup. Kept only for emergencies. */
async function _restoreReplace(data){
  const saves=[];
  /* Use 5-minute timeout for restore operations (large backups need more time) */
  const FS_RESTORE=(p,d)=>wt(sbRpc("db_write",{p,v:d===undefined?null:d}),300000);
  if(data.settings)saves.push(()=>FS_RESTORE("settings",data.settings));
  if(data.users)saves.push(()=>FS_RESTORE("users",data.users));
  if(data.transport)saves.push(()=>FS_RESTORE("transport",data.transport));
  if(data.quotations)saves.push(()=>FS_RESTORE("quotations",data.quotations));
  if(data.branches)saves.push(()=>FS_RESTORE("branches",data.branches));
  if(data.lists)saves.push(()=>FS_RESTORE("lists",data.lists));
  if(data.cities)saves.push(()=>FS_RESTORE("cities",data.cities));
  if(data.hotels){for(const[city,list]of Object.entries(data.hotels)){if(list)saves.push(()=>FS_RESTORE("hotels/"+city,list))}}
  await _runBatched(saves,3); // Run 3 at a time to reduce load
}
/* Naya default — koi bhi maujooda entry chhedi nahi jati, delete/overwrite nahi hoti.
   Sirf woh entries jo backup mein thin lekin ab system mein maujood nahi (delete ho
   gain ya kam ho gain), unhe wapis, unki apni alag Firebase key ke sath, add kiya
   jata hai — is se koi purana ya naya data zaya nahi hota. */
async function _restoreMerge(data){
  const saves=[];
  /* Use 5-minute timeout for restore operations (large backups need more time) */
  const FU_RESTORE=(p,d)=>wt(sbRpc("db_merge",{p,v:d}),300000);
  const FS_RESTORE=(p,d)=>wt(sbRpc("db_write",{p,v:d===undefined?null:d}),300000);
  // Hotels: naam (case-insensitive) se maujood check karo, missing hi add karo
  if(data.hotels){
    for(const[city,raw]of Object.entries(data.hotels)){
      if(!raw)continue;
      await ensureHotelsLoaded(city);
      if(!S.cities.some(c=>c.key===city)){S.cities.push({key:city,label:city.toUpperCase()})}
      const backupArr=_rawToHotelArr(raw);
      const liveNames=new Set((S.hotels[city]||[]).map(h=>(h.n||"").trim().toUpperCase()));
      const cityUpdates={};
      backupArr.forEach(h=>{
        const key=(h.n||"").trim().toUpperCase();
        if(!key||liveNames.has(key))return; // pehle se maujood — skip
        const id=_newHotelId();const withId={...h,id};
        S.hotels[city]=S.hotels[city]||[];S.hotels[city].push(withId);
        cityUpdates[id]=withId;
        liveNames.add(key);
      });
      if(Object.keys(cityUpdates).length)saves.push(()=>FU_RESTORE("hotels/"+city,cityUpdates));
    }
  }
  // Transport / Sectors: sector naam se maujood check karo
  if(data.transport){
    const backupArr=_rawToHotelArr(data.transport);
    const liveSec=new Set((S.transport||[]).map(t=>(t.s||"").trim().toUpperCase()));
    const trUpdates={};
    backupArr.forEach(t=>{
      const key=(t.s||"").trim().toUpperCase();
      if(!key||liveSec.has(key))return;
      const id=_newHotelId();const withId={...t,id};
      S.transport.push(withId);
      trUpdates[id]=withId;
      liveSec.add(key);
    });
    if(Object.keys(trUpdates).length)saves.push(()=>FU_RESTORE("transport",trUpdates));
    S.sectors=dedupeCI(S.transport.map(t=>t.s));
  }
  // Quotations: unki apni Firebase key se maujood check karo
  if(data.quotations){
    const qUpdates={};
    for(const[qk,q]of Object.entries(data.quotations)){
      if(!q||S.quotations[qk])continue; // yeh key pehle se maujood — skip
      qUpdates[qk]=q;
      S.quotations[qk]=q;
    }
    if(Object.keys(qUpdates).length)saves.push(()=>FU_RESTORE("quotations",qUpdates));
  }
  // Users: username (case-insensitive) se maujood check karo
  if(data.users){
    const liveU=new Set(Object.values(S.users||{}).map(u=>(u.u||"").trim().toLowerCase()));
    const uUpdates={};
    for(const[uk,u]of Object.entries(data.users)){
      if(!u)continue;
      const key=(u.u||"").trim().toLowerCase();
      if(!key||liveU.has(key)||S.users[uk])continue; // pehle se maujood — skip
      uUpdates[uk]=u;
      S.users[uk]=u;
      liveU.add(key);
    }
    if(Object.keys(uUpdates).length)saves.push(()=>FU_RESTORE("users",uUpdates));
  }
  // Branches: branch id se maujood check karo
  if(data.branches){
    const bUpdates={};
    for(const[bk,b]of Object.entries(data.branches)){
      if(!b||S.branches[bk])continue;
      bUpdates[bk]=b;
      S.branches[bk]=b;
    }
    if(Object.keys(bUpdates).length)saves.push(()=>FU_RESTORE("branches",bUpdates));
  }
  // Cities: jo city key maujood nahi, wohi add karo (poori list chhoti hai, ek hi write)
  if(data.cities){let changed=false;data.cities.forEach(c=>{if(c&&!S.cities.some(x=>x.key===c.key)){S.cities.push(c);changed=true}});if(changed)saves.push(()=>FS_RESTORE("cities",S.cities))}
  // Lists (airlines/classes/vehicles/rooms): sirf missing values add karo, case-insensitive dedupe
  if(data.lists){
    for(const[lk,arr]of Object.entries(data.lists)){
      if(!Array.isArray(arr))continue;
      const cur=S[lk==="airlines"?"airlines":lk==="classes"?"classes":lk==="vehicles"?"vehicles":lk==="rooms"?"rooms":null];
      if(!cur)continue;
      const merged=dedupeCI([...cur,...arr]);
      if(merged.length!==cur.length){S[lk]=merged;saves.push(()=>FS_RESTORE("lists/"+lk,merged))}
    }
  }
  // Settings merge mein kabhi nahi chhera jata — sirf Full Replace mode mein
  if(!saves.length)throw new Error("No entries in the backup file were missing from the system — nothing was restored (this is normal if everything already exists)");
  await _runBatched(saves,3); // Run 3 at a time to reduce load
}

/* FS/FU/FD wrap karo backup trigger ke saath */
let _bkActive=false;
let _backupWrapped=false;
function _wrapBackupFunctions(){
  if(_backupWrapped)return;_backupWrapped=true;
  _bkActive=true;
  _refreshBackupFolderUI();
  // Hook: every hotel/quotation/settings save triggers change backup
  // We use a global flag — the actual FS/FU/FD functions check this flag
  console.log("[Backup] Change backup activated");
}

// Backup-aware wrappers used directly in code after login
async function bFS(p,d){const r=await FS(p,d);if(_bkActive)window._triggerChangeBackup(p.split("/")[0]);return r}
async function bFU(p,d){const r=await FU(p,d);if(_bkActive)window._triggerChangeBackup(p.split("/")[0]);return r}
async function bFD(p){const r=await FD(p);if(_bkActive)window._triggerChangeBackup("delete");return r}
async function bFP(p,d){const r=await FP(p,d);if(_bkActive)window._triggerChangeBackup(p.split("/")[0]);return r}
/* Long-timeout versions for bulk operations (400+ hotels, large payloads) —
   12s default timeout is not enough for heavy writes, these use 120s */
async function bFU_Long(p,d){const r=await FU_LONG(p,d);if(_bkActive)window._triggerChangeBackup(p.split("/")[0]);return r}
async function bFS_Long2(p,d){const r=await FS_LONG(p,d);if(_bkActive)window._triggerChangeBackup(p.split("/")[0]);return r}

async function loadBranchesAndApply(){
  /* branches hamesha server se fresh fetch karo — pehle yeh skip ho jati thin agar
     already loaded thin, jis se branch setting changes reflect nahi hoti thin
     jab tak logout/login na karo. Ab har refresh par fresh aayengi. */
  try{const freshBranches=await FR("branches");if(freshBranches&&typeof freshBranches==="object")S.branches=freshBranches}catch(e){if(!S.branches||typeof S.branches!=="object")S.branches={}}
  const r=S.user.r;

  if(r==="superadmin"||r==="admin"){
    // Admin/Superadmin: no branch restriction on UI
    S.activeBranch=null;
    // Lekin agar admin ka khud ka branchId set hai:
    // 1) Unki settings branch se override ho
    // 2) Unki APNI purani quotations migrate ho jayein
    const myBranchId=S.user.branchId;
    if(myBranchId&&S.branches[myBranchId]&&!S.branches[myBranchId].disabled){
      if(S.branches[myBranchId].settings){
        S.settings={...S.settings,...S.branches[myBranchId].settings};
      }
      // Admin ki apni quotations bhi migrate karo
      await _migrateLegacyQuotationsToBranch(
        myBranchId,
        S.branches[myBranchId].name||"",
        S.user.u  // sirf apni quotations
      );
    }
    return;
  }

  // Normal user: load their assigned branch
  const branchId=S.user.branchId;
  if(branchId&&S.branches[branchId]&&!S.branches[branchId].disabled){
    S.activeBranch={...S.branches[branchId],id:branchId};
    if(S.branches[branchId].settings){
      S.settings={...S.settings,...S.branches[branchId].settings};
    }
    // Purani quotations migrate karo
    await _migrateLegacyQuotationsToBranch(branchId,S.branches[branchId].name||"",S.user.u);
  }else{
    S.activeBranch=null;
  }
}

/* =====================================================================
   AUTO-MIGRATE QUOTATIONS TO BRANCH
   =====================================================================
   Jab kisi bhi user (admin/superadmin/user) ko branch assign hoti hai,
   unki purani branchless quotations automatically us branch ke saath
   link ho jaati hain — login par, bina refresh ke.

   branchId   — Firebase branch key
   branchName — branch display name
   createdBy  — username filter (sirf is user ki quotations)
   ===================================================================== */
async function _migrateLegacyQuotationsToBranch(branchId,branchName,createdBy){
  if(!branchId||!createdBy)return;

  // Fresh fetch — ensure we have latest data
  let allQuots=S.quotations||{};
  if(!Object.keys(allQuots).length){
    try{allQuots=await FR("quotations")||{};S.quotations=allQuots;}catch(e){return}
  }

  // Filter: is user ki quotations jinka branchId blank/missing hai
  const toMigrate=Object.entries(allQuots).filter(([k,v])=>
    v&&
    v.createdBy===createdBy&&
    (!v.branchId||v.branchId==="")
  );

  if(!toMigrate.length){
    console.log("[BranchMigrate] No unlinked quotations for user: "+createdBy);
    return;
  }

  // 1) Local state turant update karo (UI refresh bina Firebase response ke)
  toMigrate.forEach(([k])=>{
    if(S.quotations[k]){
      S.quotations[k].branchId=branchId;
      S.quotations[k].branchName=branchName;
    }
  });

  // 2) Firebase mein save karo (parallel, non-blocking)
  const saves=toMigrate.map(([k])=>
    FU("quotations/"+k,{branchId:branchId,branchName:branchName})
    .catch(e=>console.warn("[BranchMigrate] "+k+" failed:",e.message))
  );

  Promise.all(saves).then(()=>{
    console.log("[BranchMigrate] Done: "+toMigrate.length+" quotation(s) → "+branchName);
    toast(toMigrate.length+" quotation(s) linked to 🏢 "+branchName,"ok");
  });
}

/* =====================================================================
   SUPERADMIN BULK MIGRATE — sab users ki quotations ek saath link karo
   Users page pe "Migrate All" button se call hota hai
   ===================================================================== */
window.bulkMigrateAllBranches=async function(){
  if(S.user.r!=="superadmin")return toast("Only SuperAdmin can do this","err");
  toast("Migration starting...","ok");

  // Fresh data load
  let[allUsers,allQuots]=await Promise.all([
    FR("users").catch(()=>{}),
    FR("quotations").catch(()=>{})
  ]);
  if(!allUsers||!allQuots){toast("Data failed to load","err");return}
  S.users=allUsers;S.quotations=allQuots;

  let count=0;
  const saves=[];

  // Har user ke liye: agar branchId set hai, uski unlinked quotations migrate karo
  for(const[uk,u]of Object.entries(allUsers)){
    if(!u.branchId||!S.branches[u.branchId])continue;
    const branchId=u.branchId;
    const branchName=S.branches[branchId]?.name||"";

    for(const[qk,q]of Object.entries(allQuots)){
      if(q.createdBy===u.u&&(!q.branchId||q.branchId==="")){
        // Local update
        if(S.quotations[qk]){
          S.quotations[qk].branchId=branchId;
          S.quotations[qk].branchName=branchName;
        }
        saves.push(
          FU("quotations/"+qk,{branchId:branchId,branchName:branchName})
          .catch(e=>console.warn("[BulkMigrate] "+qk,e.message))
        );
        count++;
      }
    }
  }

  if(!saves.length){
    toast("All quotations are already linked to the branch ✓","ok");
    return;
  }

  await Promise.all(saves);
  toast("✅ "+count+" quotation(s) migrated successfully!","ok");
  // UI refresh
  if(curPage==="allquot")rQLAllCore();
  if(curPage==="quot")rQLCore();
  if(curPage==="dash")_showBranchBanner();
};

/* ===== BRANCH BANNER: shown at top of dashboard when user has a branch ===== */
function _showBranchBanner(){
  if(!S.activeBranch||!S.activeBranch.name)return;
  const ct=$("CT");if(!ct)return;
  // Remove any existing banner first
  ct.querySelector("#_branchBanner")?.remove();
  // Find insertion point — before stats or first .cd
  const anchor=ct.querySelector(".stats,.cd");
  if(!anchor)return;
  const banner=document.createElement("div");
  banner.id="_branchBanner";
  banner.style.cssText=[
    "background:linear-gradient(135deg,#d1fae5,#a7f3d0)",
    "border:1px solid #6ee7b7",
    "border-left:4px solid #059669",
    "border-radius:8px",
    "padding:10px 14px",
    "margin-bottom:10px",
    "display:flex",
    "align-items:center",
    "justify-content:space-between",
    "gap:10px",
    "flex-wrap:wrap"
  ].join(";");
  const migrated=Object.values(S.quotations||{}).filter(v=>v.createdBy===S.user.u&&v.branchId===S.activeBranch.id).length;
  banner.innerHTML=`
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:1.5rem">🏢</span>
      <div>
        <div style="font-weight:700;font-size:.9rem;color:#065f46">Active Branch: ${S.activeBranch.name}</div>
      </div>
    </div>
    <div style="font-size:.68rem;background:#059669;color:#fff;padding:3px 10px;border-radius:10px;font-weight:600;flex-shrink:0">✓ Linked</div>`;
  anchor.parentNode.insertBefore(banner,anchor);
}


function applySidebarBranding(){
  const s=S.settings||{};
  if(s.logo){$("sbL").src=s.logo;$("sbL").style.display="block";$("sbLFb").style.display="none"}
  else{$("sbL").style.display="none";$("sbLFb").style.display="flex";$("sbLFb").textContent=(s.company||"P")[0]}
  // Update sidebar company name/license — target the static .nm div
  const nm=document.querySelector("#SB .nm");
  if(nm){nm.innerHTML=`${s.company||"Pak Globe Travels"}<br><small>${s.license||""}</small>`}
  // Apply brand color from active branch/settings
  if(s.brandColor){document.documentElement.style.setProperty("--brand",s.brandColor)}
  // Also update the login screen branding
  if($("lLic"))$("lLic").textContent=`${s.license||"GL # 5807"} • ${s.address?.split(",")[0]||"HYDERABAD"}`;
}

/* Get effective settings for print.
   Priority: quotation's own saved branchId → activeBranch → global settings.
   This ensures Karachi quotation always prints with Karachi details,
   even when viewed/printed by a Hyderabad admin. */
function effectiveSettings(quotation){
  if(quotation&&quotation.branchId&&S.branches&&S.branches[quotation.branchId]&&S.branches[quotation.branchId].settings){
    return Object.assign({},S.settings,S.branches[quotation.branchId].settings);
  }
  if(S.activeBranch&&S.activeBranch.settings)return Object.assign({},S.settings,S.activeBranch.settings);
  return S.settings||{};
}

/* Get the branch ID and Name for the CURRENT USER when saving a new quotation.
   - Normal user: their assigned branchId
   - Admin/Superadmin: their own branchId field (set when user was created/edited)
   This ensures every quotation is permanently linked to the creator's branch. */
function myBranchForSave(){
  const u=S.user;
  // Normal user: activeBranch already set
  if(S.activeBranch&&S.activeBranch.id)return{id:S.activeBranch.id,name:S.activeBranch.name||""};
  // Admin/Superadmin: check their own branchId in user record
  if(u.branchId&&S.branches&&S.branches[u.branchId]){
    return{id:u.branchId,name:S.branches[u.branchId].name||u.branchName||""};
  }
  return{id:"",name:""};
}

/* ===== BRANCH MANAGEMENT PAGE ===== */
function pgBranches(pg){
  if(!P("branches","view"))return pg.innerHTML=`<div class="cd"><p style="padding:20px;color:var(--t2);text-align:center">⛔ You don't have permission for this section</p></div>`;
  pg.innerHTML=`<div class="cd"><div class="cd-h">Branch Management ${P("branches","add")?`<button class="btn btn-sm btn-p" onclick="addBranch()">+ Add Branch</button>`:""}</div>
  <div id="branchList" style="display:grid;gap:8px;margin-top:6px"></div></div>`;
  renderBranches();
}
function renderBranches(){
  const el=$("branchList");if(!el)return;
  const entries=Object.entries(S.branches||{});
  if(!entries.length){el.innerHTML=`<p style="color:var(--t2);text-align:center;padding:20px">No branches yet. Click + Add Branch to create the first one.</p>`;return}
  const ce=P("branches","edit"),cd=P("branches","delete");
  el.innerHTML=entries.map(([id,b])=>`
    <div class="branch-card${b.disabled?" disabled-branch":" active-branch"}">
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;font-size:.88rem">${b.name||"—"} <span class="branch-badge${b.disabled?" dis":""}"> ${b.disabled?"Disabled":"Active"}</span></div>
        <div style="font-size:.72rem;color:var(--t2);margin-top:2px">${b.settings?.address||""} ${b.settings?.phone?("• "+b.settings.phone):""}</div>
        <div style="font-size:.7rem;color:var(--t2)">${b.settings?.license||""}</div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0">
        <button class="btn-icon" onclick="viewBranchOverview('${id}')" title="Overview — full details, users, quotations">👁</button>
        ${ce?`<button class="btn-icon" onclick="editBranch('${id}')">✏</button>
        <button class="btn-icon" onclick="toggleBranchDisabled('${id}',${!b.disabled})">${b.disabled?"✅":"🚫"}</button>`:""}
        ${cd?`<button class="btn-icon" style="color:var(--er)" onclick="deleteBranch('${id}')">🗑</button>`:""}
      </div>
    </div>`).join("");
}
window.addBranch=()=>{
  if(!P("branches","add"))return toast("You don't have permission to add branches","err");
  const s=S.settings||{};
  showModal("Add Branch",branchFormHtml({name:"",settings:{...s}},"new_branch"),async()=>{
    const nm=$("bName").value.trim();if(!nm)return toast("Enter branch name","err")||false;
    const settings=readBranchSettings();
    const id="br_"+Date.now();
    const branch={name:nm,settings,createdAt:new Date().toISOString(),createdBy:S.user.u};
    await bFS("branches/"+id,branch);
    S.branches[id]=branch;
    toast("Branch added: "+nm);renderBranches();return true},"Save Branch");
};
window.editBranch=id=>{
  if(!P("branches","edit"))return toast("You don't have permission to edit branches","err");
  const b=S.branches[id];if(!b)return;
  showModal("Edit Branch: "+b.name,branchFormHtml(b,id),async()=>{
    const nm=$("bName").value.trim();if(!nm)return toast("Enter branch name","err")||false;
    const settings=readBranchSettings();
    const upd={...b,name:nm,settings,updatedAt:new Date().toISOString(),updatedBy:S.user.u};
    await bFU("branches/"+id,upd);
    S.branches[id]=upd;
    toast("Branch updated");renderBranches();return true},"Save Changes");
};
window.toggleBranchDisabled=async(id,dis)=>{
  if(!P("branches","edit"))return toast("You don't have permission","err");
  await bFU("branches/"+id,{disabled:dis});
  S.branches[id].disabled=dis;
  toast(dis?"Branch disabled":"Branch enabled");renderBranches();
};
window.deleteBranch=id=>{
  if(!P("branches","delete"))return toast("You don't have permission to delete branches","err");
  const b=S.branches[id];if(!b)return;
  confirmModal(`Delete branch "${b.name}"? Users assigned to it will lose their branch. (Stays in Recycle Bin for 7 days)`,async()=>{
    await _trashAdd("branches",b.name,"Branch","branches/"+id,b,{});
    await bFD("branches/"+id);
    delete S.branches[id];
    toast("Branch deleted");renderBranches();
  });
};
/* ===== BRANCH OVERVIEW — pura system ek jagah: details, logo, users, quotations ===== */
window.viewBranchOverview=async(id)=>{
  const b=S.branches[id];if(!b)return;
  const s=b.settings||{};
  let quots=S.quotations;
  if(!quots||!Object.keys(quots).length){try{quots=await FR("quotations")||{};S.quotations=quots}catch(e){quots=S.quotations||{}}}
  const branchUsers=Object.values(S.users||{}).filter(u=>u.branchId===id);
  const branchQuots=Object.entries(quots||{}).filter(([k,v])=>v.branchId===id);
  const privateCount=branchQuots.filter(([k,v])=>v.type!=="group").length;
  const groupCount=branchQuots.filter(([k,v])=>v.type==="group").length;
  const logo=s.logo?`<img src="${s.logo}" style="height:60px;width:60px;object-fit:contain;border-radius:8px;background:#f0f0f0;padding:4px">`:`<div style="width:60px;height:60px;border-radius:8px;background:${s.brandColor||"#1e40af"};color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1.4rem;flex-shrink:0">${(s.company||b.name||"B")[0]}</div>`;
  const usersHtml=branchUsers.length?branchUsers.map(u=>`<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd);font-size:.78rem"><span>${u.full||u.u}</span><span class="bd bd-${roleBadge(u.r)}">${u.r}</span></div>`).join(""):`<div style="color:var(--t2);font-size:.78rem">Koi user assigned nahi</div>`;
  const recentQuots=branchQuots.sort((a,c)=>new Date(c[1].createdAt||0)-new Date(a[1].createdAt||0)).slice(0,8);
  const quotsHtml=recentQuots.length?recentQuots.map(([k,v])=>`<div style="display:flex;justify-content:space-between;gap:8px;padding:4px 0;border-bottom:1px solid var(--bd);font-size:.76rem"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.clientName||"—"} <small style="color:var(--t2)">(${v.type==="group"?"Group":"Private"})</small></span><span style="color:var(--t2);flex-shrink:0">${v.invoiceNo||""}</span></div>`).join(""):`<div style="color:var(--t2);font-size:.78rem">Koi quotation nahi</div>`;
  $("MD").innerHTML=`<div class="modal-bg"><div class="modal" style="max-width:540px">
  <h3>${b.name} — Overview</h3>
  <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px">${logo}<div><div style="font-weight:700">${s.company||b.name}</div><div style="font-size:.75rem;color:var(--t2)">${s.license||""}</div></div></div>
  <div style="font-size:.78rem;line-height:1.8;margin-bottom:10px;background:var(--bg2,#f8fafc);padding:8px 10px;border-radius:8px">
  ${s.address?`📍 ${s.address}<br>`:""}${s.phone?`📞 ${s.phone}`:""}${s.whatsapp?` &nbsp;•&nbsp; 💬 ${s.whatsapp}`:""}${s.phone||s.whatsapp?"<br>":""}${s.email?`✉ ${s.email}<br>`:""}${s.website?`🌐 ${s.website}`:""}
  </div>
  <div class="g2" style="margin-bottom:10px;gap:8px">
    <div class="cd" style="padding:10px;text-align:center;margin:0"><div style="font-size:1.3rem;font-weight:800">${privateCount}</div><div style="font-size:.7rem;color:var(--t2)">Private Quotations</div></div>
    <div class="cd" style="padding:10px;text-align:center;margin:0"><div style="font-size:1.3rem;font-weight:800">${groupCount}</div><div style="font-size:.7rem;color:var(--t2)">Group Quotations</div></div>
  </div>
  <div style="font-weight:700;font-size:.8rem;margin:10px 0 4px">👥 Users (${branchUsers.length})</div>
  <div style="max-height:120px;overflow:auto">${usersHtml}</div>
  <div style="font-weight:700;font-size:.8rem;margin:10px 0 4px">📄 Recent Quotations</div>
  <div style="max-height:170px;overflow:auto">${quotsHtml}</div>
  <div class="modal-actions"><button class="btn btn-o" onclick="closeModal()">Close</button><button class="btn btn-p" onclick="closeModal();editBranch('${id}')">Edit Details</button></div>
  </div></div>`;
};
function branchFormHtml(b,id){
  const s=b.settings||{};
  return `<div class="g2">
<div class="fg gf"><label>Branch Name</label><input id="bName" value="${(b.name||"").replace(/"/g,"&quot;")}"></div>
<div class="fg gf"><label>Company Name</label><input id="bCompany" value="${(s.company||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>License No</label><input id="bLicense" value="${(s.license||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>Brand Color</label><input type="color" id="bBrandColor" value="${s.brandColor||"#1e40af"}" style="height:38px;padding:2px;cursor:pointer"></div>
<div class="fg gf"><label>Office Address <small style="font-weight:400;text-transform:none">(long address will split 70%/30% in reports)</small></label><input id="bAddress" value="${(s.address||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>Phone</label><input id="bPhone" value="${(s.phone||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>WhatsApp</label><input id="bWhatsapp" value="${(s.whatsapp||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>Email</label><input id="bEmail" value="${(s.email||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>Website</label><input id="bWebsite" value="${(s.website||"").replace(/"/g,"&quot;")}"></div>
<div class="fg gf"><label>Disclaimer</label><input id="bDisclaimer" value="${(s.disclaimer||"").replace(/"/g,"&quot;")}"></div>
<div class="fg"><label>Invoice Prefix</label><input id="bInvPrefix" value="${s.invoicePrefix||"PGT"}"></div>
<div class="fg"><label>Invoice Next #</label><input type="number" id="bInvNext" value="${s.invoiceNext||1}" min="1"></div>
<div class="fg"><label>ROE Adult</label><input type="number" id="bROE" value="${s.defaultROE||78}"></div>
<div class="fg"><label>Visa SAR Adult</label><input type="number" id="bVisaSAR" value="${s.visaAdultSAR||560}"></div>
<div class="fg gf"><label>Logo URL</label><input id="bLogo" value="${(s.logo||"").replace(/"/g,"&quot;")}"></div>
<div class="fg gf"><label>📷 Upload Branch Logo <small style="font-weight:400;text-transform:none">(max 200KB — shown on quotations)</small></label><input type="file" id="bLogoFile" accept="image/*" onchange="uploadBranchLogo()"></div>
${s.logo?`<div class="fg gf"><img src="${s.logo}" style="height:70px;border-radius:8px;background:#f0f0f0;padding:5px;border:1px solid var(--bd)"><button type="button" class="btn btn-sm btn-o" style="margin-left:8px" onclick="$('bLogo').value='';this.previousElementSibling.remove();this.remove()">Remove Logo</button></div>`:""}
<div class="fg gf"><label>Instructions / Terms & Conditions</label><textarea id="bInstructions" rows="5">${(s.instructions||"").replace(/</g,"&lt;")}</textarea></div>
</div>`;
}
window.uploadBranchLogo=()=>{const f=$("bLogoFile")?.files?.[0];if(!f)return;if(!f.type.startsWith("image/")){toast("Please choose an image file","err");return}compressImg(f,240,0.8).then(dataUrl=>{$("bLogo").value=dataUrl;toast("Logo loaded! Click Save Branch to apply.")}).catch(()=>toast("Could not process image","err"))};
function readBranchSettings(){return{company:$("bCompany")?.value||"",license:$("bLicense")?.value||"",address:$("bAddress")?.value||"",phone:$("bPhone")?.value||"",whatsapp:$("bWhatsapp")?.value||"",email:$("bEmail")?.value||"",website:$("bWebsite")?.value||"",disclaimer:$("bDisclaimer")?.value||"",invoicePrefix:$("bInvPrefix")?.value||"PGT",invoiceNext:n($("bInvNext")?.value)||1,defaultROE:n($("bROE")?.value)||78,visaAdultSAR:n($("bVisaSAR")?.value)||560,brandColor:$("bBrandColor")?.value||"#1e40af",logo:$("bLogo")?.value||"",instructions:$("bInstructions")?.value||""}};

const pgs=[{id:"dash",ic:"📊",lb:"Dashboard",rl:["superadmin","admin","user"]},{id:"pvt",ic:"📝",lb:"Private Costing",rl:["superadmin","admin","user"]},{id:"grp",ic:"👥",lb:"Group Costing",rl:["superadmin","admin","user"]},{id:"quot",ic:"📋",lb:"My Quotations",rl:["superadmin","admin","user"]},{id:"allquot",ic:"🗂",lb:"All Quotations",rl:["superadmin","admin"]},{id:"dup",ic:"🔁",lb:"Duplicate Finder",rl:["superadmin","admin","user"]},{id:"htl",ic:"🏨",lb:"Hotels",rl:["superadmin","admin","user"]},{id:"trn",ic:"🚐",lb:"Transport",rl:["superadmin","admin","user"]},{id:"lst",ic:"📑",lb:"Lists Manager",rl:["superadmin","admin","user"]},{id:"usr",ic:"👤",lb:"Users",rl:["superadmin","admin"]},{id:"bin",ic:"🗑️",lb:"Recycle Bin",rl:["superadmin","admin","user"]},{id:"branches",ic:"🏢",lb:"Branches",rl:["superadmin"]},{id:"set",ic:"⚙️",lb:"Settings",rl:["superadmin","admin"]}];

function buildSB(){const nv=$("SN");nv.innerHTML="";
  if(S.activeBranch&&S.user.r!=="superadmin"){const bDiv=CE("div","",`<div style="padding:6px 11px 2px;font-size:.65rem;color:rgba(255,255,255,.55);text-transform:uppercase;letter-spacing:.5px">Current Branch</div><div style="padding:4px 11px 8px;font-size:.8rem;font-weight:700;color:rgba(255,255,255,.9);border-bottom:1px solid rgba(255,255,255,.12);margin-bottom:4px">${S.activeBranch.name||""}</div>`);nv.appendChild(bDiv)}
  pgs.forEach(p=>{if(!P(p.id,"view"))return;const d=CE("div","sb-i",`<span class="ic">${p.ic}</span><span>${p.lb}</span>`);d.dataset.page=p.id;d.onclick=()=>{editKey=null;nav(p.id);if(innerWidth<769)closeSB()};nv.appendChild(d)});
  const curItem=nv.querySelector(`[data-page="${curPage}"]`)||nv.querySelector(".sb-i");
  curItem?.classList.add("on");
}

let curPage="dash";
function nav(id){
  if(!P(id,"view")){
    toast("You don't have access to this page","err");
    id=P("dash","view")?"dash":(pgs.find(p=>P(p.id,"view"))?.id||"dash");
  }
  curPage=id;
  $("PT").textContent=pgs.find(p=>p.id===id)?.lb||id;
  document.querySelectorAll("#SN .sb-i").forEach(el => {
    if(el.dataset.page === id) el.classList.add("on");
    else el.classList.remove("on");
  });
  window.scrollTo({top:0,behavior:"instant"});
  const ct=$("CT");ct.innerHTML="";const pg=CE("div","");ct.appendChild(pg);
  ({dash:pgDash,pvt:pgPvt,grp:pgGrp,quot:pgQuot,allquot:pgAllQuot,dup:pgDup,htl:pgHtl,trn:pgTrn,lst:pgLst,bin:pgBin,usr:pgUsr,branches:pgBranches,set:pgSet})[id]?.(pg);
}

window.refreshAll=async()=>{
  /* SOFT REFRESH — bina logout ke poora data Supabase se dobara load hota
     hai aur current page re-render ho jata hai. Pehle yahan full page reload
     hoti thi jis se session loss/expire ho jata tha aur user ko har refresh
     ke liye logout/login karna parta tha — ab is ki zaroorat nahi. Koi bhi
     update (quotation/hotel/settings) refresh dabate hi turant nazar aata hai. */
  const btn=$("rfB");if(btn)btn.classList.add("spin");
  toast("Refreshing data...");
  try{
    await loadData();
    await loadBranchesAndApply();
    applySidebarBranding();
    buildSB(); /* Sidebar dobara build karo — permissions/branch changes reflect honge */
    /* Hotel cache bhi clear karo — taake next hotel page kholne par fresh data aaye */
    S.hotels={};for(const k in _hotelsLoading)delete _hotelsLoading[k];
    if(P("backup","view"))_wrapBackupFunctions();
    nav(curPage);
    toast("Refreshed ✓");
  }catch(e){
    toast("Refresh failed: "+e.message,"err");
  }finally{if(btn)btn.classList.remove("spin")}
};
window.nav=nav;

function hi(id,cityId,did){return`<div class="hw"><input id="${id}" autocomplete="off" placeholder="Type hotel..." style="padding-right:24px" oninput="fH('${id}','${id}d','${cityId}','${did}')" onfocus="fH('${id}','${id}d','${cityId}','${did}')" onclick="fH('${id}','${id}d','${cityId}','${did}')"><button type="button" onclick="openHotelLoc('${id}','${cityId}')" title="Open location in Google Maps" style="position:absolute;right:1px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:.8rem;padding:2px;line-height:1">📍</button></div>`}
window.openHotelLoc=(iid,cityId)=>{const inp=$(iid),cityKey=$(cityId)?.value||"makkah",nm=(inp?.value||"").trim();if(!nm)return toast("Select a hotel first","warn");const loc=hotelLoc(cityKey,nm);if(loc)window.open(loc,"_blank");else toast("No location saved for this hotel","warn")};
window.fH=async(iid,did,cityId,distid)=>{
  const inp=$(iid);
  if(!inp)return;
  let dd=$("ghdd");
  if(!dd){dd=document.createElement("div");dd.id="ghdd";dd.className="hdd";document.body.appendChild(dd)}
  const cityKey=$(cityId)?.value||"makkah";
  dd.dataset.forInput=iid;
  if(!S.hotels[cityKey]){
    // Is city ke hotels abhi tak load nahi huay — sirf ab, on-demand, fetch karo
    dd.innerHTML=`<div style="padding:8px 10px;color:var(--t2);font-size:.8rem">Loading hotels…</div>`;
    const r0=inp.getBoundingClientRect();
    dd.style.left=r0.left+"px";dd.style.width=Math.max(r0.width,220)+"px";dd.style.top=r0.bottom+"px";dd.style.bottom="";
    dd.classList.add("show");
    try{
      await ensureHotelsLoaded(cityKey);
    }catch(err){
      dd.innerHTML=`<div style="padding:8px 10px;color:var(--er);font-size:.8rem">⚠ Load failed — check your internet and type again</div>`;
      return;
    }
    if($(cityId)&&$(cityId).value!==cityKey)return; // city badal chuki hai is dauran — purana result mat dikhao
  }
  const v=inp.value.trim().toLowerCase(),ls=S.hotels[cityKey]||[],fl=v?ls.filter(h=>h.n.toLowerCase().includes(v)):ls;
  dd.innerHTML="";
  fl.slice(0,25).forEach(h=>{const d=CE("div","",`<b>${h.n}</b><small>${h.d}</small>`);d.onclick=()=>{inp.value=h.n;dd.classList.remove("show");if(distid&&$(distid))$(distid).value=h.d;triggerCalc()};dd.appendChild(d)});
  const r=inp.getBoundingClientRect(),vh=innerHeight,vw=innerWidth;
  const ddW=Math.max(r.width,220);
  let left=r.left;
  if(left+ddW>vw-8)left=Math.max(8,vw-ddW-8);
  dd.style.left=left+"px";
  dd.style.width=ddW+"px";
  const spaceBelow=vh-r.bottom;
  if(spaceBelow<220&&r.top>220){dd.style.top="";dd.style.bottom=(vh-r.top)+"px";dd.style.maxHeight=Math.min(220,r.top-16)+"px"}
  else{dd.style.bottom="";dd.style.top=r.bottom+"px";dd.style.maxHeight=Math.min(220,vh-r.bottom-16)+"px"}
  dd.classList.toggle("show",fl.length>0);
};
window.addTblRow=(tbodyId)=>{const tb=$(tbodyId);if(!tb)return;const row=tb.querySelector("tr.xrow");if(!row){toast("Maximum rows reached","warn");return}row.classList.remove("xrow");row.style.display="";attachAutoCalc();triggerCalc()};
document.addEventListener("click",e=>{
  const dd=$("ghdd");
  if(dd&&dd.classList.contains("show")){
    if(!dd.contains(e.target)&&e.target.id!==dd.dataset.forInput){dd.classList.remove("show")}
  }
});
// FIX: typing into a number field that already shows "0" (qty, rate, etc.)
// was appending instead of replacing — e.g. typing "1" over a "0" produced
// "10" because the cursor lands after the existing digit on focus. Selecting
// the whole value the moment the field is focused/clicked means the very
// first keystroke always overwrites it, matching how a fresh cell should behave.
document.addEventListener("focusin",e=>{
  const el=e.target;
  if(el&&el.tagName==="INPUT"&&el.type==="number"){
    requestAnimationFrame(()=>{try{el.select()}catch(err){}});
  }
});
window.addEventListener("scroll",e=>{const dd=$("ghdd");if(dd&&!dd.contains(e.target))dd.classList.remove("show")},true);

let calcTimer=null;
let editKey=null;
/* Quotation edit kholne ka waqt — save ke waqt agar kisi DOOSRE user ne beech
   mein update kar di ho to chupke se overwrite karne ke bajaye poocha jata hai */
let _quoteOpenedTs=0;
function _quoteConflict(existing){try{return !!(editKey&&existing&&existing.updatedAt&&_quoteOpenedTs&&Date.parse(existing.updatedAt)>_quoteOpenedTs&&existing.updatedBy&&existing.updatedBy!==S.user.u)}catch(e){return false}}
function fillIf(id,val){const el=$(id);if(el)el.value=val??""}
function setManual(id,val){const el=$(id);if(el&&(val||val===0)){el.value=val;el.dataset.manual="1"}}
function revealRows(tbodyId,count){const tb=$(tbodyId);if(!tb)return;let guard=0;while(tb.querySelectorAll("tr:not(.xrow)").length<count&&guard<10){const r=tb.querySelector("tr.xrow");if(!r)break;r.classList.remove("xrow");r.style.display="";guard++}if(guard>0)attachAutoCalc()}
function triggerCalc(){clearTimeout(calcTimer);calcTimer=setTimeout(()=>{if(document.querySelector("#pTP"))pCalc(true);if(document.querySelector("#gRes"))gCalc(true)},250);autoSaveDraft()}
window.triggerCalc=triggerCalc;
let draftTimer=null;
const _draftMem={};
function draftPageType(){if(document.querySelector("#pTP"))return"pvt";if(document.querySelector("#gRes"))return"grp";return null}

function getDraft(pt){
  try{
    const raw = localStorage.getItem("pgt_draft_" + pt) || _draftMem["draft_" + pt] || null;
    return raw ? JSON.parse(raw) : null;
  }catch(e){ return null; }
}

function setDraft(pt, draftObj){
  try{
    const str = JSON.stringify(draftObj);
    _draftMem["draft_" + pt] = str;
    localStorage.setItem("pgt_draft_" + pt, str);
  }catch(e){}
}

function clearDraft(pt){
  delete _draftMem["draft_" + pt];
  try{ localStorage.removeItem("pgt_draft_" + pt); }catch(e){}
}

function autoSaveDraftNow(){
  const pt = draftPageType();
  if(!pt) return;
  try{
    const data = {};
    document.querySelectorAll("#CT input, #CT select, #CT textarea").forEach(el => {
      if(!el.id) return;
      data[el.id] = el.type === "checkbox" ? el.checked : el.value;
    });
    if(!Object.keys(data).length) return;
    
    const visibleRows = [];
    document.querySelectorAll("#CT tr").forEach(tr => {
      if(!tr.classList.contains("xrow") && tr.style.display !== "none") {
        const firstInp = tr.querySelector("input[id], select[id]");
        if(firstInp) visibleRows.push(firstInp.id);
      }
    });

    const opB = $("opB_en")?.checked || false;
    const opC = $("opC_en")?.checked || false;

    const draftObj = {
      data,
      visibleRows,
      opB,
      opC,
      editKey: editKey || null,
      ts: Date.now(),
      user: S.user?.u || ""
    };
    setDraft(pt, draftObj);
  }catch(e){}
}

function autoSaveDraft(){
  const pt = draftPageType();
  if(!pt) return;
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => {
    autoSaveDraftNow();
  }, 100);
}

function checkDraftBanner(pt){
  const d = getDraft(pt);
  if(!d || !d.data || !Object.keys(d.data).length) return;
  if((d.editKey || null) !== (editKey || null)) return;
  if(d.user && S.user?.u && d.user !== S.user.u) return;
  const cd = $("CT").querySelector(".cd"); if(!cd) return;
  const when = fmtDT(new Date(d.ts).toISOString());
  const bar = CE("div", "", `<div id="draftBanner" style="background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:10px 14px;margin:10px 0;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:.82rem;color:#78350f;box-shadow:0 2px 6px rgba(0,0,0,0.05)"><span>📝 <b>Unsaved draft found</b> from ${when} — recover it?</span><div style="display:flex;gap:6px"><button type="button" class="btn btn-sm btn-p" onclick="restoreDraft('${pt}')">Restore Draft</button><button type="button" class="btn btn-sm btn-o" onclick="discardDraft('${pt}')">Discard</button></div></div>`);
  cd.insertBefore(bar, cd.children[1] || null);
}

function _isRowFilled(tr){
  if(!tr) return false;
  
  // 1. Flight Row Check
  const fD = tr.querySelector("input[id^='fD']");
  const fS = tr.querySelector("input[id^='fS']");
  const fS2 = tr.querySelector("input[id^='fS2']");
  const fL = tr.querySelector("input[id^='fL']");
  const fDp = tr.querySelector("input[id^='fDp']");
  const fAr = tr.querySelector("input[id^='fAr']");
  if(fD || fS || fS2 || fDp || fAr || fL){
    const hasD = !!(fD && fD.value && fD.value.trim() !== "");
    const hasS = !!(fS && fS.value && fS.value.trim() !== "");
    const hasS2 = !!(fS2 && fS2.value && fS2.value.trim() !== "");
    const hasL = !!(fL && fL.value && fL.value.trim() !== "" && fL.value.trim() !== "Kg");
    const hasDp = !!(fDp && fDp.value && fDp.value.trim() !== "" && fDp.value.trim() !== "--:--");
    const hasAr = !!(fAr && fAr.value && fAr.value.trim() !== "" && fAr.value.trim() !== "--:--");
    return hasD || hasS || hasS2 || hasL || hasDp || hasAr;
  }

  // 2. Hotel Row Check: check exact hotel name field (e.g. hA0, hB1, cH0, gH0)
  const inputs = tr.querySelectorAll("input[id]");
  for(let i=0; i<inputs.length; i++){
    const el = inputs[i];
    const id = el.id || "";
    if(/^([chg]?H[A-C]?[0-5])$/i.test(id)){
      if((el.value || "").trim() !== "") return true;
    }
  }

  // 3. Transport Row Check
  const tSec = tr.querySelector("input[id*='tS'], input[id*='TS']");
  const tQty = tr.querySelector("input[id*='tQ'], input[id*='TQ']");
  const tRate = tr.querySelector("input[id*='tR'], input[id*='TR']");
  if(tSec || tQty || tRate){
    const hasSec = !!(tSec && tSec.value && tSec.value.trim() !== "");
    const hasQty = !!(tQty && parseFloat(tQty.value) > 0);
    const hasRate = !!(tRate && parseFloat(tRate.value) > 0);
    return hasSec || hasQty || hasRate;
  }

  return false;
}

window.restoreDraft = (pt) => {
  const d = getDraft(pt);
  if(!d || !d.data) return;

  if(pt === "pvt") {
    if(d.opB && $("opB_en") && !$("opB_en").checked) {
      $("opB_en").checked = true;
      if(typeof window.toggleOp === "function") window.toggleOp('B');
    }
    if(d.opC && $("opC_en") && !$("opC_en").checked) {
      $("opC_en").checked = true;
      if(typeof window.toggleOp === "function") window.toggleOp('C');
    }
  }

  // Populate values to all form fields first
  Object.entries(d.data).forEach(([id, val]) => {
    const el = $(id);
    if(el) {
      if(el.type === "checkbox") el.checked = !!val;
      else el.value = val;
    }
  });

  // Manage visibility of dynamic xrows (Rows 2-5): keep hidden if empty!
  document.querySelectorAll("#CT tr").forEach(tr => {
    if(tr.classList.contains("xrow")) {
      if(_isRowFilled(tr)) {
        tr.style.display = "";
      } else {
        tr.style.display = "none";
      }
    }
  });

  attachAutoCalc();
  if(pt === "pvt" && document.querySelector("#pTP")) pCalc(true);
  if(pt === "grp" && document.querySelector("#gRes")) gCalc(true);
  $("draftBanner")?.remove();
  toast("Draft restored ✓");
};

window.discardDraft = (pt) => {
  clearDraft(pt);
  $("draftBanner")?.remove();
  toast("Draft discarded");
};
function clearDraft(pt){delete _draftMem["draft_"+pt];try{localStorage.removeItem("pgt_draft_"+pt)}catch(e){}}


window.showModal=(title,html,onOk,okLabel)=>{$("MD").innerHTML=`<div class="modal-bg"><div class="modal"><h3>${title}</h3>${html}<div class="modal-actions"><button class="btn btn-o" onclick="closeModal()">Cancel</button><button class="btn btn-p" id="mdOK">${okLabel||"Save"}</button></div></div></div>`;$("mdOK").onclick=()=>{const result=onOk();if(result!==false)closeModal()}};
window.closeModal=()=>{$("MD").innerHTML=""};
/* ===== STYLED CONFIRM MODAL (replaces browser confirm()) ===== */
function confirmModal(msg,onYes,yesLabel,yesCls){
  yesLabel=yesLabel||"Yes, Delete";yesCls=yesCls||"btn-d";
  $("MD").innerHTML=`<div class="modal-bg"><div class="modal" style="max-width:380px"><h3 style="color:var(--er)">⚠️ Confirm</h3><p style="margin-bottom:14px;font-size:.88rem;color:var(--t)">${msg}</p><div class="modal-actions"><button type="button" class="btn btn-o" id="cfNo">Cancel</button><button type="button" class="btn ${yesCls}" id="cfYes">${yesLabel}</button></div></div></div>`;
  // Bind with real addEventListener (not inline-onclick + a shared global
  // variable) so double-taps, fast re-opens, or the modal being re-rendered
  // mid-click can never leave the Yes/Cancel button silently doing nothing.
  const yesBtn=$("cfYes"),noBtn=$("cfNo");
  let done=false;
  const finish=(runCb)=>{
    if(done)return;done=true;
    closeModal();
    if(runCb&&typeof onYes==="function"){
      try{const r=onYes();if(r&&typeof r.then==="function")r.catch(e=>{console.error("[confirmModal]",e);toast("Action failed: "+e.message,"err")})}catch(e){console.error("[confirmModal]",e);toast("Action failed: "+e.message,"err")}
    }
  };
  if(yesBtn)yesBtn.addEventListener("click",()=>finish(true));
  if(noBtn)noBtn.addEventListener("click",()=>finish(false));
}


/* ========== INSTRUCTION PARSER ========== */
function isUrduChar(c){const code=c.charCodeAt(0);return(code>=0x0600&&code<=0x06FF)||(code>=0x0750&&code<=0x077F)||(code>=0xFB50&&code<=0xFDFF)||(code>=0xFE70&&code<=0xFEFF)}
function hasUrdu(s){for(let i=0;i<s.length;i++)if(isUrduChar(s[i]))return true;return false}
function urduRatio(s){if(!s)return 0;let u=0,t=0;for(let i=0;i<s.length;i++){const c=s[i];if(/\s/.test(c))continue;t++;if(isUrduChar(c))u++}return t?u/t:0}

function parseInstructions(raw){
  if(!raw||!raw.trim())return[];
  let text=raw.replace(/\r\n/g,"\n").replace(/\r/g,"\n").trim();
  text=text.replace(/^(\s*\d+\.\s+[^\n]*?)((?:The|This|Neither|If|A |An |In )\s)/gm,function(m,head,rest){
    if(/[.:!?]\s*$/.test(head))return m;
    return head.trim()+"\n"+rest;
  });
  const lines=text.split(/\n/).map(l=>l.replace(/\s+$/,"")).filter(l=>l.trim().length>0);
  const out=[];
  lines.forEach(line=>{
    const trimmed=line.trim();
    if(!trimmed)return;
    if(urduRatio(trimmed)>0.4){
      out.push({type:"urdu",text:trimmed});
      return;
    }
    const numHead=trimmed.match(/^(\d+)\.\s+(.+)$/);
    if(numHead){
      const rest=numHead[2].trim();
      if(rest.length<80&&!/[.!?]\s+[A-Z]/.test(rest)){
        out.push({type:"heading",text:trimmed});
        return;
      }
      const splitMatch=rest.match(/^([A-Z][A-Za-z ,&\-]+?)(\.\s+|(?=\b(The|This|If|Neither|A |An |In )\b))/);
      if(splitMatch&&splitMatch[1].length<70){
        out.push({type:"heading",text:numHead[1]+". "+splitMatch[1].trim().replace(/\.$/,"")});
        const body=rest.substring(splitMatch[0].length).trim();
        if(body)out.push({type:"body",text:body});
        return;
      }
      out.push({type:"body",text:trimmed});
      return;
    }
    if(trimmed.length<60&&/^[A-Z]/.test(trimmed)&&!/[.!?]$/.test(trimmed)&&trimmed.split(/\s+/).length<=6){
      out.push({type:"doctitle",text:trimmed});
      return;
    }
    out.push({type:"body",text:trimmed});
  });
  return out;
}

function renderInstructionsHTML(raw){
  const parts=parseInstructions(raw);
  if(!parts.length)return"";
  let html='<div class="instr-title">TERMS &amp; CONDITIONS</div>';
  parts.forEach(p=>{
    const esc=p.text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    if(p.type==="urdu"){
      html+=`<div class="urdu-line">${esc}</div>`;
    }else if(p.type==="doctitle"){
      html+=`<div class="instr-doc-title">${esc}</div>`;
    }else if(p.type==="heading"){
      html+=`<div class="instr-heading">${esc}</div>`;
    }else{
      html+=`<div class="instr-body">${esc}</div>`;
    }
  });
  return html;
}
window.renderInstructionsHTML=renderInstructionsHTML;
/* ===== WHATSAPP DIRECT SHARE SYSTEM ===== */
function buildWhatsAppText(data){
  if(!data) return "";
  const s = S.settings || {};
  const comp = (s.company || "PAK GLOBE TRAVELS").toUpperCase();
  const lic = s.license ? ` (Govt. License # ${s.license})` : "";
  const phone = s.phone ? `\n*Contact:* ${s.phone}` : "";
  const email = s.email ? `\n*Email:* ${s.email}` : "";
  const address = s.address ? `\n*Address:* ${s.address}` : "";

  const lines = [];
  lines.push("================================");
  lines.push(`*${comp}*${lic}`);
  lines.push("*UMRAH PACKAGE QUOTATION*");
  lines.push("================================");
  lines.push("");

  if(data.invoiceNo)  lines.push(`*Ref / Invoice:* #${data.invoiceNo}`);
  if(data.clientName) lines.push(`*Client Name:* ${data.clientName}`);
  if(data.contactNo)  lines.push(`*Client Contact:* ${data.contactNo}`);
  if(data.travelDates)lines.push(`*Travel Dates:* ${fmtDisplayDate(data.travelDates)}`);
  if(data.pkgIncludes)lines.push(`*Package Includes:* ${data.pkgIncludes}`);

  lines.push("");
  lines.push("--------------------------------");

  if(data.type === "group"){
    if(data.airline) lines.push(`*Airline:* ${data.airline}`);
    if(data.days) lines.push(`*Total Duration:* ${data.days} Days`);
    if(data.ticketPP) lines.push(`*Ticket Rate:* PKR ${fmt(data.ticketPP)}`);
    lines.push("");

    const ht = (data.hotels||[]).filter(h => h.name);
    if(ht.length){
      lines.push("*HOTEL ACCOMMODATION:*");
      ht.forEach((h, idx) => {
        lines.push(`  ${idx+1}. *${cityLabel(h.city)}:* ${h.name}`);
        lines.push(`     • Room: ${(h.cat||h.type||"Standard").toUpperCase()}`);
        lines.push(`     • Nights: ${h.ngt||0} Nts | Distance: ${h.dist||"Near"}`);
      });
      lines.push("");
    }

    const tr = (data.transports||[]).filter(t => t.sec && t.qty > 0);
    if(tr.length){
      lines.push("*TRANSPORT DETAILS:*");
      tr.forEach(t => {
        lines.push(`  • *Sector:* ${t.sec.toUpperCase()} (${t.veh || "Vehicle"})`);
      });
      lines.push("");
    }

    lines.push("--------------------------------");
    lines.push("*PRICING PER PERSON (PKR):*");
    lines.push("");
    const ROOM_NAMES = {5:"QUINT (5 Bed)", 4:"QUAD (4 Bed)", 3:"TRIPLE (3 Bed)", 2:"DOUBLE (2 Bed)"};
    [5, 4, 3, 2].forEach(k => {
      if(data.results?.[k]?.sell && data.results[k].sell !== "-"){
        lines.push(`  • *${ROOM_NAMES[k]}:* PKR ${data.results[k].sell}`);
      }
    });

  } else {
    // Private Package Options (Option A, Option B, Option C)
    const opts = data.options ? Object.entries(data.options) : [];
    opts.forEach(([l, o], index) => {
      if(index > 0){
        lines.push("");
        lines.push("--------------------------------");
      }
      lines.push(`*PACKAGE OPTION ${l}:*`);
      lines.push("");
      
      const fl = (o.flights||[]).filter(f => f.airline && f.airline !== "-" && f.sec);
      if(fl.length){
        lines.push("*Flight Schedule:*");
        fl.forEach(f => {
          const depT = f.dep && f.dep !== "-" ? f.dep : "--:--";
          const arrT = f.arr && f.arr !== "-" ? f.arr : "--:--";
          lines.push(`  • ${f.airline} | ${f.sec.toUpperCase()} | ${fmtDisplayDate(f.date)}`);
          lines.push(`    Timing: ${depT} - ${arrT} (${f.cls || "Economy"})`);
        });
        lines.push("");
      }

      const ht = (o.hotels||[]).filter(h => h.name);
      if(ht.length){
        lines.push("*Hotels:*");
        ht.forEach((h, hIdx) => {
          lines.push(`  ${hIdx+1}. *${cityLabel(h.city)}:* ${h.name}`);
          lines.push(`     • Room: ${(h.type||"Standard").toUpperCase()}`);
          lines.push(`     • Stay: ${h.ngt||0} Nights | Distance: ${h.dist||"Near"}`);
        });
        lines.push("");
      }

      const tr = (o.transports||[]).filter(t => t.sec && t.qty > 0);
      if(tr.length){
        lines.push("*Transport:*");
        tr.forEach(t => {
          lines.push(`  • ${t.sec.toUpperCase()} (${t.veh || "Vehicle"})`);
        });
        lines.push("");
      }

      lines.push("*RATES PER PERSON (PKR):*");
      lines.push(`  • *Adult Rate:* PKR ${fmt(o.perAdult)}`);
      if(o.childPax > 0) lines.push(`  • *Child Rate:* PKR ${fmt(o.perChild)}`);
      if(o.infantPax > 0) lines.push(`  • *Infant Rate:* PKR ${fmt(o.perInfant)}`);
      lines.push("");
    });
  }

  lines.push("================================");
  lines.push(`*${comp}*${phone}${email}${address}`);
  lines.push("");
  lines.push("_May Allah accept your Umrah & pilgrimage!_");
  return lines.join("\n");
}

function openWhatsApp(text, targetPhone){
  let cleanPhone = (targetPhone || "").replace(/[^0-9]/g, "");
  if(cleanPhone.length === 11 && cleanPhone.startsWith("03")){
    cleanPhone = "92" + cleanPhone.slice(1);
  }
  const encodedText = encodeURIComponent(text);
  let url = "";
  if(cleanPhone){
    url = `https://wa.me/${cleanPhone}?text=${encodedText}`;
  } else {
    url = `https://api.whatsapp.com/send?text=${encodedText}`;
  }
  window.open(url, "_blank");
}

window.shareWhatsAppPvt = () => {
  if(!$("pN")?.value.trim()){toast("Enter client name first","warn");return}
  pCalc(true);
  const existingNo=editKey&&S.quotations[editKey]?S.quotations[editKey].invoiceNo:"DRAFT";
  const data={type:"private",clientName:$("pN")?.value||"",contactNo:$("pPh")?.value||"",pkgIncludes:$("pInc")?.value||"",travelDates:$("pDt")?.value||"",createdBy:S.user.u,createdAt:new Date().toISOString(),invoiceNo:existingNo,options:{}};
  ['A','B','C'].forEach(L=>{if(!$(`aP${L}`))return;const o={flights:[],adultPax:n($(`aP${L}`)?.value),adultCat:$(`aCt${L}`)?.value||"",days:n($(`dDy${L}`)?.value),hotels:[],visa:{},transports:[],ticketPKR:n($(`tk${L}`)?.value),ticketQty:n($(`tkQ${L}`)?.value),markup:n($(`mk${L}`)?.value),totalAdult:0,perAdult:0,childPax:n($(`cP${L}`)?.value),infantPax:n($(`iP${L}`)?.value)};
  for(let i=0;i<6;i++)o.flights.push({airline:$(`fA${L}${i}`)?.value||"",cls:$(`fC${L}${i}`)?.value||"",sec:$(`fS${L}${i}`)?.value||"",date:$(`fD${L}${i}`)?.value||"",dep:$(`fDp${L}${i}`)?.value||"",arr:$(`fAr${L}${i}`)?.value||""});
  for(let i=0;i<6;i++)o.hotels.push({name:$(`h${L}${i}`)?.value||"",type:$(`hR${L}${i}`)?.value||"",city:$(`hCity${L}${i}`)?.value||"makkah",ngt:n($(`hN${L}${i}`)?.value),dist:$(`hD${L}${i}`)?.value||""});
  for(let i=0;i<6;i++)o.transports.push({sec:$(`tS${L}${i}`)?.value||"",veh:$(`tV${L}${i}`)?.value||"",qty:n($(`tQ${L}${i}`)?.value)});
  let hT=0;o.hotels.forEach(h=>hT+=h.rate*h.qty*h.ngt*h.roe);
  const perA=n($(`rPP${L}`)?.textContent?.replace(/,/g,""))||0;
  o.perAdult=perA;
  if(o.hotels.some(h=>h.name)||o.flights.some(f=>f.sec)||perA>0)data.options[L]=o;
  });
  const text = buildWhatsAppText(data);
  openWhatsApp(text, data.contactNo);
};

window.shareWhatsAppGrp = () => {
  if(!$("gN")?.value.trim()){toast("Enter client name first","warn");return}
  gCalc(true);
  const existingNo=editKey&&S.quotations[editKey]?S.quotations[editKey].invoiceNo:"DRAFT";
  const data={type:"group",clientName:$("gN")?.value||"",pkgIncludes:$("gInc")?.value||"",travelDates:$("gDt")?.value||"",airline:$("gAir")?.value||"",ticketPP:n($("gTk")?.value),days:n($("gDays")?.value),createdBy:S.user.u,invoiceNo:existingNo,hotels:[],transports:[],results:{}};
  for(let i=0;i<6;i++)data.hotels.push({name:$(`gH${i}`)?.value||"",cat:$(`gHC${i}`)?.value||"",city:$(`gHCity${i}`)?.value||"makkah",ngt:n($(`gHN${i}`)?.value),dist:$(`gHD${i}`)?.value||""});
  for(let i=0;i<6;i++)data.transports.push({sec:$(`gTS${i}`)?.value||"",veh:$(`gTV${i}`)?.value||"",qty:n($(`gTQ${i}`)?.value)});
  [5,4,3,2].forEach(c=>data.results[c]={sell:$(`gS${c}`)?.textContent});
  const text = buildWhatsAppText(data);
  openWhatsApp(text, "");
};

window.shareWhatsAppFromList = (k) => {
  const q = S.quotations[k];
  if(!q) return toast("Quotation not found", "err");
  const text = buildWhatsAppText(q);
  openWhatsApp(text, q.contactNo);
};

window.shareWhatsAppCurrentPrint = () => {
  if(_printData && _printData.d){
    const text = buildWhatsAppText(_printData.d);
    openWhatsApp(text, _printData.d.contactNo);
  } else {
    toast("No active quotation data to share", "warn");
  }
};

/* ========== PRINT & PDF SYSTEM ========== */
let _printHTML="";
let _printData=null;
let _printFilename="Quotation.pdf";
let _isPrinting=false;
let _isGeneratingPdf=false;

const PP_PRINT_CSS=`
*{box-sizing:border-box}
@page{size:A4;margin:0}
html,body{margin:0;padding:0;background:#fff}
.pp{background:#fff;color:#0f172a;padding:6mm 9mm 9mm;font-size:9.5px;width:210mm;max-width:210mm;min-height:296mm;margin:0 auto;font-family:'Segoe UI',Arial,sans-serif;display:flex;flex-direction:column}
.pp .pp-body{display:block;flex:1 0 auto}
.pp *{font-family:'Segoe UI',Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact;color-adjust:exact;box-sizing:border-box}
.pp .hdr{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding-bottom:8px;margin-bottom:8px;border-bottom:2px solid var(--brand,#1F4AA8)}
.pp .hdr .logo-wrap{width:40mm;height:40mm;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.pp .hdr .logo-wrap img{width:100%;height:100%;object-fit:contain}
.pp .hdr .logo-fb{width:100%;height:100%;background:var(--brand,#1F4AA8);border-radius:10px;display:flex;align-items:center;justify-content:center;color:#fff!important;font-size:46px;font-weight:700}
.pp .hdr .co-info{text-align:center}
.pp .hdr .co-info h1{font-size:21px;font-weight:800;color:var(--brand,#1F4AA8)!important;margin:0;line-height:1.15;letter-spacing:.4px}
.pp .hdr .co-info .lic{font-size:9px;color:#0f172a!important;font-weight:800;letter-spacing:1px;margin-top:3px}
.pp .hdr .co-info .addr-top{font-size:8.5px;color:#1e293b!important;font-weight:800;margin-top:3px;line-height:1.3}.pp .hdr .co-info .addr-bot{font-size:7.5px;color:#475569!important;font-weight:700;margin-top:1px;line-height:1.3}
.pp .hdr .contact-info{text-align:right;font-size:9px;color:#334155!important;line-height:1.9}
.pp .hdr .contact-info .ci-row{display:flex;align-items:center;justify-content:flex-end;gap:5px;white-space:nowrap}
.pp .hdr .contact-info .ci-ico{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;border-radius:50%;background:var(--brand,#1F4AA8);color:#fff!important;font-size:8px;flex-shrink:0}
.pp .mini-hdr{display:flex;align-items:center;gap:8px;padding-bottom:6px;margin-bottom:8px;border-bottom:1px solid var(--brand,#1F4AA8)}
.pp .mini-hdr .logo-wrap{width:12mm;height:12mm;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.pp .mini-hdr .logo-wrap img{width:100%;height:100%;object-fit:contain}
.pp .mini-hdr .logo-fb{width:12mm;height:12mm;border-radius:50%;background:var(--brand,#1F4AA8);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;flex-shrink:0}
.pp .mini-co{display:flex;flex-direction:column;gap:1px}
.pp .mini-co b{font-size:11px;color:var(--brand,#1F4AA8)}
.pp .mini-inv{font-size:8px;color:#64748b;display:block}
.pp .title{text-align:center;padding:9px 6px;font-size:13px;font-weight:800;letter-spacing:3px;color:#fff!important;background:linear-gradient(135deg,var(--brand,#1F4AA8),var(--ps,#1e3a8a));margin-bottom:9px;border-radius:8px;border-bottom:3px solid #f59e0b}
.pp .icards{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:9px}
.pp .icard{border:1px solid #dbe2ea;background:linear-gradient(180deg,#fff,#F3F6FB);border-radius:8px;padding:7px 4px 6px;text-align:center;border-top:2px solid var(--brand,#1F4AA8)}
.pp .icard .ic-ico{font-size:12px;color:var(--brand,#1F4AA8)!important;margin-bottom:2px}
.pp .icard .ic-lbl{font-size:7px;color:#64748b!important;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}
.pp .icard .ic-val{color:var(--brand,#1F4AA8)!important;font-weight:800;font-size:10px;line-height:1.25;word-break:break-word}
.pp .cinfo{display:grid;grid-template-columns:1fr 1fr;gap:2px 18px;background:#F5F7FA;border:1px solid #dbe2ea;border-left:3px solid var(--brand,#1F4AA8);border-radius:8px;padding:9px 14px;margin-bottom:10px}
.pp .cinfo-col{display:flex;flex-direction:column}
.pp .cinfo .ci-item{display:flex;gap:6px;font-size:9.5px;padding:2.5px 0;align-items:baseline}
.pp .cinfo .ci-item b{font-weight:700;color:#334155!important;white-space:nowrap;min-width:62px;display:inline-block}
.pp .cinfo .ci-item span{color:#0f172a!important;font-weight:700}
.pp .sec-hdr{display:flex;align-items:center;gap:8px;margin:10px 0 8px;text-transform:uppercase;letter-spacing:2px;font-weight:800;font-size:11px;color:var(--brand,#1F4AA8)!important}
.pp .sec-hdr::before,.pp .sec-hdr::after{content:"";flex:1;height:1px;background:var(--brand,#1F4AA8);opacity:.35}
.pp .sec-hdr .ic,.pp .thankbar .ic{font-size:13px;line-height:1;vertical-align:-2px;display:inline-block}
.pp .opt-banner{background:linear-gradient(135deg,var(--brand,#1F4AA8),var(--ps,#1e3a8a));color:#fff!important;text-align:center;padding:6px;font-size:11px;font-weight:700;margin:12px 0 6px;letter-spacing:2px;border-radius:6px}
.pp .opt-page-break{page-break-before:always;break-before:page;padding-top:8mm}
.pp .sec{display:flex;align-items:center;gap:5px;color:#fff!important;font-weight:800;padding:5px 10px;font-size:9.5px;margin:8px 0 4px;background:linear-gradient(135deg,var(--brand,#1F4AA8),var(--ps,#1e3a8a));border-radius:6px;letter-spacing:.4px;text-transform:uppercase}
.pp .sec .ic{font-size:11px;line-height:1;vertical-align:-1px;display:inline-block}
.pp table{border-collapse:collapse;width:100%;margin-bottom:6px}
.pp th{background:var(--brand,#1F4AA8);color:#fff!important;padding:4.5px 5px;font-size:7.3px;border:1px solid var(--brand,#1F4AA8);text-transform:uppercase;letter-spacing:.3px;font-weight:800;text-align:center}
.pp td{padding:4px 5px;font-size:8.3px;border:1px solid #dbe2ea;background:#fff;color:#0f172a!important;text-align:center}
.pp td b{color:#0f172a!important;font-weight:700}
.pp td.flt-time{font-weight:700;color:var(--brand,#1F4AA8)!important}
.pp td.sec-cell{font-weight:800;text-transform:uppercase}
.pp tr:nth-child(even) td{background:#f6f8fb}
.pp .transit-cell{min-width:58px}
.pp .tr-time{display:flex;align-items:center;justify-content:center;gap:3px;font-weight:800;color:#0f172a!important;font-size:9px;white-space:nowrap}
.pp .badge{display:inline-block;margin-top:3px;padding:1.5px 6px;border-radius:8px;font-size:6.3px;font-weight:800;letter-spacing:.2px;text-transform:uppercase;color:#fff!important}
.pp .badge-quick{background:#16a34a!important}
.pp .badge-long{background:#ea580c!important}
.pp .badge-overnight{background:#2563eb!important}
.pp .badge-neutral{background:#64748b!important}
.pp .hotel-boxes{display:flex;flex-direction:row;flex-wrap:nowrap;gap:5px;margin-bottom:6px;width:100%;align-items:stretch}
.pp .hotel-boxes .h-box{flex:1 1 0%;min-width:0}
.pp .h-box{display:flex;gap:0;border:1px solid #dbe2ea;border-radius:8px;overflow:hidden;background:#fff;min-width:0}
.pp .h-photo{flex:0 0 26mm;width:26mm;height:26mm;background:#eef1f5}
.pp .h-photo img{width:100%;height:100%;object-fit:cover;object-position:center;display:block;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.pp .h-photo-ph{flex:0 0 26mm;width:26mm;height:26mm;display:flex;align-items:center;justify-content:center;font-size:22px;color:#94a3b8}
.pp .h-info{flex:1;padding:6px 8px;min-width:0}
.pp .h-box .h-lbl{display:flex;align-items:center;justify-content:space-between;gap:4px;font-weight:800;font-size:7.5px;color:var(--brand,#1F4AA8)!important;text-transform:uppercase;letter-spacing:.4px;background:#eef2f9;border-radius:4px;padding:3px 6px;margin-bottom:5px}
.pp .h-box .h-pin{text-decoration:none;font-size:15px}
.pp .h-box .h-nm{font-weight:800;font-size:9.5px;color:#0f172a!important;margin-bottom:5px;line-height:1.25}
.pp .h-box .h-dt{font-size:7.8px;color:#334155!important;line-height:1.6;display:grid;grid-template-columns:auto 1fr;gap:1px 6px}
.pp .h-box .h-dt b{color:#64748b!important;font-weight:700}
.pp .summary-wrap{display:flex;justify-content:flex-end;margin:8px 0 4px}
.pp .summary-box{border:1.5px solid var(--brand,#1F4AA8);border-radius:8px;overflow:hidden;min-width:62mm}
.pp .sum-row{display:flex;justify-content:space-between;gap:10px;padding:6px 12px;font-size:9.5px;font-weight:700;color:#0f172a!important;background:#F5F7FA}
.pp .sum-row:not(:last-child){border-bottom:1px solid #dbe2ea}
.pp .sum-row b{color:var(--brand,#1F4AA8)!important;font-size:11.5px;font-weight:800}
.pp .sum-row.inf b{color:#c2410c!important}
.pp .tot{background:#F5F7FA;color:#0f172a!important;text-align:right;padding:6px 12px;font-size:10px;font-weight:700;margin:5px 0;letter-spacing:.3px;border-radius:5px;border:1px solid #e2e8f0;border-left:4px solid var(--brand,#1F4AA8)}
.pp .tot-ch{border-left-color:#c2410c!important}
.pp .tot-inf{border-left-color:#991b1b!important}
.pp .price-tbl tr.sell td{background:#F5F7FA!important;color:#065f46!important;font-weight:700;font-size:10px;padding:8px;border-left:3px solid #059669}
.pp .pp-footer{padding-top:8px;margin-top:auto}
.pp .ftr2{padding-top:8px;border-top:1px solid #dbe2ea;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.pp .ftr2-note{font-size:7.8px;color:#64748b!important;display:flex;align-items:center;gap:4px}
.pp .ftr2-dev{font-size:7.8px;color:#94a3b8!important;font-weight:600}
.pp .thankbar{margin-top:8px;background:linear-gradient(135deg,var(--brand,#1F4AA8),var(--ps,#1e3a8a));color:#fff!important;text-align:center;padding:8px;border-radius:8px;font-style:italic;font-size:9.5px;letter-spacing:.5px;border-top:2px solid #f59e0b}
.pp.instr-page{page-break-before:always;break-before:page}
.pp.pp-single{page-break-inside:avoid!important;break-inside:avoid!important}
.pp .instr{margin:0;padding:14px 18px;background:#fffbeb;border:1px solid #fde68a;border-left:3px solid #f59e0b;border-radius:4px;font-size:9px;color:#78350f!important;line-height:1.7;font-family:'Segoe UI',Arial,sans-serif!important}
.pp .instr .instr-title{display:flex;align-items:center;justify-content:center;min-height:1.3em;font-weight:700;font-size:13px;margin-bottom:10px;text-align:center;padding:8px;background:#f59e0b;color:#fff!important;border-radius:3px;letter-spacing:1.5px}
.pp .instr .instr-doc-title{display:flex;align-items:center;justify-content:center;min-height:1.3em;width:100%;font-weight:700;font-size:11px;color:#92400e!important;text-align:center!important;margin:10px 0 8px 0;padding:8px 6px;background:rgba(245,158,11,.1);border-radius:2px;letter-spacing:.5px}
.pp .instr .instr-heading{font-weight:700;font-size:10.5px;color:#92400e!important;margin:8px 0 3px 0;line-height:1.4}
.pp .instr .instr-body{font-weight:400;font-size:9px;color:#78350f!important;margin:0 0 6px 0;line-height:1.6;text-align:justify;padding-left:8px}
.pp .instr .urdu-line{direction:rtl;text-align:right;font-family:'Noto Nastaliq Urdu','Jameel Noori Nastaleeq','Segoe UI',Arial,sans-serif!important;font-size:12px;line-height:2.2;margin-bottom:10px;padding:8px 10px;border-radius:3px;color:#78350f!important;font-weight:500}
.pp .dev{text-align:center;font-size:7.5px;color:#94a3b8!important;margin-top:5px;font-weight:500}
`;

function openPrintPreview(html,filename,data){
  _printHTML=html;
  _printData=data||null;
  _printFilename=(filename||"Quotation")+".pdf";
  $("printBody").innerHTML="<div>"+html+"</div>";
  $("printOverlay").classList.add("active");
  document.body.style.overflow="hidden";
}

/* ===== BULLETPROOF MOBILE PRINT ENGINE v4 =====
   Fixes Android Chrome / Samsung Internet / Firefox blank-page bugs.

   Root causes identified & fixed:
   1. display:none container → blank on mobile  [FIXED: off-screen iframe]
   2. CSS variables (var(--brand)) not resolving in iframe  [FIXED: vars inlined]
   3. display:flex / display:grid breaking in print  [FIXED: table-based print CSS]
   4. Images not decoded before print()  [FIXED: Promise.all img.decode()]
   5. Fonts not loaded before print()  [FIXED: document.fonts.ready wait]
   6. print() called before layout settled  [FIXED: rAF+rAF+500ms chain]
   7. Samsung Internet onload not firing  [FIXED: 3s safety fallback]
   8. position:fixed elements bleeding into print  [FIXED: app chrome hidden via display:none in print CSS]
*/

/* ---- Browser detection helper ---- */
function _detectBrowser(){
  const ua=navigator.userAgent||"";
  if(/Samsung/i.test(ua)||/SamsungBrowser/i.test(ua))return"samsung";
  if(/Android/i.test(ua)&&/Chrome/i.test(ua))return"android-chrome";
  if(/Android/i.test(ua)&&/Firefox/i.test(ua))return"android-firefox";
  if(/iPhone|iPad/i.test(ua)&&/Safari/i.test(ua))return"ios-safari";
  if(/Firefox/i.test(ua))return"firefox";
  if(/Edg\//i.test(ua))return"edge";
  return"chrome";
}

/* ---- Wait for all images inside an element to fully decode ---- */
function _waitImages(el){
  const imgs=Array.from(el.querySelectorAll("img"));
  if(!imgs.length)return Promise.resolve();
  return Promise.all(imgs.map(img=>{
    if(!img.src&&!img.currentSrc)return Promise.resolve();
    if(img.complete&&img.naturalWidth>0){
      return img.decode?img.decode().catch(()=>{}):Promise.resolve();
    }
    return new Promise(res=>{
      const done=()=>res();
      img.onload=done;img.onerror=done;
      // Safety: if already loaded but naturalWidth==0, resolve after 200ms
      setTimeout(done,2000);
    });
  }));
}

/* ---- Inline CSS variable values into a string (removes var(--x) references) ---- */
function _inlineVars(css,brandColor){
  const color=brandColor||"#1F4AA8";
  return css
    .replace(/var\(--brand,\s*#[0-9a-fA-F]+\)/g,color)
    .replace(/var\(--brand\)/g,color)
    .replace(/var\(--p\)/g,color)
    .replace(/var\(--pl\)/g,"#3b82f6")
    .replace(/var\(--ps\)/g,"#1e3a8a")
    .replace(/var\(--ok\)/g,"#059669")
    .replace(/var\(--er\)/g,"#dc2626")
    .replace(/var\(--a\)/g,"#f59e0b")
    .replace(/var\(--al\)/g,"#fbbf24")
    .replace(/var\(--tealL\)/g,"#14b8a6")
    .replace(/var\(--orange\)/g,"#f97316")
    .replace(/var\(--bg\)/g,"#f1f5f9")
    .replace(/var\(--c\)/g,"#fff")
    .replace(/var\(--t\)/g,"#0f172a")
    .replace(/var\(--t2\)/g,"#64748b")
    .replace(/var\(--bd\)/g,"#e2e8f0");
}

window.doPrintNow=function(){
  if(_isPrinting){return;}
  if(!_printHTML){toast("Nothing to print","err");return;}
  _isPrinting=true;

  const browser=_detectBrowser();
  const s=S.settings||{};
  const brand=s.brandColor||"#1F4AA8";

  // Remove any previous print iframe
  const old=document.getElementById("_pf");
  if(old)old.remove();

  // Inline CSS variables so Android print engine doesn't get confused
  const resolvedPrintCSS=_inlineVars(PP_PRINT_CSS,brand);

  // Build complete standalone HTML — no external font deps, no CSS vars
  const iframeDoc=`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
@page{size:A4 portrait;margin:0}
html,body{background:#fff!important;font-family:'Segoe UI',Arial,sans-serif;
  -webkit-print-color-adjust:exact;print-color-adjust:exact;color-adjust:exact}
${resolvedPrintCSS}
/* Pixel-match the on-screen preview: flex column keeps footer pinned to page bottom */
.pp{
  display:flex!important;
  flex-direction:column!important;
  min-height:296mm!important;
  width:210mm!important;
  max-width:210mm!important;
  margin:0 auto!important;
  padding:6mm 9mm 9mm!important;
  page-break-after:always;
  break-after:page;
}
.pp.pp-single{
  page-break-inside:avoid!important;
  break-inside:avoid!important;
}
.pp .pp-body{display:block!important;flex:1 0 auto!important}
.pp .pp-footer{margin-top:auto!important;padding-top:8px!important}
.pp:last-child{page-break-after:auto!important;break-after:auto!important}
/* Remove position:fixed elements from print flow */
#LS,#LP,#APP,#TC,#MD,#printOverlay,.sidebar,.sb-overlay,.top,
[style*="position:fixed"],[style*="position: fixed"]{display:none!important}
</style>
</head><body>${_printHTML}</body></html>`;

  const iframe=document.createElement("iframe");
  iframe.id="_pf";
  // CRITICAL: NOT display:none — that causes blank on Android
  // Position off-screen but fully rendered
  iframe.style.cssText="position:fixed;left:-9999px;top:0;width:210mm;height:297mm;border:none;opacity:0;pointer-events:none;z-index:-1;visibility:visible;";
  document.body.appendChild(iframe);

  // Write content
  const iDoc=iframe.contentDocument||iframe.contentWindow.document;
  iDoc.open("text/html","replace");
  iDoc.write(iframeDoc);
  iDoc.close();

  var _printFired=false;

  function doActualPrint(){
    if(_printFired)return;
    _printFired=true;
    try{
      iframe.contentWindow.focus();
      iframe.contentWindow.print();
    }catch(e){
      // Fallback for browsers that block iframe.print()
      _fallbackPrint();
    }
    // Cleanup after print dialog closes
    setTimeout(()=>{
      const fr=document.getElementById("_pf");
      if(fr)fr.remove();
      _isPrinting=false;
    },5000);
  }

  function _fallbackPrint(){
    const pa=$("PA");
    if(!pa)return;
    const style=document.createElement("style");
    style.id="_pstyle";
    style.textContent=`@media print{
      body>*:not(#PA){display:none!important}
      #PA{display:block!important;position:static!important;background:#fff}
      @page{size:A4;margin:0}
    }`;
    document.head.appendChild(style);
    pa.innerHTML=`<style>${resolvedPrintCSS}</style>`+_printHTML;
    pa.style.cssText="display:block;position:fixed;inset:0;background:#fff;z-index:99999;overflow:auto;";
    window.print();
    setTimeout(()=>{
      pa.innerHTML="";pa.style.cssText="display:none";
      document.getElementById("_pstyle")?.remove();
    },3000);
  }

  // Phase 1: Wait for iframe onload
  iframe.onload=function(){
    // Phase 2: Wait for fonts inside iframe
    const fontWait=(iframe.contentDocument&&iframe.contentDocument.fonts)
      ?iframe.contentDocument.fonts.ready
      :Promise.resolve();

    fontWait.then(()=>{
      // Phase 3: Wait for all images to decode
      return _waitImages(iframe.contentDocument||iframe.contentWindow.document);
    }).then(()=>{
      // Phase 4: Two rAF cycles for layout to settle
      requestAnimationFrame(()=>{
        requestAnimationFrame(()=>{
          // Phase 5: Extra delay — Samsung/slow Android need more time
          const delay=(browser==="samsung"||browser==="android-chrome")?600:300;
          setTimeout(doActualPrint,delay);
        });
      });
    }).catch(()=>{
      // If any wait fails, still try to print
      setTimeout(doActualPrint,800);
    });
  };

  // Safety net: if onload doesn't fire within 4s (Samsung Internet quirk)
  setTimeout(function(){
    if(!_printFired){
      try{
        requestAnimationFrame(()=>setTimeout(doActualPrint,300));
      }catch(e){_isPrinting=false;}
    }
  },4000);
};

/* ========== PDF DOWNLOAD (native jsPDF text — copyable/selectable) ==========
   Rebuilds the same design as the on-screen Preview using real jsPDF text,
   tables (autoTable) and vector shapes — NOT an image — so every field in
   the downloaded PDF is selectable/searchable/copyable text, matching the
   preview 1:1 in layout, colors and content. Each package "option" (and the
   Terms & Conditions page) gets its own full PDF page, never merged. */
let PDF_BRAND=[31,74,168];
function hexToRgb(hex){hex=(hex||"#1F4AA8").replace("#","");if(hex.length===3)hex=hex.split("").map(c=>c+c).join("");const num=parseInt(hex,16)||0x1F4AA8;return[(num>>16)&255,(num>>8)&255,num&255]}
const _emojiCache={};
function emojiImg(emoji,px){px=px||64;const k=emoji+"_"+px;if(_emojiCache[k])return _emojiCache[k];const c=document.createElement("canvas");c.width=px;c.height=px;const ctx=c.getContext("2d");ctx.font=Math.round(px*0.8)+"px 'Segoe UI Emoji','Apple Color Emoji','Noto Color Emoji',sans-serif";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText(emoji,px/2,px/2+px*0.06);const url=c.toDataURL("image/png");_emojiCache[k]=url;return url}
function drawEmoji(pdf,emoji,x,y,sz){try{pdf.addImage(emojiImg(emoji,64),"PNG",x,y,sz,sz)}catch(e){}}
function pdfAddLogo(pdf,s,x,y,sz){
  if(s.logo){try{let fmt="PNG";if(/^data:image\/jpe?g/i.test(s.logo))fmt="JPEG";pdf.addImage(s.logo,fmt,x,y,sz,sz);return}catch(e){}}
  pdf.setFillColor(...PDF_BRAND);pdf.roundedRect(x,y,sz,sz,2,2,"F");
  pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bold");pdf.setFontSize(sz*2);
  pdf.text((s.company||"P")[0].toUpperCase(),x+sz/2,y+sz/2+sz*0.16,{align:"center"});
}
function pdfPageBorder(pdf,pw,ph){/* outline removed by design update — pages now render clean, no border */}
function checkPagePdf(pdf,y,need,pw,ph){if(y+need>ph-26){pdf.addPage();pdfPageBorder(pdf,pw,ph);return 8}return y}
function pdfHeader(pdf,s,pw,y){
  const M=9,logoSz=32;
  pdfAddLogo(pdf,s,M,y,logoSz);
  const midX=pw/2;
  pdf.setTextColor(...PDF_BRAND);pdf.setFont("helvetica","bold");pdf.setFontSize(15.5);
  pdf.text((s.company||"PAK GLOBE TRAVELS").toUpperCase(),midX,y+11,{align:"center"});
  pdf.setTextColor(15,23,42);pdf.setFont("helvetica","bold");pdf.setFontSize(7);
  if(s.license)pdf.text(s.license,midX,y+15.5,{align:"center"});
  // Address split 70% top / 30% bottom — same as HTML preview
  if(s.address){
    const addr=s.address;
    const splitIdx=Math.floor(addr.length*0.70);
    let cutAt=splitIdx;
    for(let i=splitIdx;i>splitIdx-20&&i>0;i--){if(addr[i]===","||addr[i]===" "){cutAt=i;break}}
    const top=addr.slice(0,cutAt).trim().replace(/,$/,"");
    const bot=addr.slice(cutAt).trim().replace(/^,/,"").trim();
    pdf.setTextColor(30,41,59);pdf.setFont("helvetica","bold");pdf.setFontSize(6.5);
    pdf.text(top,midX,y+19.5,{align:"center"});
    if(bot){pdf.setTextColor(71,85,105);pdf.setFont("helvetica","normal");pdf.setFontSize(6);pdf.text(bot,midX,y+22.5,{align:"center"})}
  }
  let cy=y+10;pdf.setFontSize(6.75);pdf.setTextColor(51,65,85);pdf.setFont("helvetica","normal");const rx=pw-M;
  if(s.phone){pdf.text(s.phone,rx,cy,{align:"right"});cy+=4.2}
  if(s.website){pdf.text(s.website.replace(/^https?:\/\//,"").replace(/\/$/,""),rx,cy,{align:"right"});cy+=4.2}
  if(s.email){pdf.text(s.email,rx,cy,{align:"right"});cy+=4.2}
  const bottomY=y+logoSz+2;
  pdf.setDrawColor(...PDF_BRAND);pdf.setLineWidth(0.6);pdf.line(M,bottomY,pw-M,bottomY);
  return bottomY+4;
}
function pdfTitleBar(pdf,y,pw,text){const M=9,w=pw-2*M;pdf.setFillColor(...PDF_BRAND);pdf.roundedRect(M,y,w,8,2,2,"F");pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bold");pdf.setFontSize(12);pdf.text(text,pw/2,y+5.4,{align:"center"});return y+8+4}
function pdfIcards(pdf,y,pw,items){const M=9,gap=2,w=(pw-2*M-3*gap)/4,h=15;items.forEach((it,i)=>{const x=M+i*(w+gap);pdf.setFillColor(245,247,250);pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.25);pdf.roundedRect(x,y,w,h,1.5,1.5,"FD");if(it.ico)drawEmoji(pdf,it.ico,x+w/2-2.4,y+1.2,4.8);pdf.setTextColor(100,116,139);pdf.setFont("helvetica","bold");pdf.setFontSize(6.1);pdf.text(String(it.lbl).toUpperCase(),x+w/2,y+8.4,{align:"center"});pdf.setTextColor(...PDF_BRAND);pdf.setFont("helvetica","bold");pdf.setFontSize(8.4);const valLines=pdf.splitTextToSize(String(it.val||"-"),w-4);pdf.text(valLines.slice(0,2),x+w/2,y+12.1,{align:"center"})});return y+h+5}
function pdfCinfo(pdf,y,pw,left,right){const M=9,w=pw-2*M,rowH=4.6,rows=Math.max(left.length,right.length),boxH=rows*rowH+7;pdf.setFillColor(245,247,250);pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.25);pdf.roundedRect(M,y,w,boxH,1.5,1.5,"FD");const colW=w/2;const draw=(arr,x0)=>{arr.forEach((it,i)=>{const ry=y+6+i*rowH;pdf.setFont("helvetica","bold");pdf.setFontSize(8.2);pdf.setTextColor(51,65,85);pdf.text(it.lbl,x0+5,ry);const lblW=pdf.getTextWidth(it.lbl);pdf.setFont("helvetica","bold");pdf.setFontSize(8.2);pdf.setTextColor(15,23,42);const valLines=pdf.splitTextToSize(String(it.val||""),colW-lblW-12);pdf.text(valLines[0]||"",x0+5+lblW+3,ry)})};draw(left,M);draw(right,M+colW);return y+boxH+5}
function pdfSecHdr(pdf,y,pw,text){const M=9;pdf.setFont("helvetica","bold");pdf.setFontSize(10.5);const tw=pdf.getTextWidth(text);const cx=pw/2;pdf.setDrawColor(...PDF_BRAND);pdf.setLineWidth(0.35);pdf.line(M,y,cx-tw/2-4,y);pdf.line(cx+tw/2+4,y,pw-M,y);pdf.setTextColor(...PDF_BRAND);pdf.text(text,cx,y+1.1,{align:"center"});return y+6}
function pdfSectionLabel(pdf,y,pw,text){const M=9,w=pw-2*M;pdf.setFillColor(...PDF_BRAND);pdf.roundedRect(M,y,w,6,1,1,"F");pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bold");pdf.setFontSize(8.3);pdf.text(text.toUpperCase(),M+3,y+4.1);return y+6+3}
const BADGE_RGB={"badge-quick":[22,163,74],"badge-long":[234,88,12],"badge-overnight":[37,99,235],"badge-neutral":[100,116,139]};
function pdfFlightTable(pdf,y,pw,fl){
  if(!fl.length)return y;
  y=pdfSectionLabel(pdf,y,pw,"Flight Details");
  const M=9;const transits=fl.map(f=>transitInfo(f.arr,f.dep2));
  const cleanTime = (t) => (!t || t.trim() === "" || t.trim() === "--:--") ? "-" : t.trim();
  const cleanSec = (s) => (!s || s.trim() === "") ? "-" : s.trim().toUpperCase();
  const cleanVal = (v) => (!v || v.trim() === "") ? "-" : v.trim();

  pdf.autoTable({startY:y,margin:{left:M,right:M},
    head:[[{content:"Flt#",rowSpan:2},{content:"Date",rowSpan:2},{content:"Airline",rowSpan:2},{content:"Class",rowSpan:2},{content:"SECTOR 1",colSpan:3},{content:"Layover",rowSpan:2},{content:"SECTOR 2",colSpan:3},{content:"Lug",rowSpan:2},{content:"Stay/Transit",rowSpan:2}],
      [{content:"Sector"},{content:"Dep"},{content:"Arr"},{content:"Sector"},{content:"Dep"},{content:"Arr"}]],
    body:fl.map((f,i)=>[i+1,fmtDisplayDate(f.date)||"-" ,cleanVal(f.airline),cleanVal(f.cls),cleanSec(f.sec),cleanTime(f.dep),cleanTime(f.arr),cleanVal(f.lay),cleanSec(f.sec2),cleanTime(f.dep2),cleanTime(f.arr2),cleanVal(f.lug),"-"]),
    theme:"grid",styles:{font:"helvetica",fontSize:6.6,cellPadding:1.3,textColor:[15,23,42],lineColor:[219,226,234],lineWidth:0.15,halign:"center",valign:"middle"},
    headStyles:{fillColor:[238,242,249],textColor:PDF_BRAND,fontStyle:"bold",fontSize:6.1,halign:"center"},
    alternateRowStyles:{fillColor:[250,251,252]},
    columnStyles:{0:{cellWidth:7},1:{cellWidth:18},12:{cellWidth:30,minCellHeight:10}},
    didParseCell:data=>{if(data.section==="body"&&data.column.index===12)data.cell.text=[]},
    didDrawCell:data=>{
      if(data.section!=="body"||data.column.index!==12)return;
      const ti=transits[data.row.index];if(!ti)return;
      const cell=data.cell;
      const cx=cell.x+cell.width/2;
      const availW=cell.width-3;
      pdf.setFont("helvetica","bold");pdf.setFontSize(6.8);pdf.setTextColor(15,23,42);
      const labelY=cell.y+cell.height/2-1.4;
      pdf.text(ti.label,cx,labelY,{align:"center"});
      let label=ti.badge.t.replace(/^[^\w]+/,"").toUpperCase();
      const col=BADGE_RGB[ti.badge.c]||[100,116,139];
      let fs=5.1;pdf.setFont("helvetica","bold");pdf.setFontSize(fs);
      let btw=pdf.getTextWidth(label)+4;
      while(btw>availW&&fs>3.4){fs-=0.3;pdf.setFontSize(fs);btw=pdf.getTextWidth(label)+4}
      btw=Math.min(btw,availW);
      const bx=cx-btw/2,by=cell.y+cell.height/2+0.8;
      pdf.setFillColor(...col);pdf.roundedRect(bx,by,btw,3.2,1,1,"F");
      pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bold");pdf.text(label,cx,by+2.2,{align:"center"});
    }});
  return pdf.lastAutoTable.finalY+4;
}
function pdfHotelBoxes(pdf,y,pw,list,labelFn){
  if(!list.length)return y;
  const M=9,gap=3,w=pw-2*M,perRow=Math.min(list.length,3),boxW=(w-(perRow-1)*gap)/perRow,photoH=15,boxH=26+photoH;
  list.forEach((h,i)=>{
    const col=i%perRow,row=Math.floor(i/perRow),x=M+col*(boxW+gap),by=y+row*(boxH+gap);
    pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.25);pdf.setFillColor(255,255,255);pdf.roundedRect(x,by,boxW,boxH,1.5,1.5,"FD");
    const px0=x+1.4,py0=by+1.4,pw0=boxW-2.8,ph0=photoH-1.8;
    let photoDrawn=false;
    if(h.img){try{let fmt="JPEG";if(/^data:image\/png/i.test(h.img))fmt="PNG";pdf.addImage(h.img,fmt,px0,py0,pw0,ph0);photoDrawn=true}catch(e){}}
    if(!photoDrawn){
      pdf.setFillColor(236,240,245);pdf.roundedRect(px0,py0,pw0,ph0,1,1,"F");
      const cx=x+boxW/2,cy=py0+ph0/2+0.5,bw=Math.min(9,pw0*0.35),bh=bw*0.65;
      pdf.setFillColor(196,206,218);
      pdf.rect(cx-bw/2,cy-bh/2+bw*0.28,bw,bh,"F");
      pdf.triangle(cx-bw/2-1,cy-bh/2+bw*0.28,cx+bw/2+1,cy-bh/2+bw*0.28,cx,cy-bh/2-bw*0.32,"F");
      pdf.setFillColor(255,255,255);pdf.rect(cx-1,cy-bh/2+bw*0.28+1.5,2,2,"F");
    }
    pdf.setDrawColor(238,241,245);pdf.line(x+3,by+photoH+2,x+boxW-3,by+photoH+2);
    pdf.setTextColor(...PDF_BRAND);pdf.setFont("helvetica","bold");pdf.setFontSize(6.3);
    pdf.text(String(labelFn(h)).toUpperCase(),x+boxW/2,by+photoH+5.2,{align:"center"});
    pdf.setTextColor(15,23,42);pdf.setFont("helvetica","bold");pdf.setFontSize(7.3);
    const nmLines=pdf.splitTextToSize(h.name||"",boxW-5).slice(0,2);
    nmLines.forEach((l,li)=>pdf.text(l,x+boxW/2,by+photoH+11.2+li*3.4,{align:"center"}));
    if(h.loc){
      const pinSz=4.2,px=x+boxW-pinSz-2,py=by+photoH+2.5;
      drawEmoji(pdf,"📍",px,py,pinSz);
      pdf.link(px,py,pinSz,pinSz,{url:h.loc});
    }
    let dy=by+photoH+12.5+nmLines.length*3.4+2.5;
    [["Room:",(h.type||h.cat||"-")+"x"+(h.qty||0)],["Nights:",h.ngt||0],["Distance:",h.dist||"-"]].forEach(([lb,vl])=>{
      pdf.setFont("helvetica","bold");pdf.setFontSize(6.2);pdf.setTextColor(100,116,139);pdf.text(lb,x+4,dy);
      pdf.setFont("helvetica","normal");pdf.setTextColor(15,23,42);const vlLines=pdf.splitTextToSize(String(vl),boxW-22);pdf.text(vlLines[0]||"",x+18,dy);
      dy+=3.5;
    });
  });
  return y+Math.ceil(list.length/perRow)*(boxH+gap)+2;
}
function pdfTransportTable(pdf,y,pw,list){
  if(!list.length)return y;
  y=pdfSectionLabel(pdf,y,pw,"Transport");
  const M=9;
  pdf.autoTable({startY:y,margin:{left:M,right:M},head:[["Sector","Vehicle","Qty"]],body:list.map(t=>[(t.sec||"").toUpperCase(),t.veh,t.qty]),theme:"grid",styles:{font:"helvetica",fontSize:7,cellPadding:1.6,textColor:[15,23,42],lineColor:[219,226,234],lineWidth:0.15},headStyles:{fillColor:[238,242,249],textColor:PDF_BRAND,fontStyle:"bold"}});
  return pdf.lastAutoTable.finalY+4;
}
function pdfVisaTable(pdf,y,pw,o,roe){
  if(!o)return y;
  const v=o.visa||{};const mv=o.manualVisas||[];const cmv=o.childManualVisas||[];const imv=o.infantManualVisas||[];
  const cv=o.childVisa||{};const iv=o.infantVisa||{};
  const hasVisa=(v.r&&v.r>0)||(v.q&&v.q>0);
  const hasChildVisa=o.childPax>0&&((cv.r&&cv.r>0)||(cv.q&&cv.q>0));
  const hasInfantVisa=o.infantPax>0&&((iv.r&&iv.r>0)||(iv.q&&iv.q>0));
  const hasManual=mv.length>0||cmv.length>0||imv.length>0;
  if(!hasVisa&&!hasChildVisa&&!hasInfantVisa&&!hasManual)return y;
  y=pdfSectionLabel(pdf,y,pw,"Visa Details");
  const M=9;const rows=[];
  if(hasVisa)rows.push(["UMRAH VISA","FT",v.q||o.adultPax||0]);
  mv.forEach(m=>rows.push([((m.name||"VISA").toUpperCase()),"—",m.q||0]));
  if(hasChildVisa)rows.push(["UMRAH VISA (CHILD)","FT",cv.q||o.childPax||0]);
  cmv.forEach(m=>rows.push([((m.name||"VISA").toUpperCase())+" (CHILD)","—",m.q||0]));
  if(hasInfantVisa)rows.push(["UMRAH VISA (INFANT)","FT",iv.q||o.infantPax||0]);
  imv.forEach(m=>rows.push([((m.name||"VISA").toUpperCase())+" (INFANT)","—",m.q||0]));
  pdf.autoTable({startY:y,margin:{left:M,right:M},head:[["Visa Type","Cat","Qty"]],body:rows,theme:"grid",styles:{font:"helvetica",fontSize:7,cellPadding:1.6,textColor:[15,23,42],lineColor:[219,226,234],lineWidth:0.15},headStyles:{fillColor:[238,242,249],textColor:PDF_BRAND,fontStyle:"bold"}});
  return pdf.lastAutoTable.finalY+4;
}
function pdfSummaryBox(pdf,y,pw,rows){
  const M=9,boxW=72,x=pw-M-boxW,rowH=6.4,boxH=rows.length*rowH;
  pdf.setDrawColor(...PDF_BRAND);pdf.setLineWidth(0.4);pdf.setFillColor(245,247,250);pdf.roundedRect(x,y,boxW,boxH,1.5,1.5,"FD");
  rows.forEach((r,i)=>{const ry=y+i*rowH;if(i>0){pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.2);pdf.line(x,ry,x+boxW,ry)}pdf.setFont("helvetica","bold");pdf.setFontSize(8);pdf.setTextColor(15,23,42);pdf.text(r.label,x+4,ry+4.2);pdf.setFontSize(10);pdf.setTextColor(...(r.color||PDF_BRAND));pdf.text(r.val,x+boxW-4,ry+4.2,{align:"right"})});
  return y+boxH+4;
}
function pdfFooterBlock(pdf,pw,ph,s){
  const M=9,y=ph-20;
  pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.2);pdf.line(M,y,pw-M,y);
  pdf.setFont("helvetica","normal");pdf.setFontSize(6.5);pdf.setTextColor(100,116,139);
  const noteLines=pdf.splitTextToSize("Note: "+(s.disclaimer||"All rates are subject to availability & may change without prior notice."),pw-2*M-45);
  pdf.text(noteLines[0]||"",M,y+4);
  pdf.setTextColor(148,163,184);pdf.text("Developed by Shahzaman",pw-M,y+4,{align:"right"});
  const barY=y+7,barH=7;
  pdf.setFillColor(...PDF_BRAND);pdf.roundedRect(M,barY,pw-2*M,barH,1.5,1.5,"F");
  pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bolditalic");pdf.setFontSize(8.5);
  pdf.text("Thank you for choosing "+(s.company||"Pak Globe Travels"),pw/2,barY+4.6,{align:"center"});
}
function urduLineToImage(text,widthMm){
  return new Promise(res=>{
    try{
      const scale=8,wPx=Math.round(widthMm*scale),fontPx=Math.round(3.4*scale);
      const c=document.createElement("canvas");c.width=wPx;
      const ctx=c.getContext("2d");
      ctx.font=fontPx+"px 'Noto Nastaliq Urdu','Jameel Noori Nastaleeq','Noto Sans Arabic',Tahoma,Arial";
      ctx.direction="rtl";
      const words=String(text).split(" ");const lines=[];let cur="";
      words.forEach(w=>{const test=cur?cur+" "+w:w;if(ctx.measureText(test).width>wPx-24&&cur){lines.push(cur);cur=w}else cur=test});
      if(cur)lines.push(cur);
      const lineH=fontPx*1.7,topPad=fontPx*0.9;
      c.height=Math.max(lineH,lines.length*lineH+12)+topPad;
      ctx.font=fontPx+"px 'Noto Nastaliq Urdu','Jameel Noori Nastaleeq','Noto Sans Arabic',Tahoma,Arial";
      ctx.direction="rtl";ctx.textAlign="right";ctx.textBaseline="alphabetic";ctx.fillStyle="#78350f";
      lines.forEach((l,i)=>ctx.fillText(l,wPx-12,topPad+lineH*(i+1)-lineH*0.3));
      res({dataUrl:c.toDataURL("image/png"),ratio:c.height/c.width});
    }catch(e){res(null)}
  });
}
async function pdfInstructionsPage(pdf,pw,ph,s){
  pdf.addPage();pdfPageBorder(pdf,pw,ph);
  const M=16,pageTop=18;
  pdf.setFillColor(245,158,11);pdf.roundedRect(M,pageTop,pw-2*M,9,1.5,1.5,"F");
  pdf.setTextColor(255,255,255);pdf.setFont("helvetica","bold");pdf.setFontSize(12);
  pdf.text("TERMS & CONDITIONS",pw/2,pageTop+6,{align:"center"});
  const innerM=M+7,maxW=pw-2*innerM;
  const parts=parseInstructions(s.instructions);

  // Pre-render Urdu line images (needed to know their height for layout)
  const urduImgs=[];
  for(const p of parts)urduImgs.push(p.type==="urdu"?await urduLineToImage(p.text,maxW-6):null);

  // Measure every block's height up front (no drawing yet) so we can paginate
  // and size the background box to the real content instead of the full page.
  const blocks=[];
  parts.forEach((p,idx)=>{
    if(p.type==="urdu"){
      const img=urduImgs[idx];
      if(img){const h2=(maxW-6)*img.ratio;blocks.push({kind:"urdu",img,h:h2+3})}
    }else if(p.type==="doctitle"){
      pdf.setFont("helvetica","bold");pdf.setFontSize(10.5);
      const lines=pdf.splitTextToSize(p.text,maxW-6);
      blocks.push({kind:"doctitle",lines,h:lines.length*5+2})
    }else if(p.type==="heading"){
      pdf.setFont("helvetica","bold");pdf.setFontSize(9.3);
      const lines=pdf.splitTextToSize(p.text,maxW-6);
      blocks.push({kind:"heading",lines,h:lines.length*4.6+1.5})
    }else{
      pdf.setFont("helvetica","normal");pdf.setFontSize(8.2);
      const lines=pdf.splitTextToSize(p.text,maxW-6);
      blocks.push({kind:"body",lines,h:lines.length*4.2+2})
    }
  });

  const boxPadTop=4,boxPadBottom=6,bottomSafe=ph-22;
  const contentStartFirst=pageTop+9+3+boxPadTop;
  const contentStartOther=pageTop+boxPadTop;
  const pages=[];
  let cur={blocks:[],startY:contentStartFirst,y:contentStartFirst};
  blocks.forEach(b=>{
    if(cur.y+b.h>bottomSafe&&cur.blocks.length){
      cur.endY=cur.y;pages.push(cur);
      cur={blocks:[],startY:contentStartOther,y:contentStartOther}
    }
    cur.blocks.push(b);cur.y+=b.h
  });
  cur.endY=cur.y;pages.push(cur);

  pages.forEach((pg,pi)=>{
    if(pi>0){pdf.addPage();pdfPageBorder(pdf,pw,ph)}
    const boxTop=pg.startY-boxPadTop,boxH=(pg.endY-boxTop)+boxPadBottom;
    pdf.setFillColor(255,251,235);pdf.setDrawColor(253,230,138);pdf.setLineWidth(0.3);
    pdf.roundedRect(M,boxTop,pw-2*M,boxH,2,2,"FD");
    pdf.setFillColor(245,158,11);pdf.rect(M,boxTop,1.2,boxH,"F");
    let y=pg.startY;
    pg.blocks.forEach(b=>{
      if(b.kind==="urdu"){
        pdf.addImage(b.img.dataUrl,"PNG",innerM+3,y,maxW-6,b.h-3);y+=b.h
      }else if(b.kind==="doctitle"){
        pdf.setFillColor(253,246,224);pdf.roundedRect(innerM,y-2.5,maxW,b.h-1,1.2,1.2,"F");
        pdf.setFont("helvetica","bold");pdf.setFontSize(10.5);pdf.setTextColor(146,64,14);
        b.lines.forEach(l=>{pdf.text(l,pw/2,y+3,{align:"center"});y+=5});y+=2
      }else if(b.kind==="heading"){
        pdf.setFont("helvetica","bold");pdf.setFontSize(9.3);pdf.setTextColor(146,64,14);
        b.lines.forEach(l=>{pdf.text(l,innerM+3,y+3);y+=4.6});y+=1.5
      }else{
        pdf.setFont("helvetica","normal");pdf.setFontSize(8.2);pdf.setTextColor(120,53,15);
        b.lines.forEach(l=>{pdf.text(l,innerM+3,y+3);y+=4.2});y+=2
      }
    })
  });
}
async function renderPvtPdf(pdf,d,s){
  const pw=210,ph=297,M=9;
  PDF_BRAND=hexToRgb(s.brandColor||"#1F4AA8");
  const opts=d.options?Object.entries(d.options):[];
  const vo=_filterPrintOpts(opts);
  if(!vo.length){toast("No data","warn");return}
  let td=n(vo[0]?.[1]?.days);if(!td&&vo[0]){vo[0][1].hotels?.forEach(h=>td+=n(h.ngt));td++}
  const fo=vo[0]?.[1];
  const icards=()=>[{ico:"🧾",lbl:"Invoice #",val:d.invoiceNo||"-"},{ico:"📅",lbl:"Date",val:d.createdAt?.split("T")[0]||"-"},{ico:"👤",lbl:"Prepared By",val:fullNameOf(d.createdBy)||"-"},{ico:"💼",lbl:"Package Type",val:"Customized Umrah"}];
  pdfPageBorder(pdf,pw,ph);
  let y=8;
  y=pdfHeader(pdf,s,pw,y);
  y=pdfTitleBar(pdf,y,pw,"CUSTOMIZED UMRAH PACKAGE");
  y=pdfIcards(pdf,y,pw,icards());
  y=pdfCinfo(pdf,y,pw,
    [{lbl:"Client:",val:d.clientName||""},{lbl:"Adults:",val:fo?.adultPax||"0"},{lbl:"Child:",val:fo?.childPax||"0"},{lbl:"Infant:",val:fo?.infantPax||"0"},{lbl:"Days:",val:td||""}],
    [{lbl:"Contact:",val:d.contactNo||""},{lbl:"Travel:",val:d.travelDates||_travelDatesFromSavedFlights(d.options)||""},{lbl:"Includes:",val:d.pkgIncludes||""}]);
  y=pdfSecHdr(pdf,y,pw,"TRAVEL DETAILS");
  vo.forEach(([l,o],vIdx)=>{
    const fl=o.flights?.filter(f=>f.airline&&f.airline!=="-"&&f.sec)||[];
    const ht=o.hotels?.filter(h=>h.name).map(liveHotel)||[];
    const tr=o.transports?.filter(t=>t.sec&&t.qty>0)||[];
    if(vo.length>1){
      if(vIdx>0){pdf.addPage();pdfPageBorder(pdf,pw,ph);y=8;y=pdfHeader(pdf,s,pw,y);y=pdfIcards(pdf,y,pw,icards())}
      y=pdfSecHdr(pdf,y,pw,"OPTION "+l+" — TRAVEL DETAILS");
      y+=2;
    }
    const isSingle=vo.length===1;
    /* Sequence: Flight → Hotel → Transport → Visa */
    y=pdfFlightTable(pdf,y,pw,fl);
    if(ht.length){if(!isSingle)y=checkPagePdf(pdf,y,30,pw,ph);y=pdfSectionLabel(pdf,y,pw,"Hotel Accommodation");y=pdfHotelBoxes(pdf,y,pw,ht,h=>cityLabel(h.city)+" Hotel")}
    if(tr.length){if(!isSingle)y=checkPagePdf(pdf,y,20,pw,ph);y=pdfTransportTable(pdf,y,pw,tr)}
    /* VISA details — full table with Visa Type, Cat, Qty */
    y=pdfVisaTable(pdf,y,pw,o,s?.defaultROE||78);
    const sumRows=[{label:"Adult Per Pax:",val:"PKR "+fmt(o.perAdult),color:PDF_BRAND}];
    if(o.childPax>0)sumRows.push({label:"Child Per Pax:",val:"PKR "+fmt(o.perChild),color:[194,65,12]});
    if(o.infantPax>0)sumRows.push({label:"Infant Per Pax:",val:"PKR "+fmt(o.perInfant),color:[153,27,27]});
    if(!isSingle)y=checkPagePdf(pdf,y,sumRows.length*6.4+8,pw,ph);
    y=pdfSummaryBox(pdf,y,pw,sumRows);
    pdfFooterBlock(pdf,pw,ph,s);
  });
  if(s.instructions)await pdfInstructionsPage(pdf,pw,ph,s);
}
async function renderGrpPdf(pdf,d,s){
  const pw=210,ph=297,M=9;
  PDF_BRAND=hexToRgb(s.brandColor||"#1F4AA8");
  let days=n(d.days);if(!days){d.hotels?.forEach(h=>days+=n(h.ngt));days++}
  const vh=d.hotels?.filter(h=>h.name).map(liveHotel)||[];
  const vt=d.transports?.filter(t=>t.sec&&t.qty>0)||[];
  pdfPageBorder(pdf,pw,ph);
  let y=8;
  y=pdfHeader(pdf,s,pw,y);
  y=pdfTitleBar(pdf,y,pw,"UMRAH PACKAGE — GROUP");
  y=pdfIcards(pdf,y,pw,[{ico:"🧾",lbl:"Invoice #",val:d.invoiceNo||"-"},{ico:"📅",lbl:"Date",val:d.createdAt?.split("T")[0]||"-"},{ico:"👤",lbl:"Prepared By",val:fullNameOf(d.createdBy)||"-"},{ico:"💼",lbl:"Package Type",val:"Group Umrah"}]);
  if(d.heading){pdf.setFillColor(245,247,250);pdf.setDrawColor(219,226,234);pdf.setLineWidth(0.25);pdf.roundedRect(M,y,pw-2*M,7,1.5,1.5,"FD");pdf.setTextColor(...PDF_BRAND);pdf.setFont("helvetica","bold");pdf.setFontSize(8.5);pdf.text(d.heading,pw/2,y+4.6,{align:"center"});y+=7+4}
  y=pdfCinfo(pdf,y,pw,
    [{lbl:"Client:",val:d.clientName||""},{lbl:"Airline:",val:d.airline||""},{lbl:"Days:",val:String(days)}],
    [{lbl:"Travel:",val:d.travelDates||""},{lbl:"Ticket:",val:"PKR "+fmt(d.ticketPP)},{lbl:"Includes:",val:d.pkgIncludes||""}]);
  y=pdfSecHdr(pdf,y,pw,"TRAVEL DETAILS");
  if(vh.length){y=pdfSectionLabel(pdf,y,pw,"Hotels");y=pdfHotelBoxes(pdf,y,pw,vh,h=>cityLabel(h.city))}
  if(vt.length)y=pdfTransportTable(pdf,y,pw,vt);
  y=checkPagePdf(pdf,y,30,pw,ph);
  y=pdfSectionLabel(pdf,y,pw,"Pricing Per Pax");
  pdf.autoTable({startY:y,margin:{left:M,right:M},head:[["Room","DOUBLE","TRIPLE","QUAD","QUINT"]],body:[["Selling","PKR "+(d.results?.[2]?.sell||"-"),"PKR "+(d.results?.[3]?.sell||"-"),"PKR "+(d.results?.[4]?.sell||"-"),"PKR "+(d.results?.[5]?.sell||"-")]],theme:"grid",styles:{font:"helvetica",fontSize:8,cellPadding:2.4,textColor:[6,95,70],fontStyle:"bold",lineColor:[219,226,234]},headStyles:{fillColor:[238,242,249],textColor:PDF_BRAND,fontStyle:"bold"}});
  pdfFooterBlock(pdf,pw,ph,s);
  if(s.instructions)await pdfInstructionsPage(pdf,pw,ph,s);
}

/* html2canvas cannot render object-fit:cover/contain — it draws the raw image.
   Pre-bake each fitted image into a cropped data-URL (2x for crispness) so the
   PDF shows images stretched-to-fit exactly like the on-screen preview. */
function _fitImagesForCapture(root){
  root.querySelectorAll("img").forEach(img=>{
    try{
      const fit=getComputedStyle(img).objectFit;
      if((fit!=="cover"&&fit!=="contain")||!img.naturalWidth)return;
      const w=img.clientWidth||img.offsetWidth,h=img.clientHeight||img.offsetHeight;
      if(!w||!h)return;
      const sc=2,cv=document.createElement("canvas");
      cv.width=Math.max(1,Math.round(w*sc));cv.height=Math.max(1,Math.round(h*sc));
      const ctx=cv.getContext("2d");
      ctx.fillStyle="#fff";ctx.fillRect(0,0,cv.width,cv.height);
      const iw=img.naturalWidth,ih=img.naturalHeight,boxAR=w/h,imgAR=iw/ih;
      if(fit==="cover"){
        let sw,sh,sx=0,sy=0;
        if(imgAR>boxAR){sh=ih;sw=ih*boxAR;sx=(iw-sw)/2}else{sw=iw;sh=iw/boxAR;sy=(ih-sh)/2}
        ctx.drawImage(img,sx,sy,sw,sh,0,0,cv.width,cv.height);
      }else{
        let dw,dh,dx=0,dy=0;
        if(imgAR>boxAR){dw=cv.width;dh=cv.width/imgAR;dy=(cv.height-dh)/2}else{dh=cv.height;dw=cv.height*imgAR;dx=(cv.width-dw)/2}
        ctx.drawImage(img,dx,dy,dw,dh);
      }
      img.src=cv.toDataURL("image/jpeg",0.92);
      img.style.objectFit="fill";
    }catch(e){}
  });
}

window.downloadPdfNow=async function(){
  if(_isGeneratingPdf)return;
  if(!_printHTML){toast("Nothing to print","err");return}
  if(typeof window.jspdf==="undefined"||typeof window.html2canvas==="undefined"){toast("PDF engine not loaded","err");return}
  _isGeneratingPdf=true;
  toast("Generating PDF...");
  const holder=document.createElement("div");
  holder.className="pdf-capture-mode";
  holder.style.cssText="position:fixed;left:-99999px;top:0;background:#fff;z-index:-1;";
  holder.innerHTML="<div>"+_printHTML+"</div>";
  document.body.appendChild(holder);
  try{
    const imgs=Array.from(holder.querySelectorAll("img"));
    await Promise.all(imgs.map(img=>img.complete?Promise.resolve():new Promise(res=>{img.onload=img.onerror=res})));
    await new Promise(res=>setTimeout(res,60));
    _fitImagesForCapture(holder);
    const{jsPDF}=window.jspdf;
    const pdf=new jsPDF({unit:"mm",format:"a4",compress:true});
    const pages=holder.querySelectorAll(".pp");
    if(!pages.length)throw new Error("No content to export");
    for(let i=0;i<pages.length;i++){
      // Render the ACTUAL preview HTML pixel-for-pixel (same element the
      // Preview/Print/Save-as-PDF paths use) so the download always matches
      // exactly — no separately hand-drawn layout to drift out of sync.
      // scale:3 = crisp at any zoom level; JPEG 0.92 quality = ~3x faster
      // than PNG with visually identical output for this kind of content.
      const canvas=await html2canvas(pages[i],{scale:3,useCORS:true,backgroundColor:"#ffffff",logging:false,imageTimeout:0,onclone:(clonedDoc)=>{
        // Ensure fonts and colors are locked in cloned doc
        Array.from(clonedDoc.querySelectorAll('.pp *')).forEach(el=>el.style.webkitPrintColorAdjust='exact');
      }});
      const imgData=canvas.toDataURL("image/jpeg",0.92);
      const imgWmm=210,imgHmm=imgWmm*canvas.height/canvas.width;
      if(i>0)pdf.addPage();
      let xOff=0,scaleFactor;
      if(imgHmm<=297.5){
        pdf.addImage(imgData,"JPEG",0,0,imgWmm,imgHmm,undefined,"FAST");
        scaleFactor=imgWmm/pages[i].offsetWidth;
      }else{
        const scaledW=210*(297/imgHmm);
        xOff=(210-scaledW)/2;
        pdf.addImage(imgData,"JPEG",xOff,0,scaledW,297,undefined,"FAST");
        scaleFactor=scaledW/pages[i].offsetWidth;
      }
      const pageRect=pages[i].getBoundingClientRect();
      // Clickable link overlay: html2canvas only produces pixels, so anchor
      // tags (location pins, tel/website links) are invisible to it — we
      // recover click behavior with an invisible link annotation mapped to
      // each <a> element's on-screen box.
      pages[i].querySelectorAll("a[href]").forEach(a=>{
        const r=a.getBoundingClientRect();
        const lw=r.width*scaleFactor,lh=r.height*scaleFactor;
        if(lw<=0||lh<=0)return;
        const lx=xOff+(r.left-pageRect.left)*scaleFactor;
        const ly=(r.top-pageRect.top)*scaleFactor;
        pdf.link(lx,ly,lw,lh,{url:a.getAttribute("href")});
      });
      // Invisible copyable-text layer (same trick used by "searchable
      // scanned PDF" tools): places real, selectable text with render
      // mode 3 (invisible) exactly on top of every single-line text run in
      // the image, so the PDF looks identical but text can still be
      // selected/copied. Only plain Latin-1 text is covered (numbers,
      // English/Urdu-transliterated labels) — the standard PDF font can't
      // safely encode Arabic-script Urdu or emoji, so those stay
      // image-only visually (still shown correctly) but aren't copyable.
      addInvisibleTextLayer(pdf,pages[i],pageRect,scaleFactor,xOff);
    }
    pdf.save(_printFilename);
    toast("PDF downloaded!");
  }catch(e){console.error("[PDF]",e);toast("PDF error: "+e.message,"err")}
  finally{document.body.removeChild(holder);_isGeneratingPdf=false}
};

function addInvisibleTextLayer(pdf,pageEl,pageRect,scaleFactor,xOff){
  const ptPerMM=2.834645669;
  const walker=document.createTreeWalker(pageEl,NodeFilter.SHOW_TEXT,{
    acceptNode(node){
      const txt=node.nodeValue;
      if(!txt||!txt.trim())return NodeFilter.FILTER_REJECT;
      return node.parentElement?NodeFilter.FILTER_ACCEPT:NodeFilter.FILTER_REJECT;
    }
  });
  let node;
  while(node=walker.nextNode()){
    const txt=node.nodeValue;
    // Only plain Latin-1 text — skip Urdu/Arabic script and emoji so we
    // never feed the standard PDF font characters it can't encode.
    if(!/^[\t\n\r\x20-\x7E\xA0-\xFF]*$/.test(txt))continue;
    const range=document.createRange();
    range.selectNodeContents(node);
    const rects=range.getClientRects();
    if(rects.length!==1)continue; // skip wrapped multi-line runs (would duplicate text on copy)
    const r=rects[0];
    if(r.width<=0||r.height<=0)continue;
    const cs=getComputedStyle(node.parentElement);
    const fontPx=parseFloat(cs.fontSize)||8;
    const fontSizePt=fontPx*scaleFactor*ptPerMM;
    if(fontSizePt<2)continue;
    const xmm=xOff+(r.left-pageRect.left)*scaleFactor;
    const ymm=(r.bottom-pageRect.top-fontPx*0.22)*scaleFactor;
    try{
      pdf.setFont("helvetica","normal");
      pdf.setFontSize(fontSizePt);
      pdf.text(txt,xmm,ymm,{renderingMode:"invisible"});
    }catch(e){/* skip unsupported run, image layer still shows it correctly */}
  }
}

window.closePrintPreview=()=>{
  $("printOverlay").classList.remove("active");
  document.body.style.overflow="";
  _printHTML="";_isPrinting=false;
};

// Save as PDF — uses same iframe method for consistent rendering
window.doSaveAsPdf=()=>{
  toast('Opening Save as PDF — select "Save as PDF", A4 in browser dialog');
  window.doPrintNow();
};

/* ========== PAGES ========== */

function pgDash(pg){
// Show branch banner after page renders
setTimeout(()=>_showBranchBanner(),150);
const q=Object.entries(S.quotations||{});const seeAll=P("allquot","view");
/* Dashboard mein: admins sab dekhein, users sirf apne */
let my=seeAll?q:q.filter(([k,v])=>v.createdBy===S.user.u);
// Non-admin users with branch: show only their branch's data
if(S.activeBranch?.id&&!seeAll){my=my.filter(([k,v])=>!v.branchId||v.branchId===S.activeBranch.id)}
const pv=my.filter(([k,v])=>v.type==="private"),gr=my.filter(([k,v])=>v.type==="group");
const dashTitle=seeAll?"All Quotations":"My Quotations";
/* Revenue analytics */
const now=new Date(),thisM=now.getMonth(),thisY=now.getFullYear();
/* Top 5 clients */
const clientMap={};my.forEach(([k,v])=>{const cn=(v.clientName||"Unknown").trim();if(!cn||cn==="—")return;if(!clientMap[cn])clientMap[cn]=0;clientMap[cn]+=(v.totalAdult||0)});
const topClients=Object.entries(clientMap).sort((a,b)=>b[1]-a[1]).slice(0,5);
pg.innerHTML=`<div class="stats"><div class="st"><span class="icn">📋</span><h4>${dashTitle}</h4><div class="v">${my.length}</div></div><div class="st g"><span class="icn">📝</span><h4>Private</h4><div class="v">${pv.length}</div></div><div class="st o"><span class="icn">👥</span><h4>Group</h4><div class="v">${gr.length}</div></div><div class="st pu"><span class="icn">🏨</span><h4>Hotels</h4><div class="v" id="dashHotelCount">${Object.values(S.hotels).reduce((a,l)=>a+(l?.length||0),0)}</div></div></div>
<div class="g2">
<div class="cd"><div class="cd-h">🏆 Top Clients</div>${topClients.length?`<div class="top-clients">${topClients.map(([name,amt],i)=>`<div class="top-client-row"><div class="tc-rank">${i+1}</div><div class="tc-name">${_esc(name)}</div><div class="tc-amt">PKR ${fmt(amt)}</div></div>`).join("")}</div>`:`<p style="text-align:center;padding:12px;color:var(--t2);font-size:.78rem">No data yet</p>`}</div>
<div class="cd"><div class="cd-h">Quick Actions</div><div style="display:flex;flex-direction:column;gap:5px">${P("quot","add")||P("pvt","add")?`<button class="btn btn-p" onclick="editKey=null;nav('pvt')" style="width:100%;justify-content:center">New Private Package</button>`:""}${P("quot","add")||P("grp","add")?`<button class="btn btn-a" onclick="editKey=null;nav('grp')" style="width:100%;justify-content:center">New Group Package</button>`:""}${P("quot","view")?`<button class="btn btn-o" onclick="nav('quot')" style="width:100%;justify-content:center">📋 My Quotations</button>`:""}${seeAll?`<button class="btn btn-o" onclick="nav('allquot')" style="width:100%;justify-content:center">🗂 All Quotations (Admin)</button>`:""}<button class="btn btn-o" onclick="nav('dup')" style="width:100%;justify-content:center">🔁 Duplicate Finder</button></div></div></div>
<div class="cd" style="margin-top:10px"><div class="cd-h">Recent ${seeAll?"(All Users)":"(My)"}</div><div class="ql" id="dQ"></div></div>`;
/* HOTEL COUNT LIVE UPDATE: hotels background mein load hoti hain — pehle
   dashboard 0 dikha deta tha. Ab jaise hi cities ki hotels aati hain count
   khud update ho jata hai. */
(function(){const el=$("dashHotelCount");if(!el)return;
const _upd=()=>{if(document.contains(el))el.textContent=Object.values(S.hotels).reduce((a,l)=>a+(l?.length||0),0)};
_upd();
(S.cities||[]).forEach(c=>{try{(_hotelsLoading[c.key]||ensureHotelsLoaded(c.key)).then(_upd).catch(()=>{})}catch(e){}});
})();
/* Duplicate alert badges — shown briefly after render */
setTimeout(()=>{
  const hDupes=_findLiveDupes().length;
  const qDupes=_findQuotDupes().length;
  if(hDupes||qDupes){
    const alertDiv=document.createElement("div");
    alertDiv.className="dup-alert-bar";
    alertDiv.innerHTML=`⚠️ ${[hDupes?`<b>${hDupes}</b> duplicate hotel${hDupes>1?"s":""}`:null,qDupes?`<b>${qDupes}</b> duplicate quotation${qDupes>1?"s":""}`:null].filter(Boolean).join(" and ")} found — <button class="btn btn-sm" style="background:#fff;color:#92400e;border:1px solid #f59e0b;padding:3px 10px" onclick="nav('dup')">🔁 Fix Now</button>`;
    pg.insertBefore(alertDiv,pg.firstChild);
  }
},100);
const dq=$("dQ");my.slice(-6).reverse().forEach(([k,v])=>{const updNoteDash=v.updatedBy&&v.updatedBy!==v.createdBy?` • Updated by ${fullNameOf(v.updatedBy)}`:"";const ownerInfo=seeAll?` <span style="font-size:.62rem;background:#e0e7ff;color:#3730a3;padding:1px 5px;border-radius:8px">${fullNameOf(v.createdBy)||v.createdBy}</span>`:``;dq.innerHTML+=`<div class="qc"><div class="qi"><div class="qn">${_esc(v.clientName)||"—"} <span class="bd bd-${v.type==="group"?"a":"u"}">${v.type}</span>${ownerInfo}</div><div class="qm">${_esc(v.invoiceNo)||""} • ${fmtDT(v.createdAt)}${updNoteDash}</div></div><div class="qa">PKR ${fmt(v.totalAdult||0)}</div><div class="qb"><button class="btn-icon" onclick="viewQ('${k}')">👁</button><button class="btn-icon" style="color:var(--teal)" onclick="cloneQuotation('${k}')" title="Clone">📋</button></div></div>`});
if(!my.length)dq.innerHTML=`<p style="text-align:center;padding:16px;color:var(--t2)">No quotations yet</p>`}

function pgPvt(pg){const roeDef=S.settings?.defaultROE||78;pg.innerHTML=`<div class="cd"><div class="cd-h">Private Package <span id="pEditTag"></span><div style="display:flex;gap:5px;flex-wrap:wrap"><button class="btn btn-o btn-sm" id="pCancelEditBtn" onclick="cancelEdit('pvt')">Cancel</button> <button class="btn btn-o btn-sm" onclick="pPreview()">Preview</button> <button class="btn btn-sm" style="background:#25D366;color:#fff" onclick="shareWhatsAppPvt()">📱 WhatsApp</button> <button class="btn btn-sm" style="background:#7c3aed;color:#fff" onclick="printCostingPvt()">🖨 Print Costing</button> <button class="btn btn-a btn-sm" id="pSaveBtn" onclick="pSave()">Save & Print</button></div></div>
<div class="g4"><div class="fg"><label>Client Name</label><input id="pN"></div><div class="fg"><label>Contact</label><input id="pPh"></div><div class="fg"><label>Travel Dates</label><input id="pDt"></div><div class="fg"><label>Default ROE</label><input type="number" id="pROE" value="${roeDef}" oninput="triggerCalc()"></div><div class="fg gf"><label>PKG Includes</label><input id="pInc" value="FLIGHT, HOTEL, VISA, TRANSPORT"></div></div></div>
<div class="tabs" id="pTabs"><div class="tab on" onclick="pTab('A')">Option A</div><div class="tab" onclick="pTab('B')">Option B</div><div class="tab" onclick="pTab('C')">Option C</div></div><div id="pTP"></div>`;
['A','B','C'].forEach(l=>bOpt(l));pTab('A');attachAutoCalc();_syncTravelDatesFromFlights();checkDraftBanner('pvt')}

/* ===== AUTO-TRAVEL DATES FROM FLIGHT DATES =====
   Jab user flight dates enter kare, travel dates field automatically fill ho
   jaye. Format: "YYYY-MM-DD to YYYY-MM-DD" (ya single date agar sab same hon). */
function _autoTravelDatesFromFlights(){
  const dates=[];
  ['A','B','C'].forEach(L=>{
    for(let i=0;i<6;i++){
      const v=$(`fD${L}${i}`)?.value;
      if(v)dates.push(v);
    }
  });
  if(!dates.length)return "";
  dates.sort();
  const first=dates[0],last=dates[dates.length-1];
  const d1=fmtDisplayDate(first),d2=fmtDisplayDate(last);
  return d1===d2?d1:d1+" to "+d2;
}
function _syncTravelDatesFromFlights(){
  const pDt=$("pDt");
  if(!pDt||pDt.dataset.manual)return;
  const auto=_autoTravelDatesFromFlights();
  if(auto)pDt.value=auto;
}
/* Derive travel dates string from saved flights array (for print/PDF fallback) */
function _travelDatesFromSavedFlights(options){
  const dates=[];
  if(!options)return "";
  Object.values(options).forEach(o=>{
    (o.flights||[]).forEach(f=>{if(f.date)dates.push(f.date)});
  });
  if(!dates.length)return "";
  dates.sort();
  const first=dates[0],last=dates[dates.length-1];
  const d1=fmtDisplayDate(first),d2=fmtDisplayDate(last);
  return d1===d2?d1:d1+" to "+d2;
}

function attachAutoCalc(){setTimeout(()=>{document.querySelectorAll("#CT input, #CT select").forEach(el=>{if(!el.dataset.ac){el.addEventListener("input",triggerCalc);el.addEventListener("change",triggerCalc);el.dataset.ac="1"}});
/* Auto-fill Travel Dates from flight dates — jab bhi koi flight date change ho,
   pDt field auto-update ho jaye (sirf agar user ne khud manual na likha ho) */
document.querySelectorAll('input[id^="fD"]').forEach(el=>{
  if(!el.dataset.tdHook){
    el.addEventListener("change",()=>{
      const pDt=$("pDt");
      if(!pDt)return;
      if(!pDt.dataset.manual){const auto=_autoTravelDatesFromFlights();if(auto)pDt.value=auto}
    });
    el.dataset.tdHook="1";
  }
});
/* Mark pDt as manually edited if user types in it */
const _pDtEl=$("pDt");if(_pDtEl&&!_pDtEl.dataset.manHook){_pDtEl.addEventListener("input",function(){this.dataset.manual="1"});_pDtEl.dataset.manHook="1"}
/* Number inputs: clear 0 on focus so user can type directly without getting 01, 02, etc */
document.querySelectorAll('#CT input[type=number]').forEach(el=>{
  if(!el.dataset.ac){el.setAttribute('placeholder','-')}
  if(!el.dataset.zerofix){
    el.dataset.zerofix="1";
    el.addEventListener("focus",function(){if(this.value==="0"||this.value==="0.0"||this.value==="0.00")this.select()});
    el.addEventListener("keydown",function(e){
      // If value is 0 and user presses a digit, clear it first so they get clean entry
      if((this.value==="0")&&e.key>="0"&&e.key<="9"&&!e.ctrlKey&&!e.metaKey){this.value="";triggerCalc()}
    });
  }
})},100)}

window.pTab=l=>{$("pTabs").querySelectorAll(".tab").forEach((t,i)=>t.classList.toggle("on","ABC"[i]===l));document.querySelectorAll(".tab-p").forEach(p=>p.classList.toggle("on",p.dataset.opt===l))};

function bOpt(L){const roe=$("pROE")?.value||S.settings?.defaultROE||78;const infRoe=S.settings?.defaultInfantROE||77;const visaSAR=S.settings?.visaAdultSAR||560;const infVisaSAR=S.settings?.visaInfantSAR||0;
const tp=$("pTP"),d=CE("div","tab-p"+(L==="A"?" on":""));d.dataset.opt=L;
d.innerHTML=`<div class="cd"><div class="cd-h">Flight — ${L}</div><div class="tw"><table><thead><tr><th>Date</th><th>Airline</th><th>Class</th><th>Sector</th><th>Dep</th><th>Arr</th><th>Layover</th><th>Sec 2</th><th>Dep 2</th><th>Arr 2</th><th>Lug</th></tr></thead><tbody id="fBody${L}">${[0,1,2,3,4,5].map(i=>`<tr${i>1?` class="xrow" style="display:none"`:``}><td data-label="Date"><input type="date" id="fD${L}${i}"></td><td data-label="Airline"><select id="fA${L}${i}">${so(S.airlines)}</select></td><td data-label="Class"><select id="fC${L}${i}">${so(S.classes)}</select></td><td data-label="Sector"><input id="fS${L}${i}" style="width:60px" placeholder="KHI-JED"></td><td data-label="Dep"><input class="time-inp" id="fDp${L}${i}" placeholder="--:--" onblur="fmtTime(this)"></td><td data-label="Arr"><input class="time-inp" id="fAr${L}${i}" placeholder="--:--" onblur="fmtTime(this)"></td><td data-label="Layover"><select id="fLy${L}${i}"><option>DIRECT</option><option>INDIRECT</option><option>-</option></select></td><td data-label="Sec 2"><input id="fS2${L}${i}" style="width:60px"></td><td data-label="Dep 2"><input class="time-inp" id="fD2${L}${i}" placeholder="--:--" onblur="fmtTime(this)"></td><td data-label="Arr 2"><input class="time-inp" id="fA2${L}${i}" placeholder="--:--" onblur="fmtTime(this)"></td><td data-label="Lug"><input id="fL${L}${i}" style="width:50px" placeholder="Kg" onblur="fmtLug(this)"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('fBody${L}')">+ Add Flight Row</button></div>
<div class="cd"><div class="cd-h">Adult — ${L}</div><div class="g4" style="margin-bottom:6px"><div class="fg"><label>Adult PAX</label><input type="number" id="aP${L}" value="2" min="1"></div><div class="fg"><label>Category</label><input id="aCt${L}" value="-"></div><div class="fg"><label>Total Days</label><input type="number" id="dDy${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></div><div class="fg"><label>Per PAX</label><input id="aPP${L}" readonly class="ro" style="font-weight:700;color:var(--p);background:#eff6ff"></div></div>
<div class="sec-hd sec-tkt">TICKET</div><div class="tw"><table><tbody><tr class="tr-tkt"><td class="label-cell" style="width:110px"><b>TICKET PKR</b></td><td data-label="PKR"><input type="number" id="tk${L}" placeholder="PKR"></td><td class="label-cell" style="width:60px"><b>Qty</b></td><td data-label="Qty" style="width:80px"><input type="number" id="tkQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="Total" id="tkT${L}" class="ro" style="width:130px"></td></tr></tbody></table></div>
<div class="sec-hd sec-hotel">HOTELS</div><div class="tw"><table><thead><tr><th style="width:80px">City</th><th style="min-width:180px">Hotel</th><th style="width:80px">Room</th><th style="width:60px">Rate</th><th style="width:45px">Qty</th><th style="width:75px">Dist</th><th style="width:45px">Ngts</th><th style="width:60px">ROE</th><th>Total</th></tr></thead><tbody id="hBody${L}">${[0,1,2,3,4,5].map(i=>`<tr class="tr-hotel${i>1?" xrow":""}"${i>1?` style="display:none"`:""}><td class="label-cell" data-label="City"><select id="hCity${L}${i}" onchange="if(this.value==='__newcity__'){addNewCityInline(this)}else{fH('h${L}${i}','h${L}${i}d','hCity${L}${i}','hD${L}${i}')}">${cityOptionsHtml(i%2===0?"makkah":"madina")}</select></td><td data-label="Hotel">${hi(`h${L}${i}`,`hCity${L}${i}`,`hD${L}${i}`)}</td><td data-label="Room"><select id="hR${L}${i}">${so(S.rooms)}</select></td><td data-label="Rate"><input type="number" id="hRt${L}${i}"></td><td data-label="Qty"><input type="number" id="hQ${L}${i}" value="1"></td><td data-label="Dist"><input id="hD${L}${i}" readonly></td><td data-label="Ngts"><input type="number" id="hN${L}${i}"></td><td data-label="ROE"><input type="number" id="hE${L}${i}" value="${roe}"></td><td data-label="Total" id="hT${L}${i}" class="ro"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('hBody${L}')">+ Add Hotel Row</button>
<div class="sec-hd sec-visa">VISA</div><div class="tw"><table><thead><tr><th style="width:120px">Item</th><th style="width:60px">Cat</th><th style="width:70px">SAR</th><th style="width:60px">Qty</th><th style="width:55px">ROE</th><th>Total</th></tr></thead><tbody><tr class="tr-visa"><td class="label-cell"><b>UMRAH VISA</b></td><td data-label="Cat">FT</td><td data-label="SAR"><input type="number" id="vR${L}" value="${visaSAR}" oninput="this.dataset.manual='1'"></td><td data-label="Qty"><input type="number" id="vQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE"><input type="number" id="vE${L}" value="${roe}"></td><td data-label="Total" id="vT${L}" class="ro"></td></tr></tbody></table></div>
<div style="margin:4px 0 8px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px"><span style="font-size:.72rem;font-weight:700;color:var(--tealL);text-transform:uppercase;letter-spacing:.5px">➕ Additional Visa — Adult (Optional)</span></div><div class="tw"><table><thead><tr><th style="min-width:120px">Visa Type</th><th style="width:70px">SAR</th><th style="width:55px">Qty</th><th style="width:55px">ROE</th><th style="width:80px">Total</th><th style="width:30px"></th></tr></thead><tbody id="mvBody${L}"></tbody></table></div><button type="button" class="btn btn-o btn-sm add-row-btn" onclick="addManualVisaRow('${L}','mv')" style="color:var(--tealL)">🛂 Add Visa</button></div>
<div class="sec-hd sec-trans">TRANSPORT</div><div class="tw"><table><thead><tr><th style="width:30px">#</th><th style="min-width:160px">Sector / Type</th><th style="min-width:150px">Vehicle</th><th style="width:60px">Rate</th><th style="width:45px">Qty</th><th style="width:55px">ROE</th><th>Total</th></tr></thead><tbody id="tBody${L}">${[0,1,2,3,4,5].map(i=>`<tr class="tr-trans${i>1?" xrow":""}"${i>1?` style="display:none"`:""}><td class="label-cell"><b>${i+1}</b></td><td data-label="Sector">${trAcInput(`tS${L}${i}`,"","sector")}</td><td data-label="Vehicle">${trAcInput(`tV${L}${i}`,"","vehicle")}</td><td data-label="Rate"><input type="number" id="tR${L}${i}"></td><td data-label="Qty"><input type="number" id="tQ${L}${i}" value="0"></td><td data-label="ROE"><input type="number" id="tE${L}${i}" value="${roe}"></td><td data-label="Total" id="tT${L}${i}" class="ro"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('tBody${L}')">+ Add Transport Row</button>
<div class="sec-hd sec-tkt">TOTAL</div><div class="tw"><table><tbody><tr><td colspan="4" class="label-cell" style="text-align:right;color:var(--t2)">ADD/LESS PER PAX</td><td data-label="Amount"><input type="number" id="mk${L}" value="0"></td></tr><tr class="ro" style="background:var(--bg)!important;border-top:2px solid var(--p)"><td colspan="3" class="label-cell" style="font-weight:800">TOTAL ADULT</td><td class="label-cell" style="font-weight:700">PAX: <span id="aPS${L}"></span></td><td data-label="Total" id="aT${L}" style="font-weight:800;color:var(--p)"></td></tr></tbody></table></div></div>
<div class="cd"><div class="cd-h">Child W/O Bed — ${L}</div><div class="g2" style="margin-bottom:6px"><div class="fg"><label>Child PAX</label><input type="number" id="cP${L}" value="0" min="0"></div><div class="fg"><label>Per PAX</label><input id="cPP${L}" readonly class="ro" style="font-weight:700;color:var(--a);background:#fff7ed"></div></div>
<div class="sec-hd sec-hotel">CHILD HOTEL</div><div class="tw"><table><thead><tr><th style="width:80px">City</th><th style="min-width:160px">Hotel</th><th style="width:70px">Room</th><th style="width:60px">Rate</th><th style="width:40px">Qty</th><th style="width:65px">Dist</th><th style="width:40px">Ngts</th><th style="width:55px">ROE</th><th>Total</th></tr></thead><tbody id="cHBody${L}">${[0,1,2,3,4,5].map(i=>`<tr class="tr-hotel xrow" style="display:none"><td class="label-cell" data-label="City"><select id="cHCity${L}${i}" onchange="if(this.value==='__newcity__'){addNewCityInline(this)}else{fH('cH${L}${i}','cH${L}${i}d','cHCity${L}${i}','cHD${L}${i}')}">${cityOptionsHtml("makkah")}</select></td><td data-label="Hotel">${hi(`cH${L}${i}`,`cHCity${L}${i}`,`cHD${L}${i}`)}</td><td data-label="Room"><select id="cHR${L}${i}">${so(S.rooms)}</select></td><td data-label="Rate"><input type="number" id="cHRt${L}${i}"></td><td data-label="Qty"><input type="number" id="cHQ${L}${i}" value="1"></td><td data-label="Dist"><input id="cHD${L}${i}" readonly></td><td data-label="Ngts"><input type="number" id="cHN${L}${i}"></td><td data-label="ROE"><input type="number" id="cHE${L}${i}" value="${roe}"></td><td data-label="Total" id="cHT${L}${i}" class="ro"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('cHBody${L}')">+ Add Hotel Row</button>
<div style="margin:4px 0 8px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px"><span style="font-size:.72rem;font-weight:700;color:var(--a);text-transform:uppercase;letter-spacing:.5px">➕ Additional Visa — Child (Optional)</span></div><div class="tw"><table><thead><tr><th style="min-width:120px">Visa Type</th><th style="width:70px">SAR</th><th style="width:55px">Qty</th><th style="width:55px">ROE</th><th style="width:80px">Total</th><th style="width:30px"></th></tr></thead><tbody id="cmvBody${L}"></tbody></table></div><button type="button" class="btn btn-o btn-sm add-row-btn" onclick="addManualVisaRow('${L}','cmv')" style="color:var(--a)">🛂 Add Visa</button></div>
<div class="tw"><table><thead><tr><th style="width:130px">Item</th><th style="min-width:140px">Cat</th><th style="width:70px">Rate</th><th style="width:55px">Qty</th><th style="width:55px">ROE</th><th>Total</th></tr></thead><tbody><tr class="tr-visa"><td class="label-cell"><b>VISA</b></td><td data-label="Cat">FT</td><td data-label="Rate"><input type="number" id="cvR${L}" value="${visaSAR}" oninput="this.dataset.manual='1'"></td><td data-label="Qty"><input type="number" id="cvQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE"><input type="number" id="cvE${L}" value="${roe}"></td><td data-label="Total" id="cvT${L}" class="ro"></td></tr><tr class="tr-tkt"><td class="label-cell"><b>TICKET</b></td><td data-label="Cat">PKR</td><td data-label="Rate"><input type="number" id="ctk${L}"></td><td data-label="Qty"><input type="number" id="ctkQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE">-</td><td data-label="Total" id="ctkT${L}" class="ro"></td></tr><tr class="tr-trans"><td class="label-cell"><b>TRANSPORT</b></td><td data-label="Cat"><select id="cTrV${L}"><option value="AUTO">AUTO</option>${so(S.vehicles)}</select></td><td data-label="Rate"><input type="number" id="cTrR${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="Qty"><input type="number" id="cTrQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE"><input type="number" id="cTrE${L}" value="${roe}"></td><td data-label="Total" id="cTr${L}" class="ro"></td></tr><tr><td colspan="4" class="label-cell" style="text-align:right">ADD/LESS</td><td colspan="2" data-label="Amount"><input type="number" id="cMk${L}" value="0"></td></tr><tr class="ro" style="background:var(--bg)!important;border-top:2px solid var(--a)"><td colspan="3" class="label-cell" style="font-weight:800">TOTAL CHILD</td><td class="label-cell">PAX: <span id="cPS${L}"></span></td><td colspan="2" data-label="Total" id="cTot${L}" style="font-weight:800;color:var(--a)"></td></tr></tbody></table></div></div>
<div class="cd"><div class="cd-h">Infant — ${L}</div><div class="g2" style="margin-bottom:6px"><div class="fg"><label>Infant PAX</label><input type="number" id="iP${L}" value="0" min="0"></div><div class="fg"><label>Per PAX</label><input id="iPP${L}" readonly class="ro" style="font-weight:700;color:var(--er);background:#fef2f2"></div></div>
<div style="margin:4px 0 8px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px"><span style="font-size:.72rem;font-weight:700;color:var(--er);text-transform:uppercase;letter-spacing:.5px">➕ Additional Visa — Infant (Optional)</span></div><div class="tw"><table><thead><tr><th style="min-width:120px">Visa Type</th><th style="width:70px">SAR</th><th style="width:55px">Qty</th><th style="width:55px">ROE</th><th style="width:80px">Total</th><th style="width:30px"></th></tr></thead><tbody id="imvBody${L}"></tbody></table></div><button type="button" class="btn btn-o btn-sm add-row-btn" onclick="addManualVisaRow('${L}','imv')" style="color:var(--er)">🛂 Add Visa</button></div>
<div class="tw"><table><thead><tr><th style="width:130px">Item</th><th style="width:80px">Cat</th><th style="width:70px">Rate</th><th style="width:55px">Qty</th><th style="width:55px">ROE</th><th>Total</th></tr></thead><tbody><tr class="tr-visa"><td class="label-cell"><b>VISA</b></td><td data-label="Cat">FT</td><td data-label="Rate"><input type="number" id="ivR${L}" value="${infVisaSAR}"></td><td data-label="Qty"><input type="number" id="ivQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE"><input type="number" id="ivE${L}" value="${infRoe}"></td><td data-label="Total" id="ivT${L}" class="ro"></td></tr><tr class="tr-tkt"><td class="label-cell"><b>TICKET</b></td><td data-label="Cat">PKR</td><td data-label="Rate"><input type="number" id="itk${L}"></td><td data-label="Qty"><input type="number" id="itkQ${L}" placeholder="Auto" oninput="this.dataset.manual='1'"></td><td data-label="ROE">-</td><td data-label="Total" id="itkT${L}" class="ro"></td></tr><tr><td colspan="4" class="label-cell" style="text-align:right">ADD/LESS</td><td colspan="2" data-label="Amount"><input type="number" id="iMk${L}" value="0"></td></tr><tr class="ro" style="background:var(--bg)!important;border-top:2px solid var(--er)"><td colspan="3" class="label-cell" style="font-weight:800">TOTAL INFANT</td><td class="label-cell">PAX: <span id="iPS${L}"></span></td><td colspan="2" data-label="Total" id="iTot${L}" style="font-weight:800;color:var(--er)"></td></tr></tbody></table></div></div>`;tp.appendChild(d)}

window.tLk=(L,i)=>{const s=$(`tS${L}${i}`)?.value,v=$(`tV${L}${i}`)?.value;if(s&&v)$(`tR${L}${i}`).value=gtr(s,v)};

/* ===== MANUAL / ADDITIONAL VISA: custom visa types (Umrah, Dubai, etc.) =====
   grp: "mv" = Adult, "cmv" = Child, "imv" = Infant — har group ka additional
   visa SIRF apne group ke total mein shumar hota hai. */
let _mvCounter=0;
window.addManualVisaRow=function(L,grp,name,sar,qty,roe){
  /* Purane calls (L,name,sar,qty,roe) ke sath backward compatible */
  if(grp!=="mv"&&grp!=="cmv"&&grp!=="imv"){
    roe=qty;qty=sar;sar=name;name=(typeof grp==="string"&&grp!==undefined)?grp:"";grp="mv";
  }
  grp=grp||"mv";
  const tb=$(`${grp}Body${L}`);if(!tb)return;
  const idx=_mvCounter++;
  const tr=document.createElement("tr");tr.className="tr-visa mv-row";tr.id=`${grp}Row${L}_${idx}`;
  tr.innerHTML=`<td data-label="Visa Type"><input id="${grp}N${L}_${idx}" value="${_esc(name||"")}" placeholder="e.g. Umrah Visa, Dubai Visa" style="min-width:100px"></td><td data-label="SAR"><input type="number" id="${grp}R${L}_${idx}" value="${sar||""}" placeholder="0"></td><td data-label="Qty"><input type="number" id="${grp}Q${L}_${idx}" value="${qty||""}" placeholder="0"></td><td data-label="ROE"><input type="number" id="${grp}E${L}_${idx}" value="${roe||$("pROE")?.value||78}"></td><td data-label="Total" id="${grp}T${L}_${idx}" class="ro">0</td><td style="width:30px"><button type="button" class="btn-icon" style="color:var(--er);padding:2px 6px" onclick="this.closest('.mv-row').remove();triggerCalc()">×</button></td>`;
  tb.appendChild(tr);
  attachAutoCalc();
  triggerCalc();
};
function _collectManualVisas(L,grp){
  grp=grp||"mv";
  const rows=document.querySelectorAll(`#${grp}Body${L} .mv-row`);
  const visas=[];
  rows.forEach(row=>{
    const inputs=row.querySelectorAll("input");
    if(inputs.length>=4){
      const name=inputs[0].value.trim();
      const r=n(inputs[1].value);
      const q=n(inputs[2].value);
      const roe=n(inputs[3].value);
      if(name&&(r>0||q>0)){visas.push({name,r,q,roe})}
    }
  });
  return visas;
}
function _calcManualVisaTotal(L,grp){
  grp=grp||"mv";
  let total=0;
  const rows=document.querySelectorAll(`#${grp}Body${L} .mv-row`);
  rows.forEach(row=>{
    const inputs=row.querySelectorAll("input");
    if(inputs.length>=4){
      const r=n(inputs[1].value),q=n(inputs[2].value),roe=n(inputs[3].value);
      const rowTotal=r*q*roe;
      const totalCell=row.querySelector(".ro");
      if(totalCell)totalCell.textContent=fmt(rowTotal);
      total+=rowTotal;
    }
  });
  return total;
}
function _clearManualVisaTotals(L,grp){
  document.querySelectorAll(`#${grp||"mv"}Body${L} .mv-row .ro`).forEach(c=>c.textContent="");
}

window.pCalc=(silent)=>{['A','B','C'].forEach(L=>{if(!$(`aP${L}`))return;const aP=n($(`aP${L}`)?.value)||1;const vQEl=$(`vQ${L}`),tkQEl=$(`tkQ${L}`);if(vQEl&&vQEl.dataset.manual!=='1')vQEl.value=aP;if(tkQEl&&tkQEl.dataset.manual!=='1')tkQEl.value=aP;const cP=n($(`cP${L}`)?.value);if(cP>0){const cvQEl=$(`cvQ${L}`),ctkQEl=$(`ctkQ${L}`);if(cvQEl&&cvQEl.dataset.manual!=='1')cvQEl.value=cP;if(ctkQEl&&ctkQEl.dataset.manual!=='1')ctkQEl.value=cP}const iP=n($(`iP${L}`)?.value);if(iP>0){const ivQEl=$(`ivQ${L}`),itkQEl=$(`itkQ${L}`);if(ivQEl&&ivQEl.dataset.manual!=='1')ivQEl.value=iP;if(itkQEl&&itkQEl.dataset.manual!=='1')itkQEl.value=iP}
let hT=0;let totalNgt=0;for(let i=0;i<6;i++){const ngtV=n($(`hN${L}${i}`)?.value);totalNgt+=ngtV;const t=n($(`hRt${L}${i}`)?.value)*n($(`hQ${L}${i}`)?.value)*ngtV*n($(`hE${L}${i}`)?.value);if($(`hT${L}${i}`))$(`hT${L}${i}`).textContent=fmt(t);hT+=t}
const dDyEl=$(`dDy${L}`);if(dDyEl&&dDyEl.dataset.manual!=='1')dDyEl.value=totalNgt>0?totalNgt+1:"";
const vT=n($(`vR${L}`)?.value)*n($(`vQ${L}`)?.value)*n($(`vE${L}`)?.value);if($(`vT${L}`))$(`vT${L}`).textContent=fmt(vT);
const mvT=_calcManualVisaTotal(L);
let tT=0,tRateSum=0;for(let i=0;i<6;i++){const rt=n($(`tR${L}${i}`)?.value);tRateSum+=rt;const t=rt*n($(`tQ${L}${i}`)?.value)*n($(`tE${L}${i}`)?.value);if($(`tT${L}${i}`))$(`tT${L}${i}`).textContent=fmt(t);tT+=t}
const tkT=n($(`tk${L}`)?.value)*n($(`tkQ${L}`)?.value);if($(`tkT${L}`))$(`tkT${L}`).textContent=fmt(tkT);
const mk=n($(`mk${L}`)?.value),aG=hT+vT+mvT+tT+tkT+(mk*aP);if($(`aT${L}`))$(`aT${L}`).textContent="PKR "+fmt(aG);if($(`aPP${L}`))$(`aPP${L}`).value="PKR "+fmt(aG/aP);if($(`aPS${L}`))$(`aPS${L}`).textContent=aP;
const cmvT=_calcManualVisaTotal(L,'cmv');
{/* CHILD — totals hamesha dikhao (PAX 0 par bhi) taake entered data "ghayab" na ho */
const cv=n($(`cvR${L}`)?.value)*n($(`cvQ${L}`)?.value)*n($(`cvE${L}`)?.value);if($(`cvT${L}`))$(`cvT${L}`).textContent=fmt(cv);const ct=n($(`ctk${L}`)?.value)*n($(`ctkQ${L}`)?.value);if($(`ctkT${L}`))$(`ctkT${L}`).textContent=fmt(ct);
let cH=0;for(let i=0;i<6;i++){const t=n($(`cHRt${L}${i}`)?.value)*n($(`cHQ${L}${i}`)?.value)*n($(`cHN${L}${i}`)?.value)*n($(`cHE${L}${i}`)?.value);if($(`cHT${L}${i}`))$(`cHT${L}${i}`).textContent=fmt(t);cH+=t}
const cR=$(`cTrR${L}`),cQ=$(`cTrQ${L}`),cE=$(`cTrE${L}`);
let cTr=0;
if(cP>0){
if(cQ&&cQ.dataset.manual!=='1')cQ.value=cP;
if(cR&&cR.dataset.manual!=='1'){const totalPax=aP+cP;cR.value=totalPax>0?Math.round(tRateSum/totalPax):0}
const mr=n(cR?.value),mq=n(cQ?.value),me=n(cE?.value)||1;
cTr=(mr&&mq)?mr*mq*(me>10?me:1):0;
}
if($(`cTr${L}`))$(`cTr${L}`).textContent=fmt(cTr);const cm=n($(`cMk${L}`)?.value),cG=cv+ct+cTr+cH+cmvT+(cm*cP);if($(`cTot${L}`))$(`cTot${L}`).textContent="PKR "+fmt(cG);if($(`cPP${L}`))$(`cPP${L}`).value=cP>0?"PKR "+fmt(cG/cP):"";if($(`cPS${L}`))$(`cPS${L}`).textContent=cP}
const imvT=_calcManualVisaTotal(L,'imv');
{/* INFANT — totals hamesha dikhao (PAX 0 par bhi) taake entered data "ghayab" na ho */
const iv=n($(`ivR${L}`)?.value)*n($(`ivQ${L}`)?.value)*n($(`ivE${L}`)?.value);if($(`ivT${L}`))$(`ivT${L}`).textContent=fmt(iv);const it=n($(`itk${L}`)?.value)*n($(`itkQ${L}`)?.value);if($(`itkT${L}`))$(`itkT${L}`).textContent=fmt(it);const im=n($(`iMk${L}`)?.value),iG=iv+it+imvT+(im*iP);if($(`iTot${L}`))$(`iTot${L}`).textContent="PKR "+fmt(iG);if($(`iPP${L}`))$(`iPP${L}`).value=iP>0?"PKR "+fmt(iG/iP):"";if($(`iPS${L}`))$(`iPS${L}`).textContent=iP}});if(!silent)toast("Calculated!")};

window.pSave=async()=>{if(!$("pN")?.value.trim()){toast("Enter client name","warn");return}pCalc(true);
let existing=null;if(editKey){try{existing=await FR("quotations/"+editKey)}catch(e){existing=S.quotations[editKey]||null}}
const isOwn=existing&&existing.createdBy===S.user.u;
/* Edit allowed: admin allquot edit, ya apna quotation quot edit */
const isEdit=!!editKey&&!!existing&&existing.type==="private"&&(P("allquot","edit")||(isOwn&&P("quot","edit")));
/* Naya save: quot add permission chahiye */
if(!isEdit&&!P("quot","add")){toast("You don't have permission to create quotations","err");return}
const invNo=isEdit?existing.invoiceNo:await nextInvoiceNo();
const _myBr=myBranchForSave();
const data={type:"private",clientName:$("pN")?.value||"",contactNo:$("pPh")?.value||"",pkgIncludes:$("pInc")?.value||"",travelDates:$("pDt")?.value||"",createdBy:existing?existing.createdBy:S.user.u,createdAt:existing?existing.createdAt:new Date().toISOString(),updatedBy:S.user.u,updatedAt:new Date().toISOString(),invoiceNo:invNo,branchId:isEdit?(existing.branchId||_myBr.id):_myBr.id,branchName:isEdit?(existing.branchName||_myBr.name):_myBr.name,options:{}};
['A','B','C'].forEach(L=>{if(!$(`aP${L}`))return;const o={flights:[],adultPax:n($(`aP${L}`)?.value),adultCat:$(`aCt${L}`)?.value||"",days:n($(`dDy${L}`)?.value),hotels:[],visa:{},transports:[],ticketPKR:n($(`tk${L}`)?.value),ticketQty:n($(`tkQ${L}`)?.value),markup:n($(`mk${L}`)?.value),totalAdult:0,perAdult:0,childPax:n($(`cP${L}`)?.value),childVisa:{r:n($(`cvR${L}`)?.value),q:n($(`cvQ${L}`)?.value),roe:n($(`cvE${L}`)?.value)},childTicket:{pkr:n($(`ctk${L}`)?.value),q:n($(`ctkQ${L}`)?.value)},childTransport:{veh:$(`cTrV${L}`)?.value||"AUTO",rate:n($(`cTrR${L}`)?.value),qty:n($(`cTrQ${L}`)?.value),roe:n($(`cTrE${L}`)?.value)},childHotels:[],childMarkup:n($(`cMk${L}`)?.value),totalChild:0,perChild:0,infantPax:n($(`iP${L}`)?.value),infantVisa:{r:n($(`ivR${L}`)?.value),q:n($(`ivQ${L}`)?.value),roe:n($(`ivE${L}`)?.value)},infantTicket:{pkr:n($(`itk${L}`)?.value),q:n($(`itkQ${L}`)?.value)},infantMarkup:n($(`iMk${L}`)?.value),totalInfant:0,perInfant:0};
for(let i=0;i<6;i++)o.flights.push({airline:$(`fA${L}${i}`)?.value||"",cls:$(`fC${L}${i}`)?.value||"",lug:$(`fL${L}${i}`)?.value||"",date:$(`fD${L}${i}`)?.value||"",sec:$(`fS${L}${i}`)?.value||"",dep:$(`fDp${L}${i}`)?.value||"",arr:$(`fAr${L}${i}`)?.value||"",lay:$(`fLy${L}${i}`)?.value||"",sec2:$(`fS2${L}${i}`)?.value||"",dep2:$(`fD2${L}${i}`)?.value||"",arr2:$(`fA2${L}${i}`)?.value||""});
for(let i=0;i<6;i++){const hName=$(`h${L}${i}`)?.value||"",hCityV=$(`hCity${L}${i}`)?.value||"makkah";o.hotels.push({name:hName,type:$(`hR${L}${i}`)?.value||"",city:hCityV,rate:n($(`hRt${L}${i}`)?.value),qty:n($(`hQ${L}${i}`)?.value),dist:$(`hD${L}${i}`)?.value||"",ngt:n($(`hN${L}${i}`)?.value),roe:n($(`hE${L}${i}`)?.value),loc:hotelLoc(hCityV,hName),img:hotelImg(hCityV,hName)})}for(let i=0;i<6;i++){const cName=$(`cH${L}${i}`)?.value||"",cCityV=$(`cHCity${L}${i}`)?.value||"makkah";o.childHotels.push({name:cName,type:$(`cHR${L}${i}`)?.value||"",city:cCityV,rate:n($(`cHRt${L}${i}`)?.value),qty:n($(`cHQ${L}${i}`)?.value),dist:$(`cHD${L}${i}`)?.value||"",ngt:n($(`cHN${L}${i}`)?.value),roe:n($(`cHE${L}${i}`)?.value),loc:hotelLoc(cCityV,cName),img:hotelImg(cCityV,cName)})}
o.visa={r:n($(`vR${L}`)?.value),q:n($(`vQ${L}`)?.value),roe:n($(`vE${L}`)?.value)};
o.manualVisas=_collectManualVisas(L);
o.childManualVisas=_collectManualVisas(L,'cmv');
o.infantManualVisas=_collectManualVisas(L,'imv');
for(let i=0;i<6;i++)o.transports.push({sec:$(`tS${L}${i}`)?.value||"",veh:$(`tV${L}${i}`)?.value||"",rate:n($(`tR${L}${i}`)?.value),qty:n($(`tQ${L}${i}`)?.value),roe:n($(`tE${L}${i}`)?.value)});
let hT=0;o.hotels.forEach(h=>hT+=h.rate*h.qty*h.ngt*h.roe);const vT=o.visa.r*o.visa.q*o.visa.roe;const mvT=(o.manualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);let tT=0;o.transports.forEach(t=>tT+=t.rate*t.qty*t.roe);const tkT=o.ticketPKR*o.ticketQty;o.totalAdult=hT+vT+mvT+tT+tkT+(o.markup*o.adultPax);o.perAdult=o.adultPax?o.totalAdult/o.adultPax:0;
if(o.childPax>0){const cv=o.childVisa.r*o.childVisa.q*o.childVisa.roe,ct=o.childTicket.pkr*o.childTicket.q;let cTr=0;if(o.childTransport.rate&&o.childTransport.qty){cTr=o.childTransport.rate*o.childTransport.qty*(o.childTransport.roe>10?o.childTransport.roe:1)}else{cTr=(o.adultPax+o.childPax)>0?Math.round(tT/(o.adultPax+o.childPax))*o.childPax:0}let cH=0;o.childHotels.forEach(h=>cH+=h.rate*h.qty*h.ngt*h.roe);const cmvT=(o.childManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalChild=cv+ct+cTr+cH+cmvT+(o.childMarkup*o.childPax);o.perChild=o.totalChild/o.childPax}
if(o.infantPax>0){const iv=o.infantVisa.r*o.infantVisa.q*o.infantVisa.roe,it=o.infantTicket.pkr*o.infantTicket.q;const imvT=(o.infantManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalInfant=iv+it+imvT+(o.infantMarkup*o.infantPax);o.perInfant=o.totalInfant/o.infantPax}
/* PHANTOM OPTION FIX: default auto-fill visa (SAR=settings, Qty=PAX — user ne
   kabhi touch hi nahi kiya) wale khali options ko "data" na mano. Pehle Option
   B/C sirf default visa ki wajah se result sheet mein aa jate the aur visa
   counts ghalat (6 wagairah) dikhte the. */
const _vQEl=$(`vQ${L}`),_vREl=$(`vR${L}`),_defVS=S.settings?.visaAdultSAR||560;
/* Adult visa ko real data mano agar: user ne Qty/SAR touch kiya, ya SAR default
   se alag hai, ya PAX hi change kiya hai (default 2 se) — warna yeh sirf
   auto-filled default hai (khali Option B/C phantom) */
const _visaReal=(o.visa.r>0&&o.visa.q>0)&&((_vQEl&&_vQEl.dataset.manual==='1')||(_vREl&&_vREl.dataset.manual==='1')||o.visa.r!==_defVS||o.adultPax!==2);
/* Child PAX default 0 hai — 0 se zyada matlab user ne khud daala, real data hai */
const _childReal=o.childPax>0;
const _hasFlights=o.flights.some(f=>f.airline&&f.airline!=="-"&&f.sec);
const hasData=_hasFlights||o.hotels.some(h=>h.name)||o.ticketPKR>0||o.transports.some(t=>t.sec&&t.qty>0)||_visaReal||_childReal||(o.manualVisas&&o.manualVisas.length>0)||(o.childManualVisas&&o.childManualVisas.length>0)||(o.infantManualVisas&&o.infantManualVisas.length>0)||(o.infantPax>0&&(o.infantVisa.r>0||o.infantTicket.pkr>0));if(hasData)data.options[L]=o});
if(!Object.keys(data.options).length){toast("No option data — please add at least one flight/hotel/transport/visa","warn");return}
if(!data.clientName?.trim()){toast("Client name is required — please enter a name before saving","warn");return}
data.totalAdult=Object.values(data.options)[0]?.perAdult||0;
const _write=async()=>{try{
if(isEdit){await bFS("quotations/"+editKey,data);S.quotations[editKey]=data;toast("Updated! "+data.invoiceNo);printPvt(data)}
else{const k=await bFP("quotations",data);S.quotations[k]=data;editKey=k;toast("Saved! "+data.invoiceNo);printPvt(data)}
clearDraft("pvt");
const tag=$("pEditTag");if(tag)tag.innerHTML=`<span class="bd bd-a" style="margin-left:8px">Editing ${data.invoiceNo||""}</span>`;
const cb=$("pCancelEditBtn");if(cb)cb.style.display="";
const sb=$("pSaveBtn");if(sb)sb.textContent="Update & Print";
}catch(e){toast("Error: "+e.message,"err")}};
if(isEdit&&_quoteConflict(existing)){confirmModal("⚠️ This quotation was updated by <b>"+(existing.updatedBy||"another user")+"</b> after you opened it for editing. Overwrite their changes?",()=>_write(),"Overwrite","btn-o");return}
if(!isEdit){confirmModal("Save this private quotation?",()=>{_write()},"Yes, Save","btn-p");return}
await _write();};

window.pPreview=()=>{
if(!$("pN")?.value.trim()){toast("Enter client name","warn");return}
pCalc(true);
const existingNo=editKey&&S.quotations[editKey]?S.quotations[editKey].invoiceNo:"DRAFT";
const data={type:"private",clientName:$("pN")?.value||"",contactNo:$("pPh")?.value||"",pkgIncludes:$("pInc")?.value||"",travelDates:$("pDt")?.value||"",createdBy:S.user.u,createdAt:new Date().toISOString(),invoiceNo:existingNo,options:{}};
['A','B','C'].forEach(L=>{if(!$(`aP${L}`))return;const o={flights:[],adultPax:n($(`aP${L}`)?.value),adultCat:$(`aCt${L}`)?.value||"",days:n($(`dDy${L}`)?.value),hotels:[],visa:{},transports:[],ticketPKR:n($(`tk${L}`)?.value),ticketQty:n($(`tkQ${L}`)?.value),markup:n($(`mk${L}`)?.value),totalAdult:0,perAdult:0,childPax:n($(`cP${L}`)?.value),childVisa:{r:n($(`cvR${L}`)?.value),q:n($(`cvQ${L}`)?.value),roe:n($(`cvE${L}`)?.value)},childTicket:{pkr:n($(`ctk${L}`)?.value),q:n($(`ctkQ${L}`)?.value)},childTransport:{veh:$(`cTrV${L}`)?.value||"AUTO",rate:n($(`cTrR${L}`)?.value),qty:n($(`cTrQ${L}`)?.value),roe:n($(`cTrE${L}`)?.value)},childHotels:[],childMarkup:n($(`cMk${L}`)?.value),totalChild:0,perChild:0,infantPax:n($(`iP${L}`)?.value),infantVisa:{r:n($(`ivR${L}`)?.value),q:n($(`ivQ${L}`)?.value),roe:n($(`ivE${L}`)?.value)},infantTicket:{pkr:n($(`itk${L}`)?.value),q:n($(`itkQ${L}`)?.value)},infantMarkup:n($(`iMk${L}`)?.value),totalInfant:0,perInfant:0};
for(let i=0;i<6;i++)o.flights.push({airline:$(`fA${L}${i}`)?.value||"",cls:$(`fC${L}${i}`)?.value||"",lug:$(`fL${L}${i}`)?.value||"",date:$(`fD${L}${i}`)?.value||"",sec:$(`fS${L}${i}`)?.value||"",dep:$(`fDp${L}${i}`)?.value||"",arr:$(`fAr${L}${i}`)?.value||"",lay:$(`fLy${L}${i}`)?.value||"",sec2:$(`fS2${L}${i}`)?.value||"",dep2:$(`fD2${L}${i}`)?.value||"",arr2:$(`fA2${L}${i}`)?.value||""});
for(let i=0;i<6;i++){const hName=$(`h${L}${i}`)?.value||"",hCityV=$(`hCity${L}${i}`)?.value||"makkah";o.hotels.push({name:hName,type:$(`hR${L}${i}`)?.value||"",city:hCityV,rate:n($(`hRt${L}${i}`)?.value),qty:n($(`hQ${L}${i}`)?.value),dist:$(`hD${L}${i}`)?.value||"",ngt:n($(`hN${L}${i}`)?.value),roe:n($(`hE${L}${i}`)?.value),loc:hotelLoc(hCityV,hName),img:hotelImg(hCityV,hName)})}for(let i=0;i<6;i++){const cName=$(`cH${L}${i}`)?.value||"",cCityV=$(`cHCity${L}${i}`)?.value||"makkah";o.childHotels.push({name:cName,type:$(`cHR${L}${i}`)?.value||"",city:cCityV,rate:n($(`cHRt${L}${i}`)?.value),qty:n($(`cHQ${L}${i}`)?.value),dist:$(`cHD${L}${i}`)?.value||"",ngt:n($(`cHN${L}${i}`)?.value),roe:n($(`cHE${L}${i}`)?.value),loc:hotelLoc(cCityV,cName),img:hotelImg(cCityV,cName)})}
o.visa={r:n($(`vR${L}`)?.value),q:n($(`vQ${L}`)?.value),roe:n($(`vE${L}`)?.value)};
o.manualVisas=_collectManualVisas(L);
o.childManualVisas=_collectManualVisas(L,'cmv');
o.infantManualVisas=_collectManualVisas(L,'imv');
for(let i=0;i<6;i++)o.transports.push({sec:$(`tS${L}${i}`)?.value||"",veh:$(`tV${L}${i}`)?.value||"",rate:n($(`tR${L}${i}`)?.value),qty:n($(`tQ${L}${i}`)?.value),roe:n($(`tE${L}${i}`)?.value)});
let hT=0;o.hotels.forEach(h=>hT+=h.rate*h.qty*h.ngt*h.roe);const vT=o.visa.r*o.visa.q*o.visa.roe;const mvT=(o.manualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);let tT=0;o.transports.forEach(t=>tT+=t.rate*t.qty*t.roe);const tkT=o.ticketPKR*o.ticketQty;o.totalAdult=hT+vT+mvT+tT+tkT+(o.markup*o.adultPax);o.perAdult=o.adultPax?o.totalAdult/o.adultPax:0;
if(o.childPax>0){const cv=o.childVisa.r*o.childVisa.q*o.childVisa.roe,ct=o.childTicket.pkr*o.childTicket.q;let cTr=0;if(o.childTransport.rate&&o.childTransport.qty){cTr=o.childTransport.rate*o.childTransport.qty*(o.childTransport.roe>10?o.childTransport.roe:1)}else{cTr=(o.adultPax+o.childPax)>0?Math.round(tT/(o.adultPax+o.childPax))*o.childPax:0}let cH=0;o.childHotels.forEach(h=>cH+=h.rate*h.qty*h.ngt*h.roe);const cmvT=(o.childManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalChild=cv+ct+cTr+cH+cmvT+(o.childMarkup*o.childPax);o.perChild=o.totalChild/o.childPax}
if(o.infantPax>0){const iv=o.infantVisa.r*o.infantVisa.q*o.infantVisa.roe,it=o.infantTicket.pkr*o.infantTicket.q;const imvT=(o.infantManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalInfant=iv+it+imvT+(o.infantMarkup*o.infantPax);o.perInfant=o.totalInfant/o.infantPax}
/* PHANTOM OPTION FIX: default auto-fill visa (SAR=settings, Qty=PAX — user ne
   kabhi touch hi nahi kiya) wale khali options ko "data" na mano. Pehle Option
   B/C sirf default visa ki wajah se result sheet mein aa jate the aur visa
   counts ghalat (6 wagairah) dikhte the. */
const _vQEl=$(`vQ${L}`),_vREl=$(`vR${L}`),_defVS=S.settings?.visaAdultSAR||560;
/* Adult visa ko real data mano agar: user ne Qty/SAR touch kiya, ya SAR default
   se alag hai, ya PAX hi change kiya hai (default 2 se) — warna yeh sirf
   auto-filled default hai (khali Option B/C phantom) */
const _visaReal=(o.visa.r>0&&o.visa.q>0)&&((_vQEl&&_vQEl.dataset.manual==='1')||(_vREl&&_vREl.dataset.manual==='1')||o.visa.r!==_defVS||o.adultPax!==2);
/* Child PAX default 0 hai — 0 se zyada matlab user ne khud daala, real data hai */
const _childReal=o.childPax>0;
const _hasFlights=o.flights.some(f=>f.airline&&f.airline!=="-"&&f.sec);
const hasData=_hasFlights||o.hotels.some(h=>h.name)||o.ticketPKR>0||o.transports.some(t=>t.sec&&t.qty>0)||_visaReal||_childReal||(o.manualVisas&&o.manualVisas.length>0)||(o.childManualVisas&&o.childManualVisas.length>0)||(o.infantManualVisas&&o.infantManualVisas.length>0)||(o.infantPax>0&&(o.infantVisa.r>0||o.infantTicket.pkr>0));if(hasData)data.options[L]=o});
if(!Object.keys(data.options).length){toast("No option data","warn");return}
data.totalAdult=Object.values(data.options)[0]?.perAdult||0;
printPvt(data);
};

function pgGrp(pg){pg.innerHTML=`<div class="cd"><div class="cd-h">Group Package <span id="gEditTag"></span><div style="display:flex;gap:5px;flex-wrap:wrap"><button class="btn btn-o btn-sm" id="gCancelEditBtn" onclick="cancelEdit('grp')">Cancel</button> <button class="btn btn-o btn-sm" onclick="gPreview()">Preview</button> <button class="btn btn-sm" style="background:#25D366;color:#fff" onclick="shareWhatsAppGrp()">📱 WhatsApp</button> <button class="btn btn-sm" style="background:#7c3aed;color:#fff" onclick="printCostingGrp()">🖨 Print Costing</button> <button class="btn btn-a btn-sm" id="gSaveBtn" onclick="gSave()">Save & Print</button></div></div><div class="g3"><div class="fg"><label>Client</label><input id="gN"></div><div class="fg"><label>PKG Includes</label><input id="gInc" value="FLIGHT, HOTEL, VISA, TRANSPORT"></div><div class="fg"><label>Travel Dates</label><input id="gDt"></div><div class="fg gf"><label>Heading</label><input id="gHd"></div><div class="fg"><label>Airline</label><select id="gAir">${so(S.airlines)}</select></div><div class="fg"><label>Ticket/Person PKR</label><input type="number" id="gTk" value="0"></div><div class="fg"><label>Total Days</label><input type="number" id="gDays" placeholder="Auto" oninput="this.dataset.manual='1'"></div></div></div>
<div class="cd"><div class="sec-hd sec-hotel">HOTELS</div><div class="tw"><table><thead><tr><th style="width:80px">City</th><th style="min-width:180px">Hotel</th><th style="width:80px">Cat</th><th style="width:60px">Rate</th><th style="width:45px">Qty</th><th style="width:75px">Dist</th><th style="width:45px">Ngts</th><th style="width:60px">ROE</th><th>Total</th></tr></thead><tbody id="gHBody">${[0,1,2,3,4,5].map(i=>`<tr class="tr-hotel${i>1?" xrow":""}"${i>1?` style="display:none"`:""}><td class="label-cell" data-label="City"><select id="gHCity${i}" onchange="if(this.value==='__newcity__'){addNewCityInline(this)}else{fH('gH${i}','gH${i}d','gHCity${i}','gHD${i}')}">${cityOptionsHtml(i%2===0?"makkah":"madina")}</select></td><td data-label="Hotel">${hi(`gH${i}`,`gHCity${i}`,`gHD${i}`)}</td><td data-label="Cat"><select id="gHC${i}">${so(S.rooms)}</select></td><td data-label="Rate"><input type="number" id="gHR${i}"></td><td data-label="Qty"><input type="number" id="gHQ${i}" value="${i<2?1:0}"></td><td data-label="Dist"><input id="gHD${i}" readonly></td><td data-label="Ngts"><input type="number" id="gHN${i}"></td><td data-label="ROE"><input type="number" id="gHE${i}" value="77"></td><td data-label="Total" id="gHT${i}" class="ro"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('gHBody')">+ Add Hotel Row</button>
<div class="sec-hd sec-visa">VISA</div><div class="g4" style="margin-bottom:6px"><div class="fg"><label>Visa SAR</label><input type="number" id="gVR" value="560"></div><div class="fg"><label>Qty</label><input type="number" id="gVQ" value="5"></div><div class="fg"><label>ROE</label><input type="number" id="gVE" value="77"></div><div class="fg"><label>Per Person</label><input id="gVPP" readonly class="ro"></div></div>
<div class="sec-hd sec-trans">TRANSPORT</div><div class="tw"><table><thead><tr><th style="min-width:160px">Sector / Type</th><th style="min-width:150px">Vehicle</th><th style="width:60px">Rate</th><th style="width:45px">Qty</th><th style="width:50px">ROE</th><th>Total</th></tr></thead><tbody id="gTBody">${[0,1,2,3,4,5].map(i=>`<tr class="tr-trans${i>1?" xrow":""}"${i>1?` style="display:none"`:""}><td data-label="Sector">${trAcInput(`gTS${i}`,"","sector")}</td><td data-label="Vehicle">${trAcInput(`gTV${i}`,"","vehicle")}</td><td data-label="Rate"><input type="number" id="gTR${i}"></td><td data-label="Qty"><input type="number" id="gTQ${i}" value="0"></td><td data-label="ROE"><input type="number" id="gTE${i}" value="77"></td><td data-label="Total" id="gTT${i}" class="ro"></td></tr>`).join("")}</tbody></table></div><button class="btn btn-o btn-sm add-row-btn" onclick="addTblRow('gTBody')">+ Add Transport Row</button></div>
<div class="cd"><div class="cd-h">Profit/Person</div><div class="g4"><div class="fg"><label>Quint(5)</label><input type="number" id="gPQ" value="15000"></div><div class="fg"><label>Quad(4)</label><input type="number" id="gPQd" value="15000"></div><div class="fg"><label>Triple(3)</label><input type="number" id="gPT" value="15000"></div><div class="fg"><label>Double(2)</label><input type="number" id="gPD" value="15000"></div></div></div>
<div class="cd" id="gRes"><div class="cd-h">Results</div><div class="tw"><table><thead><tr><th></th><th>QUINT</th><th>QUAD</th><th>TRIPLE</th><th>DOUBLE</th></tr></thead><tbody><tr><td class="label-cell">Total</td><td data-label="QUINT" id="gR5">0</td><td data-label="QUAD" id="gR4">0</td><td data-label="TRIPLE" id="gR3">0</td><td data-label="DOUBLE" id="gR2">0</td></tr><tr><td class="label-cell">Net/Person</td><td data-label="QUINT" id="gN5">0</td><td data-label="QUAD" id="gN4">0</td><td data-label="TRIPLE" id="gN3">0</td><td data-label="DOUBLE" id="gN2">0</td></tr><tr><td class="label-cell">Profit</td><td data-label="QUINT" id="gP5">0</td><td data-label="QUAD" id="gP4">0</td><td data-label="TRIPLE" id="gP3">0</td><td data-label="DOUBLE" id="gP2">0</td></tr><tr class="ro" style="background:var(--bg)!important;border-top:2px solid var(--ok)"><td class="label-cell"><b>SELLING</b></td><td data-label="QUINT" id="gS5">0</td><td data-label="QUAD" id="gS4">0</td><td data-label="TRIPLE" id="gS3">0</td><td data-label="DOUBLE" id="gS2">0</td></tr></tbody></table></div></div>`;attachAutoCalc();checkDraftBanner('grp')}

window.gTL=i=>{const s=$(`gTS${i}`)?.value,v=$(`gTV${i}`)?.value;if(s&&v){const r=gtr(s,v);if(r)$(`gTR${i}`).value=r}};
window.gCalc=(silent)=>{if(!$("gR5"))return;let hT=0;let totalNgt=0;for(let i=0;i<6;i++){const ngtV=n($(`gHN${i}`)?.value);totalNgt+=ngtV;const t=n($(`gHR${i}`)?.value)*n($(`gHQ${i}`)?.value)*ngtV*n($(`gHE${i}`)?.value);if($(`gHT${i}`))$(`gHT${i}`).textContent=fmt(t);hT+=t}const gDaysEl=$("gDays");if(gDaysEl&&gDaysEl.dataset.manual!=='1')gDaysEl.value=totalNgt>0?totalNgt+1:"";const vPP=n($("gVR")?.value)*n($("gVE")?.value);if($("gVPP"))$("gVPP").value=fmt(vPP);const tkPP=n($("gTk")?.value);let fixedT=0,otherT=0;for(let i=0;i<6;i++){const sec=($(`gTS${i}`)?.value||"").toUpperCase();const t=n($(`gTR${i}`)?.value)*n($(`gTQ${i}`)?.value)*n($(`gTE${i}`)?.value);if($(`gTT${i}`))$(`gTT${i}`).textContent=fmt(t);if(sec.includes("JED")&&sec.includes("MAK")&&!sec.includes("MED")){fixedT+=t}else{otherT+=t}}[5,4,3,2].forEach(c=>{const tot=hT+fixedT+(otherT*c)+(tkPP*c)+(vPP*c),net=tot/c,pr=n($(`gP${c===5?"Q":c===4?"Qd":c===3?"T":"D"}`)?.value);if($(`gR${c}`))$(`gR${c}`).textContent=fmt(tot);if($(`gN${c}`))$(`gN${c}`).textContent=fmt(net);if($(`gP${c}`))$(`gP${c}`).textContent=fmt(pr);if($(`gS${c}`))$(`gS${c}`).textContent=fmt(net+pr)});if(!silent)toast("Calculated!")};

window.gSave=async()=>{if(!$("gN")?.value.trim()){toast("Enter name","warn");return}gCalc(true);
let existing=null;if(editKey){try{existing=await FR("quotations/"+editKey)}catch(e){existing=S.quotations[editKey]||null}}
const isOwn=existing&&existing.createdBy===S.user.u;
/* Edit allowed: admin allquot edit, ya apna quotation quot edit */
const isEdit=!!editKey&&!!existing&&existing.type==="group"&&(P("allquot","edit")||(isOwn&&P("quot","edit")));
/* Naya save: quot add permission chahiye */
if(!isEdit&&!P("quot","add")){toast("You don't have permission to create quotations","err");return}
const invNo=isEdit?existing.invoiceNo:await nextInvoiceNo();
const _myBrG=myBranchForSave();
const d={type:"group",clientName:$("gN")?.value||"",pkgIncludes:$("gInc")?.value||"",travelDates:$("gDt")?.value||"",heading:$("gHd")?.value||"",airline:$("gAir")?.value||"",ticketPP:n($("gTk")?.value),days:n($("gDays")?.value),createdBy:existing?existing.createdBy:S.user.u,createdAt:existing?existing.createdAt:new Date().toISOString(),updatedBy:S.user.u,updatedAt:new Date().toISOString(),invoiceNo:invNo,branchId:isEdit?(existing.branchId||_myBrG.id):_myBrG.id,branchName:isEdit?(existing.branchName||_myBrG.name):_myBrG.name,hotels:[],visa:{r:n($("gVR")?.value),q:n($("gVQ")?.value),roe:n($("gVE")?.value)},transports:[],results:{},profit:{Q:n($("gPQ")?.value),Qd:n($("gPQd")?.value),T:n($("gPT")?.value),D:n($("gPD")?.value)}};for(let i=0;i<6;i++){const hName=$(`gH${i}`)?.value||"",hCityV=$(`gHCity${i}`)?.value||"makkah";d.hotels.push({name:hName,cat:$(`gHC${i}`)?.value||"",city:hCityV,rate:n($(`gHR${i}`)?.value),qty:n($(`gHQ${i}`)?.value),dist:$(`gHD${i}`)?.value||"",ngt:n($(`gHN${i}`)?.value),roe:n($(`gHE${i}`)?.value),loc:hotelLoc(hCityV,hName),img:hotelImg(hCityV,hName)})}for(let i=0;i<6;i++)d.transports.push({sec:$(`gTS${i}`)?.value||"",veh:$(`gTV${i}`)?.value||"",rate:n($(`gTR${i}`)?.value),qty:n($(`gTQ${i}`)?.value),roe:n($(`gTE${i}`)?.value)});[5,4,3,2].forEach(c=>d.results[c]={sell:$(`gS${c}`)?.textContent});d.totalAdult=n($("gS4")?.textContent?.replace(/,/g,""))||0;
const _write=async()=>{try{
if(isEdit){await bFS("quotations/"+editKey,d);S.quotations[editKey]=d;toast("Updated! "+d.invoiceNo);printGrp(d)}
else{const k=await bFP("quotations",d);S.quotations[k]=d;editKey=k;toast("Saved! "+d.invoiceNo);printGrp(d)}
clearDraft("grp");
const tag=$("gEditTag");if(tag)tag.innerHTML=`<span class="bd bd-a" style="margin-left:8px">Editing ${d.invoiceNo||""}</span>`;
const cb=$("gCancelEditBtn");if(cb)cb.style.display="";
const sb=$("gSaveBtn");if(sb)sb.textContent="Update & Print";
}catch(e){toast("Error: "+e.message,"err")}};
if(isEdit&&_quoteConflict(existing)){confirmModal("⚠️ This quotation was updated by <b>"+(existing.updatedBy||"another user")+"</b> after you opened it for editing. Overwrite their changes?",()=>_write(),"Overwrite","btn-o");return}
if(!isEdit){confirmModal("Save this group quotation?",()=>{_write()},"Yes, Save","btn-p");return}
await _write();};

window.gPreview=()=>{
if(!$("gN")?.value.trim()){toast("Enter name","warn");return}
gCalc(true);
const existingNo=editKey&&S.quotations[editKey]?S.quotations[editKey].invoiceNo:"DRAFT";
const d={type:"group",clientName:$("gN")?.value||"",pkgIncludes:$("gInc")?.value||"",travelDates:$("gDt")?.value||"",heading:$("gHd")?.value||"",airline:$("gAir")?.value||"",ticketPP:n($("gTk")?.value),days:n($("gDays")?.value),createdBy:S.user.u,createdAt:new Date().toISOString(),invoiceNo:existingNo,hotels:[],visa:{r:n($("gVR")?.value),q:n($("gVQ")?.value),roe:n($("gVE")?.value)},transports:[],results:{},profit:{Q:n($("gPQ")?.value),Qd:n($("gPQd")?.value),T:n($("gPT")?.value),D:n($("gPD")?.value)}};
for(let i=0;i<6;i++){const hName=$(`gH${i}`)?.value||"",hCityV=$(`gHCity${i}`)?.value||"makkah";d.hotels.push({name:hName,cat:$(`gHC${i}`)?.value||"",city:hCityV,rate:n($(`gHR${i}`)?.value),qty:n($(`gHQ${i}`)?.value),dist:$(`gHD${i}`)?.value||"",ngt:n($(`gHN${i}`)?.value),roe:n($(`gHE${i}`)?.value),loc:hotelLoc(hCityV,hName),img:hotelImg(hCityV,hName)})}
for(let i=0;i<6;i++)d.transports.push({sec:$(`gTS${i}`)?.value||"",veh:$(`gTV${i}`)?.value||"",rate:n($(`gTR${i}`)?.value),qty:n($(`gTQ${i}`)?.value),roe:n($(`gTE${i}`)?.value)});
[5,4,3,2].forEach(c=>d.results[c]={sell:$(`gS${c}`)?.textContent});
d.totalAdult=n($("gS4")?.textContent?.replace(/,/g,""))||0;
printGrp(d);
};

function pgQuot(pg){if(!P("quot","view"))return pg.innerHTML=`<div class="cd"><div class="cd-h">My Quotations</div><p style="padding:20px;color:var(--t2);text-align:center">Access not allowed</p></div>`;
const canAdd=P("quot","add");
pg.innerHTML=`<div class="cd"><div class="cd-h">My Quotations <div style="display:flex;gap:6px;flex-wrap:wrap">${canAdd?`<button class="btn btn-sm btn-p" onclick="editKey=null;nav('pvt')">+ Private</button><button class="btn btn-sm btn-a" onclick="editKey=null;nav('grp')">+ Group</button>`:""}<button class="btn btn-sm btn-o" onclick="rQL()">Refresh</button><button class="btn btn-sm btn-g" onclick="exportQuotCSV(v=>v.createdBy===S.user.u,'My_Quotations')">⬇ Export</button></div></div><div class="ql" id="qL"><p style="text-align:center;padding:20px;color:var(--t2)">⏳ Loading quotations...</p></div></div>`;rQLCore()}
/* BUG FIX: pehle is function ka naam bhi rQL tha aur neeche window.rQL wrapper
   se overwrite ho jata tha — har call infinite recursion mein ja kar
   "Maximum call stack size exceeded" deti thi aur list hamesha "Loading" rehti.
   Ab core function ka naam rQLCore hai, wrapper alag hai. */
async function rQLCore(){const l=$("qL");
/* SPEED: agar quotations pehle se memory mein hon (boot/loadData se) to FORAN
   dikha do — 5MB fetch ka intezar nahi. Fetch background mein update karti hai. */
const _render=()=>{if(!l)return;l.innerHTML="";
/* My Quotations — sirf apne hi quotations dikhain */
let en=Object.entries(S.quotations);
let fl=en.filter(([k,v])=>v&&v.createdBy===S.user.u);
/* Branch filter removed: My Quotations mein apne SAARE quotations dikhne chahiye,
   chahe kisi bhi branch ke hon — warna branch change hone par quotations
   "ghayab" ho jate hain. Branch badge already har quotation pe dikhai deta hai. */
console.log("[rQL] Filter:",fl.length,"of",en.length,"quotations belong to",S.user.u);
if(!fl.length){const otherUsers=en.filter(([k,v])=>v&&v.createdBy!==S.user.u);l.innerHTML=`<p style="text-align:center;padding:20px;color:var(--t2)">No quotations found for <b>${_esc(S.user.u)}</b>.</p><p style="text-align:center;font-size:.72rem;color:var(--t2)">Total in system: ${en.length} quotation(s)${otherUsers.length?" ("+otherUsers.length+" by other users — check All Quotations)":""}</p><div style="text-align:center;margin-top:10px"><button class="btn btn-sm btn-o" onclick="rQL()">🔄 Retry Loading</button></div>`;return}
fl.reverse().forEach(([k,v])=>{const updNote=v.updatedBy&&v.updatedBy!==v.createdBy?` <span style="color:var(--t2);font-size:.62rem">• Updated by ${fullNameOf(v.updatedBy)}</span>`:"";const isGrp=v.type==="group";
const branchBadge=v.branchName?` <span style="font-size:.63rem;background:#d1fae5;color:#065f46;padding:1px 5px;border-radius:8px;font-weight:600">🏢 ${_esc(v.branchName)}</span>`:"";
/* My Quotations mein: sirf apne edit/delete kar sakte hain — quot permissions se */
const canEdit=P("quot","edit");
const canDel=P("quot","delete");
l.innerHTML+=`<div class="qc"><div class="qi"><div class="qn">${_esc(v.clientName)||"—"} <span class="bd bd-${isGrp?"a":"u"}">${v.type}</span>${branchBadge}</div><div class="qm">${_esc(v.invoiceNo)||""} • ${fmtDT(v.createdAt)}${updNote}</div></div><div class="qa">PKR ${fmt(v.totalAdult||0)}</div><div class="qb"><button class="btn-icon" onclick="viewQ('${k}')">👁</button><button class="btn-icon" style="color:#25D366" onclick="shareWhatsAppFromList('${k}')" title="Share to WhatsApp">📱</button><button class="btn-icon" style="color:var(--teal)" onclick="cloneQuotation('${k}')" title="Clone">📋</button>${canEdit?`<button class="btn-icon" style="color:var(--p)" onclick="editQOwn('${k}')">✏</button>`:""}${canDel?`<button class="btn-icon" style="color:var(--er)" onclick="delQOwn('${k}')">🗑</button>`:""}</div></div>`})};
const _hadData=S.quotations&&Object.keys(S.quotations).length>0;
if(_hadData)_render();else if(l)l.innerHTML=`<p style="text-align:center;padding:20px;color:var(--t2)">⏳ Loading quotations...</p>`;
try{const fetched=await wt(sbRpc("db_read",{p:"quotations"}),30000);if(fetched&&typeof fetched==="object")S.quotations=fetched;else if(!fetched)S.quotations={};console.log("[rQL] Fetched",Object.keys(S.quotations).length,"quotations")}catch(e){console.warn("[rQL] Fetch failed:",e.message);if(!(S.quotations&&Object.keys(S.quotations).length))toast("Could not load quotations: "+e.message+" — showing cached data","err")}
_render()}
window.rQL=async()=>{await rQLCore();toast("Refreshed")};
/* My Quotations ke liye alag edit/delete — sirf apne quotations pe kaam karta hai */
window.editQOwn=k=>{const q=S.quotations[k];if(!q)return;if(q.createdBy!==S.user.u){toast("You can only edit your own quotations","err");return}if(!P("quot","edit")){toast("You don't have edit permission","err");return}if(q.type==="group"){nav("grp");editKey=k;_quoteOpenedTs=Date.now();loadGrpForm(q)}else{nav("pvt");editKey=k;_quoteOpenedTs=Date.now();loadPvtForm(q)}};
window.delQOwn=async k=>{const v=S.quotations[k];if(!v){toast("Quotation not found","err");return}if(v.createdBy!==S.user.u){toast("You can only delete your own quotations","err");return}if(!P("quot","delete")){toast("You don't have delete permission","err");return}confirmModal("Delete this quotation? (Stays in Recycle Bin for 7 days)",async()=>{await _trashAdd("quotation",(v.invoiceNo||"Quotation")+" — "+(v.clientName||""),v.type==="group"?"Group":"Private","quotations/"+k,v,{});FD("quotations/"+k).then(()=>{delete S.quotations[k];rQLCore();toast("Deleted — Moved to Recycle Bin")}).catch(e=>toast("Delete failed: "+e.message,"err"))});};

function pgAllQuot(pg){
/* All Quotations — sirf admin/superadmin ke liye */
if(!P("allquot","view"))return pg.innerHTML=`<div class="cd"><div class="cd-h">All Quotations</div><p style="padding:20px;color:var(--t2);text-align:center">⛔ Access not allowed — Admins only</p></div>`;
const userOpts=Object.values(S.users||{}).sort((a,b)=>(a.full||a.u).localeCompare(b.full||b.u)).map(u=>`<option value="${_esc(u.u)}">${_esc(u.full||u.u)} (${u.r})</option>`).join("");
const branchOpts=Object.entries(S.branches||{}).map(([id,b])=>`<option value="${id}">${b.name}</option>`).join("");
pg.innerHTML=`<div class="cd"><div class="cd-h">All Quotations <span class="bd bd-a" style="font-size:.65rem">Admin View</span> <div style="display:flex;gap:6px;flex-wrap:wrap">${P("allquot","add")?`<button class="btn btn-sm btn-p" onclick="editKey=null;nav('pvt')">+ Private</button><button class="btn btn-sm btn-a" onclick="editKey=null;nav('grp')">+ Group</button>`:""}<button class="btn btn-sm btn-o" onclick="rQLAll()">Refresh</button><button class="btn btn-sm btn-g" onclick="exportAllQuotFiltered()">⬇ Export</button></div></div>
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
<div class="fg" style="max-width:200px;margin-bottom:0"><label>Filter by Branch</label><select id="qAllBranchFilter" onchange="applyAllQuotFilter()"><option value="">All Branches</option>${branchOpts}</select></div>
<div class="fg" style="max-width:220px;margin-bottom:0"><label>Filter by User</label><select id="qAllUserFilter" onchange="applyAllQuotFilter()"><option value="">All Users</option>${userOpts}</select></div>
<div class="fg" style="max-width:150px;margin-bottom:0"><label>Filter by Type</label><select id="qAllTypeFilter" onchange="applyAllQuotFilter()"><option value="">All Types</option><option value="group">Group</option><option value="private">Private</option></select></div>
</div>
<div id="qAllStats" style="font-size:.72rem;color:var(--t2);margin-bottom:8px"></div>
<div class="ql" id="qLAll"></div></div>`;rQLAllCore()}
async function rQLAllCore(){
/* SPEED: memory mein data ho to foran paint karo, fresh fetch background mein */
const _paintAll=()=>{const l=$("qLAll");if(!l)return;l.innerHTML="";const fUser=$("qAllUserFilter")?.value||"";const fType=$("qAllTypeFilter")?.value||"";const fBranch=$("qAllBranchFilter")?.value||"";let en=Object.entries(S.quotations);if(fBranch)en=en.filter(([k,v])=>v.branchId===fBranch);if(fUser)en=en.filter(([k,v])=>v.createdBy===fUser);if(fType)en=en.filter(([k,v])=>(fType==="group"?v.type==="group":v.type!=="group"));
const stats=$("qAllStats");if(stats)stats.textContent=`Total: ${en.length} quotation(s) shown`;
if(!en.length){l.innerHTML=`<p style="text-align:center;padding:20px;color:var(--t2)">No quotations found</p>`;return}
en.reverse().forEach(([k,v])=>{
/* All Quotations admin panel mein: allquot permissions se edit/delete */
const canEdit=P("allquot","edit");
const canDel=P("allquot","delete");
const updNoteAll=v.updatedBy&&v.updatedBy!==v.createdBy?` <span style="color:var(--t2);font-size:.62rem">• Updated by ${fullNameOf(v.updatedBy)}</span>`:"";
const ownerBadge=`<span style="font-size:.63rem;background:#e0e7ff;color:#3730a3;padding:1px 5px;border-radius:8px;font-weight:600">${fullNameOf(v.createdBy)||v.createdBy}</span>`;
const branchBadge=v.branchName?`<span style="font-size:.63rem;background:#d1fae5;color:#065f46;padding:1px 5px;border-radius:8px;font-weight:600">🏢 ${v.branchName}</span>`:"";
l.innerHTML+=`<div class="qc"><div class="qi"><div class="qn">${_esc(v.clientName)||"—"} <span class="bd bd-${v.type==="group"?"a":"u"}">${v.type}</span> ${ownerBadge} ${branchBadge}</div><div class="qm">${_esc(v.invoiceNo)||""} • ${fmtDT(v.createdAt)}${updNoteAll}</div></div><div class="qa">PKR ${fmt(v.totalAdult||0)}</div><div class="qb"><button class="btn-icon" onclick="viewQ('${k}')">👁</button><button class="btn-icon" style="color:#25D366" onclick="shareWhatsAppFromList('${k}')" title="Share to WhatsApp">📱</button><button class="btn-icon" style="color:var(--teal)" onclick="cloneQuotation('${k}')" title="Clone">📋</button>${canEdit?`<button class="btn-icon" style="color:var(--p)" onclick="editQ('${k}')">✏</button>`:""}${canDel?`<button class="btn-icon" style="color:var(--er)" onclick="delQ('${k}')">🗑</button>`:""}</div></div>`})};
const _hadAll=S.quotations&&Object.keys(S.quotations).length>0;
if(_hadAll)_paintAll();else{const l=$("qLAll");if(l)l.innerHTML=`<p style="text-align:center;padding:20px;color:var(--t2)">⏳ Loading quotations...</p>`}
try{const fetched=await wt(sbRpc("db_read",{p:"quotations"}),30000);if(fetched&&typeof fetched==="object")S.quotations=fetched}catch(e){console.warn("[rQLAll] Fetch failed:",e.message)}
_paintAll()}
window.applyAllQuotFilter=()=>rQLAllCore();
window.rQLAll=async()=>{await rQLAllCore();toast("Refreshed")};
window.viewQ=k=>{const q=S.quotations[k];if(!q)return;q.type==="group"?printGrp(q):printPvt(q)};
/* editQ — All Quotations (admin panel) se use hota hai */
window.editQ=k=>{const q=S.quotations[k];if(!q)return;if(!P("allquot","edit")){toast("You don't have All Quotations edit permission","err");return}
if(q.type==="group"){nav("grp");editKey=k;_quoteOpenedTs=Date.now();loadGrpForm(q)}else{nav("pvt");editKey=k;_quoteOpenedTs=Date.now();loadPvtForm(q)}};
window.cancelEdit=kind=>{const wasEditing=!!editKey;const msg=wasEditing?"Discard unsaved changes and cancel edit?":"Clear this form?";confirmModal(msg,()=>{editKey=null;clearDraft(kind);nav(kind);toast(wasEditing?"Edit cancelled":"Form cleared")},"Yes","btn-o")};
/* delQ — All Quotations (admin panel) se use hota hai */
window.delQ=async k=>{const v=S.quotations[k];if(!v){toast("Quotation not found","err");return}if(!P("allquot","delete")){toast("You don't have All Quotations delete permission","err");return}confirmModal("Delete this quotation? (Stays in Recycle Bin for 7 days)",async()=>{await _trashAdd("quotation",(v.invoiceNo||"Quotation")+" — "+(v.clientName||""),v.type==="group"?"Group":"Private","quotations/"+k,v,{});FD("quotations/"+k).then(()=>{delete S.quotations[k];if(curPage==="allquot")rQLAllCore();toast("Deleted — Moved to Recycle Bin")}).catch(e=>toast("Delete failed: "+e.message,"err"))});};
function loadPvtForm(data){
fillIf("pN",data.clientName);fillIf("pPh",data.contactNo);fillIf("pInc",data.pkgIncludes);fillIf("pDt",data.travelDates);
['A','B','C'].forEach(L=>{const o=data.options?.[L];if(!o)return;
fillIf(`aP${L}`,o.adultPax);fillIf(`aCt${L}`,o.adultCat);setManual(`dDy${L}`,o.days);
let fCount=2;(o.flights||[]).forEach((f,i)=>{if(f.sec||f.date||f.dep||f.arr||f.lug||f.sec2)fCount=Math.max(fCount,i+1)});
revealRows(`fBody${L}`,fCount);
(o.flights||[]).forEach((f,i)=>{fillIf(`fA${L}${i}`,f.airline);fillIf(`fC${L}${i}`,f.cls);fillIf(`fL${L}${i}`,f.lug);fillIf(`fD${L}${i}`,f.date);fillIf(`fS${L}${i}`,f.sec);fillIf(`fDp${L}${i}`,f.dep);fillIf(`fAr${L}${i}`,f.arr);fillIf(`fLy${L}${i}`,f.lay);fillIf(`fS2${L}${i}`,f.sec2);fillIf(`fD2${L}${i}`,f.dep2);fillIf(`fA2${L}${i}`,f.arr2)});
let hCount=2;(o.hotels||[]).forEach((h,i)=>{if(h.name)hCount=Math.max(hCount,i+1)});
revealRows(`hBody${L}`,hCount);
(o.hotels||[]).forEach((h,i)=>{fillIf(`hCity${L}${i}`,h.city||"makkah");fillIf(`h${L}${i}`,h.name);fillIf(`hR${L}${i}`,h.type);fillIf(`hRt${L}${i}`,h.rate);fillIf(`hQ${L}${i}`,h.qty);fillIf(`hD${L}${i}`,h.dist);fillIf(`hN${L}${i}`,h.ngt);fillIf(`hE${L}${i}`,h.roe)});
if(o.visa){fillIf(`vR${L}`,o.visa.r);setManual(`vQ${L}`,o.visa.q);fillIf(`vE${L}`,o.visa.roe)}
/* Load manual visa rows if they exist — adult (mv), child (cmv), infant (imv) */
if(o.manualVisas&&o.manualVisas.length){o.manualVisas.forEach(mv=>{addManualVisaRow(L,'mv',mv.name,mv.r,mv.q,mv.roe)})}
if(o.childManualVisas&&o.childManualVisas.length){o.childManualVisas.forEach(mv=>{addManualVisaRow(L,'cmv',mv.name,mv.r,mv.q,mv.roe)})}
if(o.infantManualVisas&&o.infantManualVisas.length){o.infantManualVisas.forEach(mv=>{addManualVisaRow(L,'imv',mv.name,mv.r,mv.q,mv.roe)})}
let tCount=2;(o.transports||[]).forEach((t,i)=>{if(t.sec)tCount=Math.max(tCount,i+1)});
revealRows(`tBody${L}`,tCount);
(o.transports||[]).forEach((t,i)=>{fillIf(`tS${L}${i}`,t.sec);fillIf(`tV${L}${i}`,t.veh);fillIf(`tR${L}${i}`,t.rate);fillIf(`tQ${L}${i}`,t.qty);fillIf(`tE${L}${i}`,t.roe)});
fillIf(`tk${L}`,o.ticketPKR);setManual(`tkQ${L}`,o.ticketQty);fillIf(`mk${L}`,o.markup);
fillIf(`cP${L}`,o.childPax);
if(o.childVisa){fillIf(`cvR${L}`,o.childVisa.r);setManual(`cvQ${L}`,o.childVisa.q);fillIf(`cvE${L}`,o.childVisa.roe)}
if(o.childTicket){fillIf(`ctk${L}`,o.childTicket.pkr);setManual(`ctkQ${L}`,o.childTicket.q)}
if(o.childTransport){fillIf(`cTrV${L}`,o.childTransport.veh);setManual(`cTrR${L}`,o.childTransport.rate);setManual(`cTrQ${L}`,o.childTransport.qty);fillIf(`cTrE${L}`,o.childTransport.roe)}
const chList=(o.childHotels&&o.childHotels.length?o.childHotels:(o.childHotel&&o.childHotel.name?[o.childHotel]:[]));
let cHCount=0;chList.forEach((h,i)=>{if(h.name)cHCount=Math.max(cHCount,i+1)});
revealRows(`cHBody${L}`,cHCount);
chList.forEach((h,i)=>{fillIf(`cHCity${L}${i}`,h.city||"makkah");fillIf(`cH${L}${i}`,h.name);fillIf(`cHR${L}${i}`,h.type);fillIf(`cHRt${L}${i}`,h.rate);fillIf(`cHQ${L}${i}`,h.qty);fillIf(`cHD${L}${i}`,h.dist);fillIf(`cHN${L}${i}`,h.ngt);fillIf(`cHE${L}${i}`,h.roe)});
fillIf(`cMk${L}`,o.childMarkup);
fillIf(`iP${L}`,o.infantPax);
if(o.infantVisa){fillIf(`ivR${L}`,o.infantVisa.r);setManual(`ivQ${L}`,o.infantVisa.q);fillIf(`ivE${L}`,o.infantVisa.roe)}
if(o.infantTicket){fillIf(`itk${L}`,o.infantTicket.pkr);setManual(`itkQ${L}`,o.infantTicket.q)}
fillIf(`iMk${L}`,o.infantMarkup)});
pCalc(true);pTab('A');
const tag=$("pEditTag");if(tag)tag.innerHTML=`<span class="bd bd-a" style="margin-left:8px">Editing ${data.invoiceNo||""}</span>`;
const cb=$("pCancelEditBtn");if(cb)cb.style.display="";
const sb=$("pSaveBtn");if(sb)sb.textContent="Update & Print";
toast("Loaded for editing")}
function loadGrpForm(data){
fillIf("gN",data.clientName);fillIf("gInc",data.pkgIncludes);fillIf("gDt",data.travelDates);fillIf("gHd",data.heading);fillIf("gAir",data.airline);fillIf("gTk",data.ticketPP);setManual("gDays",data.days);
let hCount=2;(data.hotels||[]).forEach((h,i)=>{if(h.name)hCount=Math.max(hCount,i+1)});
revealRows("gHBody",hCount);
(data.hotels||[]).forEach((h,i)=>{fillIf(`gHCity${i}`,h.city||"makkah");fillIf(`gH${i}`,h.name);fillIf(`gHC${i}`,h.cat);fillIf(`gHR${i}`,h.rate);fillIf(`gHQ${i}`,h.qty);fillIf(`gHD${i}`,h.dist);fillIf(`gHN${i}`,h.ngt);fillIf(`gHE${i}`,h.roe)});
if(data.visa){fillIf("gVR",data.visa.r);fillIf("gVQ",data.visa.q);fillIf("gVE",data.visa.roe)}
let tCount=2;(data.transports||[]).forEach((t,i)=>{if(t.sec)tCount=Math.max(tCount,i+1)});
revealRows("gTBody",tCount);
(data.transports||[]).forEach((t,i)=>{fillIf(`gTS${i}`,t.sec);fillIf(`gTV${i}`,t.veh);fillIf(`gTR${i}`,t.rate);fillIf(`gTQ${i}`,t.qty);fillIf(`gTE${i}`,t.roe)});
if(data.profit){fillIf("gPQ",data.profit.Q);fillIf("gPQd",data.profit.Qd);fillIf("gPT",data.profit.T);fillIf("gPD",data.profit.D)}
gCalc(true);
const tag=$("gEditTag");if(tag)tag.innerHTML=`<span class="bd bd-a" style="margin-left:8px">Editing ${data.invoiceNo||""}</span>`;
const cb=$("gCancelEditBtn");if(cb)cb.style.display="";
const sb=$("gSaveBtn");if(sb)sb.textContent="Update & Print";
toast("Loaded for editing")}

/* ========== COSTING SHEET PRINT (Internal — for team review) ==========
   Prints a full internal costing breakdown with all rates, ROE, visa, ticket etc.
   Not shown to clients — for internal use only. */

function buildCostingCss(){
  return `
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif}
@page{size:A4;margin:8mm}
body{background:#fff;color:#0f172a;font-size:9px}
.cost-pg{background:#fff;width:100%;max-width:210mm;margin:0 auto 6mm;padding:4mm 6mm}
.cost-hdr{background:#1e3a8a;color:#fff;padding:6px 10px;border-radius:4px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px}
.cost-hdr h1{font-size:13px;font-weight:800;letter-spacing:1px}
.cost-hdr .sub{font-size:8px;opacity:.85}
.cost-meta{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}
.cost-meta .m-item{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:4px 8px;font-size:8.5px;flex:1;min-width:80px}
.cost-meta .m-item b{display:block;font-size:7px;color:#64748b;text-transform:uppercase;letter-spacing:.4px;margin-bottom:1px}
.opt-banner{background:#1e40af;color:#fff;padding:4px 8px;font-size:9px;font-weight:700;letter-spacing:1.5px;border-radius:3px;margin:8px 0 5px;text-align:center}
.sec-title{background:#334155;color:#fff;padding:3px 8px;font-size:7.5px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin:6px 0 3px;border-radius:2px}
table{width:100%;border-collapse:collapse;margin-bottom:6px;font-size:8px}
th{background:#e2e8f0;color:#334155;padding:2px 4px;font-size:7px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;border:1px solid #cbd5e1;text-align:center;line-height:1.2}
td{padding:2px 4px;border:1px solid #e2e8f0;text-align:center;background:#fff;line-height:1.2;overflow-wrap:break-word;word-break:break-word}
td.lbl{text-align:left;font-weight:600;color:#334155;background:#f8fafc}
tr:nth-child(even) td{background:#fafbfc}
.total-row td{background:#eff6ff!important;font-weight:800;color:#1e40af;font-size:9px;border-top:2px solid #1e40af}
.grand-box{border:2px solid #1e40af;border-radius:5px;padding:6px 12px;margin:6px 0;background:#eff6ff}
.grand-box .grand-row{display:flex;justify-content:space-between;font-size:10px;font-weight:700;padding:2px 0;border-bottom:1px solid #bfdbfe}
.grand-box .grand-row:last-child{border-bottom:none;font-size:11px;color:#1e40af}
.grand-box .grand-row span{color:#334155}
.confidential{text-align:center;font-size:7px;color:#94a3b8;margin-top:8px;border-top:1px solid #e2e8f0;padding-top:5px;font-style:italic}
.page-break{page-break-before:always;break-before:page}
`;
}

function pvtCostingOptHtml(L,o,d){
  if(!o)return"";
  const aP=o.adultPax||1;
  const roe=S.settings?.defaultROE||78;
  let rows="";
  // Flight
  const fl=(o.flights||[]).filter(f=>f.airline&&f.airline!=="-"&&f.sec);
  if(fl.length){
    rows+=`<div class="sec-title">✈ Ticket / Flight — Option ${L}</div>`;
    rows+=`<table><thead><tr><th>Date</th><th>Airline</th><th>Class</th><th>Sector</th><th>Departure</th><th>Arrival</th><th>Layover</th><th>Luggage</th></tr></thead><tbody>`;
    fl.forEach(f=>{rows+=`<tr><td>${fmtDisplayDate(f.date)||"-"}</td><td>${f.airline||"-"}</td><td>${f.cls||"-"}</td><td>${(f.sec||"").toUpperCase()}${f.sec2?" / "+(f.sec2||"").toUpperCase():""}</td><td>${f.dep||"-"}${f.dep2?" / "+f.dep2:""}</td><td>${f.arr||"-"}${f.arr2?" / "+f.arr2:""}</td><td>${f.lay||"-"}</td><td>${f.lug||"-"}</td></tr>`});
    rows+=`</tbody></table>`;
    const tkPKR=o.ticketPKR||0,tkQ=o.ticketQty||aP,tkT=tkPKR*tkQ;
    rows+=`<table><thead><tr><th>Ticket PKR</th><th>Qty</th><th>Total PKR</th><th>Per Adult</th></tr></thead><tbody><tr><td>${fmt(tkPKR)}</td><td>${tkQ}</td><td class="lbl">${fmt(tkT)}</td><td class="lbl">${fmt(tkPKR)}</td></tr></tbody></table>`;
  }
  // Hotels Adult
  const ht=(o.hotels||[]).filter(h=>h.name);
  if(ht.length){
    rows+=`<div class="sec-title">🏨 Hotels (Adult) — Option ${L}</div>`;
    rows+=`<table><thead><tr><th>City</th><th>Hotel</th><th>Room</th><th>Rate SAR</th><th>Qty</th><th>Nights</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>`;
    let hTot=0;
    ht.forEach(h=>{const t=h.rate*h.qty*h.ngt*h.roe;hTot+=t;rows+=`<tr><td>${cityLabel(h.city)}</td><td class="lbl">${h.name}</td><td>${h.type||"-"}</td><td>${fmt(h.rate)}</td><td>${h.qty||0}</td><td>${h.ngt||0}</td><td>${h.roe||roe}</td><td><b>${fmt(t)}</b></td></tr>`});
    rows+=`<tr class="total-row"><td colspan="7" class="lbl">Hotel Total</td><td>${fmt(hTot)}</td></tr></tbody></table>`;
  }
  // Visa Adult
  const v=o.visa||{};
  rows+=`<div class="sec-title">🛂 Visa (Adult) — Option ${L}</div>`;
  const vT=(v.r||0)*(v.q||aP)*(v.roe||roe);
  rows+=`<table><thead><tr><th>Visa SAR</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody><tr><td>${v.r||0}</td><td>${v.q||aP}</td><td>${v.roe||roe}</td><td class="lbl"><b>${fmt(vT)}</b></td></tr></tbody></table>`;
  /* Manual visas — show only if they exist */
  const mv=o.manualVisas||[];
  if(mv.length){
    let mvTot=0;
    mv.forEach(m=>{const t=(m.r||0)*(m.q||0)*(m.roe||roe);mvTot+=t;rows+=`<table><thead><tr><th>Visa Type</th><th>SAR</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody><tr><td class="lbl">${(m.name||"").toUpperCase()}</td><td>${m.r||0}</td><td>${m.q||0}</td><td>${m.roe||roe}</td><td class="lbl"><b>${fmt(t)}</b></td></tr></tbody></table>`});
    rows+=`<table><tbody><tr class="total-row"><td colspan="4" class="lbl">Manual Visa Total</td><td>${fmt(mvTot)}</td></tr></tbody></table>`;
  }
  // Transport Adult
  const tr=(o.transports||[]).filter(t=>t.sec&&t.qty>0);
  if(tr.length){
    rows+=`<div class="sec-title">🚌 Transport (Adult) — Option ${L}</div>`;
    rows+=`<table><thead><tr><th>Sector</th><th>Vehicle</th><th>Rate SAR</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>`;
    let tTot=0;
    tr.forEach(t=>{const tt=t.rate*t.qty*t.roe;tTot+=tt;rows+=`<tr><td class="lbl">${(t.sec||"").toUpperCase()}</td><td>${t.veh||"-"}</td><td>${fmt(t.rate)}</td><td>${t.qty||0}</td><td>${t.roe||roe}</td><td><b>${fmt(tt)}</b></td></tr>`});
    rows+=`<tr class="total-row"><td colspan="5" class="lbl">Transport Total</td><td>${fmt(tTot)}</td></tr></tbody></table>`;
  }
  // Markup
  if(o.markup){rows+=`<table><thead><tr><th>Markup / Adjustment</th><th>Per Pax</th><th>PAX</th><th>Total</th></tr></thead><tbody><tr><td class="lbl">ADD/LESS</td><td>${fmt(o.markup)}</td><td>${aP}</td><td>${fmt(o.markup*aP)}</td></tr></tbody></table>`}
  // Summary Adult
  rows+=`<div class="grand-box"><div class="grand-row"><span>Total Adult Cost:</span><b>PKR ${fmt(o.totalAdult||0)}</b></div><div class="grand-row"><span>Adult Per Pax:</span><b>PKR ${fmt(o.perAdult||0)}</b></div></div>`;
  // Child
  if(o.childPax>0){
    rows+=`<div class="sec-title">👧 Child — Option ${L} (${o.childPax} Pax)</div>`;
    const cv=o.childVisa||{},ct=o.childTicket||{};
    const cvT=(cv.r||0)*(cv.q||o.childPax)*(cv.roe||roe),ctT=(ct.pkr||0)*(ct.q||o.childPax);
    let cHT=0;(o.childHotels||[]).filter(h=>h.name).forEach(h=>{cHT+=h.rate*h.qty*h.ngt*h.roe});
    const cTrT=o.childTransport?.rate&&o.childTransport?.qty?o.childTransport.rate*o.childTransport.qty*(o.childTransport.roe>10?o.childTransport.roe:1):0;
    let cmvT=0;(o.childManualVisas||[]).forEach(m=>{cmvT+=(m.r||0)*(m.q||0)*(m.roe||roe)});
    rows+=`<table><thead><tr><th>Item</th><th>Rate</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>`;
    rows+=`<tr><td class="lbl">Umrah Visa</td><td>${cv.r||0} SAR</td><td>${cv.q||o.childPax}</td><td>${cv.roe||roe}</td><td>${fmt(cvT)}</td></tr>`;
    (o.childManualVisas||[]).forEach(m=>{const t=(m.r||0)*(m.q||0)*(m.roe||roe);rows+=`<tr><td class="lbl">➕ ${(m.name||"VISA").toUpperCase()} (Additional)</td><td>${m.r||0} SAR</td><td>${m.q||0}</td><td>${m.roe||roe}</td><td>${fmt(t)}</td></tr>`});
    rows+=`<tr><td class="lbl">Ticket</td><td>PKR ${fmt(ct.pkr||0)}</td><td>${ct.q||o.childPax}</td><td>—</td><td>${fmt(ctT)}</td></tr>`;
    if(cHT)rows+=`<tr><td class="lbl">Hotels</td><td>—</td><td>—</td><td>—</td><td>${fmt(cHT)}</td></tr>`;
    if(cTrT)rows+=`<tr><td class="lbl">Transport</td><td>—</td><td>—</td><td>—</td><td>${fmt(cTrT)}</td></tr>`;
    if(o.childMarkup)rows+=`<tr><td class="lbl">Markup</td><td>${fmt(o.childMarkup)}</td><td>${o.childPax}</td><td>—</td><td>${fmt(o.childMarkup*o.childPax)}</td></tr>`;
    rows+=`<tr class="total-row"><td colspan="4" class="lbl">Child Total</td><td>${fmt(o.totalChild||0)}</td></tr></tbody></table>`;
    rows+=`<div class="grand-box"><div class="grand-row"><span>Child Per Pax:</span><b>PKR ${fmt(o.perChild||0)}</b></div></div>`;
  }
  // Infant
  if(o.infantPax>0){
    rows+=`<div class="sec-title">👶 Infant — Option ${L} (${o.infantPax} Pax)</div>`;
    const iv=o.infantVisa||{},it=o.infantTicket||{};
    const ivT=(iv.r||0)*(iv.q||o.infantPax)*(iv.roe||S.settings?.defaultInfantROE||77);
    const itT=(it.pkr||0)*(it.q||o.infantPax);
    let imvT=0;(o.infantManualVisas||[]).forEach(m=>{imvT+=(m.r||0)*(m.q||0)*(m.roe||roe)});
    rows+=`<table><thead><tr><th>Item</th><th>Rate</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>`;
    rows+=`<tr><td class="lbl">Umrah Visa</td><td>${iv.r||0} SAR</td><td>${iv.q||o.infantPax}</td><td>${iv.roe||S.settings?.defaultInfantROE||77}</td><td>${fmt(ivT)}</td></tr>`;
    (o.infantManualVisas||[]).forEach(m=>{const t=(m.r||0)*(m.q||0)*(m.roe||roe);rows+=`<tr><td class="lbl">➕ ${(m.name||"VISA").toUpperCase()} (Additional)</td><td>${m.r||0} SAR</td><td>${m.q||0}</td><td>${m.roe||roe}</td><td>${fmt(t)}</td></tr>`});
    rows+=`<tr><td class="lbl">Ticket</td><td>PKR ${fmt(it.pkr||0)}</td><td>${it.q||o.infantPax}</td><td>—</td><td>${fmt(itT)}</td></tr>`;
    if(o.infantMarkup)rows+=`<tr><td class="lbl">Markup</td><td>${fmt(o.infantMarkup)}</td><td>${o.infantPax}</td><td>—</td><td>${fmt(o.infantMarkup*o.infantPax)}</td></tr>`;
    rows+=`<tr class="total-row"><td colspan="4" class="lbl">Infant Total</td><td>${fmt(o.totalInfant||0)}</td></tr></tbody></table>`;
    rows+=`<div class="grand-box"><div class="grand-row"><span>Infant Per Pax:</span><b>PKR ${fmt(o.perInfant||0)}</b></div></div>`;
  }
  return rows;
}

window.printCostingPvt=function(){
  if(!$("pN")?.value.trim()){toast("Please enter client name","warn");return}
  pCalc(true);
  const s=effectiveSettings({branchId:S.activeBranch?.id});
  const clientName=$("pN")?.value||"";
  const contact=$("pPh")?.value||"";
  const travelDates=$("pDt")?.value||_autoTravelDatesFromFlights()||"";
  const inc=$("pInc")?.value||"";
  const invNo=(editKey&&S.quotations[editKey])?S.quotations[editKey].invoiceNo:"DRAFT";
  const now=new Date().toLocaleDateString("en-CA");
  const metaHtml=`<div class="cost-meta">
    <div class="m-item"><b>Client</b>${clientName}</div>
    <div class="m-item"><b>Contact</b>${contact||"—"}</div>
    <div class="m-item"><b>Travel Dates</b>${travelDates||"—"}</div>
    <div class="m-item"><b>Includes</b>${inc||"—"}</div>
    <div class="m-item"><b>Invoice #</b>${invNo}</div>
    <div class="m-item"><b>Date</b>${now}</div>
    <div class="m-item"><b>Prepared By</b>${S.user?.full||S.user?.u||"—"}</div>
    <div class="m-item"><b>Branch</b>${s.company||"—"}</div>
  </div>`;
  let optHtml="";
  ['A','B','C'].forEach(L=>{
    if(!$(`aP${L}`))return;
    const aP=n($(`aP${L}`)?.value)||1;
    const tk=n($(`tk${L}`)?.value),tkQ=n($(`tkQ${L}`)?.value)||aP,tkT=tk*tkQ;
    let hT=0;for(let i=0;i<6;i++)hT+=n($(`hRt${L}${i}`)?.value)*n($(`hQ${L}${i}`)?.value)*n($(`hN${L}${i}`)?.value)*n($(`hE${L}${i}`)?.value);
    const vT=n($(`vR${L}`)?.value)*n($(`vQ${L}`)?.value)*n($(`vE${L}`)?.value);
    const mvT=_calcManualVisaTotal(L);
    let tT=0;for(let i=0;i<6;i++)tT+=n($(`tR${L}${i}`)?.value)*n($(`tQ${L}${i}`)?.value)*n($(`tE${L}${i}`)?.value);
    const mk=n($(`mk${L}`)?.value),tot=hT+vT+mvT+tT+tkT+(mk*aP),perPax=aP?tot/aP:0;
    /* Sirf wahi option print ho jis mein WAQAI data ho — sirf default visa SAR
       (560) wale khali options B/C phantom rows na dikhayen */
    const _cvT=n($(`cvR${L}`)?.value)*n($(`cvQ${L}`)?.value)*n($(`cvE${L}`)?.value),_ivT=n($(`ivR${L}`)?.value)*n($(`ivQ${L}`)?.value)*n($(`ivE${L}`)?.value);
    const _hasFlights=(()=>{for(let i=0;i<6;i++){const a=$(`fA${L}${i}`)?.value||"",s=$(`fS${L}${i}`)?.value||"";if(a&&a!=="-"&&s)return true}return false})();
    const _hasReal=_hasFlights||hT>0||tk>0||tT>0||mvT>0||_collectManualVisas(L,'cmv').length>0||_collectManualVisas(L,'imv').length>0||(n($(`cP${L}`)?.value)>0&&(_cvT>0||n($(`ctk${L}`)?.value)>0))||(n($(`iP${L}`)?.value)>0&&(_ivT>0||n($(`itk${L}`)?.value)>0));
    if(!_hasReal)return;
    const o={adultPax:aP,adultCat:$(`aCt${L}`)?.value||"",days:n($(`dDy${L}`)?.value),flights:[],hotels:[],visa:{r:n($(`vR${L}`)?.value),q:n($(`vQ${L}`)?.value),roe:n($(`vE${L}`)?.value)},manualVisas:_collectManualVisas(L),transports:[],ticketPKR:tk,ticketQty:tkQ,markup:mk,totalAdult:tot,perAdult:perPax,childPax:n($(`cP${L}`)?.value)||0,childVisa:{r:n($(`cvR${L}`)?.value),q:n($(`cvQ${L}`)?.value),roe:n($(`cvE${L}`)?.value)},childManualVisas:_collectManualVisas(L,'cmv'),childTicket:{pkr:n($(`ctk${L}`)?.value),q:n($(`ctkQ${L}`)?.value)},childTransport:{veh:$(`cTrV${L}`)?.value||"AUTO",rate:n($(`cTrR${L}`)?.value),qty:n($(`cTrQ${L}`)?.value),roe:n($(`cTrE${L}`)?.value)},childHotels:[],childMarkup:n($(`cMk${L}`)?.value),totalChild:0,perChild:0,infantPax:n($(`iP${L}`)?.value)||0,infantVisa:{r:n($(`ivR${L}`)?.value),q:n($(`ivQ${L}`)?.value),roe:n($(`ivE${L}`)?.value)},infantManualVisas:_collectManualVisas(L,'imv'),infantTicket:{pkr:n($(`itk${L}`)?.value),q:n($(`itkQ${L}`)?.value)},infantMarkup:n($(`iMk${L}`)?.value),totalInfant:0,perInfant:0};
    for(let i=0;i<6;i++)o.flights.push({airline:$(`fA${L}${i}`)?.value||"",cls:$(`fC${L}${i}`)?.value||"",lug:$(`fL${L}${i}`)?.value||"",date:$(`fD${L}${i}`)?.value||"",sec:$(`fS${L}${i}`)?.value||"",dep:$(`fDp${L}${i}`)?.value||"",arr:$(`fAr${L}${i}`)?.value||"",lay:$(`fLy${L}${i}`)?.value||"",sec2:$(`fS2${L}${i}`)?.value||"",dep2:$(`fD2${L}${i}`)?.value||"",arr2:$(`fA2${L}${i}`)?.value||""});
    for(let i=0;i<6;i++){const hName=$(`h${L}${i}`)?.value||"",hCityV=$(`hCity${L}${i}`)?.value||"makkah";o.hotels.push({name:hName,type:$(`hR${L}${i}`)?.value||"",city:hCityV,rate:n($(`hRt${L}${i}`)?.value),qty:n($(`hQ${L}${i}`)?.value),dist:$(`hD${L}${i}`)?.value||"",ngt:n($(`hN${L}${i}`)?.value),roe:n($(`hE${L}${i}`)?.value)})}
    for(let i=0;i<6;i++)o.transports.push({sec:$(`tS${L}${i}`)?.value||"",veh:$(`tV${L}${i}`)?.value||"",rate:n($(`tR${L}${i}`)?.value),qty:n($(`tQ${L}${i}`)?.value),roe:n($(`tE${L}${i}`)?.value)});
    for(let i=0;i<6;i++){const cName=$(`cH${L}${i}`)?.value||"",cCity=$(`cHCity${L}${i}`)?.value||"makkah";o.childHotels.push({name:cName,type:$(`cHR${L}${i}`)?.value||"",city:cCity,rate:n($(`cHRt${L}${i}`)?.value),qty:n($(`cHQ${L}${i}`)?.value),ngt:n($(`cHN${L}${i}`)?.value),roe:n($(`cHE${L}${i}`)?.value)})}
    if(o.childPax>0){const cv=o.childVisa.r*o.childVisa.q*o.childVisa.roe,ct=o.childTicket.pkr*o.childTicket.q;let cH=0;o.childHotels.forEach(h=>cH+=h.rate*h.qty*h.ngt*h.roe);const cTr=o.childTransport.rate&&o.childTransport.qty?o.childTransport.rate*o.childTransport.qty*(o.childTransport.roe>10?o.childTransport.roe:1):0;const cmvT=(o.childManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalChild=cv+ct+cTr+cH+cmvT+(o.childMarkup*o.childPax);o.perChild=o.totalChild/o.childPax}
    if(o.infantPax>0){const iv=o.infantVisa.r*o.infantVisa.q*o.infantVisa.roe,it=o.infantTicket.pkr*o.infantTicket.q;const imvT=(o.infantManualVisas||[]).reduce((s,v)=>s+v.r*v.q*v.roe,0);o.totalInfant=iv+it+imvT+(o.infantMarkup*o.infantPax);o.perInfant=o.totalInfant/o.infantPax}
    const isFirst=!optHtml;
    optHtml+=`${isFirst?"":""}<div class="opt-banner">OPTION ${L} — PRIVATE COSTING</div>${pvtCostingOptHtml(L,o,{})}`;
  });
  if(!optHtml){toast("No data found","warn");return}
  const html=`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Costing — ${clientName}</title><style>${buildCostingCss()}</style></head><body><div class="cost-pg"><div class="cost-hdr"><div><h1>PRIVATE COSTING SHEET</h1><div class="sub">⚠ CONFIDENTIAL — Internal Use Only — Team Review</div></div><div class="sub" style="text-align:right">${s.company||""}<br>${s.phone||""}</div></div>${metaHtml}${optHtml}<div class="confidential">CONFIDENTIAL — Do not share with clients. For internal team review only. | ${s.company||""} | ${now}</div></div></body></html>`;
  _openCostingPrint(html,"Costing_Private_"+clientName.replace(/[^a-zA-Z0-9]/g,"_"));
};

window.printCostingGrp=function(){
  if(!$("gN")?.value.trim()){toast("Please enter client name","warn");return}
  gCalc(true);
  const s=effectiveSettings({branchId:S.activeBranch?.id});
  const clientName=$("gN")?.value||"";
  const travelDates=$("gDt")?.value||"";
  const heading=$("gHd")?.value||"";
  const airline=$("gAir")?.value||"";
  const inc=$("gInc")?.value||"";
  const tk=n($("gTk")?.value);
  const invNo=(editKey&&S.quotations[editKey])?S.quotations[editKey].invoiceNo:"DRAFT";
  const now=new Date().toLocaleDateString("en-CA");
  const roe=77;
  // Hotels
  let hTot=0,hRows="";
  for(let i=0;i<6;i++){const hName=$(`gH${i}`)?.value||"",city=$(`gHCity${i}`)?.value||"makkah",rate=n($(`gHR${i}`)?.value),qty=n($(`gHQ${i}`)?.value),ngt=n($(`gHN${i}`)?.value),r=n($(`gHE${i}`)?.value)||roe,t=rate*qty*ngt*r;if(!hName)continue;hTot+=t;hRows+=`<tr><td>${cityLabel(city)}</td><td class="lbl">${hName}</td><td>${$(`gHC${i}`)?.value||"-"}</td><td>${fmt(rate)}</td><td>${qty}</td><td>${ngt}</td><td>${r}</td><td><b>${fmt(t)}</b></td></tr>`}
  // Visa
  const vR=n($("gVR")?.value),vQ=n($("gVQ")?.value),vE=n($("gVE")?.value)||roe,vT=vR*vQ*vE;
  // Transport
  let tTot=0,tRows="";
  for(let i=0;i<6;i++){const sec=$(`gTS${i}`)?.value||"",veh=$(`gTV${i}`)?.value||"",rate=n($(`gTR${i}`)?.value),qty=n($(`gTQ${i}`)?.value),r=n($(`gTE${i}`)?.value)||roe,t=rate*qty*r;if(!sec||!qty)continue;tTot+=t;tRows+=`<tr><td class="lbl">${sec.toUpperCase()}</td><td>${veh}</td><td>${fmt(rate)}</td><td>${qty}</td><td>${r}</td><td><b>${fmt(t)}</b></td></tr>`}
  const metaHtml=`<div class="cost-meta">
    <div class="m-item"><b>Client</b>${clientName}</div>
    <div class="m-item"><b>Heading</b>${heading||"—"}</div>
    <div class="m-item"><b>Airline</b>${airline||"—"}</div>
    <div class="m-item"><b>Travel Dates</b>${travelDates||"—"}</div>
    <div class="m-item"><b>Includes</b>${inc||"—"}</div>
    <div class="m-item"><b>Ticket/Person</b>PKR ${fmt(tk)}</div>
    <div class="m-item"><b>Invoice #</b>${invNo}</div>
    <div class="m-item"><b>Date</b>${now}</div>
    <div class="m-item"><b>Prepared By</b>${S.user?.full||S.user?.u||"—"}</div>
    <div class="m-item"><b>Branch</b>${s.company||"—"}</div>
  </div>`;
  let body=`<div class="opt-banner">GROUP COSTING BREAKDOWN</div>`;
  if(hRows){body+=`<div class="sec-title">🏨 Hotels</div><table><thead><tr><th>City</th><th>Hotel</th><th>Cat</th><th>Rate SAR</th><th>Qty</th><th>Nights</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>${hRows}<tr class="total-row"><td colspan="7" class="lbl">Hotel Total</td><td>${fmt(hTot)}</td></tr></tbody></table>`}
  body+=`<div class="sec-title">🛂 Visa</div><table><thead><tr><th>Visa SAR</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody><tr><td>${vR}</td><td>${vQ}</td><td>${vE}</td><td class="lbl"><b>${fmt(vT)}</b></td></tr></tbody></table>`;
  if(tRows){body+=`<div class="sec-title">🚌 Transport</div><table><thead><tr><th>Sector</th><th>Vehicle</th><th>Rate SAR</th><th>Qty</th><th>ROE</th><th>Total PKR</th></tr></thead><tbody>${tRows}<tr class="total-row"><td colspan="5" class="lbl">Transport Total</td><td>${fmt(tTot)}</td></tr></tbody></table>`}
  body+=`<div class="sec-title">💰 Pricing Per Room Type</div>`;
  body+=`<table><thead><tr><th>Room Type</th><th>PAX</th><th>Ticket PKR</th><th>Hotel/Person</th><th>Visa/Person</th><th>Transport/Person</th><th>Net Cost</th><th>Profit</th><th>Selling Price</th></tr></thead><tbody>`;
  [["Quint",5,"gPQ"],["Quad",4,"gPQd"],["Triple",3,"gPT"],["Double",2,"gPD"]].forEach(([nm,c,pid])=>{
    const net=($(`gN${c}`)?.textContent||"").replace(/,/g,"");
    const pr=($(`gP${c}`)?.textContent||"").replace(/,/g,"");
    const sell=($(`gS${c}`)?.textContent||"").replace(/,/g,"");
    const tot=($(`gR${c}`)?.textContent||"").replace(/,/g,"");
    const hPer=hTot?fmt(hTot/c):"—",vPer=vT?fmt(vT/c):"—",tPer=tTot?fmt(tTot/c):"—";
    body+=`<tr><td class="lbl">${nm} (${c})</td><td>${c}</td><td>${fmt(tk)}</td><td>${hPer}</td><td>${vPer}</td><td>${tPer}</td><td><b>${fmt(parseFloat(net)||0)}</b></td><td>${fmt(n($(`g${c===5?"PQ":c===4?"PQd":c===3?"PT":"PD"}`)?.value))}</td><td style="color:#059669;font-weight:800">PKR ${fmt(parseFloat(sell)||0)}</td></tr>`;
  });
  body+=`</tbody></table>`;
  const html=`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Costing — ${clientName}</title><style>${buildCostingCss()}</style></head><body><div class="cost-pg"><div class="cost-hdr"><div><h1>GROUP COSTING SHEET</h1><div class="sub">⚠ CONFIDENTIAL — Internal Use Only — Team Review</div></div><div class="sub" style="text-align:right">${s.company||""}<br>${s.phone||""}</div></div>${metaHtml}${body}<div class="confidential">CONFIDENTIAL — Do not share with clients. For internal team review only. | ${s.company||""} | ${now}</div></div></body></html>`;
  _openCostingPrint(html,"Costing_Group_"+clientName.replace(/[^a-zA-Z0-9]/g,"_"));
};
function _openCostingPrint(html,filename){
  // Show as full overlay print preview with Download PDF + Print options
  const overlay=document.createElement("div");
  overlay.id="_costingOverlay";
  overlay.style.cssText="position:fixed;inset:0;z-index:99995;background:#f1f5f9;overflow-y:auto;display:flex;flex-direction:column";
  overlay.innerHTML=`<div style="position:sticky;top:0;z-index:10;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;padding:10px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;box-shadow:0 2px 10px rgba(0,0,0,.3);flex-shrink:0">
    <span style="font-weight:700;font-size:.85rem">🖨 Costing Sheet Preview</span>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button onclick="_costingDownloadPdf()" style="background:#10b981;color:#fff;border:none;padding:8px 14px;border-radius:7px;font-weight:700;font-size:.75rem;cursor:pointer">⬇ Download PDF</button>
      <button onclick="_costingPrint()" style="background:#0ea5e9;color:#fff;border:none;padding:8px 14px;border-radius:7px;font-weight:700;font-size:.75rem;cursor:pointer">🖨 Print</button>
      <button onclick="document.getElementById('_costingOverlay').remove()" style="background:#ef4444;color:#fff;border:none;padding:8px 14px;border-radius:7px;font-weight:700;font-size:.75rem;cursor:pointer">✕ Close</button>
    </div>
  </div>
  <div style="flex:1;padding:16px;display:flex;justify-content:center">
    <iframe id="_costingFrame" style="width:210mm;max-width:100%;min-height:297mm;border:none;background:#fff;box-shadow:0 4px 20px rgba(0,0,0,.15);border-radius:4px" scrolling="auto"></iframe>
  </div>`;
  document.body.appendChild(overlay);
  const fr=document.getElementById("_costingFrame");
  const doc=fr.contentDocument||fr.contentWindow.document;
  doc.open();doc.write(html);doc.close();
  window._costingHtml=html;
  window._costingFilename=filename;
}

window._costingPrint=function(){
  const fr=document.getElementById("_costingFrame");
  if(fr&&fr.contentWindow){try{fr.contentWindow.focus();fr.contentWindow.print()}catch(e){window.print()}}
};

window._costingDownloadPdf=async function(){
  toast("Preparing PDF...");
  try{
    await loadPdfLibs();
    const {jsPDF}=window.jspdf;
    const holder=document.createElement("div");
    holder.style.cssText="position:fixed;left:-99999px;top:0;background:#fff;width:210mm;z-index:-1";
    holder.innerHTML=window._costingHtml||"";
    document.body.appendChild(holder);
    const pages=holder.querySelectorAll(".cost-pg");
    if(!pages.length){document.body.removeChild(holder);toast("Content not found","err");return}
    const pdf=new jsPDF({unit:"mm",format:"a4",compress:true});
    for(let i=0;i<pages.length;i++){
      const canvas=await html2canvas(pages[i],{scale:3,useCORS:true,backgroundColor:"#ffffff",logging:false,imageTimeout:0});
      const imgData=canvas.toDataURL("image/jpeg",0.92);
      const imgH=210*canvas.height/canvas.width;
      if(i>0)pdf.addPage();
      if(imgH<=297){pdf.addImage(imgData,"JPEG",0,0,210,imgH,undefined,"FAST")}
      else{const sw=210*(297/imgH);pdf.addImage(imgData,"JPEG",(210-sw)/2,0,sw,297,undefined,"FAST")}
    }
    pdf.save((window._costingFilename||"Costing")+".pdf");
    toast("PDF downloaded successfully!");
    document.body.removeChild(holder);
  }catch(e){toast("PDF error: "+e.message,"err")}
};

/* printPvt: entry point — stores data then shows option selector if multiple options exist */
function printPvt(d){
  _currentPrintData=d;
  printPvtWithOptionSelector(d);
}

/* ===== CUSTOM PREVIEW SELECTOR ===== */
/* If there's only 1 valid option, skip the modal and go straight to the Preview page.
   If there are 2+, show a "Select Options to Preview" modal so the user can choose which
   ones to include, then open the Preview page with only those selected options. */
function showOptionPreviewModal(title,items,onConfirm){
  const cards=items.map(it=>`<div class="opt-sel-btn selected" data-val="${it.value}" onclick="this.classList.toggle('selected')">
    <div>${it.label}</div>${it.sub?`<div style="font-weight:400;font-size:.68rem;color:var(--t2);margin-top:2px">${it.sub}</div>`:""}
  </div>`).join("");
  const body=`<p style="font-size:.78rem;color:var(--t2);margin-bottom:6px">Choose which options to include. Each selected option will generate a complete quotation.</p>
    <div class="opt-sel-grid" id="_optPrvWrap">${cards}</div>
    <div style="display:flex;gap:6px;margin-top:2px">
      <button type="button" class="btn btn-o btn-sm" onclick="document.querySelectorAll('#_optPrvWrap .opt-sel-btn').forEach(c=>c.classList.add('selected'))">Select All</button>
      <button type="button" class="btn btn-o btn-sm" onclick="document.querySelectorAll('#_optPrvWrap .opt-sel-btn').forEach(c=>c.classList.remove('selected'))">Clear All</button>
    </div>`;
  showModal(title,body,()=>{
    const sel=[...document.querySelectorAll("#_optPrvWrap .opt-sel-btn.selected")].map(c=>c.dataset.val);
    if(!sel.length){toast("Select at least one option","warn");return false}
    onConfirm(sel);
    return true;
  },"Preview Selected");
}

function printPvtWithOptionSelector(d){
  const s=effectiveSettings(d);
  const opts=d.options?Object.entries(d.options):[];
  const validOpts=_filterPrintOpts(opts);
  if(!validOpts.length){toast("No option data to print","warn");return}
  if(validOpts.length===1){printPvtDirect(d,s,validOpts.map(([l])=>l));return}
  const items=validOpts.map(([l,o])=>{
    const pax=(o.adultPax||0)+(o.childPax||0)+(o.infantPax||0);
    return{value:l,label:`Option ${l}`,sub:`PAX: ${pax}`};
  });
  showOptionPreviewModal("Select Options to Preview",items,sel=>printPvtDirect(d,s,sel));
}
let _currentPrintData=null;

function printPvtDirect(d,s,selectedLabels){
  // Use selected labels or all valid options
  const opts=d.options?Object.entries(d.options):[];
  const vo=selectedLabels?opts.filter(([l])=>selectedLabels.includes(l)):_filterPrintOpts(opts);
  if(!vo.length){toast("No data to print","warn");return}
  const logo=s.logo?`<div class="logo-wrap"><img src="${s.logo}"></div>`:`<div class="logo-fb">${(s.company||"P")[0]}</div>`;
  const fn=(d.clientName||"Quotation").replace(/[^a-zA-Z0-9 ]/g,"").trim()+(d.invoiceNo?"-"+d.invoiceNo:"");

  /* ---- Client info block: built PER OPTION using that option's pax data ---- */
  const makeCinfoHtml=(o)=>{
    let td=n(o?.days)||0;if(!td&&o){o.hotels?.forEach(h=>td+=n(h.ngt));td++}
    return `<div class="cinfo"><div class="cinfo-col">
      <div class="ci-item"><b>Client:</b><span>${d.clientName||""}</span></div>
      <div class="ci-item"><b>Adults:</b><span>${o?.adultPax||"0"} Pax</span></div>
      <div class="ci-item"><b>Child:</b><span>${o?.childPax||"0"} Pax</span></div>
      <div class="ci-item"><b>Infant:</b><span>${o?.infantPax||"0"} Pax</span></div>
      <div class="ci-item"><b>Days:</b><span>${td||""}</span></div>
    </div><div class="cinfo-col">
      <div class="ci-item"><b>📞 Contact:</b><span>${d.contactNo||""}</span></div>
      <div class="ci-item"><b>📅 Travel:</b><span>${fmtDisplayDate(d.travelDates||_travelDatesFromSavedFlights(d.options)||"")}</span></div>
      <div class="ci-item"><b>✅ Includes:</b><span>${d.pkgIncludes||""}</span></div>
    </div></div>`;
  };

  /* ---- Instruction page HTML ---- */
  const instrPageHtml=s.instructions
    ?`<div class="pp instr-page"><div class="instr">${renderInstructionsHTML(s.instructions)}</div></div>`
    :"";

  if(vo.length===1){
    /* Single option — simple layout, instructions at end */
    const [l,o]=vo[0];
    const fl=o.flights?.filter(f=>f.airline&&f.airline!=="-"&&f.sec)||[];
    const ht=o.hotels?.filter(h=>h.name).map(liveHotel)||[];
    const tr=o.transports?.filter(t=>t.sec&&t.qty>0)||[];
    let body=`<div class="sec-hdr"><span class="ic">✈️</span> TRAVEL DETAILS <span class="ic">✈️</span></div>`;
    /* Sequence: Flight → Hotel → Transport → Visa */
    body+=ppFlightTable(fl);
    if(ht.length)body+=`<div class="sec"><span class="ic">🏨</span> Hotel Accommodation</div>${ppHotelBoxes(ht,h=>cityLabel(h.city)+" Hotel")}`;
    body+=ppTransportTable(tr);
    /* VISA details — show Umrah visa + manual visas */
    body+=ppVisaTable(o,s?.defaultROE||78);
    body+=`<div class="summary-wrap"><div class="summary-box"><div class="sum-row"><span>Adult Per Pax:</span><b>PKR ${fmt(o.perAdult)}</b></div>`;
    if(o.childPax>0)body+=`<div class="sum-row"><span>Child Per Pax:</span><b style="color:#c2410c!important">PKR ${fmt(o.perChild)}</b></div>`;
    if(o.infantPax>0)body+=`<div class="sum-row inf"><span>Infant Per Pax:</span><b>PKR ${fmt(o.perInfant)}</b></div>`;
    body+=`</div></div>`;
    const html=`<div class="pp pp-single" style="--brand:${s.brandColor||"#1F4AA8"}">${ppHeader(s,logo)}<div class="title">CUSTOMIZED UMRAH PACKAGE</div>${ppIcards(d,"Customized Umrah")}${makeCinfoHtml(o)}<div class="pp-body">${body}</div>${ppFooter(s)}</div>${instrPageHtml}`;
    openPrintPreview(html,fn,{kind:"pvt",d,s});
  }else{
    /* Multiple options:
       - HAR option par: full header + full client details + option travel details
       - Instructions: SARE options ke baad SIRF EK BAAR (last page) */
    let pagesHtml="";
    vo.forEach(([l,o])=>{
      const fl=o.flights?.filter(f=>f.airline&&f.airline!=="-"&&f.sec)||[];
      const ht=o.hotels?.filter(h=>h.name).map(liveHotel)||[];
      const tr=o.transports?.filter(t=>t.sec&&t.qty>0)||[];
      const optTitle=`<div class="sec-hdr"><span class="ic">✈️</span>&nbsp;OPTION ${l} — TRAVEL DETAILS&nbsp;<span class="ic">✈️</span></div>`;
      let body=optTitle;
      /* Sequence: Flight → Hotel → Transport → Visa */
      body+=ppFlightTable(fl);
      if(ht.length)body+=`<div class="sec"><span class="ic">🏨</span> Hotel Accommodation</div>${ppHotelBoxes(ht,h=>cityLabel(h.city)+" Hotel")}`;
      body+=ppTransportTable(tr);
      /* VISA details — show Umrah visa + manual visas */
      body+=ppVisaTable(o,s?.defaultROE||78);
      body+=`<div class="summary-wrap"><div class="summary-box"><div class="sum-row"><span>Adult Per Pax:</span><b>PKR ${fmt(o.perAdult)}</b></div>`;
      if(o.childPax>0)body+=`<div class="sum-row"><span>Child Per Pax:</span><b style="color:#c2410c!important">PKR ${fmt(o.perChild)}</b></div>`;
      if(o.infantPax>0)body+=`<div class="sum-row inf"><span>Infant Per Pax:</span><b>PKR ${fmt(o.perInfant)}</b></div>`;
      body+=`</div></div>`;
      /* Full header + FULL client details on EVERY option page */
      const topBlock=`${ppHeader(s,logo)}<div class="title">CUSTOMIZED UMRAH PACKAGE — OPTION ${l}</div>${ppIcards(d,"Customized Umrah")}${makeCinfoHtml(o)}`;
      pagesHtml+=`<div class="pp" style="--brand:${s.brandColor||"#1F4AA8"}">${topBlock}<div class="pp-body">${body}</div>${ppFooter(s)}</div>`;
    });
    /* Instructions: sirf ek baar sab options ke baad */
    pagesHtml+=instrPageHtml;
    openPrintPreview(pagesHtml,fn,{kind:"pvt",d,s});
  }
}

/* ===== GROUP PACKAGE ROOM-TYPE SELECTOR (equivalent of A/B/C for Group Package) =====
   Group quotations don't have lettered options like Private — their variation axis is
   room type (Double/Triple/Quad/Quint). This lets the user pick which room-type
   pricing columns to include before printing/downloading, same UX as Private's selector. */
const ROOM_LABELS={2:"DOUBLE",3:"TRIPLE",4:"QUAD",5:"QUINT"};
let _currentGrpPrintData=null;

function printGrp(d){
  _currentGrpPrintData=d;
  printGrpWithOptionSelector(d);
}

function printGrpWithOptionSelector(d){
  const rooms=[2,3,4,5].filter(k=>d.results?.[k]&&n(d.results[k].sell)>0);
  const validRooms=rooms.length?rooms:[2,3,4,5];
  if(validRooms.length<=1){printGrpDirect(d,validRooms);return}
  const items=validRooms.map(k=>({value:String(k),label:ROOM_LABELS[k],sub:`PKR ${d.results?.[k]?.sell||0}`}));
  showOptionPreviewModal("Select Room Types to Preview",items,sel=>printGrpDirect(d,sel.map(v=>parseInt(v))));
}

function printGrpDirect(d,selectedRooms){
const rooms=selectedRooms&&selectedRooms.length?selectedRooms:[2,3,4,5];
const s=effectiveSettings(d);
let days=n(d.days);if(!days){d.hotels?.forEach(h=>days+=n(h.ngt));days++}
const logo=s.logo?`<div class="logo-wrap"><img src="${s.logo}"></div>`:`<div class="logo-fb">${(s.company||"P")[0]}</div>`;
const vh=d.hotels?.filter(h=>h.name).map(liveHotel)||[];const vt=d.transports?.filter(t=>t.sec&&t.qty>0)||[];
const instrHtml=s.instructions?`<div class="pp instr-page"><div class="instr">${renderInstructionsHTML(s.instructions)}</div></div>`:"";
const priceHead=rooms.map(k=>`<th>${ROOM_LABELS[k]}</th>`).join("");
const priceRow=rooms.map(k=>`<td>PKR ${d.results?.[k]?.sell||"-"}</td>`).join("");
const html=`<div class="pp" style="--brand:${s.brandColor||"#1F4AA8"}">${ppHeader(s,logo)}<div class="title">UMRAH PACKAGE — GROUP</div>${ppIcards(d,"Group Umrah")}${d.heading?`<div style="text-align:center;padding:6px;font-weight:800;font-size:10px;color:var(--brand,#1F4AA8);margin-bottom:8px;background:#F5F7FA;border:1px solid #dbe2ea;border-radius:5px">${d.heading}</div>`:""}<div class="cinfo"><div class="cinfo-col"><div class="ci-item"><b>Client:</b><span>${d.clientName||""}</span></div><div class="ci-item"><b>Airline:</b><span>${d.airline||""}</span></div><div class="ci-item"><b>Days:</b><span>${days}</span></div></div><div class="cinfo-col"><div class="ci-item"><b>📅 Travel Dates:</b><span>${fmtDisplayDate(d.travelDates||"")}</span></div><div class="ci-item"><b>🎟 Ticket:</b><span>PKR ${fmt(d.ticketPP)}</span></div><div class="ci-item"><b>✅ Includes:</b><span>${d.pkgIncludes||""}</span></div></div></div><div class="pp-body"><div class="sec-hdr"><span class="ic">✈️</span> TRAVEL DETAILS <span class="ic">✈️</span></div>${vh.length?`<div class="sec"><span class="ic">🏨</span> Hotels</div>${ppHotelBoxes(vh,h=>cityLabel(h.city))}`:""}${ppTransportTable(vt)}${ppVisaTable(d,s?.defaultROE||78)}<div class="sec">Pricing Per Pax</div><table class="price-tbl"><thead><tr><th>Room</th>${priceHead}</tr></thead><tbody><tr class="sell"><td>Selling</td>${priceRow}</tr></tbody></table></div>${ppFooter(s)}</div>${instrHtml}`;
const fnG=(d.clientName||"Quotation").replace(/[^a-zA-Z0-9 ]/g,"").trim()+(d.invoiceNo?"-"+d.invoiceNo:"");
openPrintPreview(html,fnG,{kind:"grp",d,s})
}


async function pgHtl(pg){const canAdd=P("htl","add"),canEdit=P("htl","edit"),canDel=P("htl","delete"),ro=!canAdd&&!canEdit&&!canDel;
pg.innerHTML=`<div class="cd" style="text-align:center;padding:28px;color:var(--t2)">⏳ Loading hotels…</div>`;
try{
  await Promise.all(S.cities.map(c=>ensureHotelsLoaded(c.key)));
}catch(e){
  if(pg.isConnected)pg.innerHTML=`<div class="cd" style="text-align:center;padding:28px;color:var(--er)">⚠ Hotels could not be loaded — please check your internet.<br><small style="color:var(--t2)">${e.message}</small><br><button class="btn btn-sm btn-p" style="margin-top:10px" onclick="pgHtl($('CT').firstChild)">🔄 Retry</button></div>`;
  return;
}
if(!pg.isConnected)return; // is dauran user kisi aur page par chala gaya
// Branch-wise hotel info
const branchNote=S.activeBranch?`<div style="background:#d1fae5;border:1px solid #6ee7b7;border-radius:6px;padding:8px 12px;font-size:.75rem;color:#065f46;margin-bottom:8px">🏢 Hotels shown for your branch: <b>${S.activeBranch.name}</b>. SuperAdmin can see hotels for all branches.</div>`:"";
let html=branchNote+`<div class="cd" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><div style="font-weight:700">${canAdd?"Hotels Management":"Hotels (View Only)"}</div><div style="display:flex;gap:6px;flex-wrap:wrap">${canAdd?`<button class="btn btn-sm btn-o" onclick="addCity()">+ Add City</button><button class="btn btn-sm btn-g" onclick="openImportHotels()">⬆ Import Hotels</button>`:""}<button class="btn btn-sm btn-a" onclick="findDupes()">🔍 Find Duplicates</button></div></div>`;
S.cities.forEach(c=>{const isCore=c.key==="makkah"||c.key==="madina";html+=`<div class="cd"><div class="coll-h" onclick="this.classList.toggle('closed');this.nextElementSibling.classList.toggle('closed')">${c.label} (${(S.hotels[c.key]||[]).length}) <span class="arr">▼</span></div><div class="coll-b">${canAdd?`<div style="margin-bottom:6px;display:flex;gap:6px;flex-wrap:wrap"><button class="btn btn-sm btn-p" onclick="addH('${c.key}')">+ Add Hotel</button>${isCore?"":`<button class="btn btn-sm btn-d" onclick="delCity('${c.key}')">🗑 Remove City</button>`}</div>`:""}<div class="tw tw-fit" style="max-height:400px;overflow-y:auto;overflow-x:auto"><table style="table-layout:auto;width:100%"><thead><tr><th style="width:1%;white-space:nowrap">#</th><th>Name</th><th style="width:62px">Dist.</th><th style="width:${ro?30:82}px"></th></tr></thead><tbody id="hL_${c.key}"></tbody></table></div></div></div>`});
pg.innerHTML=html;rH()}
function rH(){const canEdit=P("htl","edit"),canDel=P("htl","delete");const ic="style=\"padding:3px 5px;font-size:.78rem;line-height:1;display:inline-flex;align-items:center;justify-content:center\"";S.cities.forEach(c=>{const el=$("hL_"+c.key);if(!el)return;const list=S.hotels[c.key]||[];el.innerHTML=list.length?list.map((h,i)=>`<tr><td class="label-cell" style="white-space:nowrap">#${i+1}</td><td data-label="Name" style="word-break:break-word;white-space:normal">${_esc(h.n)}</td><td data-label="Dist" style="color:var(--t2);word-break:break-word;white-space:normal">${_esc(h.d)}</td><td data-label="Actions"><div style="display:flex;align-items:center;gap:2px">${h.loc?`<a href="${_esc(h.loc)}" target="_blank" rel="noopener" class="btn-icon" ${ic} title="Open in Google Maps">📍</a>`:""}${canEdit?`<button class="btn-icon" ${ic} onclick="eH('${c.key}',${i})">✏</button>`:""}${canDel?`<button class="btn-icon" ${ic} style="color:var(--er)" onclick="dH('${c.key}',${i})">🗑</button>`:""}</div></td></tr>`).join(""):`<tr><td colspan="4" style="text-align:center;color:var(--t2)">Empty</td></tr>`})}
window.addCity=()=>{if(!P("htl","add"))return toast("Not allowed","err");showModal("Add City",`<div class="fg"><label>City / Category Name</label><input id="cName" placeholder="e.g. Jeddah, Taif"></div>`,()=>{const nm=$("cName").value.trim();if(!nm)return toast("Enter city name","err")||false;const key=normalizeCityKey(nm);if(S.cities.some(c=>c.key===key))return toast("City already exists","err")||false;S.hotels[key]=[];FR("cities").then(raw=>{const live=(Array.isArray(raw)&&raw.length)?raw.filter(Boolean):S.cities.filter(Boolean);if(!live.some(x=>x&&x.key===key))live.push({key,label:nm});S.cities=live;return Promise.all([bFS("cities",S.cities),bFS("hotels/"+key,{})])}).then(()=>{toast("City added");pgHtl($("CT").firstChild)}).catch(e=>toast("Save failed: "+e.message,"err"));return true})};
window.delCity=async key=>{if(!P("htl","delete"))return toast("Not allowed","err");if(key==="makkah"||key==="madina")return;confirmModal("Delete city and ALL its hotels? (Stays in Recycle Bin for 7 days)",async()=>{const _cObj=(S.cities.find(x=>x.key===key))||{key,label:key};const _rawH=await FR("hotels/"+key).catch(()=>null);await _trashAdd("city",_cObj.label||key,"City + all hotels","",{city:_cObj,hotels:_rawH},{city:_cObj,hotels:_rawH});let live=S.cities.filter(c=>c.key!==key);try{const raw=await FR("cities");if(Array.isArray(raw)&&raw.length)live=raw.filter(c=>c&&c.key!==key)}catch(e){}S.cities=live;delete S.hotels[key];await Promise.all([bFS("cities",S.cities),bFD("hotels/"+key)]).catch(e=>toast("Delete failed: "+e.message,"err"));toast("City removed");pgHtl($("CT").firstChild)});};
/* Resize+compress any image to keep DB payloads small (large stored photos were slowing down every load) */
function compressImg(file,maxW=480,quality=0.7){
  return new Promise((resolve,reject)=>{
    const fr=new FileReader();
    fr.onload=e=>{
      const img=new Image();
      img.onload=()=>{
        const scale=Math.min(1,maxW/img.width);
        const w=Math.max(1,Math.round(img.width*scale)),h=Math.max(1,Math.round(img.height*scale));
        const cv=document.createElement("canvas");cv.width=w;cv.height=h;
        cv.getContext("2d").drawImage(img,0,0,w,h);
        resolve(cv.toDataURL("image/jpeg",quality));
      };
      img.onerror=()=>reject(new Error("Invalid image"));
      img.src=e.target.result;
    };
    fr.onerror=()=>reject(new Error("Read failed"));
    fr.readAsDataURL(file);
  });
}
window.hImgPick=(inputId,hiddenId,previewId)=>{const f=$(inputId)?.files?.[0];if(!f)return;if(!f.type.startsWith("image/")){toast("Please choose an image file","err");return}compressImg(f).then(dataUrl=>{$(hiddenId).value=dataUrl;const pv=$(previewId);if(pv){pv.src=dataUrl;pv.style.display="block"}}).catch(()=>toast("Could not process image","err"))};
window.hImgPaste=(ev,hiddenId,previewId)=>{
  const items=(ev.clipboardData||ev.originalEvent?.clipboardData)?.items;
  if(!items)return;
  let found=false;
  for(const item of items){
    if(item.type&&item.type.indexOf("image")===0){
      found=true;
      const f=item.getAsFile();
      if(!f)continue;
      ev.preventDefault();
      compressImg(f).then(dataUrl=>{$(hiddenId).value=dataUrl;const pv=$(previewId);if(pv){pv.src=dataUrl;pv.style.display="block"}toast("Image pasted!")}).catch(()=>toast("Could not process image","err"));
      break;
    }
  }
  if(!found){ev.preventDefault();toast("No image found in clipboard — paste an image (Ctrl+V)","warn")}
};
window.addH=c=>{if(!P("htl","add"))return toast("Not allowed","err");showModal("Add Hotel",`<div class="fg"><label>Name</label><input id="hName"></div><div class="fg"><label>Distance</label><input id="hDist"></div><div class="fg"><label>Location (Google Maps link)</label><input id="hLoc" placeholder="https://maps.app.goo.gl/..."></div><div class="fg"><label>Hotel Photo (optional — shown on quotations, falls back to 🏨 if empty)</label><input type="file" id="hImgFile" accept="image/*" onchange="hImgPick('hImgFile','hImg','hImgPv')"><div class="paste-zone" tabindex="0" onpaste="hImgPaste(event,'hImg','hImgPv')">📋 Click here and paste an image (Ctrl+V)</div><input type="hidden" id="hImg" value=""><img id="hImgPv" style="display:none;max-width:120px;max-height:90px;object-fit:cover;border-radius:6px;margin-top:6px;border:1px solid var(--bd)"></div>`,()=>{const nm=$("hName").value.trim(),d=$("hDist").value.trim(),loc=$("hLoc").value.trim(),img=$("hImg")?.value||"";if(!nm)return toast("Enter name","err")||false;if(!S.hotels[c])S.hotels[c]=[];
const _ex=(S.hotels[c]||[]).find(x=>((x.n||"").trim().toUpperCase()===nm.toUpperCase()));
if(_ex){confirmModal(`"${nm.toUpperCase()}" already exists. Merge new details into existing hotel? (missing distance/location/photo will be added)`,async()=>{_mergeHotelFields(_ex,{d,loc,img});try{if(_ex.id)await bFS("hotels/"+c+"/"+_ex.id,_ex);toast("Merged ✅");rH()}catch(e2){toast("Merge failed: "+e2.message,"err")}},"Merge","btn-p");return true}
const hotel={n:nm.toUpperCase(),d,loc:loc.replace(/^javascript:/i,''),img};bFP("hotels/"+c,hotel).then(id=>{hotel.id=id;S.hotels[c].push(hotel);toast("Added");rH()}).catch(e=>{toast("Hotel save failed: "+e.message,"err")});return true})};
window.eH=(c,i)=>{if(!P("htl","edit"))return toast("Not allowed","err");const h=S.hotels[c][i];showModal("Edit",`<div class="fg"><label>Name</label><input id="hName" value="${_esc(h.n)}"></div><div class="fg"><label>Distance</label><input id="hDist" value="${_esc(h.d)}"></div><div class="fg"><label>Location (Google Maps link)</label><input id="hLoc" value="${_esc(h.loc||"")}" placeholder="https://maps.app.goo.gl/..."></div><div class="fg"><label>Hotel Photo (optional — shown on quotations, falls back to 🏨 if empty)</label><input type="file" id="hImgFile" accept="image/*" onchange="hImgPick('hImgFile','hImg','hImgPv')"><div class="paste-zone" tabindex="0" onpaste="hImgPaste(event,'hImg','hImgPv')">📋 Click here and paste an image (Ctrl+V)</div><input type="hidden" id="hImg" value="${h.img||""}">${h.img?`<div><button type="button" class="btn btn-sm btn-o" style="margin-top:6px" onclick="$('hImg').value='';$('hImgPv').style.display='none'">Remove Photo</button></div>`:""}<img id="hImgPv" style="${h.img?"display:block":"display:none"};max-width:120px;max-height:90px;object-fit:cover;border-radius:6px;margin-top:6px;border:1px solid var(--bd)" src="${h.img||""}"></div>`,()=>{const nm=$("hName").value.trim(),d=$("hDist").value.trim(),loc=$("hLoc").value.trim(),img=$("hImg")?.value||"";if(!nm)return toast("Enter name","err")||false;const id=h.id;const safeLoc=loc.replace(/^javascript:/i,'');const updated={n:nm.toUpperCase(),d,loc:safeLoc,img,id};const p=id?bFS_Long2("hotels/"+c+"/"+id,updated):(async()=>{updated.id=_newHotelId();S.hotels[c][i]=updated;await _safeArrWrite("hotels/"+c,S.hotels[c],a=>a.filter(x=>x&&x.id!==updated.id).concat(updated))})();p.then(()=>{S.hotels[c][i]=updated;toast("Updated");rH()}).catch(e=>toast("Update failed: "+e.message,"err"));return true})};
window.dH=async(c,i)=>{if(!P("htl","delete"))return toast("Not allowed","err");confirmModal("Delete this hotel? (Stays in Recycle Bin for 7 days)",async()=>{const h=S.hotels[c][i];const removed=S.hotels[c].splice(i,1)[0];await _trashAdd("hotel",(removed&&removed.n)||"Hotel",(S.cities.find(x=>x.key===c)||{}).label||c,h&&h.id?("hotels/"+c+"/"+h.id):"",removed,{city:c});try{if(h&&h.id)await bFD("hotels/"+c+"/"+h.id);else await _safeArrWrite("hotels/"+c,S.hotels[c],a=>a.filter(x=>x&&x.id!==(removed&&removed.id)));toast("Deleted");pgHtl($("CT").firstChild)}catch(e){toast("Delete failed: "+e.message,"err");S.hotels[c].splice(i,0,removed)}});};
function parseHotelImport(raw,defaultCityKey){const lines=raw.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);const buckets={};let count=0;
lines.forEach(line=>{const cols=line.includes("\t")?line.split("\t"):line.split(",");const parts=cols.map(x=>x.trim());if(!parts.length)return;let name="",dist="",city="",loc="";
if(parts.length>=5&&/^\d+$/.test(parts[0])){name=parts[1];dist=parts[2];city=parts[3];loc=parts[4]}
else if(parts.length>=4&&/^\d+$/.test(parts[0])){name=parts[1];dist=parts[2];city=parts[3]}
else if(parts.length===3&&/^\d+$/.test(parts[0])){name=parts[1];dist=parts[2];city=defaultCityKey}
else if(parts.length>=4){name=parts[0];dist=parts[1];city=parts[2];loc=parts[3]}
else if(parts.length===3){name=parts[0];dist=parts[1];city=parts[2]}
else if(parts.length===2){name=parts[0];dist=parts[1];city=defaultCityKey}
else if(parts.length===1){name=parts[0];dist="";city=defaultCityKey}
name=(name||"").trim();if(!name)return;dist=(dist||"").trim();city=(city||defaultCityKey||"makkah").trim();loc=(loc||"").trim();
const norm=normalizeCityKey(city);const existing=S.cities.find(c=>c.key===norm||c.label.toLowerCase()===city.toLowerCase());
const cityKey=existing?existing.key:norm,cityLbl=existing?existing.label:city;
if(!buckets[cityKey])buckets[cityKey]={label:cityLbl,items:[]};
buckets[cityKey].items.push({n:name.toUpperCase(),d:dist,loc});count++});
return{buckets,count}}
async function applyHotelImport(result){const{buckets}=result;let citiesChanged=false;
await Promise.all(Object.keys(buckets).map(key=>ensureHotelsLoaded(key)));
const saves=[];
const dupes=[]; /* same naam ke hotels — skip nahi, Duplicate Review mein jayenge */
for(const key in buckets){if(!S.cities.some(c=>c.key===key)){S.cities.push({key,label:buckets[key].label});citiesChanged=true}
if(!S.hotels[key])S.hotels[key]=[];
const cityUpdates={};
buckets[key].items.forEach(item=>{const ex=S.hotels[key].find(h=>h.n===item.n);if(!ex){const id=_newHotelId();const withId={...item,id};S.hotels[key].push(withId);cityUpdates[id]=withId}else{dupes.push({city:key,cityLabel:(S.cities.find(x=>x.key===key)||{label:key}).label,keep:ex,dupe:{n:item.n,d:item.d||"",loc:item.loc||"",img:""}})}});
if(Object.keys(cityUpdates).length)saves.push(bFU_Long("hotels/"+key,cityUpdates));
}
if(citiesChanged){try{const raw=await FR("cities");if(Array.isArray(raw)&&raw.length)raw.forEach(c=>{if(c&&!S.cities.some(x=>x&&x.key===c.key))S.cities.push(c)})}catch(e){}saves.push(bFS("cities",S.cities))}
await Promise.all(saves);
if(dupes.length){toast(dupes.length+" duplicate hotel(s) found — choose Merge or Skip","warn");_openDupesReview(dupes,"import")}}
window.impFileChange=()=>{const f=$("impFile")?.files?.[0];if(!f)return;const reader=new FileReader();
reader.onload=async e=>{try{
if(f.name.toLowerCase().endsWith(".csv")){$("impData").value=e.target.result}
else{await loadXlsx();if(window.XLSX){const wb=XLSX.read(e.target.result,{type:"binary"});const ws=wb.Sheets[wb.SheetNames[0]];$("impData").value=XLSX.utils.sheet_to_csv(ws)}else{toast("Excel reader failed, save as CSV","err")}}
}catch(ex){toast("Could not read file: "+ex.message,"err")}};
if(f.name.toLowerCase().endsWith(".csv"))reader.readAsText(f);else reader.readAsBinaryString(f)};
window.openImportHotels=()=>{if(!P("htl","add"))return toast("Not allowed","err");showModal("Import Hotels",`<div class="fg"><label>Upload Excel/CSV File (optional)</label><input type="file" id="impFile" accept=".csv,.xlsx,.xls" onchange="impFileChange()"></div><div class="fg"><label>Default City (used only if a row has no city column)</label><select id="impCity">${cityOptionsHtml("makkah")}</select></div><div class="fg"><label>Paste Data — one hotel per line</label><textarea id="impData" rows="8" placeholder="1&#9;Makkah Tower&#9;0m&#9;Makkah&#9;https://maps.app.goo.gl/xxxx"></textarea></div><div style="font-size:.72rem;color:var(--t2)">Columns: S.No, Hotel Name, Distance, City, Location (Google Maps link) — upload a file above or paste directly from Excel (tab-separated)/comma-separated. S.No, City and Location are optional; new cities are created automatically. Duplicate hotels with the same name appear in <b>Duplicate Review</b> where you can choose to <b>Merge</b> or <b>Skip</b> them.</div>`,()=>{const raw=$("impData").value,defCity=$("impCity").value;if(!raw.trim())return toast("Paste or upload some data","err")||false;const result=parseHotelImport(raw,defCity);if(!result.count)return toast("No valid rows found","err")||false;applyHotelImport(result).then(()=>{toast(`Imported ${result.count} hotel(s)`);rH()}).catch(e=>toast("Import failed: "+e.message,"err"));return true})};

function pgTrn(pg){const canAdd=P("trn","add");pg.innerHTML=`<div class="cd"><div class="cd-h">Transport ${canAdd?`<button class="btn btn-sm btn-p" onclick="addTr()">+ Add</button>`:""}</div><div class="tw"><table><thead><tr><th>Sector</th><th>SEDAN</th><th>H1</th><th>STARIA</th><th>GMC</th><th>HIACE</th><th>COASTER</th><th>BUS</th>${(P("trn","edit")||P("trn","delete"))?`<th style="width:80px"></th>`:""}</tr></thead><tbody id="tL"></tbody></table></div></div>`;rT()}
function rT(){const el=$("tL");if(!el)return;const canEdit=P("trn","edit"),canDel=P("trn","delete");el.innerHTML=S.transport.map((t,i)=>`<tr><td class="label-cell" style="white-space:normal;min-width:160px;font-weight:600">${t.s}</td><td data-label="SEDAN">${t.SEDAN||0}</td><td data-label="H1">${t.H1||0}</td><td data-label="STARIA">${t.STARIA||0}</td><td data-label="GMC">${t.GMC||0}</td><td data-label="HIACE">${t.HIACE||0}</td><td data-label="COASTER">${t.COASTER||0}</td><td data-label="BUS">${t.BUS||0}</td>${(canEdit||canDel)?`<td data-label="Actions">${canEdit?`<button class="btn-icon" onclick="eTr(${i})">✏</button>`:""}${canDel?`<button class="btn-icon" style="color:var(--er)" onclick="dTr(${i})">🗑</button>`:""}</td>`:""}</tr>`).join("")}
window.addTr=()=>{if(!P("trn","add"))return toast("Not allowed","err");showModal("Add Sector",`<div class="fg"><label>Sector</label><input id="tS"></div><div class="g2"><div class="fg"><label>SEDAN</label><input type="number" id="tSEDAN" value="0"></div><div class="fg"><label>H1</label><input type="number" id="tH1" value="0"></div><div class="fg"><label>STARIA</label><input type="number" id="tSTARIA" value="0"></div><div class="fg"><label>GMC</label><input type="number" id="tGMC" value="0"></div><div class="fg"><label>HIACE</label><input type="number" id="tHIACE" value="0"></div><div class="fg"><label>COASTER</label><input type="number" id="tCOASTER" value="0"></div><div class="fg gf"><label>BUS</label><input type="number" id="tBUS" value="0"></div></div>`,()=>{const s=$("tS").value.trim();if(!s)return toast("Enter sector","err")||false;if(S.transport.some(t=>(t.s||"").trim().toUpperCase()===s.toUpperCase()))return toast("This sector already exists","err")||false;const rec={s:s.toUpperCase(),SEDAN:n($("tSEDAN").value),H1:n($("tH1").value),STARIA:n($("tSTARIA").value),GMC:n($("tGMC").value),HIACE:n($("tHIACE").value),COASTER:n($("tCOASTER").value),BUS:n($("tBUS").value)};bFP("transport",rec).then(id=>{rec.id=id;S.transport.push(rec);S.sectors=dedupeCI(S.transport.map(t=>t.s));toast("Added");rT()}).catch(e=>toast("Save failed: "+e.message,"err"));return true})};
window.eTr=i=>{if(!P("trn","edit"))return toast("Not allowed","err");const t=S.transport[i];showModal("Edit: "+_esc(t.s),`<div class="fg"><label>Sector</label><input id="tS" value="${_esc(t.s)}"></div><div class="g2"><div class="fg"><label>SEDAN</label><input type="number" id="tSEDAN" value="${t.SEDAN||0}"></div><div class="fg"><label>H1</label><input type="number" id="tH1" value="${t.H1||0}"></div><div class="fg"><label>STARIA</label><input type="number" id="tSTARIA" value="${t.STARIA||0}"></div><div class="fg"><label>GMC</label><input type="number" id="tGMC" value="${t.GMC||0}"></div><div class="fg"><label>HIACE</label><input type="number" id="tHIACE" value="${t.HIACE||0}"></div><div class="fg"><label>COASTER</label><input type="number" id="tCOASTER" value="${t.COASTER||0}"></div><div class="fg gf"><label>BUS</label><input type="number" id="tBUS" value="${t.BUS||0}"></div></div>`,()=>{const s=$("tS").value.trim();if(!s)return toast("Enter sector","err")||false;if(S.transport.some((o,j)=>j!==i&&(o.s||"").trim().toUpperCase()===s.toUpperCase()))return toast("This sector already exists","err")||false;const id=t.id;const updated={s:s.toUpperCase(),SEDAN:n($("tSEDAN").value),H1:n($("tH1").value),STARIA:n($("tSTARIA").value),GMC:n($("tGMC").value),HIACE:n($("tHIACE").value),COASTER:n($("tCOASTER").value),BUS:n($("tBUS").value),id};const p=id?bFS("transport/"+id,updated):(async()=>{updated.id=_newHotelId();S.transport[i]=updated;await _safeArrWrite("transport",S.transport,a=>a.filter(x=>x&&x.id!==updated.id).concat(updated))})();p.then(()=>{S.transport[i]=updated;S.sectors=dedupeCI(S.transport.map(t=>t.s));toast("Updated");rT()}).catch(e=>toast("Update failed: "+e.message,"err"));return true})};
window.dTr=async i=>{if(!P("trn","delete"))return toast("Not allowed","err");confirmModal("Delete this transport sector? (Stays in Recycle Bin for 7 days)",async()=>{const t=S.transport[i];const removed=S.transport.splice(i,1)[0];await _trashAdd("transport",(removed&&removed.s)||"Sector","Transport","transport/"+(removed&&removed.id),removed,{});try{if(removed&&removed.id)await bFD("transport/"+removed.id);else await _safeArrWrite("transport",S.transport,a=>a.filter(x=>x&&x.id!==(removed&&removed.id)));S.sectors=dedupeCI(S.transport.map(t=>t.s));toast("Deleted");rT()}catch(e){toast("Delete failed: "+e.message,"err");S.transport.splice(i,0,removed);S.sectors=dedupeCI(S.transport.map(t=>t.s))}});};

/* ===== RECYCLE BIN (Recently Deleted) =====
   Jo bhi delete hota hai (hotel, transport, city, quotation, list item,
   user, branch) pehle yahan aata hai aur 7 DIN tak restore ho sakta hai.
   7 din baad item khud ba khud permanently delete ho jata hai. */
const TRASH_TTL=7*24*60*60*1000;
async function _trashAdd(type,label,sub,path,data,meta){
  try{
    if(!S.trash)S.trash={};
    const id=_newHotelId();
    const item={id,type,label:label||"",sub:sub||"",path:path||"",data:data||null,meta:meta||{},deletedBy:(S.user&&S.user.u)||"?",deletedAt:Date.now()};
    S.trash[id]=item;
    await FS("trash/"+id,item);
  }catch(e){console.warn("[Trash] bin mein move fail:",e.message)}
}
function _trashAlive(){const now=Date.now();return Object.entries(S.trash||{}).filter(([id,t])=>t&&t.deletedAt&&(now-t.deletedAt)<=TRASH_TTL)}
function _purgeExpiredTrash(){const now=Date.now();for(const id in (S.trash||{})){const t=S.trash[id];if(t&&t.deletedAt&&(now-t.deletedAt)>TRASH_TTL){delete S.trash[id];FD("trash/"+id).catch(()=>{})}}}
function pgBin(pg){
  _purgeExpiredTrash();
  const items=_trashAlive().sort((a,b)=>(b[1].deletedAt||0)-(a[1].deletedAt||0));
  const TIC={hotel:"🏨",city:"🏙️",transport:"🚐",quotation:"📋",lists:"📑",users:"👤",branches:"🏢"};
  pg.innerHTML=`<div class="cd"><div class="cd-h" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><span>🗑️ Recycle Bin — Recently Deleted <span class="bd bd-u" style="font-size:.62rem">Auto-deleted after 7 days</span></span>${items.length?`<button class="btn btn-sm btn-d" onclick="emptyBin()">🗑 Empty Bin</button>`:""}</div>
  ${items.length?`<div class="ql">${items.map(([id,t])=>{const left=Math.max(1,Math.ceil((t.deletedAt+TRASH_TTL-Date.now())/86400000));return `<div class="qc"><div class="qi"><div class="qn">${TIC[t.type]||"🗑"} ${t.label||"—"}</div><div class="qm">${t.sub?t.sub+" • ":""}Deleted by ${t.deletedBy||"?"} • ${new Date(t.deletedAt).toLocaleString()} • <b style="color:var(--er)">${left} days remaining</b></div></div><div class="qb" style="display:flex;gap:6px;align-items:center"><button class="btn btn-sm btn-p" onclick="restoreBin('${id}')">♻️ Restore</button><button class="btn btn-sm btn-d" onclick="purgeBin('${id}')">✖ Permanent</button></div></div>`}).join("")}</div>`:`<div style="text-align:center;padding:30px;color:var(--t2)">Recycle Bin is empty 🎉</div>`}</div>`;
}
window.restoreBin=async id=>{const t=(S.trash||{})[id];if(!t)return toast("Item not found","err");
confirmModal(`Restore "${t.label||"item"}" from Recycle Bin?`,async()=>{
try{
  if(t.type==="city"){const m=t.meta||{};const cObj=m.city||{};const raw=await FR("cities");const live=(Array.isArray(raw)&&raw.length)?raw.filter(Boolean):S.cities.filter(Boolean);if(cObj.key&&!live.some(x=>x&&x.key===cObj.key))live.push(cObj);S.cities=live;await FS_LONG("cities",live);if(cObj.key){delete S.hotels[cObj.key];if(m.hotels)await FS_LONG("hotels/"+cObj.key,m.hotels);ensureHotelsLoaded(cObj.key).catch(()=>{})}}
  else if(t.type==="lists"){const m=t.meta||{};if(m.list){const raw=await FR("lists/"+m.list);const arr=raw?(Array.isArray(raw)?raw:Object.values(raw)):[];if(!arr.includes(m.value))arr.push(m.value);await FS_LONG("lists/"+m.list,arr);S[m.list]=arr}}
  else if(t.path&&t.data){await FS_LONG(t.path,t.data);
    if(t.type==="hotel"){const c=(t.meta||{}).city;if(c&&S.hotels[c]){if(!S.hotels[c].some(x=>x.id===t.data.id))S.hotels[c].push(t.data)}}
    else if(t.type==="transport"){if(!S.transport.some(x=>x.id===t.data.id)){S.transport.push(t.data);S.sectors=dedupeCI(S.transport.map(x=>x.s))}}
    else if(t.type==="quotation"){const k=t.path.split("/")[1];if(k)S.quotations[k]=t.data}
    else if(t.type==="branches"){const k=t.path.split("/")[1];if(k)S.branches[k]=t.data}}
  else{toast("This item cannot be restored","err");return}
  await FD("trash/"+id);delete S.trash[id];toast("Restored successfully! ✅");nav("bin");
}catch(e){toast("Restore failed: "+e.message,"err")}},"Yes, Restore","btn-p")};
window.purgeBin=id=>{const t=(S.trash||{})[id];if(!t)return;confirmModal("Permanently delete '"+(t.label||"item")+"'? This cannot be undone.",async()=>{try{await FD("trash/"+id)}catch(e){}delete S.trash[id];toast("Permanently deleted");nav("bin")},"Yes, Delete","btn-d")};
window.emptyBin=()=>{const items=_trashAlive();if(!items.length)return toast("Bin already empty","warn");confirmModal("Bin has "+items.length+" item(s) will be PERMANENTLY deleted. Continue?",async()=>{for(const[id]of items){try{await FD("trash/"+id)}catch(e){}delete S.trash[id]}toast("Bin emptied");nav("bin")},"Yes, Empty","btn-d")};

/* ===== DUPLICATE FINDER (Hotels) =====
   Same city mein same naam ke hotels detect hotay hain. User ki marzi:
   MERGE (missing details existing mein daal do), DELETE DUPLICATE, ya SKIP. */
function _mergeHotelFields(target,src){let changed=false;["d","loc","img"].forEach(f=>{if(src&&src[f]&&!target[f]){target[f]=src[f];changed=true}});return changed}
let _skippedHotelDupes=new Set();
function _findLiveDupes(){const out=[];S.cities.forEach(c=>{const list=S.hotels[c.key]||[];const seen={};list.forEach((h,i)=>{const k=(h.n||"").trim().toUpperCase();if(!k)return;if(seen[k]!==undefined){const skipKey=`${c.key}::${list[seen[k]].id||seen[k]}::${h.id||i}`;if(_skippedHotelDupes.has(skipKey))return;out.push({city:c.key,cityLabel:c.label,keep:list[seen[k]],dupe:h,skipKey})}else seen[k]=i})});return out}
let _dupesCtx=null;
window.findDupes=()=>{const items=_findLiveDupes();if(!items.length)return toast("No duplicates found — all clear ✅");_openDupesReview(items,"live")};
function _openDupesReview(items,ctx){_dupesCtx={items:items.slice(),ctx:ctx||"live"};_renderDupesModal()}
function _renderDupesModal(){
const c=_dupesCtx;if(!c)return;
const rows=c.items.map((it,i)=>`<div style="border:1px solid var(--bd);border-radius:8px;padding:8px 10px;margin-bottom:8px">
<div style="font-size:.68rem;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px">${it.cityLabel||it.city} — <b>${it.keep.n}</b></div>
<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:.76rem">
<div style="flex:1;min-width:170px;background:rgba(5,150,105,.08);border-radius:6px;padding:5px 8px"><b style="color:var(--ok)">✔ KEEP</b><br>Dist: ${it.keep.d||"—"} • Map: ${it.keep.loc?"📍 yes":"—"} • Photo: ${it.keep.img?"🖼 yes":"—"}</div>
<div style="flex:1;min-width:170px;background:rgba(220,38,38,.06);border-radius:6px;padding:5px 8px"><b style="color:var(--er)">✖ ${c.ctx==="import"?"INCOMING (duplicate)":"DUPLICATE"}</b><br>Dist: ${it.dupe.d||"—"} • Map: ${it.dupe.loc?"📍 yes":"—"} • Photo: ${it.dupe.img?"🖼 yes":"—"}</div>
</div>
<div style="display:flex;gap:6px;margin-top:7px;flex-wrap:wrap"><button class="btn btn-sm btn-p" onclick="dupeAct(${i},'merge')">🔀 Merge</button>${c.ctx==="live"?`<button class="btn btn-sm btn-d" onclick="dupeAct(${i},'del')">🗑 Delete Duplicate</button>`:""}<button class="btn btn-sm btn-o" onclick="dupeAct(${i},'skip')">⏭ Skip</button></div>
</div>`).join("");
showModal(`🔁 Duplicate Hotels (${c.items.length})`,`<div style="font-size:.76rem;color:var(--t2);margin-bottom:8px"><b>Merge</b> = Missing details (distance / map link / photo) will be copied to the KEEP hotel${c.ctx==="live"?" and the duplicate entry will be deleted":" (incoming entry will not be added)"}. <b>Skip</b> = no action.</div><div style="max-height:380px;overflow-y:auto">${rows||'<div style="text-align:center;padding:16px;color:var(--t2)">All resolved ✅</div>'}</div>`,()=>true,"Done")}
window.dupeAct=async(i,act)=>{
const c=_dupesCtx;if(!c||!c.items[i])return;const it=c.items[i];

if(act==="skip"){
  confirmModal(`"${it.dupe.n}" — skip this duplicate?`,()=>{
    if(it.skipKey)_skippedHotelDupes.add(it.skipKey);
    c.items.splice(i,1);_renderDupesModal();
  },"Yes, Skip","btn-o");
  return;
}

if(act==="merge"){
  confirmModal(`<b>MERGE:</b> Missing details (distance/map/photo) from duplicate will be copied to the KEEP hotel${c.ctx==="live"?" and the duplicate entry will be deleted":""}. Continue?`,async()=>{
    try{
      const changed=_mergeHotelFields(it.keep,it.dupe);
      if(it.keep.id)await FS("hotels/"+it.city+"/"+it.keep.id,it.keep);else await FS("hotels/"+it.city,S.hotels[it.city]);
      if(c.ctx==="live"){if(it.dupe.id)await FD("hotels/"+it.city+"/"+it.dupe.id);S.hotels[it.city]=(S.hotels[it.city]||[]).filter(x=>x.id!==it.dupe.id)}
      toast(changed?"Merged ✅ — missing details were added":"Merged ✅ (details already existed)");
      c.items.splice(i,1);_renderDupesModal();
    }catch(e){toast("Action failed: "+e.message,"err")}
  },"Yes, Merge","btn-p");
  return;
}

if(act==="del"&&c.ctx==="live"){
  confirmModal(`Duplicate hotel <b>${it.dupe.n}</b> permanently delete? (will NOT go to Recycle Bin — direct delete)`,async()=>{
    try{
      if(it.dupe.id)await FD("hotels/"+it.city+"/"+it.dupe.id);
      S.hotels[it.city]=(S.hotels[it.city]||[]).filter(x=>x.id!==it.dupe.id);
      toast("Duplicate permanently deleted");
      c.items.splice(i,1);_renderDupesModal();
    }catch(e){toast("Action failed: "+e.message,"err")}
  },"Yes, Delete","btn-d");
}
};

/* ===== QUOTATION DUPLICATE FINDER =====
   Poori details compare karta hai (client name, dates, hotels, flights, amounts).
   Agar SARI cheezein same hain (sirf invoice# alag) = TRUE DUPLICATE.
   User options: View (print), Merge (ek ko dusre mein merge), Delete Duplicate, Skip. */
function _normName(s){return(s||"").trim().toLowerCase().replace(/\s+/g," ")}
function _quotSignature(q){
  /* Deep fingerprint: ALL details except invoice# and timestamps.
     Two quotations are duplicates ONLY if every single detail matches. */
  let sig=`${q.type||""}|${_normName(q.clientName)}|${_normName(q.travelDates||"")}|${_normName(q.pkgIncludes||"")}|${_normName(q.contactNo||"")}|${_normName(q.heading||"")}|${_normName(q.airline||"")}|${q.ticketPP||0}|${q.days||0}|`;
  // Private: options A/B/C
  if(q.options){
    ['A','B','C'].forEach(L=>{
      const o=q.options[L];
      if(!o){sig+=`${L}:empty|`;return}
      sig+=`${L}:${o.adultPax||0},${_normName(o.adultCat||"")},${o.days||0},${o.ticketPKR||0},${o.ticketQty||0},${o.markup||0},${o.childPax||0},${o.childMarkup||0},${o.infantPax||0},${o.infantMarkup||0}|`;
      (o.hotels||[]).forEach(h=>{sig+=`h:${_normName(h.name)},${h.type||""},${_normName(h.city||"")},${h.rate||0},${h.qty||0},${h.ngt||0},${h.roe||0}|`});
      (o.childHotels||[]).forEach(h=>{sig+=`ch:${_normName(h.name)},${h.type||""},${_normName(h.city||"")},${h.rate||0},${h.qty||0},${h.ngt||0},${h.roe||0}|`});
      (o.flights||[]).filter(f=>f.sec||f.airline).forEach(f=>{sig+=`f:${_normName(f.airline)},${f.cls||""},${f.sec||""},${f.date||""},${f.dep||""},${f.arr||""},${f.lay||""},${f.sec2||""},${f.dep2||""},${f.arr2||""}|`});
      const v=o.visa||{};sig+=`v:${v.r||0},${v.q||0},${v.roe||0}|`;
      const cv=o.childVisa||{};sig+=`cv:${cv.r||0},${cv.q||0},${cv.roe||0}|`;
      const ct=o.childTicket||{};sig+=`ct:${ct.pkr||0},${ct.q||0}|`;
      const ctr=o.childTransport||{};sig+=`ctr:${ctr.veh||""},${ctr.rate||0},${ctr.qty||0},${ctr.roe||0}|`;
      const iv=o.infantVisa||{};sig+=`iv:${iv.r||0},${iv.q||0},${iv.roe||0}|`;
      const it=o.infantTicket||{};sig+=`it:${it.pkr||0},${it.q||0}|`;
      (o.transports||[]).filter(t=>t.sec).forEach(t=>{sig+=`t:${t.sec||""},${t.veh||""},${t.rate||0},${t.qty||0},${t.roe||0}|`});
    });
  }
  // Group: hotels/transport at top level
  if(q.hotels){
    (q.hotels||[]).forEach(h=>{sig+=`gh:${_normName(h.name)},${h.cat||""},${_normName(h.city||"")},${h.rate||0},${h.qty||0},${h.ngt||0},${h.roe||0}|`});
  }
  if(q.visa){sig+=`gv:${q.visa.r||0},${q.visa.q||0},${q.visa.roe||0}|`}
  if(q.transports){
    (q.transports||[]).filter(t=>t.sec).forEach(t=>{sig+=`gt:${t.sec||""},${t.veh||""},${t.rate||0},${t.qty||0},${t.roe||0}|`});
  }
  if(q.results){Object.keys(q.results).sort().forEach(k=>{sig+=`r${k}:${q.results[k]?.sell||0}|`})}
  return sig;
}
let _skippedQuotDupes=new Set();
function _findQuotDupes(){
  const out=[];const seen={};
  const entries=Object.entries(S.quotations||{});
  entries.forEach(([k,v])=>{
    const sig=_quotSignature(v);
    if(!sig||sig.length<5)return;
    if(seen[sig]!==undefined){
      const grp=seen[sig];
      if(!out[grp].dupes)out[grp].dupes=[];
      const skipKey=`${out[grp].keep.key}::${k}`;
      if(_skippedQuotDupes.has(skipKey))return; // previously skipped
      out[grp].dupes.push({key:k,q:v,skipKey});
    }else{
      seen[sig]=out.length;
      out.push({keep:{key:k,q:v},dupes:[]});
    }
  });
  return out.filter(g=>g.dupes&&g.dupes.length>0);
}
/* _quotDupWarning removed — ek client ke multiple quotations bilkul normal hain, save pe koi warning nahi */
/* Merge: dupe ki missing info keep walay mein copy karo, phir dupe delete */
async function _mergeQuotFields(keepKey,dupeKey){
  const k=S.quotations[keepKey],d=S.quotations[dupeKey];
  if(!k||!d)return;
  let changed=false;
  ["contactNo","pkgIncludes","travelDates"].forEach(f=>{if(d[f]&&!k[f]){k[f]=d[f];changed=true}});
  if(!k.options&&d.options){k.options=d.options;changed=true}
  if(changed)await bFS("quotations/"+keepKey,k);
  // trash mein daalte hain delete se pehle
  await _trashAdd("quotation",(d.invoiceNo||"Quotation")+" — "+(d.clientName||""),d.type==="group"?"Group (merged)":"Private (merged)","quotations/"+dupeKey,d,{});
  await bFD("quotations/"+dupeKey);
  delete S.quotations[dupeKey];
  return changed;
}
let _quotDupCtx=null;
window.openQuotDupFinder=()=>{
  const groups=_findQuotDupes();
  if(!groups.length)return toast("No duplicate quotations found ✅","ok");
  _quotDupCtx={groups:groups.map(g=>({keep:{...g.keep},dupes:[...g.dupes]}))};
  _renderQuotDupModal();
};
function _renderQuotDupModal(){
  const ctx=_quotDupCtx;if(!ctx)return;
  if(!ctx.groups.length){
    // All resolved
    closeModal();toast("All duplicates resolved ✅");if(curPage==="dup")nav("dup");return;
  }
  const rows=ctx.groups.map((g,gi)=>{
    const keep=g.keep.q;
    const dupRows=g.dupes.map((d,di)=>`
    <div class="dup-card" style="margin-left:16px;margin-bottom:6px">
      <div class="dup-row">
        <div class="dup-keep">
          <b style="color:var(--ok)">✔ KEEP</b><br>
          <b>${keep.invoiceNo||"?"}</b> • ${keep.type||""}<br>
          Client: ${keep.clientName||"—"}<br>
          Date: ${(keep.createdAt||"").split("T")[0]||"—"}<br>
          Amount: PKR ${fmt(keep.totalAdult||0)}<br>
          By: ${fullNameOf(keep.createdBy)||keep.createdBy||"?"}
        </div>
        <div class="dup-dupe">
          <b style="color:var(--er)">✖ DUPLICATE</b><br>
          <b>${d.q.invoiceNo||"?"}</b> • ${d.q.type||""}<br>
          Client: ${d.q.clientName||"—"}<br>
          Date: ${(d.q.createdAt||"").split("T")[0]||"—"}<br>
          Amount: PKR ${fmt(d.q.totalAdult||0)}<br>
          By: ${fullNameOf(d.q.createdBy)||d.q.createdBy||"?"}
        </div>
      </div>
      <div class="dup-actions">
        <button class="btn btn-sm btn-p" onclick="quotDupAct(${gi},${di},'merge')">🔀 Merge</button>
        <button class="btn btn-sm btn-d" onclick="quotDupAct(${gi},${di},'del')">🗑 Delete Duplicate</button>
        <button class="btn btn-sm" style="background:var(--ok);color:#fff" onclick="quotDupAct(${gi},${di},'view')">👁 View Dup</button>
        <button class="btn btn-sm btn-o" onclick="quotDupAct(${gi},${di},'skip')">⏭ Skip</button>
      </div>
    </div>`).join("");
    return `<div style="margin-bottom:12px">
    <div class="dup-card-hdr">👤 Client: <b>${keep.clientName||"—"}</b> — ${g.dupes.length} duplicate${g.dupes.length>1?"s":""}</div>
    ${dupRows}
    </div>`;
  }).join("");
  const total=ctx.groups.reduce((a,g)=>a+g.dupes.length,0);
  showModal(`🔁 Duplicate Quotations (${total})`,
    `<div style="font-size:.76rem;color:var(--t2);margin-bottom:10px;padding:8px;background:var(--bg-flat);border-radius:6px">
      <b>Merge</b> = duplicate will be deleted (moved to Recycle Bin), missing info will be copied to the KEEP entry.<br>
      <b>Delete</b> = duplicate will be moved to Recycle Bin.<br>
      <b>Skip</b> = leave this duplicate for now (you can review it later).
    </div>
    <div style="max-height:420px;overflow-y:auto">${rows}</div>`,
    ()=>true,"Done");
}
window.quotDupAct=async(gi,di,act)=>{
  const ctx=_quotDupCtx;if(!ctx||!ctx.groups[gi])return;
  const g=ctx.groups[gi];const d=g.dupes[di];if(!d)return;
  
  if(act==="view"){
    d.q.type==="group"?printGrp(d.q):printPvt(d.q);
    return;
  }
  
  if(act==="skip"){
    confirmModal("Skip this duplicate for now? (you can review it later)",()=>{
      if(d.skipKey)_skippedQuotDupes.add(d.skipKey);
      g.dupes.splice(di,1);
      if(!g.dupes.length)ctx.groups.splice(gi,1);
      _renderQuotDupModal();
    },"Yes, Skip","btn-o");
    return;
  }
  
  if(act==="merge"){
    if(!P("quot","delete")&&!P("allquot","delete"))return toast("You don't have delete permission — merge cannot proceed","err");
    confirmModal(`<b>MERGE:</b> Duplicate quotation <b>${d.q.invoiceNo||"?"}</b> will be deleted (moved to Recycle Bin) and missing info will be copied to KEEP entry <b>${g.keep.q.invoiceNo||"?"}</b>. Continue?`,async()=>{
      try{
        const changed=await _mergeQuotFields(g.keep.key,d.key);
        toast(changed?"Merged ✅ — missing info was copied":"Merged ✅ (nothing copied, already identical)");
        g.dupes.splice(di,1);
        if(!g.dupes.length)ctx.groups.splice(gi,1);
        _renderQuotDupModal();
      }catch(e){toast("Merge failed: "+e.message,"err")}
    },"Yes, Merge","btn-p");
    return;
  }
  
  if(act==="del"){
    if(!P("quot","delete")&&!P("allquot","delete"))return toast("You don't have delete permission","err");
    confirmModal(`Permanently delete duplicate quotation <b>${d.q.invoiceNo||"?"}</b>? (Stays in Recycle Bin for 7 days)`,async()=>{
      try{
        await _trashAdd("quotation",(d.q.invoiceNo||"Quot")+" — "+(d.q.clientName||""),d.q.type==="group"?"Group":"Private","quotations/"+d.key,d.q,{});
        await bFD("quotations/"+d.key);
        delete S.quotations[d.key];
        toast("Duplicate deleted — Moved to Recycle Bin");
        g.dupes.splice(di,1);
        if(!g.dupes.length)ctx.groups.splice(gi,1);
        _renderQuotDupModal();
      }catch(e){toast("Delete failed: "+e.message,"err")}
    },"Yes, Delete","btn-d");
    return;
  }
};

/* ===== DUPLICATE FINDER PAGE =====
   Ek jagah hotels aur quotations dono ke duplicates dekhein aur resolve karein */
function pgDup(pg){
  const hDupes=_findLiveDupes();
  const qDupes=_findQuotDupes();
  const totalH=hDupes.length,totalQ=qDupes.reduce((a,g)=>a+g.dupes.length,0);
  pg.innerHTML=`<div class="cd">
    <div class="cd-h" style="flex-wrap:wrap;gap:8px">
      🔁 Duplicate Finder
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn btn-sm btn-a" onclick="window.findDupes()">🏨 Scan Hotels</button>
        <button class="btn btn-sm btn-p" onclick="window.openQuotDupFinder()">📋 Scan Quotations</button>
        <button class="btn btn-sm btn-o" onclick="nav('dup')">🔄 Refresh</button>
        <button class="btn btn-sm btn-o" onclick="_skippedHotelDupes.clear();_skippedQuotDupes.clear();nav('dup')" title="Show previously skipped duplicates again">↩ Show Skipped</button>
      </div>
    </div>

    <!-- Summary Stats -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
      <div class="st ${totalH>0?"o":"g"}" style="cursor:pointer" onclick="${totalH>0?"window.findDupes()":"toast('No hotel duplicates found ✅')"}">
        <span class="icn">🏨</span><h4>Hotel Duplicates</h4>
        <div class="v">${totalH}</div>
        <div style="font-size:.68rem;color:var(--t2);margin-top:4px">${totalH>0?"⚠️ Click to resolve":"✅ All clear"}</div>
      </div>
      <div class="st ${totalQ>0?"o":"g"}" style="cursor:pointer" onclick="window.openQuotDupFinder()">
        <span class="icn">📋</span><h4>Quotation Duplicates</h4>
        <div class="v">${totalQ}</div>
        <div style="font-size:.68rem;color:var(--t2);margin-top:4px">${totalQ>0?"⚠️ Click to resolve":"✅ No duplicates"}</div>
      </div>
    </div>

    <!-- Hotel Duplicates List -->
    <div class="dup-section-hdr">🏨 Hotel Duplicates (${totalH})</div>
    ${totalH===0
      ? `<div style="padding:16px;text-align:center;color:var(--t2);font-size:.82rem">✅ No duplicate hotels found</div>`
      : `<div style="max-height:320px;overflow-y:auto">${hDupes.map((it,i)=>`
        <div class="dup-card">
          <div class="dup-card-hdr">${it.cityLabel||it.city} — <b>${it.keep.n}</b></div>
          <div class="dup-row">
            <div class="dup-keep"><b style="color:var(--ok)">✔ KEEP</b><br>Dist: ${it.keep.d||"—"} • Map: ${it.keep.loc?"📍":"—"} • Photo: ${it.keep.img?"🖼":"—"}</div>
            <div class="dup-dupe"><b style="color:var(--er)">✖ DUPLICATE</b><br>Dist: ${it.dupe.d||"—"} • Map: ${it.dupe.loc?"📍":"—"} • Photo: ${it.dupe.img?"🖼":"—"}</div>
          </div>
          <div class="dup-actions">
            <button class="btn btn-sm btn-p" onclick="_pgDupHotelAct(${i},'merge')">🔀 Merge</button>
            <button class="btn btn-sm btn-d" onclick="_pgDupHotelAct(${i},'del')">🗑 Delete Duplicate</button>
            <button class="btn btn-sm btn-o" onclick="_pgDupHotelAct(${i},'skip')">⏭ Skip</button>
          </div>
        </div>`).join("")}</div>`
    }

    <!-- Quotation Duplicates List -->
    <div class="dup-section-hdr" style="margin-top:16px">📋 Quotation Duplicates (${totalQ})</div>
    ${totalQ===0
      ? `<div style="padding:16px;text-align:center;color:var(--t2);font-size:.82rem">✅ No duplicate quotations found</div>`
      : `<div style="max-height:320px;overflow-y:auto">${qDupes.map((g,gi)=>g.dupes.map((d,di)=>`
        <div class="dup-card">
          <div class="dup-card-hdr">👤 Client: <b>${g.keep.q.clientName||"—"}</b></div>
          <div class="dup-row">
            <div class="dup-keep"><b style="color:var(--ok)">✔ KEEP</b> ${g.keep.q.invoiceNo||"?"}<br>${g.keep.q.type||""} • ${(g.keep.q.createdAt||"").split("T")[0]||"—"}<br>PKR ${fmt(g.keep.q.totalAdult||0)}</div>
            <div class="dup-dupe"><b style="color:var(--er)">✖ DUPLICATE</b> ${d.q.invoiceNo||"?"}<br>${d.q.type||""} • ${(d.q.createdAt||"").split("T")[0]||"—"}<br>PKR ${fmt(d.q.totalAdult||0)}</div>
          </div>
          <div class="dup-actions">
            <button class="btn btn-sm btn-p" onclick="_pgDupQuotAct(${gi},${di},'merge')">🔀 Merge</button>
            <button class="btn btn-sm btn-d" onclick="_pgDupQuotAct(${gi},${di},'del')">🗑 Delete Dup</button>
            <button class="btn btn-sm" style="background:var(--ok);color:#fff" onclick="_pgDupQuotAct(${gi},${di},'view')">👁 View</button>
            <button class="btn btn-sm btn-o" onclick="_pgDupQuotAct(${gi},${di},'skip')">⏭ Skip</button>
          </div>
        </div>`).join("")).join("")}</div>`
    }
  </div>`;
  /* Store current dup lists for inline page actions */
  pg._hDupes=hDupes.slice();
  pg._qDupeGroups=qDupes.map(g=>({keep:{...g.keep},dupes:[...g.dupes]}));
}

/* Inline hotel dup action from pgDup page */
window._pgDupHotelAct=async(i,act)=>{
  const pg=$("CT").firstChild;if(!pg)return;
  const list=pg._hDupes;if(!list||!list[i])return;
  const it=list[i];

  if(act==="skip"){
    confirmModal("Skip this hotel duplicate for now?",()=>{
      if(it.skipKey)_skippedHotelDupes.add(it.skipKey);
      list.splice(i,1);nav("dup");
    },"Yes, Skip","btn-o");
    return;
  }

  if(act==="merge"){
    confirmModal(`<b>MERGE:</b> Missing details (distance/map/photo) from duplicate will be copied to the KEEP hotel and the duplicate entry will be deleted. Continue?`,async()=>{
      try{
        const changed=_mergeHotelFields(it.keep,it.dupe);
        if(it.keep.id)await bFS("hotels/"+it.city+"/"+it.keep.id,it.keep);
        if(it.dupe.id){await _trashAdd("hotel",(it.dupe.n||"Hotel"),(S.cities.find(x=>x.key===it.city)||{}).label||it.city,"hotels/"+it.city+"/"+it.dupe.id,it.dupe,{city:it.city});await bFD("hotels/"+it.city+"/"+it.dupe.id);}
        S.hotels[it.city]=(S.hotels[it.city]||[]).filter(x=>x.id!==it.dupe.id);
        toast(changed?"Merged ✅ — missing info was copied":"Merged ✅");
        list.splice(i,1);nav("dup");
      }catch(e){toast("Failed: "+e.message,"err")}
    },"Yes, Merge","btn-p");
    return;
  }

  if(act==="del"){
    confirmModal(`Delete duplicate hotel <b>${it.dupe.n}</b>? (Stays in Recycle Bin for 7 days)`,async()=>{
      try{
        if(it.dupe.id){await _trashAdd("hotel",(it.dupe.n||"Hotel"),(S.cities.find(x=>x.key===it.city)||{}).label||it.city,"hotels/"+it.city+"/"+it.dupe.id,it.dupe,{city:it.city});await bFD("hotels/"+it.city+"/"+it.dupe.id);}
        S.hotels[it.city]=(S.hotels[it.city]||[]).filter(x=>x.id!==it.dupe.id);
        toast("Duplicate deleted — Moved to Recycle Bin");
        list.splice(i,1);nav("dup");
      }catch(e){toast("Failed: "+e.message,"err")}
    },"Yes, Delete","btn-d");
  }
};
/* Inline quotation dup action from pgDup page */
window._pgDupQuotAct=async(gi,di,act)=>{
  const pg=$("CT").firstChild;if(!pg)return;
  const groups=pg._qDupeGroups;if(!groups||!groups[gi])return;
  const g=groups[gi];const d=g.dupes[di];if(!d)return;

  if(act==="view"){d.q.type==="group"?printGrp(d.q):printPvt(d.q);return}

  if(act==="skip"){
    confirmModal("Skip this quotation duplicate for now?",()=>{
      if(d.skipKey)_skippedQuotDupes.add(d.skipKey);
      g.dupes.splice(di,1);if(!g.dupes.length)groups.splice(gi,1);nav("dup");
    },"Yes, Skip","btn-o");
    return;
  }

  if(!P("quot","delete")&&!P("allquot","delete"))return toast("You don't have delete permission","err");

  if(act==="merge"){
    confirmModal(`<b>MERGE:</b> Duplicate <b>${d.q.invoiceNo||"?"}</b> will be deleted (moved to Recycle Bin) and missing info will be copied to KEEP entry <b>${g.keep.q.invoiceNo||"?"}</b>. Continue?`,async()=>{
      try{const changed=await _mergeQuotFields(g.keep.key,d.key);toast(changed?"Merged ✅":"Merged ✅ (nothing to copy)");g.dupes.splice(di,1);if(!g.dupes.length)groups.splice(gi,1);nav("dup")}catch(e){toast("Failed: "+e.message,"err")}
    },"Yes, Merge","btn-p");
    return;
  }

  if(act==="del"){
    confirmModal(`Delete duplicate <b>${d.q.invoiceNo||"?"}</b>? (Stays in Recycle Bin for 7 days)`,async()=>{
      try{await _trashAdd("quotation",(d.q.invoiceNo||"Quot")+" — "+(d.q.clientName||""),d.q.type==="group"?"Group":"Private","quotations/"+d.key,d.q,{});await bFD("quotations/"+d.key);delete S.quotations[d.key];toast("Duplicate deleted — Moved to Recycle Bin");g.dupes.splice(di,1);if(!g.dupes.length)groups.splice(gi,1);nav("dup")}catch(e){toast("Failed: "+e.message,"err")}
    },"Yes, Delete","btn-d");
  }
};

function pgLst(pg){const canAdd=P("lst","add");pg.innerHTML=`<div class="cd"><div class="cd-h">Lists</div>${[["airlines","Airlines","lstAir"],["classes","Classes","lstCls"],["vehicles","Vehicles","lstVeh"],["rooms","Rooms","lstRms"]].map(([k,l,id])=>`<div class="list-mgr"><div class="list-mgr-h">${l} (${S[k].length}) ${canAdd?`<button class="btn btn-sm btn-p" onclick="addLstItem('${k}','${l}')">+ Add</button>`:""}</div><div class="chip-list" id="${id}"></div></div>`).join("")}</div>`;renderChips()}
function renderChips(){const canEdit=P("lst","edit"),canDel=P("lst","delete");[["airlines","lstAir"],["classes","lstCls"],["vehicles","lstVeh"],["rooms","lstRms"]].forEach(([k,id])=>{const el=$(id);if(!el)return;el.innerHTML=S[k].map((x,i)=>`<span class="chip">${x} ${canEdit?`<button onclick="editLstItem('${k}',${i})" style="color:var(--p)">✏</button>`:""}${canDel?`<button onclick="delLstItem('${k}',${i})">×</button>`:""}</span>`).join("")||"<em style='color:var(--t2);font-size:.75rem'>Empty</em>"})}
window.addLstItem=(k,l)=>{if(!P("lst","add"))return toast("Not allowed","err");showModal("Add",`<div class="fg"><label>${l}</label><input id="lstName"></div>`,()=>{const v=$("lstName").value.trim();if(!v)return toast("Enter value","err")||false;if(S[k].some(x=>(x||"").trim().toLowerCase()===v.toLowerCase()))return toast("Already exists (duplicate)","err")||false;S[k].push(v);bFS("lists/"+k,S[k]).then(()=>{toast("Added");pgLst($("CT").firstChild)}).catch(e=>{toast("Save failed: "+e.message,"err");S[k].pop()});return true})};
window.editLstItem=(k,i)=>{if(!P("lst","edit"))return toast("Not allowed","err");showModal("Edit",`<div class="fg"><label>Value</label><input id="lstName" value="${S[k][i]}"></div>`,()=>{const v=$("lstName").value.trim();if(!v)return toast("Enter","err")||false;S[k][i]=v;bFS("lists/"+k,S[k]).then(()=>{toast("Updated");renderChips()}).catch(e=>toast("Update failed: "+e.message,"err"));return true})};
window.delLstItem=async(k,i)=>{if(!P("lst","delete"))return toast("Not allowed","err");confirmModal("Delete this item? (Stays in Recycle Bin for 7 days)",async()=>{const _v=S[k][i];await _trashAdd("lists",_v,"List: "+k,"",{value:_v,list:k},{value:_v,list:k});S[k].splice(i,1);await bFS("lists/"+k,S[k]).catch(e=>{toast("Delete failed: "+e.message,"err");return});toast("Deleted — Moved to Recycle Bin");pgLst($("CT").firstChild)});};

function pgUsr(pg){pg.innerHTML=`<div class="cd"><div class="cd-h">Users ${P("usr","add")?`<button class="btn btn-sm btn-p" onclick="addU()">+ Add</button>`:""}</div><div id="uL" style="margin-top:8px"></div></div>`;rU()}
let _userGroupOpen={};
async function rU(){try{S.users=await FR("users")||{}}catch(e){toast("Failed","err");return}
const el=$("uL");if(!el)return;const rows=Object.entries(S.users).filter(([k,u])=>canSeeUserRow(u));
if(!rows.length){el.innerHTML=`<p style="text-align:center;color:var(--t2);padding:20px">No users</p>`;return}
/* Har branch ka apna alag collapsible group — branch name pe click/arrow se admins+users khulte hain */
const groups={};
rows.forEach(([k,u])=>{
  const bid=(u.branchId&&S.branches?.[u.branchId])?u.branchId:"_none";
  const bname=bid==="_none"?"No Branch / Head Office":(S.branches[bid]?.name||u.branchName||"Branch");
  if(!groups[bid])groups[bid]={name:bname,rows:[]};
  groups[bid].rows.push([k,u]);
});
const orderedKeys=Object.keys(groups).filter(k=>k!=="_none").sort((a,b)=>groups[a].name.localeCompare(groups[b].name));
if(groups["_none"])orderedKeys.push("_none");
el.innerHTML=orderedKeys.map(bid=>{
  const g=groups[bid];const gid="ugrp_"+bid;const isOpen=!!_userGroupOpen[gid];
  const rowsHtml=g.rows.map(([k,u])=>{
    const mng=canManageUserRow(u);const ce=P("usr","edit")&&mng;const cd=P("usr","delete")&&mng&&k!==S.user.key;
    /* Password display — if hashed show lock icon, if plain show masked */
    const isHashed=u.p&&u.p.startsWith('h:');
    const pwCell=mng?(isHashed?`<span style="color:var(--ok);font-size:.8rem">🔒 Secured</span>`:`<span id="pwv_${k}" data-pw="${String(u.p||"").replace(/"/g,"&quot;")}">••••••</span> <button type="button" class="btn-icon" style="padding:2px 4px" onclick="togglePwRow('${k}')">👁</button>`):"••••••";
    return`<tr><td data-label="Full Name">${u.full||"—"}</td><td data-label="Username"><b>${u.u}</b></td><td data-label="Password">${pwCell}</td><td data-label="Role"><span class="bd bd-${roleBadge(u.r)}">${u.r}</span></td><td data-label="Actions">${ce?`<button class="btn-icon" onclick="eU('${k}')">✏</button>`:""} ${cd?`<button class="btn-icon" style="color:var(--er)" onclick="dU('${k}')">🗑</button>`:""}</td></tr>`;
  }).join("");
  return`<div class="branch-grp" style="margin-bottom:8px;border:1px solid var(--bd);border-radius:8px;overflow:hidden">
  <div onclick="toggleUserGroup('${gid}')" style="cursor:pointer;display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg2,#f8fafc);font-weight:700;font-size:.82rem">
    <span>🏢 ${g.name} <span style="font-weight:400;color:var(--t2);font-size:.72rem">(${g.rows.length})</span></span>
    <span id="arrow_${gid}" style="display:inline-block;transition:transform .15s${isOpen?';transform:rotate(90deg)':""}">▶</span>
  </div>
  <div id="${gid}" class="tw" style="display:${isOpen?"block":"none"};padding:0 4px">
    <table><thead><tr><th>Full Name</th><th>Username</th><th>Password</th><th>Role</th><th style="width:90px"></th></tr></thead><tbody>${rowsHtml}</tbody></table>
  </div>
</div>`;
}).join("");
}
window.toggleUserGroup=(gid)=>{
  const el=$(gid);if(!el)return;
  const open=el.style.display!=="none";
  el.style.display=open?"none":"block";
  _userGroupOpen[gid]=!open;
  const arrow=$("arrow_"+gid);
  if(arrow)arrow.style.transform=open?"rotate(0deg)":"rotate(90deg)";
};
window.togglePwRow=k=>{const el=$("pwv_"+k);if(!el)return;const shown=el.dataset.shown==="1";el.textContent=shown?"••••••":el.dataset.pw;el.dataset.shown=shown?"0":"1"};
window.onUserRoleChange=(gridId)=>{const r=$("uRole").value;const wrap=$(gridId+"_wrap");if(wrap)wrap.style.display=(r==="superadmin")?"none":"";permGridSetAll(gridId,false);const dp=defaultPerms(r);PERM_FEATURES.forEach(f=>f.acts.forEach(a=>{if(dp[f.key]&&dp[f.key][a]){const el=$(`${gridId}_${f.key}_${a}`);if(el)el.checked=true}}))};
/* Branch selector: show for all roles */
window.onUserRoleChangeBranch=(gridId)=>{onUserRoleChange(gridId)};
window.addU=()=>{if(!P("usr","add"))return toast("Not allowed","err");const rl=S.user.r==="superadmin"?["superadmin","admin","user"]:["user"];const gridId="addPermGrid";
const branchOpts=Object.entries(S.branches||{}).filter(([id,b])=>!b.disabled).map(([id,b])=>`<option value="${id}">${b.name}</option>`).join("");
const branchField=branchOpts?`<div id="uBranchWrap" class="fg"><label>Assigned Branch <small style="font-weight:400;text-transform:none">(determines which branch details print on quotations)</small></label><select id="uBranch"><option value="">-- No Branch --</option>${branchOpts}</select></div>`:``;
const defRole=rl[0];
showModal("Add User",`<div class="fg"><label>Full Name</label><input id="uFull"></div><div class="fg"><label>Username</label><input id="uName"></div><div class="fg"><label>Password</label><input type="password" id="uPass"><div style="font-size:.67rem;color:var(--t2);margin-top:2px">Min 6 characters</div></div><div class="fg"><label>Role</label><select id="uRole" onchange="onUserRoleChangeBranch('${gridId}')">${rl.map(r=>`<option>${r}</option>`).join("")}</select></div>${branchField}${permGridHtml(gridId,defaultPerms(defRole),defRole)}`,()=>{const u=$("uName").value.trim(),full=$("uFull").value.trim(),p=$("uPass").value.trim(),r=$("uRole").value,branchId=$("uBranch")?.value||"";if(!u||!p)return toast("Fill all fields","err")||false;if(p.length<6)return toast("Password must be at least 6 characters","err")||false;const perms=readPermGrid(gridId);const userData={u,r,full,perms};if(branchId){userData.branchId=branchId;const br=S.branches[branchId];if(br)userData.branchName=br.name||""}hashPw(p).then(hashed=>{userData.p=hashed;return bFS("users/"+u.toLowerCase().replace(/[^a-z0-9]/g,"")+Date.now().toString().slice(-4),userData)}).then(()=>{toast("User added!");rU()});return true});
// Apply initial visibility based on default role
setTimeout(()=>onUserRoleChangeBranch(gridId),50)};
window.eU=k=>{const target=S.users[k];if(!target||!canManageUserRow(target)||!P("usr","edit"))return toast("Not allowed","err");
const canChangeRole=S.user.r==="superadmin"&&k!==S.user.key;
const gridId="editPermGrid";
const roleField=canChangeRole?`<div class="fg"><label>Role</label><select id="uRole" onchange="onUserRoleChange('${gridId}')"><option ${target.r==="superadmin"?"selected":""}>superadmin</option><option ${target.r==="admin"?"selected":""}>admin</option><option ${target.r==="user"?"selected":""}>user</option></select></div>`:`<div class="fg"><label>Role</label><input value="${target.r}" disabled></div>`;
const branchOpts=Object.entries(S.branches||{}).filter(([id,b])=>!b.disabled).map(([id,b])=>`<option value="${id}" ${target.branchId===id?"selected":""}>${b.name}</option>`).join("");
const branchField=branchOpts?`<div class="fg"><label>Assigned Branch <small style="font-weight:400;text-transform:none">(determines which branch settings print on quotations)</small></label><select id="uBranch"><option value="">-- No Branch --</option>${branchOpts}</select></div>`:"";
showModal("Edit User: "+target.u,`<div class="fg"><label>Full Name</label><input id="uFull" value="${target.full||""}"></div><div class="fg"><label>New Password <small style="font-weight:400;text-transform:none">(leave blank = no change, min 6 chars)</small></label><input type="password" id="uPass" placeholder="Leave blank to keep current"></div>${roleField}${branchField}${permGridHtml(gridId,getPerms(target),target.r)}`,()=>{const full=$("uFull").value.trim(),p=$("uPass").value.trim();const r=canChangeRole?$("uRole").value:target.r;const branchId=$("uBranch")?.value||"";const perms=readPermGrid(gridId);if(p&&p.length<6)return toast("Password must be at least 6 characters","err")||false;const upd={full,r,perms};if(branchId){upd.branchId=branchId;const br=S.branches[branchId];if(br)upd.branchName=br.name||""}else{upd.branchId="";upd.branchName=""}
const doSave=(extraUpd)=>{
  const finalUpd=extraUpd?{...upd,...extraUpd}:upd;
  bFU("users/"+k,finalUpd).then(async()=>{
    if(k===S.user.key){S.user={...S.user,...finalUpd};saveSession()}
    const brMsg=branchId?` | Branch: ${finalUpd.branchName||branchId}`:" | Branch removed";
    toast("Updated!"+brMsg);
    // Auto-link unlinked quotations to the newly assigned branch
    if(branchId&&S.branches&&S.branches[branchId]){
      const targetUser=S.users[k]?.u||"";
      if(targetUser&&S.quotations){
        const toLink=Object.entries(S.quotations).filter(([qk,q])=>q.createdBy===targetUser&&(!q.branchId||q.branchId===""));
        if(toLink.length){
          await Promise.all(toLink.map(([qk])=>FU("quotations/"+qk,{branchId:branchId,branchName:finalUpd.branchName||""}).catch(()=>{})));
          toast(toLink.length+" quotation(s) linked to branch ✓");
          // Update local state
          toLink.forEach(([qk])=>{if(S.quotations[qk]){S.quotations[qk].branchId=branchId;S.quotations[qk].branchName=finalUpd.branchName||""}});
        }
      }
    }
    rU();
  });
};
if(p){hashPw(p).then(hashed=>{doSave({p:hashed})})}
else{doSave()}
return true});};
window.dU=async k=>{const target=S.users[k];if(!target||!canManageUserRow(target)||!P("usr","delete"))return toast("Not allowed","err");if(k===S.user.key)return toast("Can't delete self","err");confirmModal("Delete this user? (Stays in Recycle Bin for 7 days)",async()=>{await _trashAdd("users",target.u||"User","User account","users/"+k,target,{});await bFD("users/"+k).catch(e=>{toast("Delete failed: "+e.message,"err");return});toast("Deleted — Moved to Recycle Bin");rU()});};

function pgSet(pg){const s=S.settings;const ro=!P("set","edit");pg.innerHTML=`<div class="cd"><div class="cd-h">Settings${ro?` <span class="bd bd-u">View Only</span>`:""}</div><div class="g2" ${ro?'style="opacity:.7;pointer-events:none"':''}>
<div class="fg"><label>Company</label><input id="sC" value="${s.company||""}"></div>
<div class="fg"><label>License</label><input id="sL" value="${s.license||""}"></div>
<div class="fg gf"><label>Address</label><input id="sA" value="${s.address||""}"></div>
<div class="fg"><label>Website</label><input id="sW" value="${s.website||""}"></div>
<div class="fg"><label>Phone</label><input id="sPh" value="${s.phone||""}"></div>
<div class="fg"><label>Email</label><input id="sEm" value="${s.email||""}"></div>
<div class="fg"><label>Brand Color (report banners)</label><input type="color" id="sBC" value="${s.brandColor||"#1e40af"}" style="height:38px;padding:2px;cursor:pointer"></div>
<div class="fg gf"><label>Disclaimer</label><input id="sD" value="${s.disclaimer||""}"></div>
<div class="fg gf"><label>Instructions / Terms & Conditions (auto-fits to one page in PDF)</label><textarea id="sI" rows="12" style="font-family:'Segoe UI','Noto Nastaliq Urdu',Arial,sans-serif;line-height:1.7;font-size:.85rem">${(s.instructions||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}</textarea></div>
<div class="fg"><label>Prefix</label><input id="sIP" value="${s.invoicePrefix||"PGT"}"></div>
<div class="fg"><label>Next #</label><input type="number" id="sIN" value="${s.invoiceNext||1}"></div>
<div class="fg"><label>ROE Adult</label><input type="number" id="sROE" value="${s.defaultROE||78}"></div>
<div class="fg"><label>ROE Infant</label><input type="number" id="sIROE" value="${s.defaultInfantROE||77}"></div>
<div class="fg"><label>Visa SAR Adult</label><input type="number" id="sVA" value="${s.visaAdultSAR||560}"></div>
<div class="fg"><label>Visa SAR Infant</label><input type="number" id="sVI" value="${s.visaInfantSAR||0}"></div>
<div class="fg gf"><label>Logo URL</label><input id="sLo" value="${s.logo||""}"></div>
<div class="fg gf"><label>Upload Logo</label><input type="file" id="sLoFile" accept="image/*" onchange="uploadLogo()"></div>
${s.logo?`<div class="fg gf"><img src="${s.logo}" style="height:80px;border-radius:8px;background:#f0f0f0;padding:6px"></div>`:""}</div>
<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;padding-top:12px;border-top:1px solid var(--bd)">
${ro?"":`<button class="btn btn-p" onclick="saveSt()">Save Settings</button>`}
<button class="btn btn-o" onclick="chPw()">🔑 Change My Password</button>
${P("backup","view")?`
<button class="btn btn-sm" style="background:#059669;color:#fff;padding:9px 16px;border-radius:8px;font-size:.78rem;font-weight:700;border:none;cursor:pointer" onclick="manualFullBackup()" title="Download complete database backup JSON">⬇ Manual Backup</button>
<button class="btn btn-sm" style="background:#7c3aed;color:#fff;padding:9px 16px;border-radius:8px;font-size:.78rem;font-weight:700;border:none;cursor:pointer" onclick="pickBackupFolder()" title="Chrome/Edge: choose a folder — backups save here automatically">📁 Set Backup Folder</button>
`:""}
${S.user.r==="superadmin"?`
<button class="btn btn-sm" style="background:#0ea5e9;color:#fff;padding:9px 16px;border-radius:8px;font-size:.78rem;font-weight:700;border:none;cursor:pointer" onclick="restoreFromBackup()" title="Restore from a previously downloaded backup JSON file">⬆ Restore Backup</button>
<button class="btn btn-d" onclick="rstAll()">⚠ Reset All Quotations</button>
`:""}
</div>
${P("backup","view")?`
<div style="background:#ecfdf5;border:1px solid #6ee7b7;border-radius:8px;padding:12px 14px;margin-top:10px">
  <div style="font-size:.78rem;font-weight:800;color:#065f46;margin-bottom:6px">💾 Backup System Status${S.user.r!=="superadmin"?` <span style="font-weight:600;color:#047857">(for this PC — granted by SuperAdmin)</span>`:""}</div>
  <div style="font-size:.72rem;color:#047857;line-height:1.7">
    ✅ <b>Live Backup:</b> Checks every 60 seconds when data changes and saves to a single file (<code>PGT_LiveBackup_LATEST.json</code>) — as long as data grows or stays the same. If any entry gets <b>deleted/reduced</b>, the old file is NOT overwritten — that state is saved to a <b>new CHECKPOINT file</b> instead, so the last complete backup is always preserved.<br>
    ⏰ <b>Hourly Backup:</b> An extra safety copy every hour (file: <code>PGT_HourlyBackup_LATEST.json</code>) — it follows the same delta-aware logic<br>
    📁 <b>Backup Folder:</b> <span id="backupFolderStatus">Downloads (default — no folder set)</span><br>
    <small style="opacity:.85">In Chrome/Edge, select a folder once via "Set Backup Folder" — after that, all backups save directly to that folder. This doesn't work in Firefox/Safari, where you'll get the normal Downloads folder instead.</small><br>
    🔄 <b>Restore:</b> Use "Restore Backup" above to restore the whole system from any backup JSON file (SuperAdmin only)
  </div>
</div>
`:""}
</div>`}

window.uploadLogo=()=>{const f=$("sLoFile")?.files?.[0];if(!f)return;if(!f.type.startsWith("image/")){toast("Please choose an image file","err");return}compressImg(f,240,0.8).then(dataUrl=>{$("sLo").value=dataUrl;toast("Logo loaded! Click Save to apply.")}).catch(()=>toast("Could not process image","err"))};
window.saveSt=async()=>{if(!P("set","edit"))return toast("Not allowed","err");confirmModal("Save the current settings?",async()=>{const ns={company:$("sC")?.value||"",license:$("sL")?.value||"",address:$("sA")?.value||"",website:$("sW")?.value||"",phone:$("sPh")?.value||"",email:$("sEm")?.value||"",disclaimer:$("sD")?.value||"",instructions:$("sI")?.value||"",invoicePrefix:$("sIP")?.value||"PGT",invoiceNext:n($("sIN")?.value)||1,logo:$("sLo")?.value||"",brandColor:$("sBC")?.value||"#1e40af",visaAdultSAR:n($("sVA")?.value)||560,visaInfantSAR:n($("sVI")?.value)||0,defaultROE:n($("sROE")?.value)||78,defaultInfantROE:n($("sIROE")?.value)||77};try{await bFS("settings",ns)}catch(e){toast("Settings save failed: "+e.message,"err");return}S.settings=ns;applySidebarBranding();toast("Settings saved!")},"Yes, Save","btn-p")};
window.chPw=()=>{showModal("Change Password",`<div class="fg"><label>New Password</label><input type="password" id="npass"><div style="font-size:.67rem;color:var(--t2);margin-top:2px">Min 6 characters</div></div><div class="fg"><label>Confirm Password</label><input type="password" id="npass2"></div>`,()=>{const p=$("npass").value.trim(),p2=$("npass2").value.trim();if(!p)return toast("Enter password","err")||false;if(p.length<6)return toast("Password must be at least 6 characters","err")||false;if(p!==p2)return toast("Passwords do not match","err")||false;hashPw(p).then(hashed=>{bFU("users/"+S.user.key,{p:hashed}).then(()=>{S.user.p=hashed;saveSession();toast("Password changed! Logging out...");setTimeout(()=>doLogout(),1500)})});return true});};
window.rstAll=()=>{showModal("Reset",`<p style="color:var(--er)">Delete ALL quotations!</p><div class="fg"><label>Type RESET</label><input id="rstConf"></div>`,()=>{if($("rstConf").value!=="RESET")return toast("Type RESET","err")||false;FD("quotations").then(()=>FU("settings",{invoiceNext:1})).then(()=>{S.quotations={};S.settings.invoiceNext=1;toast("Cleared")});return true})};

setTimeout(()=>{$("lgU")?.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();$("lgP").focus()}})},100);
window.addEventListener("resize",()=>{if(innerWidth>=769){$("SB").classList.remove("closed");$("SB").classList.remove("open");$("sbOv").classList.remove("show")}else{if(!$("SB").classList.contains("open"))$("SB").classList.add("closed")}});

/* ===== GLOBAL SEARCH ===== */
let _gsTimer=null;
function gSearchInit(){const inp=$("gSearch"),dd=$("gSearchResults");if(!inp||!dd)return;
inp.addEventListener("input",()=>{clearTimeout(_gsTimer);const q=inp.value.trim();if(!q){dd.classList.remove("show");dd.innerHTML="";return}_gsTimer=setTimeout(()=>gSearchRun(q),200)});
inp.addEventListener("keydown",e=>{if(e.key==="Escape"){dd.classList.remove("show");inp.blur()}if(e.key==="Enter"){const first=dd.querySelector(".gs-item");if(first)first.click()}});
document.addEventListener("click",e=>{if(!e.target.closest(".gsearch-wrap"))dd.classList.remove("show")})}
function gSearchRun(q){const dd=$("gSearchResults");if(!dd)return;const ql=q.toLowerCase();const results=[];
const seeAll=P("allquot","view");const entries=Object.entries(S.quotations||{});
const myQ=seeAll?entries:entries.filter(([k,v])=>v.createdBy===S.user.u);
myQ.forEach(([k,v])=>{const cn=(v.clientName||"").toLowerCase(),inv=(v.invoiceNo||"").toLowerCase(),ct=(v.contactNo||"").toLowerCase();
if(cn.includes(ql)||inv.includes(ql)||ct.includes(ql)){results.push({type:"quot",icon:v.type==="group"?"👥":"📝",title:v.clientName||"—",sub:`${v.invoiceNo||""} • ${v.type} • PKR ${fmt(v.totalAdult||0)}`,key:k})}});
Object.entries(S.hotels||{}).forEach(([city,list])=>{(list||[]).forEach((h,i)=>{if((h.n||"").toLowerCase().includes(ql)){const cLabel=(S.cities.find(c=>c.key===city)||{}).label||city;results.push({type:"hotel",icon:"🏨",title:h.n,sub:`${cLabel} • ${h.d||""}`,city,idx:i})}})});
if(results.length>20)results.length=20;
gSearchRender(results,q)}
function gSearchRender(results,q){const dd=$("gSearchResults");if(!dd)return;
if(!results.length){dd.innerHTML=`<div class="gs-empty">No results for "${_esc(q)}"</div>`;dd.classList.add("show");return}
dd.innerHTML=results.map((r,i)=>`<div class="gs-item" data-idx="${i}" data-type="${r.type}" data-key="${r.key||""}" data-city="${r.city||""}"><span class="gs-ic">${r.icon}</span><div class="gs-info"><div class="gs-title">${_esc(r.title)}</div><div class="gs-sub">${_esc(r.sub)}</div></div></div>`).join("");
dd.classList.add("show");
dd.querySelectorAll(".gs-item").forEach(el=>{el.addEventListener("click",()=>{const t=el.dataset.type;if(t==="quot"){const k=el.dataset.key;viewQ(k)}else if(t==="hotel"){nav("htl")}
dd.classList.remove("show");$("gSearch").value=""})})}

/* ===== EXCEL/CSV EXPORT ===== */
window.exportQuotCSV=(filterFn,filename)=>{const entries=Object.entries(S.quotations||{}).filter(([k,v])=>filterFn(v));
if(!entries.length){toast("No quotations to export","warn");return}
const hdr="Invoice#,Client,Type,Contact,Amount (PKR),Date,Created By,Branch";
const rows=entries.map(([k,v])=>{const dt=v.createdAt?new Date(v.createdAt).toLocaleDateString():"";const by=fullNameOf(v.createdBy)||v.createdBy||"";return`"${(v.invoiceNo||"").replace(/"/g,'""')}","${(v.clientName||"").replace(/"/g,'""')}","${v.type||""}","${(v.contactNo||"").replace(/"/g,'""')}",${v.totalAdult||0},"${dt}","${by.replace(/"/g,'""')}","${(v.branchName||"").replace(/"/g,'""')}"`});
const csv=hdr+"\n"+rows.join("\n");const blob=new Blob(["\uFEFF"+csv],{type:"text/csv;charset=utf-8;"});const url=URL.createObjectURL(blob);
const a=document.createElement("a");a.href=url;a.download=(filename||"Quotations")+"_"+new Date().toISOString().slice(0,10)+".csv";document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);toast(`Exported ${entries.length} quotation(s) to CSV`)};

window.exportAllQuotFiltered=()=>{const fUser=$("qAllUserFilter")?.value||"";const fType=$("qAllTypeFilter")?.value||"";const fBranch=$("qAllBranchFilter")?.value||"";const fn=v=>{if(fBranch&&v.branchId!==fBranch)return false;if(fUser&&v.createdBy!==fUser)return false;if(fType&&fType==="group"&&v.type!=="group")return false;if(fType&&fType==="private"&&v.type==="group")return false;return true};exportQuotCSV(fn,"All_Quotations")};

/* ===== QUICK CLONE QUOTATION ===== */
window.cloneQuotation=key=>{const q=S.quotations[key];if(!q)return toast("Quotation not found","err");
const clone=JSON.parse(JSON.stringify(q));delete clone.invoiceNo;delete clone.createdAt;delete clone.updatedAt;delete clone.createdBy;delete clone.updatedBy;delete clone.branchId;delete clone.branchName;
editKey=null;_quoteOpenedTs=Date.now();
if(q.type==="group"){nav("grp");setTimeout(()=>loadGrpForm(clone),100)}else{nav("pvt");setTimeout(()=>loadPvtForm(clone),100)}
toast("Cloned! Modify details and save as new quotation.")};

/* ===== UNSAVED CHANGES WARNING =====
   Jab user quotation edit kar raha ho aur achanak page band ya refresh kar de,
   to browser warning dikhaye — taake mehnat se banaya hua quotation ghalti se
   lose na ho. Yeh ek chota sa safety net hai. */
window.addEventListener("beforeunload",function(e){
  if(editKey){
    e.preventDefault();
    e.returnValue="You have unsaved changes. Are you sure you want to leave?";
    return e.returnValue;
  }
});

/* ===== AUTO-SAVE DRAFT (quotation form data backup to IndexedDB) =====
   Har 15 second quotation form ka draft IndexedDB mein save hota hai.
   Agar browser crash/refresh ho jaye to draft wapas aa sakta hai.
   Yeh user ki mehnat bachata hai jab internet ya system issue ho. */
let _draftSaveTimer=null;
function _startDraftAutoSave(){
  if(_draftSaveTimer)clearInterval(_draftSaveTimer);
  _draftSaveTimer=setInterval(async()=>{
    if(!editKey)return; /* sirf editing mein draft save karo */
    try{
      const ct=$("CT");
      if(!ct)return;
      /* Check if we're on pvt or grp page */
      const pN=$("pN"),gC=$("gC");
      if(pN){await _idbSet("draft_pvt",JSON.stringify({clientName:pN.value,ts:Date.now()}))}
      else if(gC){await _idbSet("draft_grp",JSON.stringify({clientName:gC.value,ts:Date.now()}))}
    }catch(e){/* silently fail — draft save is non-critical */}
  },15000);
}
_startDraftAutoSave();

/* ===== AUTO-REFRESH ON TAB VISIBILITY CHANGE =====
   Jab user doosre tab/window mein kaam kar ke wapas is tab par aaye,
   to data automatically refresh ho jaye — taake doosre user ke changes
   ya khud ke doosre device ke changes turant nazar aayein.
   Pehle yeh feature nahi tha — user ko manually refresh button dabana
   parta tha ya logout/login karna parta tha.
   Rule: Agar 30 second se ziyada doosre tab mein raha to auto-refresh karo. */
let _lastVisibleTs=Date.now();
document.addEventListener("visibilitychange",async()=>{
  if(!S.user)return;
  if(document.visibilityState==="hidden"){
    _lastVisibleTs=Date.now();
    autoSaveDraftNow();
  }else if(document.visibilityState==="visible"){
    const away=Date.now()-_lastVisibleTs;
    if(away>30000){
      try{
        await loadData();
        await loadBranchesAndApply();
        applySidebarBranding();
        buildSB();
        if(curPage!=="pvt"&&curPage!=="grp"){
          nav(curPage);
        }
        toast("Auto-refreshed ✓");
      }catch(e){}
    }
  }
});
window.addEventListener("blur",()=>autoSaveDraftNow());
window.addEventListener("beforeunload",()=>autoSaveDraftNow());

boot();
