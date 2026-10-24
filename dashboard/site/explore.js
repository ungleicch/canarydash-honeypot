// Explore: local, read-only querying of the static archive via /api/x/* on this machine. Not a live feed.
(()=>{
const LC="cowrie.login.success,cowrie.login.failed",PT={timeZone:"America/Los_Angeles"},OFF=7*3600e3;
const FIELDS=[["era","Source","multi"],["from","From (PT)","dt"],["to","To (PT)","dt"],["ip","IP / CIDR (comma-separated)","text"],["proto","Protocol","sel"],["eventid","Event type","multi"],["port","Port","text"],["usr","Username (exact; (empty) = blank)","text"],["pwd","Password (exact; (empty) = blank)","text"],["cmd","Command contains","text"],["hash_like","Malware hash contains","text"],["url","URL / path contains","text"],["country","Country","sel"],["asn","ASN / network contains","text"],["persona","Persona","sel"],["sess","Session id","text"]];
const XS=[["hour","Time · hour"],["day","Time · day"],["minute","Time · minute"],["hourofday","Hour of day (PT)"],["weekday","Weekday (PT)"],["ip","IP"],["country","Country"],["asn","ASN"],["port","Port"],["usr","Username"],["pwd","Password"],["cmd","Command"],["hash","Malware hash"],["url","URL"],["eventid","Event type"],["era","Source"],["proto","Protocol"],["persona","Persona"],["sess","Session"]];
const YS=[["events","Events"],["ips","Unique IPs"],["sessions","Sessions"],["downloads","Downloads"]],TYPES=["line","area","bar","stacked bar","pie","heatmap","scatter"];
const TIMEX=new Set(["hour","day","minute"]),WD=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
const pt=(s)=>{if(!s)return"";const[d,t]=s.split("T"),[y,m,dd]=d.split("-").map(Number),[h,mi]=(t||"0:0").split(":").map(Number);return Date.UTC(y,m-1,dd,h,mi)+OFF};
const fmt=(ms,x)=>{const d=new Date(ms);if(x==="day")return d.toLocaleDateString("en-US",{...PT,month:"short",day:"numeric"});return d.toLocaleString("en-US",{...PT,month:"short",day:"numeric",hour:"2-digit",minute:x==="minute"?"2-digit":undefined,hour12:false})};
const lab=(v,x)=>v==null?"(none)":TIMEX.has(x)?fmt(v,x):x==="weekday"?WD[v]:x==="hourofday"?String(v).padStart(2,"0")+":00":v===""?"(empty)":String(v);
const EX=[
 ["“ximo” campaign over time","Logins with username ximo, by hour, split by country",{f:{usr:"ximo",eventid:LC},c:{type:"stacked bar",x:"hour",y:"events",split:"country",top:5}}],
 ["mdrfckr key planters by country","Sessions that wrote the mdrfckr SSH key, unique IPs by country",{f:{cmd:"mdrfckr"},c:{type:"bar",x:"country",y:"ips",top:15}}],
 ["Telnet vs SSH per hour","Cowrie sessions per hour by protocol",{f:{eventid:"cowrie.session.connect"},c:{type:"area",x:"hour",y:"events",split:"proto"}}],
 ["One IP's full timeline","182.115.160.251, the busiest IP: events per hour by type",{f:{ip:"182.115.160.251"},c:{type:"stacked bar",x:"hour",y:"events",split:"eventid",top:6}}],
 ["Malware 12013662… spread","Downloads of the top hash per day, unique IPs by country",{f:{hash_like:"12013662",eventid:"cowrie.session.file_download"},c:{type:"stacked bar",x:"day",y:"ips",split:"country",top:6}}],
 ["Redis hits by ASN","OpenCanary Redis (6379) events by network, log scale",{f:{port:"6379"},c:{type:"bar",x:"asn",y:"events",top:12,log:1}}],
 ["Events during the known gap","2026-10-16 10:00 to 10-17 17:00 PT, by source (Cowrie outage)",{f:{from:"2026-10-16T08:00",to:"2026-10-17T18:00"},c:{type:"line",x:"hour",y:"events",split:"era",log:1}}],
 ["Top passwords for root","Login attempts with username root, by password",{f:{usr:"root",eventid:LC},c:{type:"bar",x:"pwd",y:"events",top:20}}],
 ["Time-of-day heatmap","All Cowrie sessions, weekday × hour (PT)",{f:{eventid:"cowrie.session.connect"},c:{type:"heatmap",x:"hourofday",y:"events",split:"weekday"}}]];
let XHEAT=null,META=null,ST=null,CH=null,TS={sort:"ts",dir:"desc",page:0},tm=null,seq=0;
const q=(ep,p)=>{const u=new URLSearchParams({f:JSON.stringify(ST.f),...p});return fetch(`/api/x/${ep}?${u}`,{cache:"no-store"}).then(async r=>{const j=await r.json();if(!r.ok||j.error)throw new Error(j.error||r.status);return j})};
const wire=(f)=>{const o={},nt=[];for(const[k,v]of Object.entries(f)){if(k==="not")continue;if(v===""||v==null||(Array.isArray(v)&&!v.length))continue;o[k]=k==="from"||k==="to"?pt(v):v}(f.not||[]).forEach(k=>{if(o[k]!=null)nt.push(k)});if(nt.length)o.not=nt;return o};
function save(){location.replace("#explore?s="+encodeURIComponent(btoa(unescape(encodeURIComponent(JSON.stringify(ST))))))}
function load(){const m=location.hash.match(/s=([^&]+)/);try{if(m)return JSON.parse(decodeURIComponent(escape(atob(decodeURIComponent(m[1])))))}catch(e){}return{f:{},c:{type:"line",x:"hour",y:"events",split:"",top:10,log:0}}}
const opt=(arr,sel)=>arr.map(a=>{const[v,l]=Array.isArray(a)?a:[a,a];return`<option value="${esc(v)}"${String(sel)===String(v)?" selected":""}>${esc(l)}</option>`}).join("");
function field([k,l,t]){const v=ST.f[k]??"",neg=(ST.f.not||[]).includes(k),nb=t==="dt"?"":`<label class="neg" title="Exclude matches"><input type="checkbox" data-neg="${k}"${neg?" checked":""}>exclude</label>`;
 let inp;if(t==="dt")inp=`<input type="datetime-local" data-k="${k}" value="${esc(v)}">`;
 else if(t==="multi"){const vals=Array.isArray(v)?v:String(v).split(",").filter(Boolean);inp=`<select multiple size="${k==="era"?3:5}" data-k="${k}">${(META[k]||[]).map(o=>`<option${vals.includes(o)?" selected":""}>${esc(o)}</option>`).join("")}</select>`}
 else if(t==="sel")inp=`<select data-k="${k}"><option value="">Any</option>${(META[k]||[]).map(o=>`<option${o===v?" selected":""}>${esc(o)}</option>`).join("")}</select>`;
 else inp=`<input data-k="${k}" value="${esc(v)}" spellcheck="false">`;
 return`<div class="fld"><div class="fl"><span>${l}</span>${nb}</div>${inp}</div>`}
function ui(){const c=ST.c,r=META.range;$("#main").innerHTML=`<h1>Explore</h1><p class="lede">Query the archive on this machine. Pick a subset of the data, count it, chart it and export it. Filters are combined with AND, and "exclude" turns a filter into NOT. Queries run on your own computer against the bundled logs (${nf(r[2])} entries, ${fmt(r[0],"hour")} to ${fmt(r[1],"hour")} PT). This is not a live feed.</p>
<div class="exs">${EX.map((e,i)=>`<button class="ex" data-ex="${i}"><b>${esc(e[0])}</b><span>${esc(e[1])}</span></button>`).join("")}</div>
<div class="grid"><section class="card w12"><div class="hd"><h3>Filters</h3><span class="sp"></span>
<span class="presets">Time: <button data-pr="all">All</button><button data-pr="d1">First day</button><button data-pr="last24">Last 24 h</button><button data-pr="gap">Cowrie outage</button><button data-pr="oom">VM freeze</button></span><button id="xclear">Clear</button></div>
<div class="flds">${FIELDS.map(field).join("")}</div>
<div class="cnt"><span id="xcount">…</span><span id="xcmeta"></span></div></section>
<section class="card w12"><div class="hd"><h3>Chart</h3><span class="sp"></span>
<label>Type <select data-c="type">${opt(TYPES,c.type)}</select></label><label>X / group by <select data-c="x">${opt(XS,c.x)}</select></label><label>Y <select data-c="y">${opt(YS,c.y)}</select></label>
<label>Split by <select data-c="split"><option value="">None</option>${opt(XS,c.split)}</select></label><label>Top N <input data-c="top" type="number" min="1" max="200" value="${c.top||10}" style="width:60px"></label><label><input type="checkbox" data-c="log"${c.log?" checked":""}> Log scale</label></div>
<div class="hd" id="xchtools" style="margin:-4px 0 8px"><span class="sp"></span></div><div class="ch tall" id="xchwrap"><canvas id="xch"></canvas></div><div id="xheat" class="heat2"></div><p class="note" id="xcnote"></p></section>
<section class="card w12"><div class="hd"><h3>Matching entries</h3><span class="sp"></span><span id="xpg"></span><button id="xprev">Prev</button><button id="xnext">Next</button><a id="xcsv" class="btn" href="#">Export CSV</a></div><div class="tw" id="xtbl"></div></section></div>`;
 $("#main").querySelectorAll("[data-k]").forEach(e=>e.addEventListener(e.tagName==="INPUT"&&e.type!=="datetime-local"?"input":"change",()=>{const k=e.dataset.k;ST.f[k]=e.multiple?[...e.selectedOptions].map(o=>o.value).join(","):e.value;changed()}));
 $("#main").querySelectorAll("[data-neg]").forEach(e=>e.onchange=()=>{const s=new Set(ST.f.not||[]);e.checked?s.add(e.dataset.neg):s.delete(e.dataset.neg);ST.f.not=[...s];changed()});
 $("#main").querySelectorAll("[data-c]").forEach(e=>e.onchange=()=>{const k=e.dataset.c;ST.c[k]=e.type==="checkbox"?(e.checked?1:0):e.type==="number"?+e.value:e.value;save();chart()});
 $("#main").querySelectorAll("[data-ex]").forEach(b=>b.onclick=()=>{EXN=EX[+b.dataset.ex][0];const e=EX[+b.dataset.ex][2];ST=JSON.parse(JSON.stringify({f:e.f,c:{top:10,log:0,split:"",...e.c}}));TS.page=0;save();ui();run()});
 $("#main").querySelectorAll("[data-pr]").forEach(b=>b.onclick=()=>{const p=b.dataset.pr,R={all:["",""],d1:["2026-10-14T20:00","2026-10-15T20:00"],last24:["2026-10-22T16:16","2026-10-23T16:17"],gap:["2026-10-16T10:00","2026-10-17T17:00"],oom:["2026-10-15T09:00","2026-10-15T11:30"]}[p];ST.f.from=R[0];ST.f.to=R[1];save();ui();run()});
 CDX.tools($("#xchtools"),()=>{const c=ST.c,xl=(XS.find(a=>a[0]===c.x)||[0,c.x])[1],yl=(YS.find(a=>a[0]===c.y)||[0,c.y])[1],sl=c.split?(XS.find(a=>a[0]===c.split)||[0,c.split])[1]:"";
  return{title:`${yl} by ${xl}${sl?` split by ${sl}`:""}`,name:"explore-"+(EXN||summary().slice(0,40)),caption:["Filters: "+summary(),"Time range (PT): "+(ST.f.from||"start")+" to "+(ST.f.to||"end")+(ST.f.from||ST.f.to?"":" (full archive, 2026-10-14 20:51 to 2026-10-23 16:16)"),`Chart: ${c.type}${c.log?", log scale":""}${c.split?`, top ${c.top}`:""}`],chart:CH,heat:XHEAT}});
 $("#xclear").onclick=()=>{ST.f={};TS.page=0;save();ui();run()};
 $("#xprev").onclick=()=>{if(TS.page>0){TS.page--;table()}};$("#xnext").onclick=()=>{TS.page++;table()};
 $("#xcsv").onclick=e=>{e.preventDefault();const u=new URLSearchParams({f:JSON.stringify(wire(ST.f)),sort:TS.sort,dir:TS.dir});location.href="/api/x/csv?"+u}}
function summary(){const f=ST.f,neg=new Set(f.not||[]),p=[];for(const[k,l]of FIELDS.map(a=>[a[0],a[1]])){if(k==="from"||k==="to")continue;const v=f[k];if(v==null||v===""||(Array.isArray(v)&&!v.length))continue;p.push(`${l.split(" (")[0]} ${neg.has(k)?"≠":"="} ${Array.isArray(v)?v.join(","):v}`)}return p.join(" · ")||"none (all entries)"}
let EXN="";
function changed(){EXN="";TS.page=0;save();clearTimeout(tm);tm=setTimeout(run,350)}
async function count(){const n=++seq;$("#xcount").textContent="Counting…";try{const r=await qq("count");if(n!==seq)return;$("#xcount").innerHTML=`<b>${nf(r.count)}</b> matching entries · ${nf(r.ips)} unique IPs`;$("#xcmeta").textContent=(r.first_ts?`${fmt(r.first_ts,"minute")} to ${fmt(r.last_ts,"minute")} PT · `:"")+`${r.ms} ms`}catch(e){$("#xcount").textContent="Error: "+e.message;$("#xcmeta").textContent=""}}
const qq=(ep,p={})=>{const s=ST.f;ST.f=wire(s);const pr=q(ep,p);ST.f=s;return pr};
async function table(){try{const r=await qq("rows",{sort:TS.sort,dir:TS.dir,page:TS.page,size:50});$("#xpg").textContent=`Page ${TS.page+1} · ${r.ms} ms`;
 $("#xtbl").innerHTML=`<table><thead><tr>${r.cols.map(c=>`<th data-s="${c}" class="srt">${c}${TS.sort===c?(TS.dir==="asc"?" ↑":" ↓"):""}</th>`).join("")}</tr></thead><tbody>${r.rows.map(row=>`<tr>${row.map((v,i)=>`<td class="${["cmd","hash","url","sess","pwd","usr","asn"].includes(r.cols[i])?"mono clip":""}"${v!=null&&i>0?` title="${esc(String(v).slice(0,2000))}"`:""}>${v==null?"":esc(i===0?fmt(v,"minute")+":"+String(new Date(v).getUTCSeconds()).padStart(2,"0"):String(v).slice(0,2000))}</td>`).join("")}</tr>`).join("")||`<tr><td colspan="15" class="note">No rows</td></tr>`}</tbody></table>`;
 $("#xtbl").querySelectorAll("td.clip").forEach(td=>td.onclick=()=>td.classList.toggle("open"));$("#xtbl").querySelectorAll("th.srt").forEach(th=>th.onclick=()=>{const s=th.dataset.s;TS.dir=TS.sort===s&&TS.dir==="desc"?"asc":"desc";TS.sort=s;TS.page=0;table()})}catch(e){$("#xtbl").innerHTML=`<p class="note">Error: ${esc(e.message)}</p>`}}
async function chart(){const c=ST.c;XHEAT=null;if(CH){CH.destroy();CH=null}$("#xheat").innerHTML="";$("#xchwrap").style.display="";$("#xcnote").textContent="Loading…";
 try{const split=c.type==="heatmap"&&!c.split?(c.x==="hourofday"?"weekday":"era"):c.split;const r=await qq("agg",{x:c.x,y:c.y,split:split||"",top:c.top||10});
 const tx=TIMEX.has(c.x)||c.x==="hourofday"||c.x==="weekday",ac=css("--ac"),tx2=css("--tx"),dim=css("--mu");
 const P=[ac,tx2,dim,"#c9a227","#3ecf8e","#e07a5f","#9b8cff","#5fb3c4","#b8b8be","#d97aa5","#7f8c4f","#6d6d74"];
 let keys=[];if(tx){const s=new Set();r.series.forEach(se=>se.points.forEach(p=>s.add(p[0])));keys=[...s].sort((a,b)=>a-b);
  const STEP={minute:60e3,hour:3600e3,day:86400e3}[c.x];if(c.x==="hourofday")keys=[...Array(24).keys()];else if(c.x==="weekday")keys=[...Array(7).keys()];
  else if(STEP&&keys.length&&(keys[keys.length-1]-keys[0])/STEP<5000){const a=[];for(let k=keys[0];k<=keys[keys.length-1];k+=STEP)a.push(k);keys=a}}else{const t={};r.series.forEach(se=>se.points.forEach(p=>t[p[0]]=(t[p[0]]||0)+(+p[1]||0)));keys=Object.keys(t).sort((a,b)=>t[b]-t[a]);if(r.series.length===1)keys=r.series[0].points.map(p=>p[0])}
 const labels=keys.map(k=>lab(k,c.x)),val=(se)=>{const m=new Map(se.points.map(p=>[String(p[0]),p[1]]));return keys.map(k=>{const v=m.get(String(k))??(tx?0:null);return c.log&&v===0?null:v})};
 const sn=(se)=>split?lab(se.name,split):(YS.find(y=>y[0]===c.y)||[0,c.y])[1];
 const total=r.series.reduce((a,se)=>a+se.points.reduce((b,p)=>b+(+p[1]||0),0),0);
 $("#xcnote").textContent=`${labels.length} groups${split?` × ${r.series.length} series (top ${r.series.length})`:""} · ${r.ms} ms${c.x==="minute"&&labels.length>=2000?" · capped at 2,000 minute buckets, narrow the time range":""}${c.y!=="events"&&split?" · unique counts are per group":""}${tx?(c.log?" · empty buckets show as breaks (log scale can't plot 0)":" · empty buckets plotted as 0"):""}`;
 if(c.type==="heatmap"){$("#xchwrap").style.display="none";const rows=r.series.map(se=>({n:sn(se),v:val(se)})),mx=Math.max(1,...rows.flatMap(x=>x.v.map(Number).filter(Boolean)));
  if(split==="weekday")rows.sort((a,b)=>WD.indexOf(a.n)-WD.indexOf(b.n));XHEAT={rows,labels};
  $("#xheat").style.gridTemplateColumns=`120px repeat(${labels.length},minmax(6px,1fr))`;
  $("#xheat").innerHTML='<div class="lb"></div>'+labels.map((l,i)=>`<div class="lb c">${labels.length>30&&i%Math.ceil(labels.length/12)?"":esc(l)}</div>`).join("")+rows.map(x=>`<div class="lb">${esc(String(x.n).slice(0,18))}</div>`+x.v.map((v,i)=>`<div class="cell" title="${esc(x.n)} · ${esc(labels[i])}: ${nf(v||0)}" style="background:${ac};opacity:${v?(0.08+0.92*v/mx).toFixed(3):0.03}"></div>`).join("")).join("");return}
 const t=c.type,base={maintainAspectRatio:false,animation:false,interaction:{mode:t==="pie"?"nearest":"index",intersect:false},plugins:{legend:{display:r.series.length>1||t==="pie",position:t==="pie"?"right":"top"}}};
 if(t==="pie"){const se=r.series[0]||{points:[]},pts=split?r.series.map(s=>[sn(s),s.points.reduce((a,p)=>a+(+p[1]||0),0)]):se.points.map(p=>[lab(p[0],c.x),p[1]]);
  CH=new Chart($("#xch"),{type:"doughnut",data:{labels:pts.map(p=>p[0]),datasets:[{data:pts.map(p=>p[1]),backgroundColor:P,borderColor:css("--bg1"),borderWidth:2}]},options:{...base,cutout:"55%"}});return}
 const ds=r.series.map((se,i)=>({label:sn(se),data:t==="scatter"?keys.map((k,j)=>({x:tx?+k:j,y:val(se)[j]})).filter(p=>p.y!=null):val(se),borderColor:P[i%P.length],backgroundColor:t==="area"?P[i%P.length]+"55":P[i%P.length],borderWidth:t==="bar"||t==="stacked bar"?0:1.25,pointRadius:t==="scatter"?2.5:0,fill:t==="area"?(split?"stack":"origin"):false,borderRadius:t.includes("bar")?2:0,tension:0}));
 const stacked=t==="stacked bar"||(t==="area"&&!!split),yS={type:c.log?"logarithmic":"linear",stacked,grid:{color:css("--line")},beginAtZero:!c.log};
 const xS=t==="scatter"?{type:"linear",grid:{display:false},ticks:{callback:v=>tx?lab(v,c.x):labels[v]??""}}:{stacked,grid:{display:false},ticks:{maxTicksLimit:tx?16:40,autoSkip:true}};
 const horiz=!tx&&(t==="bar"||t==="stacked bar")&&labels.length>8;
 CH=new Chart($("#xch"),{type:t==="scatter"?"scatter":(t.includes("bar")?"bar":"line"),data:{labels:labels.map(l=>l.length>40?l.slice(0,39)+"…":l),datasets:ds},options:{...base,indexAxis:horiz?"y":"x",scales:horiz?{x:yS,y:{...xS,ticks:{autoSkip:false}}}:{x:xS,y:yS}}})}
 catch(e){$("#xcnote").textContent="Error: "+e.message}}
function run(){count();chart();table()}
window.renderExplore=async function(){ST=load();try{if(!META){$("#main").innerHTML='<h1>Explore</h1><p class="lede">Loading…</p>';META=await (await get("/api/x/meta")).json();if(META.error)throw new Error(META.error)}}
 catch(e){$("#main").innerHTML=`<h1>Explore</h1><p class="lede">The query index isn't available (${esc(e.message)}). Run <code>./setup.sh</code> once, then restart <code>python3 dashboard/full/server.py 8802</code>. The overview pages work without it.</p>`;return}
 theme();ui();run()};
})();
