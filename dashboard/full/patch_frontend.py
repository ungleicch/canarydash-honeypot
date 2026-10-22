import sys
s = open("index.orig.html").read()
def rep(a, b, n=1):
    global s
    assert s.count(a) == n, (a[:60], s.count(a)); s = s.replace(a, b)
rep("<title>CanaryDash</title>", "<title>CanaryDash · local full dataset</title>")
rep('<span class="node">csulb-canary-1 · 20.98.51.91</span>', '<span class="node">LOCAL full dataset · Mac offline copy of 20.98.51.91</span>')
rep('<button data-v="d">30 days</button></div>',
    '<button data-v="d">30 days</button></div><select id="fera" title="Data source / era"><option value="">All sources</option><option value="live opencanary">Live OpenCanary</option><option value="pre-cowrie snapshot">Pre-cowrie snapshot</option><option value="cowrie">Cowrie</option></select>')
FULL = '''<div class="sec">Full dataset (every event in the local copy, computed on this Mac)</div>
<div class="card c12" id="full"><h2>All-time totals <small id="full-sub"></small><span class="sp"></span><span class="seg" id="fera2"><button data-v="" class="on">All</button><button data-v="live opencanary">Live OpenCanary</button><button data-v="pre-cowrie snapshot">Pre-cowrie snapshot</button><button data-v="cowrie">Cowrie</button></span></h2>
<div id="full-kpi" class="fkpi"></div><div id="full-eras" class="sub" style="margin:8px 0 4px"></div>
<h2 style="margin-top:14px">Events per day (PT), by source</h2><div id="full-days"></div>
<div class="fgrid"><div><h2>By service</h2><div class="bars" id="f-svc"></div></div><div><h2>By port</h2><div class="bars" id="f-port"></div></div><div><h2>Top IPs</h2><div class="bars" id="f-ip"></div></div>
<div><h2>Countries (events)</h2><div class="bars" id="f-cty"></div></div><div><h2>Countries (unique IPs)</h2><div class="bars" id="f-ctyip"></div></div><div><h2>Top credentials tried</h2><div class="bars" id="f-cred"></div></div>
<div><h2>Cowrie logins that worked</h2><div class="bars" id="f-ok"></div></div><div><h2>Top usernames</h2><div class="bars" id="f-user"></div></div><div><h2>Top passwords</h2><div class="bars" id="f-pass"></div></div>
<div style="grid-column:span 2"><h2>Top shell commands</h2><div class="bars" id="f-cmd"></div></div><div><h2>Malware download hosts</h2><div class="bars" id="f-dlh"></div></div></div>
<h2 style="margin-top:14px">Captured malware (unique SHA-256)</h2><div class="tw" id="f-mal"></div>
<div class="sub" id="f-ingest" style="margin-top:10px"></div></div>
<div class="sec">Live views (interactive; loads the newest events first, use "Load everything" at the bottom for all of it)</div>
'''
rep("<main>\n", "<main>\n" + FULL)
rep("const srcTag=e=>e.cw?", 'const srcTag=e=>e.era=="pre-cowrie snapshot"?\'<span class="src pre">Pre-cowrie</span>\':e.cw?')
rep("return{t,cw,sess:", 'return{t,cw,era:e._era||(cw?"cowrie":"live opencanary"),sess:')
rep('function render(){const hide=$("hidetest").checked,all=hide?EV.filter(e=>!e.test):EV,',
    'function render(){const hide=$("hidetest").checked,ERA=$("fera").value,all=(hide?EV.filter(e=>!e.test):EV).filter(e=>!ERA||e.era==ERA),')
CSS = '''.src.pre{background:#2a2140;color:#b79cff}.fkpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.fkpi div{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:10px 12px}.fkpi b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.fkpi span{color:var(--mut);font-size:12px}
.fgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-top:14px}.drow{display:grid;grid-template-columns:90px 1fr 90px;gap:10px;align-items:center;font-size:12px;padding:2px 0}.dbar{display:flex;height:14px;border-radius:4px;overflow:hidden;background:#141b24}.dbar i{display:block;height:100%}
</style>'''
rep("</style>", CSS)
JS = r'''<script>
const ERACOL={"live opencanary":"#4fd1a5","pre-cowrie snapshot":"#b79cff","cowrie":"#f5b942"},ERALAB={"live opencanary":"Live OpenCanary","pre-cowrie snapshot":"Pre-cowrie snapshot","cowrie":"Cowrie"};
let FERA="";
async function loadSummary(){try{const r=await (await fetch("/api/summary?era="+encodeURIComponent(FERA),{cache:"no-store"})).json(),S=r.summary,R=r.report||{};
 const fd=v=>v?fmtS.format(v):"–";$("full-sub").textContent=(FERA?ERALAB[FERA]:"all sources")+" · "+fd(S.first_ts)+" → "+fd(S.last_ts)+" PT";
 const k=[["Events",S.total],["Unique IPs",S.unique_ips],["Countries",S.n_countries],["Cowrie sessions",S.cowrie_sessions],["Login attempts",S.login_attempts],["Cowrie logins OK",S.cowrie_login_ok],["Shell commands",S.commands_total],["Unique commands",S.commands_unique],["File downloads",S.downloads_total],["Unique malware",S.malware.length],["Brazil bot events",S.brazil_bot]];
 $("full-kpi").innerHTML=k.map(([l,v])=>`<div><b>${nf(v||0)}</b><span>${l}</span></div>`).join("");
 $("full-eras").innerHTML=Object.entries(S.by_era).map(([e,n])=>`<span class="src" style="background:#1a2230;color:${ERACOL[e]}">${ERALAB[e]||e}</span> ${nf(n)}`).join(" &nbsp; ")+(R.overlap_pre_vs_live!=null?` &nbsp;·&nbsp; pre-cowrie lines that were also in opencanary.log (counted once): <b>${nf(R.overlap_pre_vs_live)}</b>`:"");
 const mx=Math.max(1,...S.days.map(d=>d[1]));$("full-days").innerHTML=S.days.map(([d,n])=>{const e=S.era_days[d]||{};return`<div class="drow"><span class="mono">${d}</span><div class="dbar" style="width:${Math.max(2,n/mx*100)}%">${Object.entries(e).map(([x,v])=>`<i title="${ERALAB[x]||x}: ${nf(v)}" style="width:${v/n*100}%;background:${ERACOL[x]||"#888"}"></i>`).join("")}</div><span>${nf(n)}</span></div>`}).join("")+`<div class="legend">${Object.keys(ERACOL).map(x=>`<span><b style="background:${ERACOL[x]}"></b>${ERALAB[x]}</span>`).join("")}</div>`;
 bars("f-svc",S.by_logtype.slice(0,14).map(([t,n])=>[NAMES[t]||("Type "+t),n]),{mono:false});
 bars("f-port",S.by_port.slice(0,14).map(([p,n])=>[":"+p,n]),{color:()=>"#5aa9ff"});
 bars("f-ip",S.top_ips.slice(0,14).map(x=>[x.ip+"  "+flag(x.cc)+" "+x.country,x.n]),{color:()=>"#ff6b6b"});
 bars("f-cty",S.countries_by_events.slice(0,14).map(([c,cc,n])=>[flag(cc)+" "+c,n]),{mono:false,color:()=>"#5aa9ff"});
 bars("f-ctyip",S.countries_by_ips.slice(0,14).map(([c,cc,n])=>[flag(cc)+" "+c,n]),{mono:false,color:()=>"#7f8cff"});
 const cr=(u,p)=>(u??"")+" / "+(p??"");
 bars("f-cred",S.top_creds.slice(0,14).map(([u,p,n])=>[cr(u,p),n]));bars("f-ok",S.ok_creds.slice(0,14).map(([u,p,n])=>[cr(u,p),n]),{color:()=>"#4fd1a5"});
 bars("f-user",S.top_users.slice(0,14));bars("f-pass",S.top_passwords.slice(0,14));
 bars("f-cmd",S.top_commands.slice(0,20).map(([c,n])=>[c.length>110?c.slice(0,110)+"…":c,n]));
 bars("f-dlh",S.download_hosts.slice(0,14),{color:()=>"#ff6b6b"});
 $("f-mal").innerHTML=S.malware.length?`<table><thead><tr><th>SHA-256</th><th>Type</th><th>Size</th><th>Fetches</th><th>IPs</th><th>First seen (PT)</th><th>Last seen (PT)</th><th>Example URL</th></tr></thead><tbody>${S.malware.slice(0,200).map(x=>`<tr><td class="mono">${esc(x.sha256)}</td><td>${esc(x.type)}</td><td>${x.size!=null?nf(+x.size)+" B":""}</td><td>${nf(x.n)}</td><td>${x.ips}</td><td>${fmt.format(x.first)}</td><td>${fmt.format(x.last)}</td><td class="d mono">${esc(x.url)}</td></tr>`).join("")}</tbody></table>`:'<div class="empty">No downloads</div>';
 $("f-ingest").textContent="Local database built "+fmtS.format(R.ingested_at*1000)+" PT from "+(r.root||"")+" · run ~/Developer/CanaryDash/full/refresh.sh to pull new data from the VM";
}catch(e){console.error(e);$("full-sub").textContent="summary failed to load"}}
$("fera2").onclick=e=>{const b=e.target.closest("button");if(!b)return;FERA=b.dataset.v;[...$("fera2").children].forEach(x=>x.classList.toggle("on",x==b));$("fera").value=FERA;loadSummary();render()};
$("fera").addEventListener("input",()=>{FERA=$("fera").value;[...$("fera2").children].forEach(x=>x.classList.toggle("on",x.dataset.v==FERA));loadSummary();render()});
loadSummary();setInterval(loadSummary,300000);
</script>
</body>'''
rep("</body>", JS)
rep('<button id="arch-all"', '<button id="arch-all"', 1)
rep('$("k-all").textContent=nf(all.length);$("t-all").textContent=nf(ips(all).size)+" IPs since the start";',
    '$("k-all").textContent=nf(all.length);$("t-all").textContent=nf(ips(all).size)+" IPs in loaded events"+(META.total>RAW.size?" (of "+nf(META.total)+" stored)":"");')
open("index.html", "w").write(s)
print("ok", len(s))
