// PNG export / copy for charts and heatmaps. No external libs. Renders at 2x with an opaque, theme-matched background and a caption.
(()=>{
const cssv=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const FONT=()=>getComputedStyle(document.body).fontFamily;
const stamp=()=>{const d=new Date(),p=n=>String(n).padStart(2,"0");return`${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`};
const slug=s=>String(s).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,60)||"chart";
function chartImage(chart){const o=chart.options.devicePixelRatio;chart.options.devicePixelRatio=2;chart.resize();const c=document.createElement("canvas");c.width=chart.canvas.width;c.height=chart.canvas.height;c.getContext("2d").drawImage(chart.canvas,0,0);chart.options.devicePixelRatio=o;chart.resize();return c}
function heatImage(h){const S=2,lw=110,cw=Math.max(14,Math.min(36,Math.floor(900/h.labels.length))),ch=20,top=22,W=lw+cw*h.labels.length,Hh=top+ch*h.rows.length;
 const c=document.createElement("canvas");c.width=W*S;c.height=Hh*S;const x=c.getContext("2d");x.scale(S,S);x.font=`11px ${FONT()}`;x.fillStyle=cssv("--mu");x.textBaseline="middle";
 const mx=Math.max(1,...h.rows.flatMap(r=>r.v.map(Number).filter(Boolean))),ac=cssv("--ac"),step=Math.ceil(h.labels.length/24);
 h.labels.forEach((l,i)=>{if(i%step===0){x.textAlign="center";x.fillText(String(l).slice(0,8),lw+i*cw+cw/2,top/2)}});
 h.rows.forEach((r,j)=>{x.textAlign="left";x.fillStyle=cssv("--mu");x.fillText(String(r.n).slice(0,16),0,top+j*ch+ch/2);r.v.forEach((v,i)=>{x.globalAlpha=v?0.08+0.92*v/mx:0.03;x.fillStyle=ac;x.fillRect(lw+i*cw+1,top+j*ch+1,cw-2,ch-2);x.globalAlpha=1})});return c}
function compose(img,title,caption){const S=2,pad=24,W=Math.max(img.width/S,640)+pad*2,lines=[].concat(caption||[]).filter(Boolean);
 const head=pad+20+lines.length*17+12,foot=34,H=head+img.height/S+foot;const c=document.createElement("canvas");c.width=W*S;c.height=H*S;const x=c.getContext("2d");x.scale(S,S);
 x.fillStyle=cssv("--bg1")||"#111";x.fillRect(0,0,W,H);x.fillStyle=cssv("--tx");x.font=`600 15px ${FONT()}`;x.textBaseline="top";x.fillText(title,pad,pad);
 x.fillStyle=cssv("--mu");x.font=`12px ${FONT()}`;lines.forEach((l,i)=>x.fillText(l.length>150?l.slice(0,149)+"…":l,pad,pad+24+i*17));
 x.drawImage(img,pad,head,img.width/S,img.height/S);x.strokeStyle=cssv("--line");x.beginPath();x.moveTo(pad,H-foot+6);x.lineTo(W-pad,H-foot+6);x.stroke();
 x.fillStyle=cssv("--dim");x.font=`11px ${FONT()}`;x.fillText("CanaryDash honeypot archive · static data 2026-10-14 20:51 to 2026-10-21 20:37 PT",pad,H-foot+14);return c}
function render(spec){const img=spec.heat?heatImage(spec.heat):chartImage(spec.chart);return compose(img,spec.title,spec.caption)}
async function out(spec,mode){const c=render(spec);
 const blob=await new Promise(r=>c.toBlob(r,"image/png"));
 if(mode==="copy"){try{await navigator.clipboard.write([new ClipboardItem({"image/png":blob})]);return"Copied"}catch(e){return"Copy failed"}}
 const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`canarydash_${slug(spec.name||spec.title)}_${stamp()}.png`;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1000);return"Saved"}
// tools(el, getSpec): adds "PNG" and "Copy" buttons into el. getSpec() -> {title, caption:[...], name, chart | heat:{rows:[{n,v:[]}],labels:[]}}
window.CDX={tools(el,getSpec){if(!el||el.querySelector(".xp"))return;const w=document.createElement("span");w.className="xp";
 w.innerHTML='<button type="button" data-m="png" title="Download PNG (2x)">PNG</button><button type="button" data-m="copy" title="Copy image to clipboard">Copy</button>';
 w.querySelectorAll("button").forEach(b=>b.onclick=async()=>{const s=getSpec();if(!s||(!s.chart&&!s.heat))return;const t=b.textContent;b.textContent=await out(s,b.dataset.m);setTimeout(()=>b.textContent=t,1200)});el.appendChild(w);el._spec=getSpec},out,render};
})();
