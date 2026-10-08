(() => {
  if (window.top !== window.self) return;
  const host = location.hostname;
  if (host === "127.0.0.1" || host === "localhost") return;

  let overlay;
  function removeOverlay(){ if(overlay){overlay.remove();overlay=null;} }
  function showWarning(data, medium=false){
    if(overlay) return;
    overlay=document.createElement("div");
    overlay.id="phishguard-warning";
    overlay.innerHTML=`
      <div style="position:fixed;inset:0;background:rgba(3,7,18,.96);z-index:2147483647;color:#eef3ff;font-family:Inter,Segoe UI,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px">
        <div style="max-width:620px;width:100%;background:#0e1729;border:1px solid ${medium?'#f6c85f':'#ff667b'};border-radius:22px;padding:30px;box-shadow:0 30px 100px rgba(0,0,0,.6)">
          <div style="font-size:12px;letter-spacing:.14em;color:${medium?'#f6c85f':'#ff8797'};font-weight:800">PHISHGUARD SECURITY WARNING</div>
          <h1 style="font-size:32px;margin:10px 0">${medium?'Proceed with caution':'Potentially dangerous website'}</h1>
          <p style="color:#aab6d0;word-break:break-all">${escapeHtml(location.href)}</p>
          <div style="font-size:42px;font-weight:900;margin:22px 0">${data.risk_score ?? '—'}<span style="font-size:16px;color:#8290ad"> / 100</span></div>
          <p style="color:#c7d0e4">${escapeHtml(data.prediction || 'Risk detected')}</p>
          <ul style="color:#aeb9d2;line-height:1.7">${(data.reasons||[]).slice(0,5).map(r=>`<li>${escapeHtml(r)}</li>`).join("")}</ul>
          <div style="display:flex;gap:10px;margin-top:25px">
            <button id="pgBack" style="padding:13px 18px;border:0;border-radius:11px;background:#ff667b;color:white;font-weight:800">Go Back</button>
            <button id="pgContinue" style="padding:13px 18px;border:1px solid #31405f;border-radius:11px;background:#17233b;color:#dce4f6;font-weight:800">Continue Anyway</button>
          </div>
          <p style="font-size:11px;color:#66738e;margin-top:18px">PhishGuard is a security aid and cannot guarantee that a website is safe.</p>
        </div>
      </div>`;
    document.documentElement.appendChild(overlay);
    document.getElementById("pgBack").onclick=()=>history.length>1?history.back():location.href="about:blank";
    document.getElementById("pgContinue").onclick=removeOverlay;
  }
  function escapeHtml(v){return String(v??"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));}

  // Give the page a moment to establish its DOM, but scan the URL itself only.
  setTimeout(async()=>{
    try{
      const r=await fetch("http://127.0.0.1:8080/scan",{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({url:location.href})
      });
      if(!r.ok)return;
      const data=await r.json();
      if((data.risk_score||0)>=80) showWarning(data,false);
      else if((data.risk_score||0)>=60) showWarning(data,true);
    }catch(_){}
  },250);
})();