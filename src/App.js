import { useState, useRef, useEffect, useCallback } from "react";

// ─── THREAT DATABASE ──────────────────────────────────────────────────────────
const FAKE_BRANDS = [
  "paypa1","pay-pal","paypall","paypa-l","arnazon","amaz0n","amazon-",
  "g00gle","go0gle","googie","micros0ft","microsooft","app1e","appl3",
  "apple-id","apple-verify","faceb00k","facebok","netf1ix","netflx",
  "binance-","coinbase-","crypto-verify","bank-verify","banking-secure",
  "account-verify","login-verify","secure-login","verify-account","whatsap",
];
const HIGH_RISK_TLDS = ["tk","ml","ga","cf","gq","xyz","top","click","link","work","party","racing","date","download","bid","win","loan","review","science","stream","gdn","faith","cricket","trade","accountant","men"];
const PHISHING_WORDS = ["login","verify","secure","update","confirm","account","banking","password","signin","wallet","crypto","urgent","prize","winner","free-gift","limited-offer","claim-now","verify-now","suspended","unusual-activity","alert-required"];
const TRUSTED = ["google.com","youtube.com","facebook.com","instagram.com","twitter.com","x.com","github.com","microsoft.com","apple.com","amazon.com","netflix.com","wikipedia.org","whatsapp.com","linkedin.com","reddit.com","tiktok.com","paypal.com","binance.com","yahoo.com","outlook.com","anthropic.com","openai.com","cloudflare.com","mozilla.org"];

// ─── SCAN ENGINE ──────────────────────────────────────────────────────────────
const isValidUrl = s => { try { new URL(s.startsWith("http") ? s : "https://"+s); return true; } catch { return false; } };
const norm = s => s.startsWith("http") ? s : "https://"+s;
const getDomain = u => { try { return new URL(norm(u)).hostname.replace(/^www\./,""); } catch { return u; } };
const getBase = d => { const p = d.split("."); return p.length >= 2 ? p.slice(-2).join(".") : d; };

function deepScan(raw) {
  const url = norm(raw), domain = getDomain(raw), base = getBase(domain);
  const tld = domain.split(".").pop().toLowerCase(), lo = url.toLowerCase();
  const checks = []; let score = 0, flags = [];

  const trusted = TRUSTED.includes(base);
  checks.push({ name:"Trusted Domain Database", passed:trusted, note: trusted ? `✓ ${base} is a verified legitimate domain` : `${base} is not in our trusted domain list` });
  if (trusted) score -= 20;

  const https = url.startsWith("https://");
  checks.push({ name:"HTTPS Encryption", passed:https, note: https ? "Encrypted connection (HTTPS)" : "⚠️ No encryption — data travels in plain text!" });
  if (!https) { score += 25; flags.push("No HTTPS"); }

  const brand = FAKE_BRANDS.find(b => lo.includes(b));
  checks.push({ name:"Brand Impersonation", passed:!brand, note: brand ? `🚨 Fake pattern: "${brand}" — mimicking a real company!` : "No brand impersonation detected" });
  if (brand) { score += 70; flags.push(`Impersonating: ${brand}`); }

  const badTld = HIGH_RISK_TLDS.includes(tld);
  checks.push({ name:"Domain Extension Risk", passed:!badTld, note: badTld ? `⚠️ .${tld} is a high-abuse extension used for scams` : `.${tld} is a standard extension` });
  if (badTld) { score += 30; flags.push(`Risky TLD: .${tld}`); }

  const kw = PHISHING_WORDS.filter(k => lo.includes(k));
  checks.push({ name:"Phishing Keywords", passed:kw.length===0, note: kw.length ? `Found: ${kw.slice(0,3).join(", ")}` : "No phishing keywords" });
  if (kw.length) { score += kw.length * 8; flags.push("Phishing keywords"); }

  const ipHit = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(url);
  checks.push({ name:"IP Address in URL", passed:!ipHit, note: ipHit ? "🚨 Raw IP used — real sites use domain names!" : "Uses proper domain name" });
  if (ipHit) { score += 50; flags.push("Raw IP address"); }

  const subs = domain.split(".").length - 2;
  checks.push({ name:"Subdomain Structure", passed:subs<=1, note: subs>1 ? `${subs} subdomains — hackers hide behind subdomains` : "Normal subdomain structure" });
  if (subs > 1) { score += 20; flags.push("Suspicious subdomains"); }

  const len = url.length;
  checks.push({ name:"URL Length", passed:len<80, note: len>=80 ? `${len} chars — very long URLs hide real destinations` : `${len} chars — normal length` });
  if (len >= 80) score += 10;

  const badChars = (url.match(/@|%00|%0d|%0a|javascript:/gi)||[]);
  checks.push({ name:"URL Obfuscation", passed:badChars.length===0, note: badChars.length ? `Dangerous chars: ${badChars.join(" ")}` : "No obfuscation detected" });
  if (badChars.length) { score += 40; flags.push("URL obfuscation"); }

  const final = trusted ? Math.max(0, Math.min(score, 15)) : Math.min(Math.max(score, 0), 100);
  const level = trusted && final < 15 ? "CLEAN" : final < 20 ? "CLEAN" : final < 50 ? "LOW" : "HIGH";
  return { url, domain, base, tld, score:final, level, flags, checks, trusted, safe: level!=="HIGH" };
}

// ─── AI ───────────────────────────────────────────────────────────────────────
const SYS = `You are CyberShield AI, built by Abubakar Usman Bida — a cybersecurity student at github.com/abubakarusmanbida17-dev/Cybersecurity-journey.
MISSION: Help anyone understand cybersecurity in plain English. Be calm, warm, empowering.
FORMAT: Use emoji headers 🔍 🚨 🛠️ 🛡️ 🎓, number steps, explain all jargon.
Always end with: "🛡️ CyberShield Verdict: [one powerful sentence]"`;

const URL_PROMPT = (url, r) => `Analyze this scan for a beginner:
URL: ${url} | Level: ${r.level} | Score: ${r.score}/100 | Threats: ${r.flags.join(", ")||"None"}
Checks: ${r.checks.map(c=>`${c.name}:${c.passed?"✓":"✗"}`).join(", ")}

Write sections:
## 🔍 What We Found
## ${r.level==="CLEAN"?"✅ Why This Looks Safe":r.level==="LOW"?"⚠️ What's Suspicious":"🚨 Why This Is Dangerous"}
## 🛠️ What To Do RIGHT NOW
## 🛡️ How To Stay Safe Next Time
## 🎓 Explain To A Beginner
## 🛡️ CyberShield Verdict:`;

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const TL = {
  CLEAN:   { color:"#00ff88", bg:"rgba(0,255,136,0.07)", label:"SAFE",    icon:"✓", glow:"#00ff88", msg:"This link passed all security checks." },
  LOW:     { color:"#ffcc00", bg:"rgba(255,204,0,0.07)",  label:"CAUTION", icon:"!", glow:"#ffcc00", msg:"Suspicious patterns found. Proceed with care." },
  HIGH:    { color:"#ff4444", bg:"rgba(255,68,68,0.08)",  label:"DANGER",  icon:"✕", glow:"#ff4444", msg:"DO NOT visit this link. It is dangerous." },
  UNKNOWN: { color:"#444",    bg:"rgba(60,60,60,0.07)",   label:"SCAN",    icon:"?", glow:"#444",    msg:"Ready to scan." },
};
const NAV_ITEMS = [
  { id:"scanner", icon:"⬡", label:"Scanner" },
  { id:"chat",    icon:"◈", label:"AI Advisor" },
  { id:"learn",   icon:"◎", label:"Learn" },
  { id:"tools",   icon:"⬢", label:"Tools" },
];
const TIPS = [
  { icon:"🔐", title:"Strong Passwords",      body:"Use 12+ characters mixing letters, numbers & symbols. Use Bitwarden (free) to remember them.", level:"beginner" },
  { icon:"📱", title:"Two-Factor Auth (2FA)", body:"Even if someone steals your password, 2FA stops them cold. Enable it in every app's security settings.", level:"beginner" },
  { icon:"🎣", title:"Spot Phishing",         body:"Check the real sender email. Hover links before clicking. Urgency and prizes are always red flags.", level:"beginner" },
  { icon:"🌐", title:"HTTPS Only",            body:"Always look for 🔒 before entering any password or payment info. HTTP = unsafe.", level:"beginner" },
  { icon:"📶", title:"Public Wi-Fi Risk",     body:"Anyone on the same Wi-Fi can spy on you. Use ProtonVPN (free) on public networks.", level:"beginner" },
  { icon:"🔄", title:"Update Everything",     body:"Hackers exploit old software. Enable auto-updates — patches close doors hackers use.", level:"beginner" },
  { icon:"💾", title:"Backup Your Data",      body:"3-2-1 rule: 3 copies, 2 devices, 1 cloud. Ransomware can't hurt you if you have backups.", level:"intermediate" },
  { icon:"🔎", title:"Check Data Breaches",   body:"Go to haveibeenpwned.com and type your email to see if hackers already have your password.", level:"beginner" },
];
const FREE_TOOLS = [
  { name:"Have I Been Pwned", url:"https://haveibeenpwned.com",         desc:"Check if your email was leaked in a breach",    tag:"Privacy",   icon:"🔎", color:"#ff6b6b" },
  { name:"VirusTotal",        url:"https://virustotal.com",             desc:"Scan files & URLs with 70+ antivirus engines",  tag:"Malware",   icon:"🦠", color:"#ff9f43" },
  { name:"Bitwarden",         url:"https://bitwarden.com",             desc:"Free open-source password manager",             tag:"Passwords", icon:"🔐", color:"#00d2d3" },
  { name:"ProtonVPN",         url:"https://protonvpn.com",             desc:"Free VPN — protects public Wi-Fi sessions",     tag:"VPN",       icon:"🛡️", color:"#7bed9f" },
  { name:"EFF Privacy Guide", url:"https://ssd.eff.org",              desc:"Step-by-step privacy guides for everyone",      tag:"Privacy",   icon:"📖", color:"#48dbfb" },
  { name:"SSL Labs",          url:"https://ssllabs.com/ssltest",       desc:"Test a website's SSL security certificate",     tag:"Websites",  icon:"🔒", color:"#00ff88" },
  { name:"MXToolbox",         url:"https://mxtoolbox.com",            desc:"Check if your domain or email is blacklisted",  tag:"Email",     icon:"📬", color:"#fd79a8" },
  { name:"CyberChef",         url:"https://gchq.github.io/CyberChef","desc":"Decode & analyze data like a professional",   tag:"Advanced",  icon:"🍳", color:"#ffeaa7" },
];

// ─── STYLES ───────────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { width: 100%; min-height: 100%; overflow-x: hidden; }
  body { background: #060810; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 3px; }
  ::-webkit-scrollbar-track { background: #060810; }
  ::-webkit-scrollbar-thumb { background: #1a2a1a; border-radius: 2px; }

  /* Animations — reduced motion for low-end devices */
  @media (prefers-reduced-motion: no-preference) {
    @keyframes fl   { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-16px)} }
    @keyframes rp   { 0%{opacity:.5;transform:scale(1)} 100%{opacity:0;transform:scale(1.8)} }
    @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
    @keyframes spin { to{transform:rotate(360deg)} }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
    @keyframes pulse { 0%,100%{box-shadow:0 0 6px #00ff88} 50%{box-shadow:0 0 18px #00ff88,0 0 36px #00ff8822} }
    @keyframes scanline { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
  }
  @media (prefers-reduced-motion: reduce) {
    @keyframes fl    { 0%,100%{opacity:.6} 50%{opacity:1} }
    @keyframes rp    { 0%,100%{opacity:.2} }
    @keyframes fadeUp { from{opacity:0} to{opacity:1} }
    @keyframes spin  { to{transform:rotate(360deg)} }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
    @keyframes pulse { 0%,100%{opacity:.8} 50%{opacity:1} }
    @keyframes scanline { 0%{opacity:0} 100%{opacity:0} }
  }

  /* Utility */
  .fade  { animation: fadeUp .35s ease both; }
  .spin  { animation: spin .8s linear infinite; }
  .blink { animation: blink .8s infinite; }
  .pulse { animation: pulse 3s ease-in-out infinite; }

  /* Nav scrollable on small screens */
  .nav-scroll { display:flex; overflow-x:auto; -webkit-overflow-scrolling:touch; scrollbar-width:none; gap:.25rem; padding:.25rem .75rem; }
  .nav-scroll::-webkit-scrollbar { display:none; }

  /* Cards */
  .card-hover { transition: transform .2s ease, border-color .2s ease; }
  .card-hover:hover { transform: translateY(-3px); }
  .card-hover:active { transform: scale(.98); }

  /* Buttons — touch friendly */
  .btn { min-height: 44px; min-width: 44px; cursor: pointer; font-family: inherit; transition: all .2s ease; -webkit-tap-highlight-color: transparent; }
  .btn:active { transform: scale(.97); }
  .btn:disabled { opacity: .4; cursor: not-allowed; }

  /* Inputs */
  .inp { font-family: inherit; transition: border-color .2s; -webkit-appearance: none; }
  .inp:focus { outline: none; border-color: #00ff8850 !important; }

  /* Grid layout helpers */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: clamp(.6rem,2vw,1rem); }
  @media (max-width: 600px) { .grid-2 { grid-template-columns: 1fr; } }

  .grid-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 260px), 1fr)); gap: clamp(.6rem,2vw,1rem); }

  /* Scanline overlay */
  .scanline { position:fixed; top:0; left:0; width:100%; height:4px; background:linear-gradient(transparent,rgba(0,255,136,.06),transparent); animation: scanline 6s linear infinite; pointer-events:none; z-index:1; }

  /* Chip tags */
  .chip { font-size: clamp(.55rem,.9vw+.4rem,.7rem); padding: .2rem .55rem; border-radius: 20px; letter-spacing: .05em; display:inline-block; }

  /* AI text formatting */
  .ai-h2 { font-size: clamp(.75rem,1.2vw+.5rem,.9rem); font-weight:700; color:#00ff88; margin:1rem 0 .35rem; letter-spacing:.02em; }
  .ai-step { padding:.25rem 0 .25rem .9rem; border-left:2px solid #00ff8822; margin:.2rem 0; font-size:clamp(.65rem,1vw+.45rem,.8rem); color:#aaa; line-height:1.6; }
  .ai-body { font-size:clamp(.65rem,1vw+.45rem,.8rem); color:#777; line-height:1.75; }

  /* Responsive text */
  .hero-title { font-family:'Syne',sans-serif; font-size:clamp(1.6rem,5vw+.8rem,3rem); font-weight:800; color:#fff; line-height:1.1; letter-spacing:.02em; }
  .hero-sub   { font-size:clamp(.7rem,1.2vw+.45rem,.85rem); color:#334; margin-top:.6rem; }
  .section-title { font-family:'Syne',sans-serif; font-size:clamp(1.2rem,3vw+.6rem,1.8rem); font-weight:800; color:#fff; }
  .label-xs   { font-size:clamp(.55rem,.8vw+.4rem,.7rem); letter-spacing:.15em; color:#334; }
  .body-sm    { font-size:clamp(.65rem,1vw+.45rem,.8rem); color:#445; line-height:1.7; }
  .verdict    { font-family:'Syne',sans-serif; font-size:clamp(1.4rem,4vw+.6rem,2rem); font-weight:800; letter-spacing:.12em; }
`;

// ─── SUB-COMPONENTS ───────────────────────────────────────────────────────────

// Background grid + particles — lightweight for mobile
function BgGrid() {
  return (
    <div aria-hidden style={{ position:"fixed", inset:0, zIndex:0, pointerEvents:"none", overflow:"hidden", width:"100%", height:"100%" }}>
      {/* Grid SVG */}
      <svg width="100%" height="100%" style={{ opacity:.018, position:"absolute", inset:0 }}>
        <defs>
          <pattern id="csg" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M48 0L0 0 0 48" fill="none" stroke="#00ff88" strokeWidth=".6"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#csg)"/>
      </svg>
      {/* Particles — only 8 for low-end perf */}
      {[...Array(8)].map((_,i)=>(
        <div key={i} style={{
          position:"absolute",
          width: `${(i%3)+1}px`, height:`${(i%3)+1}px`,
          background:["#00ff88","#00aaff","#ff4444"][i%3],
          borderRadius:"50%",
          left:`${(i*13)+5}%`, top:`${(i*11)+8}%`,
          opacity:.18,
          animation:`fl ${7+i}s ease-in-out infinite`,
          animationDelay:`${i*.5}s`,
          willChange:"transform",
        }}/>
      ))}
      {/* Radial gradient vignette */}
      <div style={{ position:"absolute", inset:0, background:"radial-gradient(ellipse at 50% 50%, transparent 40%, #060810 100%)", pointerEvents:"none" }}/>
    </div>
  );
}

// Radar animation
function Radar({ level }) {
  const c = TL[level]?.glow || "#00ff88";
  const size = "clamp(70px, 12vw, 100px)";
  return (
    <div style={{ position:"relative", width:size, height:size, flexShrink:0, aspectRatio:"1" }}>
      {[0,1,2].map(i=>(
        <div key={i} style={{
          position:"absolute", inset:`${i*14}%`,
          border:`1px solid ${c}`, borderRadius:"50%",
          opacity:.12+i*.1,
          animation:`rp 2.2s ease-out infinite`,
          animationDelay:`${i*.55}s`,
          willChange:"transform,opacity",
        }}/>
      ))}
      <div style={{
        position:"absolute", inset:"30%",
        background:c, borderRadius:"50%",
        boxShadow:`0 0 16px ${c}, 0 0 36px ${c}33`,
        display:"flex", alignItems:"center", justifyContent:"center",
        fontSize:"clamp(.9rem,2.5vw,1.3rem)", color:"#000", fontWeight:900,
      }}>{TL[level]?.icon}</div>
    </div>
  );
}

// Threat meter bar
function Meter({ score }) {
  const c = score<20 ? "#00ff88" : score<50 ? "#ffcc00" : "#ff4444";
  return (
    <div style={{ marginTop:"clamp(.6rem,1.5vw,.9rem)", width:"100%" }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:"4px" }}>
        <span className="label-xs">THREAT SCORE</span>
        <span style={{ fontSize:"clamp(.6rem,.9vw+.4rem,.72rem)", color:c, fontWeight:700 }}>{score}/100</span>
      </div>
      <div style={{ height:"clamp(3px,0.8vw,6px)", background:"#0d1117", borderRadius:"3px", overflow:"hidden" }}>
        <div style={{
          height:"100%", width:`${score}%`,
          background:`linear-gradient(90deg,#00ff88,${c})`,
          boxShadow:`0 0 6px ${c}`,
          transition:"width 1.4s cubic-bezier(.4,0,.2,1)",
          borderRadius:"3px",
        }}/>
      </div>
      <div style={{ display:"flex", justifyContent:"space-between", marginTop:"3px" }}>
        {["SAFE","SUSPICIOUS","DANGER"].map(l=>(
          <span key={l} style={{ fontSize:"clamp(.45rem,.6vw+.3rem,.58rem)", color:"#222", letterSpacing:".05em" }}>{l}</span>
        ))}
      </div>
    </div>
  );
}

// Single check row
function CheckRow({ c }) {
  const col = c.passed ? "#00ff88" : "#ff4444";
  return (
    <div style={{ display:"flex", gap:"clamp(.5rem,1.5vw,.75rem)", padding:"clamp(.5rem,1.5vw,.65rem) clamp(.6rem,2vw,.9rem)", borderBottom:"1px solid #ffffff06", alignItems:"flex-start" }}>
      <div style={{ width:"clamp(14px,3vw,18px)", height:"clamp(14px,3vw,18px)", borderRadius:"50%", border:`1.5px solid ${col}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:"clamp(.5rem,.8vw+.35rem,.65rem)", color:col, flexShrink:0, marginTop:"2px" }}>
        {c.passed?"✓":"✕"}
      </div>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:"clamp(.6rem,.9vw+.4rem,.72rem)", color:"#bbb", fontWeight:600, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{c.name}</div>
        <div style={{ fontSize:"clamp(.55rem,.8vw+.35rem,.65rem)", color:"#445", marginTop:"2px", lineHeight:1.5 }}>{c.note}</div>
      </div>
    </div>
  );
}

// AI text renderer
function AiText({ text }) {
  if (!text) return null;
  return (
    <div>
      {text.split("\n").map((line,i)=>{
        if (line.startsWith("## ")) return <div key={i} className="ai-h2">{line.replace("## ","")}</div>;
        if (/^\d+\. /.test(line)) return <div key={i} className="ai-step">{line}</div>;
        if (line.startsWith("- ")) return <div key={i} className="ai-step">• {line.slice(2)}</div>;
        if (!line.trim()) return <div key={i} style={{ height:".4rem" }}/>;
        return <div key={i} className="ai-body">{line}</div>;
      })}
    </div>
  );
}

// Progress bar for scan
function ScanProgress({ progress }) {
  const labels = ["Checking domain…","Scanning patterns…","Analyzing threats…","Building report…"];
  const idx = Math.min(Math.floor(progress/25), 3);
  return (
    <div style={{ marginTop:"clamp(.7rem,2vw,1rem)" }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:"5px" }}>
        <span className="label-xs" style={{ color:"#445" }}>{labels[idx]}</span>
        <span className="label-xs" style={{ color:"#00ff88" }}>{Math.round(progress)}%</span>
      </div>
      <div style={{ height:"clamp(3px,.8vw,5px)", background:"#0a0f0a", borderRadius:"2px", overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${progress}%`, background:"linear-gradient(90deg,#00ff88,#00aaff)", borderRadius:"2px", transition:"width .3s ease", boxShadow:"0 0 8px #00ff8860" }}/>
      </div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [nav,     setNav]     = useState("scanner");
  const [url,     setUrl]     = useState("");
  const [scanning,setScanning]= useState(false);
  const [progress,setProgress]= useState(0);
  const [result,  setResult]  = useState(null);
  const [aiText,  setAiText]  = useState("");
  const [aiLoad,  setAiLoad]  = useState(false);
  const [msgs,    setMsgs]    = useState([]);
  const [chatIn,  setChatIn]  = useState("");
  const [chatLoad,setChatLoad]= useState(false);
  const chatEnd = useRef(null);
  const inputRef = useRef(null);

  useEffect(()=>{ chatEnd.current?.scrollIntoView({behavior:"smooth"}); },[msgs]);

  const callClaude = useCallback(async (messages) => {
    const r = await fetch("https://api.anthropic.com/v1/messages",{
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ model:"claude-sonnet-4-20250514", max_tokens:1000, system:SYS, messages }),
    });
    const d = await r.json();
    return d.content?.map(b=>b.text||"").join("") || "Analysis unavailable.";
  },[]);

  const typewrite = useCallback((text, setter) => {
    let i = 0;
    const tw = setInterval(()=>{
      i += 5;
      setter(text.slice(0,i));
      if (i >= text.length) clearInterval(tw);
    }, 10);
  },[]);

  const scan = async () => {
    const t = url.trim();
    if (!t || !isValidUrl(t)) {
      inputRef.current?.focus();
      return;
    }
    setScanning(true); setResult(null); setAiText(""); setProgress(0);
    const iv = setInterval(()=>setProgress(p=>Math.min(p+Math.random()*14,90)),220);
    await new Promise(r=>setTimeout(r,900));
    const data = deepScan(t);
    clearInterval(iv); setProgress(100);
    await new Promise(r=>setTimeout(r,250));
    setResult(data); setScanning(false);
    setAiLoad(true);
    try { const reply = await callClaude([{role:"user",content:URL_PROMPT(t,data)}]); typewrite(reply,setAiText); }
    catch { setAiText("⚠️ AI analysis unavailable. Scan results above are still accurate."); }
    finally { setAiLoad(false); }
  };

  const sendChat = async (text) => {
    const m = text || chatIn.trim();
    if (!m || chatLoad) return;
    setChatIn("");
    const updated = [...msgs, {role:"user",content:m}];
    setMsgs(updated); setChatLoad(true);
    try {
      const reply = await callClaude(updated);
      setMsgs(prev=>[...prev,{role:"assistant",content:""}]);
      typewrite(reply, txt=>setMsgs(prev=>{const n=[...prev];n[n.length-1]={role:"assistant",content:txt};return n;}));
    } catch { setMsgs(prev=>[...prev,{role:"assistant",content:"⚠️ Connection error. Try again."}]); }
    finally { setChatLoad(false); }
  };

  const tl = result?.level || "UNKNOWN";
  const tlD = TL[tl];

  // ── SCANNER PAGE ────────────────────────────────────────────────────────────
  const ScannerPage = (
    <div style={{ maxWidth:"min(100%,900px)", margin:"0 auto", padding:"clamp(1rem,4vw,2rem) clamp(.75rem,4vw,1.25rem)" }}>

      {/* Hero */}
      <div style={{ textAlign:"center", marginBottom:"clamp(1.2rem,4vw,2rem)" }}>
        <h1 className="hero-title">
          Is This Link<br/>
          <span style={{ color:"#00ff88", textShadow:"0 0 28px rgba(0,255,136,.35)" }}>Safe or Fake?</span>
        </h1>
        <p className="hero-sub">Paste any suspicious link — 9 security checks run instantly</p>
      </div>

      {/* Input card */}
      <div style={{ background:"rgba(255,255,255,.015)", border:"1px solid #00ff8815", borderRadius:"clamp(.7rem,2vw,1rem)", padding:"clamp(.9rem,3vw,1.4rem)", marginBottom:"clamp(.75rem,2.5vw,1.2rem)" }}>
        <div className="label-xs" style={{ marginBottom:".6rem" }}>⬡ PASTE URL TO SCAN</div>
        <div style={{ display:"flex", gap:"clamp(.4rem,1.5vw,.6rem)", flexWrap:"nowrap" }}>
          <div style={{ flex:1, position:"relative", minWidth:0 }}>
            <span style={{ position:"absolute", left:"clamp(.6rem,2vw,.9rem)", top:"50%", transform:"translateY(-50%)", fontSize:"clamp(.8rem,2vw,1rem)", color:"#223", pointerEvents:"none" }}>🔗</span>
            <input
              ref={inputRef}
              value={url}
              onChange={e=>setUrl(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&scan()}
              placeholder="https://any-link.com…"
              className="inp"
              style={{ width:"100%", background:"rgba(0,0,0,.55)", border:"1px solid #0f1a0f", borderRadius:"clamp(.4rem,1.5vw,.6rem)", color:"#b0ffcc", padding:"clamp(.55rem,1.5vw,.8rem) clamp(.6rem,2vw,.9rem) clamp(.55rem,1.5vw,.8rem) clamp(1.8rem,5vw,2.5rem)", fontSize:"clamp(.7rem,1.2vw+.45rem,.85rem)" }}
            />
          </div>
          <button onClick={scan} disabled={scanning||!url.trim()} className="btn"
            style={{ background:"rgba(0,255,136,.1)", border:"1px solid #00ff8840", color:"#00ff88", padding:"0 clamp(.75rem,2.5vw,1.2rem)", borderRadius:"clamp(.4rem,1.5vw,.6rem)", fontSize:"clamp(.65rem,1vw+.45rem,.8rem)", letterSpacing:"1.5px", whiteSpace:"nowrap", flexShrink:0 }}>
            {scanning ? "…" : "⬡ SCAN"}
          </button>
        </div>
        {scanning && <ScanProgress progress={progress}/>}
      </div>

      {/* Result */}
      {result && (
        <div className="fade">
          {/* Verdict banner */}
          <div style={{ background:tlD.bg, border:`1px solid ${tlD.color}25`, borderRadius:"clamp(.7rem,2vw,1rem)", padding:"clamp(.9rem,3vw,1.4rem)", marginBottom:"clamp(.7rem,2vw,1rem)", display:"flex", alignItems:"center", gap:"clamp(.75rem,3vw,1.4rem)", boxShadow:`0 0 36px ${tlD.glow}12` }}>
            <Radar level={tl}/>
            <div style={{ flex:1, minWidth:0 }}>
              <div className="label-xs" style={{ marginBottom:".3rem" }}>SCAN VERDICT</div>
              <div className="verdict" style={{ color:tlD.color, textShadow:`0 0 18px ${tlD.glow}45` }}>{tlD.label}</div>
              <div className="body-sm" style={{ marginTop:".3rem", color:"#445" }}>{result.base}</div>
              <Meter score={result.score}/>
            </div>
          </div>

          {/* Alert bar */}
          <div style={{ padding:"clamp(.7rem,2.5vw,1rem) clamp(.9rem,3vw,1.2rem)", background:tl==="CLEAN"?"rgba(0,255,136,.05)":tl==="LOW"?"rgba(255,204,0,.05)":"rgba(255,68,68,.08)", border:`1px solid ${tlD.color}20`, borderRadius:"clamp(.5rem,1.5vw,.75rem)", marginBottom:"clamp(.7rem,2vw,1rem)", fontSize:"clamp(.68rem,1vw+.45rem,.82rem)", color:tlD.color, lineHeight:1.7 }}>
            {tl==="CLEAN" && "✅ This link passed all 9 security checks. Safe to visit — stay alert and never enter passwords unless you fully trust the site."}
            {tl==="LOW"   && "⚠️ Suspicious patterns detected. Do NOT enter passwords, card details or personal information on this site."}
            {tl==="HIGH"  && "🚨 STOP! This link is dangerous. Do NOT visit it. If someone sent this to you — warn them immediately and delete it."}
          </div>

          {/* Checks + summary — stack on mobile */}
          <div className="grid-2" style={{ marginBottom:"clamp(.7rem,2vw,1rem)" }}>
            {/* Checks */}
            <div style={{ background:"rgba(255,255,255,.015)", border:"1px solid #ffffff06", borderRadius:"clamp(.6rem,2vw,.9rem)", overflow:"hidden" }}>
              <div className="label-xs" style={{ padding:"clamp(.6rem,2vw,.85rem) clamp(.7rem,2.5vw,1rem)", borderBottom:"1px solid #ffffff06" }}>9 SECURITY CHECKS</div>
              {result.checks.map((c,i)=><CheckRow key={i} c={c}/>)}
            </div>
            {/* Summary */}
            <div style={{ background:"rgba(255,255,255,.015)", border:"1px solid #ffffff06", borderRadius:"clamp(.6rem,2vw,.9rem)", padding:"clamp(.8rem,3vw,1.1rem)" }}>
              <div className="label-xs" style={{ marginBottom:".8rem" }}>SCAN SUMMARY</div>
              {[["Domain",result.base],["Protocol",result.url.startsWith("https")?"✓ HTTPS":"✕ HTTP"],["Extension",`.${result.tld}`],["Trusted",result.trusted?"✓ Yes":"✕ No"],["Score",`${result.score}/100`],["Threats",result.flags.length?`${result.flags.length} found`:"None"]].map(([k,v])=>(
                <div key={k} style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", padding:"clamp(.35rem,1vw,.5rem) 0", borderBottom:"1px solid #ffffff04", gap:".5rem" }}>
                  <span className="body-sm" style={{ color:"#334", flexShrink:0 }}>{k}</span>
                  <span style={{ fontSize:"clamp(.62rem,.9vw+.42rem,.76rem)", color:k==="Score"&&result.score>40?"#ff4444":k==="Trusted"&&result.trusted?"#00ff88":"#556", textAlign:"right", wordBreak:"break-all" }}>{v}</span>
                </div>
              ))}
              {result.flags.length>0 && (
                <div style={{ marginTop:".7rem" }}>
                  <div className="label-xs" style={{ marginBottom:".4rem" }}>FLAGS</div>
                  {result.flags.map((f,i)=>(
                    <div key={i} style={{ fontSize:"clamp(.55rem,.8vw+.38rem,.68rem)", color:"#ff7070", padding:".2rem .5rem", background:"rgba(255,68,68,.06)", borderRadius:"4px", marginBottom:".25rem" }}>⚠ {f}</div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* AI Analysis */}
          <div style={{ background:"rgba(0,255,136,.012)", border:"1px solid #00ff8812", borderRadius:"clamp(.6rem,2vw,.9rem)", overflow:"hidden" }}>
            <div style={{ padding:"clamp(.6rem,2vw,.85rem) clamp(.8rem,3vw,1.1rem)", borderBottom:"1px solid #00ff8812", display:"flex", alignItems:"center", gap:".5rem" }}>
              <div style={{ width:"7px", height:"7px", background:"#00ff88", borderRadius:"50%", animation:aiLoad?"blink .6s infinite":"none" }}/>
              <span className="label-xs" style={{ color:"#00ff88" }}>AI SECURITY ANALYSIS</span>
              {aiLoad && <span className="label-xs" style={{ marginLeft:"auto" }}>Generating…</span>}
            </div>
            <div style={{ padding:"clamp(.8rem,3vw,1.1rem)", minHeight:"60px" }}>
              {aiLoad && !aiText && (
                <div style={{ display:"flex", gap:".5rem", alignItems:"center", color:"#223" }}>
                  <div className="spin" style={{ width:"13px", height:"13px", border:"2px solid #00ff8830", borderTopColor:"#00ff88", borderRadius:"50%" }}/>
                  <span className="body-sm">CyberShield AI is analyzing the threat…</span>
                </div>
              )}
              <AiText text={aiText}/>
            </div>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !scanning && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(min(100%,150px),1fr))", gap:"clamp(.5rem,2vw,.75rem)", marginTop:".25rem" }}>
          {[{icon:"🎣",label:"Phishing Link?",eg:"Suspicious email/SMS"},{icon:"🛒",label:"Fake Shop?",eg:"Too-good-to-be-true deal"},{icon:"🚨",label:"Scam Alert?",eg:"Urgent account warning"}].map(c=>(
            <div key={c.label} style={{ background:"rgba(255,255,255,.015)", border:"1px solid #ffffff06", borderRadius:"clamp(.5rem,1.5vw,.75rem)", padding:"clamp(.75rem,3vw,1rem)", textAlign:"center" }}>
              <div style={{ fontSize:"clamp(1.2rem,4vw,1.6rem)", marginBottom:".4rem" }}>{c.icon}</div>
              <div style={{ fontSize:"clamp(.65rem,1vw+.45rem,.78rem)", color:"#556", fontWeight:600 }}>{c.label}</div>
              <div style={{ fontSize:"clamp(.55rem,.8vw+.38rem,.65rem)", color:"#223", marginTop:".2rem" }}>{c.eg}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  // ── CHAT PAGE ───────────────────────────────────────────────────────────────
  const ChatPage = (
    <div style={{ maxWidth:"min(100%,780px)", margin:"0 auto", padding:"clamp(.75rem,3vw,1.2rem) clamp(.75rem,4vw,1.25rem)", display:"flex", flexDirection:"column", height:"calc(100dvh - clamp(100px,18vw,130px))" }}>
      <div className="label-xs" style={{ marginBottom:".9rem" }}>◈ AI SECURITY ADVISOR</div>
      <div style={{ flex:1, overflowY:"auto", display:"flex", flexDirection:"column", gap:"clamp(.6rem,2vw,.9rem)", paddingBottom:".75rem" }}>
        {msgs.length===0 && (
          <div className="fade" style={{ margin:"auto", textAlign:"center", padding:"clamp(1rem,5vw,2rem)" }}>
            <div style={{ fontSize:"clamp(2rem,8vw,3rem)", marginBottom:".75rem" }}>🛡️</div>
            <div style={{ fontFamily:"'Syne',sans-serif", fontSize:"clamp(1rem,3vw,1.3rem)", color:"#fff", marginBottom:".4rem" }}>Ask me anything</div>
            <div className="body-sm" style={{ marginBottom:"1.4rem", maxWidth:"380px", margin:"0 auto .9rem" }}>No question is too basic. I explain everything in plain English.</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:".4rem", justifyContent:"center" }}>
              {["I think I've been hacked — what do I do?","How do I spot a fake website?","What is ransomware?","How do I set up 2FA?","Someone sent me a suspicious link"].map(q=>(
                <button key={q} onClick={()=>sendChat(q)} className="btn"
                  style={{ background:"rgba(0,255,136,.05)", border:"1px solid #00ff8820", color:"#00ff88", padding:".45rem .75rem", borderRadius:"20px", fontSize:"clamp(.6rem,.9vw+.42rem,.75rem)" }}
                  onMouseEnter={e=>e.currentTarget.style.background="rgba(0,255,136,.12)"}
                  onMouseLeave={e=>e.currentTarget.style.background="rgba(0,255,136,.05)"}
                >{q}</button>
              ))}
            </div>
          </div>
        )}
        {msgs.map((m,i)=>(
          <div key={i} className="fade" style={{ display:"flex", gap:"clamp(.5rem,2vw,.75rem)", flexDirection:m.role==="user"?"row-reverse":"row", alignItems:"flex-start" }}>
            <div style={{ width:"clamp(24px,5vw,30px)", height:"clamp(24px,5vw,30px)", borderRadius:"50%", flexShrink:0, display:"flex", alignItems:"center", justifyContent:"center", fontSize:"clamp(.65rem,2vw,.85rem)", background:m.role==="user"?"rgba(0,170,255,.12)":"rgba(0,255,136,.08)", border:`1px solid ${m.role==="user"?"#0af3":"#00ff8828"}` }}>
              {m.role==="user"?"👤":"🛡️"}
            </div>
            <div style={{ maxWidth:"min(78%,580px)", background:m.role==="user"?"rgba(0,170,255,.06)":"rgba(0,255,136,.03)", border:`1px solid ${m.role==="user"?"#0af2":"#00ff8812"}`, borderRadius:m.role==="user"?"clamp(.6rem,2vw,1rem) clamp(.6rem,2vw,1rem) .25rem clamp(.6rem,2vw,1rem)":"clamp(.6rem,2vw,1rem) clamp(.6rem,2vw,1rem) clamp(.6rem,2vw,1rem) .25rem", padding:"clamp(.55rem,2vw,.8rem) clamp(.7rem,2.5vw,1rem)" }}>
              <div style={{ fontSize:"clamp(.68rem,1vw+.46rem,.82rem)", color:m.role==="user"?"#9ec8ff":"#99eebb", lineHeight:1.75, whiteSpace:"pre-wrap", wordBreak:"break-word" }}>
                {m.content}
                {m.role==="assistant"&&i===msgs.length-1&&chatLoad&&<span className="blink" style={{ color:"#00ff88" }}>▌</span>}
              </div>
            </div>
          </div>
        ))}
        {chatLoad && msgs[msgs.length-1]?.role==="user" && (
          <div style={{ display:"flex", gap:".5rem", alignItems:"center" }}>
            <div style={{ width:"clamp(24px,5vw,30px)", height:"clamp(24px,5vw,30px)", borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center", border:"1px solid #00ff8828", background:"rgba(0,255,136,.08)", fontSize:"clamp(.65rem,2vw,.85rem)" }}>🛡️</div>
            <div style={{ padding:".75rem 1rem", background:"rgba(0,255,136,.03)", border:"1px solid #00ff8812", borderRadius:"clamp(.6rem,2vw,1rem) clamp(.6rem,2vw,1rem) clamp(.6rem,2vw,1rem) .25rem", display:"flex", gap:".3rem", alignItems:"center" }}>
              {[0,.25,.5].map((d,i)=><div key={i} style={{ width:"5px", height:"5px", background:"#00ff88", borderRadius:"50%", animation:`blink 1s ${d}s infinite` }}/>)}
            </div>
          </div>
        )}
        <div ref={chatEnd}/>
      </div>
      {/* Input */}
      <div style={{ borderTop:"1px solid #ffffff06", paddingTop:"clamp(.6rem,2vw,.9rem)", display:"flex", gap:"clamp(.4rem,1.5vw,.6rem)", alignItems:"flex-end" }}>
        <textarea value={chatIn} onChange={e=>setChatIn(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendChat();}}}
          placeholder="Ask anything… (Enter = send)" rows={2} disabled={chatLoad} className="inp"
          style={{ flex:1, background:"rgba(0,0,0,.55)", border:"1px solid #0f1a0f", borderRadius:"clamp(.4rem,1.5vw,.65rem)", color:"#99eebb", padding:"clamp(.5rem,1.5vw,.75rem) clamp(.6rem,2vw,.9rem)", fontSize:"clamp(.68rem,1vw+.46rem,.82rem)", resize:"none", lineHeight:1.5 }}
        />
        <button onClick={()=>sendChat()} disabled={chatLoad||!chatIn.trim()} className="btn"
          style={{ background:"rgba(0,255,136,.1)", border:"1px solid #00ff8840", color:"#00ff88", padding:"0 clamp(.7rem,2.5vw,1.1rem)", borderRadius:"clamp(.4rem,1.5vw,.65rem)", fontSize:"clamp(.65rem,1vw+.45rem,.8rem)", letterSpacing:"1px", height:"clamp(44px,8vw,54px)", flexShrink:0 }}>
          SEND
        </button>
      </div>
    </div>
  );

  // ── LEARN PAGE ──────────────────────────────────────────────────────────────
  const LearnPage = (
    <div style={{ maxWidth:"min(100%,900px)", margin:"0 auto", padding:"clamp(1rem,4vw,2rem) clamp(.75rem,4vw,1.25rem)" }}>
      <div style={{ marginBottom:"clamp(1rem,3vw,1.5rem)" }}>
        <h2 className="section-title">Security <span style={{ color:"#00ff88" }}>Hub</span></h2>
        <p className="body-sm" style={{ marginTop:".4rem" }}>Essential habits — explained simply for everyone</p>
      </div>
      <div className="grid-cards">
        {TIPS.map((t,i)=>(
          <div key={i} className="card-hover" style={{ background:"rgba(255,255,255,.015)", border:"1px solid #ffffff08", borderRadius:"clamp(.6rem,2vw,.9rem)", padding:"clamp(.9rem,3vw,1.2rem)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:"clamp(.6rem,2vw,.9rem)", marginBottom:".75rem" }}>
              <span style={{ fontSize:"clamp(1.3rem,4vw,1.6rem)" }}>{t.icon}</span>
              <div>
                <div style={{ fontSize:"clamp(.72rem,1.1vw+.48rem,.85rem)", fontWeight:600, color:"#ccc" }}>{t.title}</div>
                <div className="chip" style={{ color:t.level==="beginner"?"#00ff88":"#ffcc00", border:`1px solid ${t.level==="beginner"?"#00ff8830":"#ffcc0030"}`, background:t.level==="beginner"?"rgba(0,255,136,.06)":"rgba(255,204,0,.06)", marginTop:".25rem" }}>{t.level}</div>
              </div>
            </div>
            <p className="body-sm">{t.body}</p>
            <button onClick={()=>{setNav("chat");setTimeout(()=>sendChat(`Explain in detail: ${t.title}`),100);}} className="btn"
              style={{ marginTop:".75rem", width:"100%", background:"none", border:"1px solid #00ff8815", color:"#00ff8860", borderRadius:"20px", fontSize:"clamp(.58rem,.85vw+.38rem,.7rem)", letterSpacing:".05em" }}
              onMouseEnter={e=>{e.currentTarget.style.background="rgba(0,255,136,.07)";e.currentTarget.style.color="#00ff88";}}
              onMouseLeave={e=>{e.currentTarget.style.background="none";e.currentTarget.style.color="#00ff8860";}}
            >Ask AI to explain → </button>
          </div>
        ))}
      </div>
    </div>
  );

  // ── TOOLS PAGE ──────────────────────────────────────────────────────────────
  const ToolsPage = (
    <div style={{ maxWidth:"min(100%,900px)", margin:"0 auto", padding:"clamp(1rem,4vw,2rem) clamp(.75rem,4vw,1.25rem)" }}>
      <div style={{ marginBottom:"clamp(1rem,3vw,1.5rem)" }}>
        <h2 className="section-title">Free Security <span style={{ color:"#00ff88" }}>Tools</span></h2>
        <p className="body-sm" style={{ marginTop:".4rem" }}>Trusted by professionals — all 100% free</p>
      </div>
      <div className="grid-cards">
        {FREE_TOOLS.map((t,i)=>(
          <a key={i} href={t.url} target="_blank" rel="noreferrer" className="card-hover"
            style={{ background:"rgba(255,255,255,.015)", border:"1px solid #ffffff08", borderRadius:"clamp(.6rem,2vw,.9rem)", padding:"clamp(.9rem,3vw,1.2rem)", textDecoration:"none", display:"block" }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:".7rem" }}>
              <span style={{ fontSize:"clamp(1.3rem,4vw,1.6rem)" }}>{t.icon}</span>
              <span className="chip" style={{ color:t.color, border:`1px solid ${t.color}35`, background:`${t.color}0e` }}>{t.tag}</span>
            </div>
            <div style={{ fontSize:"clamp(.72rem,1.1vw+.48rem,.85rem)", fontWeight:600, color:"#bbb", marginBottom:".4rem" }}>{t.name} ↗</div>
            <p className="body-sm">{t.desc}</p>
          </a>
        ))}
      </div>
      {/* Footer credit */}
      <div style={{ marginTop:"clamp(1.2rem,4vw,2rem)", padding:"clamp(.9rem,3vw,1.2rem)", border:"1px solid #00ff8812", borderRadius:"clamp(.6rem,2vw,.9rem)", background:"rgba(0,255,136,.012)", textAlign:"center" }}>
        <p className="body-sm" style={{ lineHeight:2.2 }}>
          Built by <span style={{ color:"#00ff88", fontWeight:700 }}>Abubakar Usman Bida</span> · Cybersecurity Student<br/>
          <a href="https://github.com/abubakarusmanbida17-dev/Cybersecurity-journey" target="_blank" rel="noreferrer"
            style={{ color:"#0af", fontSize:"clamp(.58rem,.85vw+.38rem,.7rem)", textDecoration:"none" }}>
            github.com/abubakarusmanbida17-dev/Cybersecurity-journey
          </a><br/>
          <span style={{ fontSize:"clamp(.52rem,.75vw+.35rem,.64rem)", color:"#223" }}>CyberShield Pro v4.0 · Powered by Claude AI · Mobile-First Build</span>
        </p>
      </div>
    </div>
  );

  // ── RENDER ──────────────────────────────────────────────────────────────────
  return (
    <div style={{ minHeight:"100dvh", minWidth:"100%", background:"#060810", color:"#e0e8ff", fontFamily:"'JetBrains Mono','Fira Code','Courier New',monospace", display:"flex", flexDirection:"column", overflowX:"hidden", position:"relative" }}>
      <style>{CSS}</style>
      <div className="scanline" aria-hidden/>
      <BgGrid/>

      {/* ── HEADER ── */}
      <header style={{ position:"sticky", top:0, zIndex:100, background:"rgba(6,8,16,.97)", backdropFilter:"blur(20px)", WebkitBackdropFilter:"blur(20px)", borderBottom:"1px solid #00ff8812", padding:"0 clamp(.75rem,4vw,1.5rem)", height:"clamp(52px,10vw,64px)", display:"flex", alignItems:"center", justifyContent:"space-between", flexShrink:0, width:"100%" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"clamp(.6rem,2.5vw,1rem)" }}>
          <div style={{ position:"relative", flexShrink:0 }}>
            <div className="pulse" style={{ width:"clamp(30px,6vw,38px)", height:"clamp(30px,6vw,38px)", background:"rgba(0,255,136,.07)", border:"1.5px solid #00ff8845", borderRadius:"clamp(.35rem,1vw,.55rem)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:"clamp(.9rem,2.5vw,1.1rem)" }}>🛡️</div>
            <div style={{ position:"absolute", top:"-2px", right:"-2px", width:"clamp(7px,1.5vw,9px)", height:"clamp(7px,1.5vw,9px)", background:"#00ff88", borderRadius:"50%", border:"2px solid #060810" }}/>
          </div>
          <div>
            <div style={{ fontFamily:"'Syne',sans-serif", fontSize:"clamp(.85rem,2.5vw,1.1rem)", fontWeight:800, letterSpacing:".18em", color:"#fff", lineHeight:1.1 }}>
              CYBER<span style={{ color:"#00ff88" }}>SHIELD</span><span style={{ color:"#00aaff", fontSize:"clamp(.55rem,1.2vw,.7rem)", marginLeft:".25rem", letterSpacing:".05em" }}>PRO</span>
            </div>
            <div className="label-xs" style={{ marginTop:"1px" }}>BY ABUBAKAR USMAN BIDA</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:"clamp(.3rem,1vw,.5rem)", alignItems:"center" }}>
          <div className="chip" style={{ color:"#00ff88", border:"1px solid #00ff8825", background:"rgba(0,255,136,.07)" }}>● LIVE</div>
          <a href="https://github.com/abubakarusmanbida17-dev/Cybersecurity-journey" target="_blank" rel="noreferrer"
            className="chip btn" style={{ color:"#0af", border:"1px solid #0af3", background:"rgba(0,170,255,.07)", textDecoration:"none" }}>⌥ GH</a>
        </div>
      </header>

      {/* ── NAV ── */}
      <nav style={{ position:"sticky", top:"clamp(52px,10vw,64px)", zIndex:99, background:"rgba(6,8,16,.95)", borderBottom:"1px solid #ffffff06", flexShrink:0, width:"100%" }}>
        <div className="nav-scroll">
          {NAV_ITEMS.map(n=>(
            <button key={n.id} onClick={()=>setNav(n.id)} className="btn"
              style={{ background:nav===n.id?"rgba(0,255,136,.09)":"transparent", border:"none", borderBottom:nav===n.id?"2px solid #00ff88":"2px solid transparent", color:nav===n.id?"#00ff88":"#334", padding:"clamp(.5rem,1.5vw,.75rem) clamp(.7rem,2.5vw,1.1rem)", fontSize:"clamp(.62rem,.95vw+.42rem,.76rem)", letterSpacing:"1.2px", whiteSpace:"nowrap", display:"flex", alignItems:"center", gap:".35rem", flexShrink:0 }}>
              <span style={{ fontSize:"clamp(.7rem,2vw,.9rem)" }}>{n.icon}</span>
              {n.label}
            </button>
          ))}
        </div>
      </nav>

      {/* ── PAGE CONTENT ── */}
      <main style={{ flex:1, overflowY:"auto", overflowX:"hidden", position:"relative", zIndex:10, width:"100%" }}>
        {nav==="scanner" && ScannerPage}
        {nav==="chat"    && ChatPage}
        {nav==="learn"   && LearnPage}
        {nav==="tools"   && ToolsPage}
      </main>
    </div>
  );
}
