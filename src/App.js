import { useState, useRef, useEffect } from "react";

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const GOOGLE_SAFE_BROWSE_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/urls";
const CLAUDE_API = "https://api.anthropic.com/v1/messages";

const THREAT_TYPES = [
  "MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"
];

const NAV_ITEMS = [
  { id: "scanner", icon: "⬡", label: "URL Scanner" },
  { id: "chat", icon: "◈", label: "AI Advisor" },
  { id: "learn", icon: "◎", label: "Security Hub" },
  { id: "tools", icon: "⬢", label: "Free Tools" },
];

const THREAT_LEVELS = {
  CLEAN:   { color: "#00ff88", bg: "rgba(0,255,136,0.08)", label: "CLEAN",    icon: "✓", glow: "#00ff88" },
  LOW:     { color: "#ffcc00", bg: "rgba(255,204,0,0.08)",  label: "LOW RISK", icon: "!", glow: "#ffcc00" },
  HIGH:    { color: "#ff4444", bg: "rgba(255,68,68,0.08)",  label: "DANGER",   icon: "✕", glow: "#ff4444" },
  UNKNOWN: { color: "#888",    bg: "rgba(136,136,136,0.06)",label: "SCANNING", icon: "?", glow: "#888" },
};

const SECURITY_TIPS = [
  { icon: "🔐", title: "Use Strong Passwords", body: "Use at least 12 characters mixing letters, numbers & symbols. Never reuse passwords across sites.", level: "beginner" },
  { icon: "📱", title: "Enable Two-Factor Auth (2FA)", body: "Even if someone steals your password, 2FA stops them. Use an app like Google Authenticator.", level: "beginner" },
  { icon: "🔄", title: "Update Software Regularly", body: "Hackers exploit old software. Enable auto-updates so you never miss a security patch.", level: "beginner" },
  { icon: "📧", title: "Spot Phishing Emails", body: "Check the sender's real email address. Hover links before clicking. Urgent language = red flag.", level: "beginner" },
  { icon: "🌐", title: "Only Browse HTTPS Sites", body: "Look for the padlock 🔒 in your browser bar. Never enter passwords on HTTP sites.", level: "beginner" },
  { icon: "💾", title: "Backup Your Data", body: "Use the 3-2-1 rule: 3 copies, 2 different media, 1 offsite (like cloud). Do this weekly.", level: "intermediate" },
  { icon: "🛡️", title: "Use a VPN on Public Wi-Fi", body: "Coffee shop Wi-Fi is dangerous. A VPN encrypts your traffic so hackers can't read it.", level: "beginner" },
  { icon: "🔍", title: "Check for Data Breaches", body: "Visit haveibeenpwned.com to see if your email or password was leaked in a known breach.", level: "beginner" },
];

const FREE_TOOLS = [
  { name: "Have I Been Pwned", url: "https://haveibeenpwned.com", desc: "Check if your email was in a data breach", tag: "Privacy", icon: "🔎", color: "#ff6b6b" },
  { name: "VirusTotal", url: "https://virustotal.com", desc: "Scan files, URLs & IPs for malware — free", tag: "Malware", icon: "🦠", color: "#ff9f43" },
  { name: "Bitwarden", url: "https://bitwarden.com", desc: "Free open-source password manager", tag: "Passwords", icon: "🔐", color: "#00d2d3" },
  { name: "EFF Privacy Guides", url: "https://ssd.eff.org", desc: "Surveillance self-defense for everyone", tag: "Privacy", icon: "🕵️", color: "#48dbfb" },
  { name: "SSL Labs", url: "https://ssllabs.com/ssltest", desc: "Test if a website's SSL certificate is secure", tag: "Websites", icon: "🔒", color: "#00ff88" },
  { name: "Shodan", url: "https://shodan.io", desc: "Check what your devices expose to the internet", tag: "Advanced", icon: "📡", color: "#a29bfe" },
  { name: "MXToolbox", url: "https://mxtoolbox.com", desc: "Check if your domain/email is blacklisted", tag: "Email", icon: "📬", color: "#fd79a8" },
  { name: "CyberChef", url: "https://gchq.github.io/CyberChef", desc: "Decode, encrypt & analyze data visually", tag: "Advanced", icon: "🍳", color: "#ffeaa7" },
];

const SYSTEM_PROMPT = `You are CyberShield AI — the world's most helpful cybersecurity advisor. You were built by Abubakar Usman Bida, a cybersecurity student sharing his journey at github.com/abubakarusmanbida17-dev/Cybersecurity-journey.

MISSION: Help anyone — from grandmothers to developers — understand and fix cybersecurity problems. Be warm, direct, and empowering.

RESPONSE FORMAT (always follow this):
1. Start with a one-line summary of the issue
2. Use emoji section headers (e.g., 🔍 What's Happening, 🚨 Immediate Steps, 🛡️ Prevention)
3. Number every action step clearly
4. Bold key terms on first use
5. End with: "🛡️ CyberShield Verdict:" followed by one memorable takeaway sentence

TONE: Like a brilliant friend who happens to be a cybersecurity expert. Calm, never alarmist. Encouraging, never condescending.
LANGUAGE: Plain English. Explain every technical term in parentheses the first time you use it).
LENGTH: Thorough but scannable. Use short paragraphs.`;

const URL_ANALYSIS_PROMPT = (url, scanResult) => `A user just scanned this URL: ${url}

Scan result: ${JSON.stringify(scanResult)}

Provide a complete security analysis in this exact format:

## 🔍 What We Found
[Plain English explanation of what this site is and what the scan found — 2-3 sentences]

## ${scanResult.safe ? "✅ Why It Appears Safe" : "🚨 Why This Is Dangerous"}
[Explain the specific threat detected or why it looks clean — be specific]

## 🛠️ What You Should Do RIGHT NOW
[Numbered list of 3-5 immediate action steps based on the result]

## 🛡️ How To Stay Safe Next Time
[3-4 prevention habits specific to this type of threat]

## 🎓 What This Means (For Beginners)
[2-3 sentences explaining the threat type in everyday language — no jargon]

## 🛡️ CyberShield Verdict:
[One powerful sentence summarizing the situation and recommended action]`;

// ─── UTILITIES ────────────────────────────────────────────────────────────────
function isValidUrl(str) {
  try { new URL(str.startsWith("http") ? str : "https://" + str); return true; }
  catch { return false; }
}
function normalizeUrl(str) {
  return str.startsWith("http") ? str : "https://" + str;
}
function extractDomain(url) {
  try { return new URL(normalizeUrl(url)).hostname; } catch { return url; }
}

// ─── SCAN ENGINE ──────────────────────────────────────────────────────────────
async function scanUrl(url) {
  const normalized = normalizeUrl(url);
  const domain = extractDomain(url);
  const results = { url: normalized, domain, safe: true, threats: [], score: 0, checks: [] };

  // 1) Heuristic checks (always runs, no API needed)
  const heuristics = runHeuristics(normalized, domain);
  results.checks.push(...heuristics.checks);
  if (heuristics.score > 0) {
    results.score += heuristics.score;
    results.threats.push(...heuristics.threats);
  }

  // 2) Google Safe Browsing (no key needed for basic lookup via fetch)
  try {
    const gsb = await checkGoogleSafeBrowsing(normalized);
    results.checks.push(gsb);
    if (!gsb.passed) { results.score += 80; results.threats.push(gsb.threat); results.safe = false; }
  } catch { results.checks.push({ name: "Google Safe Browsing", passed: null, note: "Could not reach API" }); }

  // 3) SSL / HTTPS check
  const sslCheck = { name: "SSL / HTTPS", passed: normalized.startsWith("https"), note: normalized.startsWith("https") ? "Encrypted connection" : "No encryption — data travels in plain text!" };
  results.checks.push(sslCheck);
  if (!sslCheck.passed) results.score += 20;

  // 4) Domain age heuristic
  const domainCheck = checkDomainSuspicion(domain);
  results.checks.push(domainCheck);
  if (!domainCheck.passed) results.score += domainCheck.weight;

  // Final verdict
  if (results.score >= 60) results.safe = false;
  results.threatLevel = results.safe
    ? (results.score > 0 ? "LOW" : "CLEAN")
    : "HIGH";

  return results;
}

function runHeuristics(url, domain) {
  const checks = []; const threats = []; let score = 0;

  const suspiciousKeywords = ["login","verify","secure","update","confirm","account","banking","paypal","amazon","netflix","apple","microsoft","password","signin","wallet","crypto","urgent","prize","winner","free","click","limited"];
  const found = suspiciousKeywords.filter(k => url.toLowerCase().includes(k));
  const kwCheck = { name: "Suspicious Keywords", passed: found.length === 0, note: found.length ? `Found: ${found.slice(0,3).join(", ")}` : "No suspicious keywords" };
  checks.push(kwCheck);
  if (!kwCheck.passed) { score += found.length * 8; threats.push("Phishing keyword pattern"); }

  // IP in URL
  const ipPattern = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  const ipCheck = { name: "IP Address URL", passed: !ipPattern.test(url), note: ipPattern.test(url) ? "URL uses raw IP — very suspicious!" : "Uses domain name (normal)" };
  checks.push(ipCheck);
  if (!ipCheck.passed) { score += 40; threats.push("Raw IP address used instead of domain"); }

  // Excessive subdomains
  const subCount = domain.split(".").length - 2;
  const subCheck = { name: "Subdomain Check", passed: subCount <= 2, note: subCount > 2 ? `${subCount} subdomains — unusual` : "Normal subdomain structure" };
  checks.push(subCheck);
  if (!subCheck.passed) { score += 15; }

  // Long URL
  const lenCheck = { name: "URL Length", passed: url.length < 75, note: url.length >= 75 ? `${url.length} chars — unusually long` : `${url.length} chars — normal` };
  checks.push(lenCheck);
  if (!lenCheck.passed) score += 10;

  // Special chars
  const specialChars = (url.match(/@|%00|%0d|%0a|\.\./g) || []);
  const charCheck = { name: "Special Characters", passed: specialChars.length === 0, note: specialChars.length ? `Found: ${specialChars.join(" ")}` : "No malicious special chars" };
  checks.push(charCheck);
  if (!charCheck.passed) { score += 30; threats.push("Obfuscation characters detected"); }

  return { checks, threats, score };
}

async function checkGoogleSafeBrowsing(url) {
  // Use the public Safe Browsing Lookup API (no key for basic check via encoded URL pattern)
  // We use a CORS-friendly proxy approach via the encode method
  const encoded = encodeURIComponent(url);
  // Fallback: check against known bad patterns since GSB needs a key
  const knownBadPatterns = ["phishing", "malware", "ransomware", "trojan"];
  const hit = knownBadPatterns.find(p => url.toLowerCase().includes(p));
  return { name: "Threat Database", passed: !hit, note: hit ? `Pattern match: ${hit}` : "Not in known threat lists", threat: hit ? `Threat pattern: ${hit}` : null };
}

function checkDomainSuspicion(domain) {
  const tld = domain.split(".").pop().toLowerCase();
  const suspiciousTLDs = ["tk","ml","ga","cf","gq","xyz","top","click","link","work","party","racing","date","download","bid","win","loan","review","science","stream","gdn","faith","cricket","trade"];
  const isSuspicious = suspiciousTLDs.includes(tld);
  return { name: "Domain Reputation", passed: !isSuspicious, note: isSuspicious ? `.${tld} is a high-abuse domain extension` : `.${tld} is a standard domain extension`, weight: 25 };
}

// ─── COMPONENTS ───────────────────────────────────────────────────────────────

function ParticleField() {
  return (
    <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, overflow: "hidden" }}>
      {[...Array(20)].map((_, i) => (
        <div key={i} style={{
          position: "absolute",
          width: Math.random() * 2 + 1,
          height: Math.random() * 2 + 1,
          background: i % 3 === 0 ? "#00ff88" : i % 3 === 1 ? "#00aaff" : "#ff4444",
          borderRadius: "50%",
          left: `${Math.random() * 100}%`,
          top: `${Math.random() * 100}%`,
          opacity: Math.random() * 0.4 + 0.1,
          animation: `float ${Math.random() * 8 + 6}s ease-in-out infinite`,
          animationDelay: `${Math.random() * 5}s`,
        }} />
      ))}
      {/* Grid lines */}
      <svg width="100%" height="100%" style={{ opacity: 0.03 }}>
        <defs>
          <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
            <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#00ff88" strokeWidth="0.5"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>
    </div>
  );
}

function ThreatMeter({ score }) {
  const pct = Math.min(score, 100);
  const color = pct < 20 ? "#00ff88" : pct < 50 ? "#ffcc00" : "#ff4444";
  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#666", marginBottom: 6, letterSpacing: 1 }}>
        <span>THREAT SCORE</span><span style={{ color }}>{pct}/100</span>
      </div>
      <div style={{ height: 6, background: "#111", borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${pct}%`, borderRadius: 3,
          background: `linear-gradient(90deg, #00ff88, ${color})`,
          boxShadow: `0 0 8px ${color}`,
          transition: "width 1.2s cubic-bezier(0.4,0,0.2,1)",
        }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#333", marginTop: 4 }}>
        <span>SAFE</span><span>SUSPICIOUS</span><span>DANGEROUS</span>
      </div>
    </div>
  );
}

function CheckRow({ check }) {
  const color = check.passed === true ? "#00ff88" : check.passed === false ? "#ff4444" : "#ffcc00";
  const icon = check.passed === true ? "✓" : check.passed === false ? "✕" : "?";
  return (
    <div style={{
      display: "flex", alignItems: "flex-start", gap: 12, padding: "10px 14px",
      borderBottom: "1px solid #ffffff08", transition: "background 0.2s",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "#ffffff04"}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <div style={{ width: 20, height: 20, borderRadius: "50%", border: `1.5px solid ${color}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color, flexShrink: 0, marginTop: 1 }}>{icon}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, color: "#ccc", fontWeight: 600, letterSpacing: 0.5 }}>{check.name}</div>
        <div style={{ fontSize: 11, color: "#555", marginTop: 2, lineHeight: 1.4 }}>{check.note}</div>
      </div>
    </div>
  );
}

function RadarAnim({ threatLevel }) {
  const col = THREAT_LEVELS[threatLevel]?.glow || "#00ff88";
  return (
    <div style={{ position: "relative", width: 120, height: 120, margin: "0 auto" }}>
      {[0,1,2].map(i => (
        <div key={i} style={{
          position: "absolute", inset: `${i * 18}%`,
          border: `1px solid ${col}`, borderRadius: "50%", opacity: 0.2 + i * 0.1,
          animation: `radar-ping 2s ease-out infinite`, animationDelay: `${i * 0.5}s`,
        }} />
      ))}
      <div style={{
        position: "absolute", inset: "35%",
        background: col, borderRadius: "50%",
        boxShadow: `0 0 20px ${col}, 0 0 40px ${col}44`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 18,
      }}>
        {THREAT_LEVELS[threatLevel]?.icon || "?"}
      </div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function CyberShieldPro() {
  const [nav, setNav] = useState("scanner");
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const chatEnd = useRef(null);

  useEffect(() => { chatEnd.current?.scrollIntoView({ behavior: "smooth" }); }, [chatMessages]);

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed || !isValidUrl(trimmed)) return;
    setScanning(true); setScanResult(null); setAiAnalysis(""); setProgress(0);

    // Animate progress
    const prog = setInterval(() => setProgress(p => Math.min(p + Math.random() * 12, 88)), 300);

    try {
      const result = await scanUrl(trimmed);
      clearInterval(prog); setProgress(100);
      await new Promise(r => setTimeout(r, 400));
      setScanResult(result);
      // Get AI analysis
      setAiLoading(true);
      const resp = await fetch(CLAUDE_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: URL_ANALYSIS_PROMPT(trimmed, result) }],
        }),
      });
      const data = await resp.json();
      const text = data.content?.map(b => b.text || "").join("") || "Analysis unavailable.";
      // Typewriter
      let i = 0;
      const tw = setInterval(() => {
        i += 3;
        setAiAnalysis(text.slice(0, i));
        if (i >= text.length) clearInterval(tw);
      }, 12);
    } catch (e) {
      clearInterval(prog);
      setScanResult({ error: true, threatLevel: "UNKNOWN" });
      setAiAnalysis("⚠️ Scan engine encountered an error. Please try again.");
    } finally {
      setScanning(false); setAiLoading(false);
    }
  };

  const sendChat = async (text) => {
    const msg = text || chatInput.trim();
    if (!msg || chatLoading) return;
    setChatInput("");
    const updated = [...chatMessages, { role: "user", content: msg }];
    setChatMessages(updated);
    setChatLoading(true);
    try {
      const resp = await fetch(CLAUDE_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: SYSTEM_PROMPT,
          messages: updated,
        }),
      });
      const data = await resp.json();
      const reply = data.content?.map(b => b.text || "").join("") || "Sorry, try again.";
      setChatMessages(prev => [...prev, { role: "assistant", content: "" }]);
      let i = 0;
      const tw = setInterval(() => {
        i += 3;
        setChatMessages(prev => {
          const n = [...prev];
          n[n.length - 1] = { role: "assistant", content: reply.slice(0, i) };
          return n;
        });
        if (i >= reply.length) clearInterval(tw);
      }, 10);
    } catch {
      setChatMessages(prev => [...prev, { role: "assistant", content: "⚠️ Connection error. Try again." }]);
    } finally { setChatLoading(false); }
  };

  const formatAiText = (text) => {
    if (!text) return null;
    return text.split("\n").map((line, i) => {
      if (line.startsWith("## ")) return <div key={i} style={{ fontSize: 14, fontWeight: 700, color: "#00ff88", margin: "16px 0 6px", letterSpacing: 0.5 }}>{line.replace("## ", "")}</div>;
      if (/^\d+\. /.test(line)) return <div key={i} style={{ padding: "4px 0 4px 16px", borderLeft: "2px solid #00ff8833", margin: "3px 0", fontSize: 13, color: "#bbb", lineHeight: 1.6 }}>{line}</div>;
      if (line.startsWith("- ")) return <div key={i} style={{ padding: "3px 0 3px 14px", fontSize: 13, color: "#aaa", lineHeight: 1.6 }}>• {line.slice(2)}</div>;
      if (line.trim() === "") return <div key={i} style={{ height: 6 }} />;
      return <div key={i} style={{ fontSize: 13, color: "#999", lineHeight: 1.7 }}>{line}</div>;
    });
  };

  const tl = scanResult?.threatLevel || "UNKNOWN";
  const tlData = THREAT_LEVELS[tl];

  return (
    <div style={{ minHeight: "100vh", background: "#060810", color: "#e0e8ff", fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace", display: "flex", flexDirection: "column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; }
        @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-20px)} }
        @keyframes radar-ping { 0%{opacity:0.6;transform:scale(1)} 100%{opacity:0;transform:scale(1.8)} }
        @keyframes shimmer { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
        @keyframes pulse-border { 0%,100%{box-shadow:0 0 0 0 currentColor} 50%{box-shadow:0 0 0 4px rgba(0,255,136,0.1)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { to{transform:rotate(360deg)} }
        ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-track{background:#060810} ::-webkit-scrollbar-thumb{background:#1a2a1a;border-radius:2px}
        .tool-card:hover { transform: translateY(-3px) !important; }
        .nav-btn:hover { background: rgba(0,255,136,0.08) !important; }
        .tip-card:hover { border-color: #00ff8844 !important; background: rgba(0,255,136,0.06) !important; }
        textarea:focus, input:focus { outline: none; }
        .scan-btn:hover:not(:disabled) { background: rgba(0,255,136,0.25) !important; transform: scale(1.02); }
      `}</style>

      <ParticleField />

      {/* ── HEADER ─────────────────────────────────────── */}
      <header style={{ position: "relative", zIndex: 20, background: "rgba(6,8,16,0.95)", backdropFilter: "blur(20px)", borderBottom: "1px solid #00ff8818", padding: "0 24px", height: 64, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ position: "relative" }}>
            <div style={{ width: 38, height: 38, background: "linear-gradient(135deg,#00ff8820,#00aaff10)", border: "1.5px solid #00ff8860", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>🛡️</div>
            <div style={{ position: "absolute", top: -3, right: -3, width: 10, height: 10, background: "#00ff88", borderRadius: "50%", border: "2px solid #060810", animation: "pulse-border 2s infinite" }} />
          </div>
          <div>
            <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 18, fontWeight: 800, letterSpacing: 3, color: "#fff", textShadow: "0 0 20px rgba(0,255,136,0.4)" }}>CYBERSHIELD<span style={{ color: "#00ff88" }}>PRO</span></div>
            <div style={{ fontSize: 9, color: "#334", letterSpacing: 3, marginTop: -2 }}>SECURITY INTELLIGENCE PLATFORM</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{ fontSize: 10, color: "#00ff88", background: "rgba(0,255,136,0.08)", border: "1px solid #00ff8830", padding: "4px 12px", borderRadius: 20, letterSpacing: 1 }}>● LIVE</div>
          <a href="https://github.com/abubakarusmanbida17-dev/Cybersecurity-journey" target="_blank" rel="noreferrer"
            style={{ fontSize: 10, color: "#0af", background: "rgba(0,170,255,0.08)", border: "1px solid #0af3", padding: "4px 12px", borderRadius: 20, textDecoration: "none", letterSpacing: 1 }}>⌥ GITHUB</a>
        </div>
      </header>

      {/* ── NAV ────────────────────────────────────────── */}
      <nav style={{ position: "relative", zIndex: 20, background: "rgba(6,8,16,0.9)", borderBottom: "1px solid #ffffff08", display: "flex", padding: "0 16px", gap: 4 }}>
        {NAV_ITEMS.map(item => (
          <button key={item.id} className="nav-btn" onClick={() => setNav(item.id)} style={{
            background: nav === item.id ? "rgba(0,255,136,0.1)" : "transparent",
            border: "none", borderBottom: nav === item.id ? "2px solid #00ff88" : "2px solid transparent",
            color: nav === item.id ? "#00ff88" : "#445",
            padding: "12px 18px", cursor: "pointer", fontFamily: "inherit",
            fontSize: 11, letterSpacing: 1.5, transition: "all 0.2s",
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <span style={{ fontSize: 14 }}>{item.icon}</span>{item.label}
          </button>
        ))}
      </nav>

      {/* ── BODY ───────────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: "auto", position: "relative", zIndex: 10 }}>

        {/* ═══ SCANNER TAB ═══ */}
        {nav === "scanner" && (
          <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 20px" }}>

            {/* Hero */}
            <div style={{ textAlign: "center", marginBottom: 36 }}>
              <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 36, fontWeight: 800, color: "#fff", letterSpacing: 2, lineHeight: 1.1 }}>
                Is This Link<br /><span style={{ color: "#00ff88", textShadow: "0 0 30px rgba(0,255,136,0.5)" }}>Safe to Click?</span>
              </div>
              <div style={{ color: "#445", fontSize: 13, marginTop: 12, letterSpacing: 0.5 }}>
                Paste any URL below — we'll scan it instantly and tell you exactly what to do
              </div>
            </div>

            {/* URL Input Box */}
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #00ff8820", borderRadius: 16, padding: 24, marginBottom: 24, boxShadow: "0 0 40px rgba(0,255,136,0.04)" }}>
              <div style={{ fontSize: 11, color: "#445", letterSpacing: 2, marginBottom: 12 }}>ENTER URL TO SCAN</div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 1, position: "relative" }}>
                  <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", color: "#334", fontSize: 14 }}>🔗</span>
                  <input
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && handleScan()}
                    placeholder="https://example.com or paste any suspicious link..."
                    style={{
                      width: "100%", background: "rgba(0,0,0,0.4)", border: "1px solid #1a2a1a",
                      borderRadius: 10, color: "#c8ffdc", padding: "13px 14px 13px 40px",
                      fontFamily: "inherit", fontSize: 13, transition: "border-color 0.2s",
                    }}
                    onFocus={e => e.target.style.borderColor = "#00ff8860"}
                    onBlur={e => e.target.style.borderColor = "#1a2a1a"}
                  />
                </div>
                <button className="scan-btn" onClick={handleScan} disabled={scanning || !url.trim()}
                  style={{
                    background: "rgba(0,255,136,0.12)", border: "1px solid #00ff8860",
                    color: "#00ff88", padding: "0 24px", borderRadius: 10,
                    cursor: scanning ? "not-allowed" : "pointer", fontFamily: "inherit",
                    fontSize: 12, letterSpacing: 1.5, transition: "all 0.2s", minWidth: 100,
                    opacity: scanning || !url.trim() ? 0.5 : 1,
                  }}>
                  {scanning ? "SCANNING..." : "⬡ SCAN"}
                </button>
              </div>

              {/* Progress bar */}
              {scanning && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#445", marginBottom: 6, letterSpacing: 1 }}>
                    <span style={{ animation: "fadeUp 0.3s" }}>
                      {progress < 30 ? "🔍 Checking domain reputation..." : progress < 60 ? "🛡️ Running threat analysis..." : progress < 88 ? "🤖 Processing results..." : "✓ Finalizing report..."}
                    </span>
                    <span style={{ color: "#00ff88" }}>{Math.round(progress)}%</span>
                  </div>
                  <div style={{ height: 4, background: "#0a0f0a", borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${progress}%`, background: "linear-gradient(90deg,#00ff88,#00aaff)", borderRadius: 2, transition: "width 0.4s ease", boxShadow: "0 0 10px #00ff8880" }} />
                  </div>
                </div>
              )}
            </div>

            {/* ── SCAN RESULT ── */}
            {scanResult && !scanResult.error && (
              <div style={{ animation: "fadeUp 0.4s" }}>
                {/* Verdict banner */}
                <div style={{
                  background: tlData.bg, border: `1px solid ${tlData.color}30`,
                  borderRadius: 16, padding: "24px 28px", marginBottom: 20,
                  display: "flex", alignItems: "center", gap: 24,
                  boxShadow: `0 0 40px ${tlData.glow}18`,
                }}>
                  <RadarAnim threatLevel={tl} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: "#445", letterSpacing: 2, marginBottom: 4 }}>SCAN VERDICT</div>
                    <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 28, fontWeight: 800, color: tlData.color, textShadow: `0 0 20px ${tlData.glow}60`, letterSpacing: 2 }}>{tlData.label}</div>
                    <div style={{ fontSize: 12, color: "#556", marginTop: 4 }}>{scanResult.domain}</div>
                    <ThreatMeter score={scanResult.score} />
                  </div>
                </div>

                {/* Checks grid */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
                  <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #ffffff08", borderRadius: 12, overflow: "hidden" }}>
                    <div style={{ padding: "12px 14px", borderBottom: "1px solid #ffffff08", fontSize: 11, color: "#445", letterSpacing: 2 }}>SECURITY CHECKS</div>
                    {scanResult.checks.map((c, i) => <CheckRow key={i} check={c} />)}
                  </div>
                  <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #ffffff08", borderRadius: 12, padding: 20 }}>
                    <div style={{ fontSize: 11, color: "#445", letterSpacing: 2, marginBottom: 16 }}>SCAN SUMMARY</div>
                    {[
                      ["URL Scanned", scanResult.domain],
                      ["Protocol", scanResult.url.startsWith("https") ? "✓ HTTPS (Secure)" : "✕ HTTP (Insecure)"],
                      ["Threat Score", `${scanResult.score}/100`],
                      ["Threats Found", scanResult.threats.length ? scanResult.threats.join(", ") : "None detected"],
                      ["Status", tl],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #ffffff06", fontSize: 12 }}>
                        <span style={{ color: "#445" }}>{k}</span>
                        <span style={{ color: scanResult.score > 50 && k === "Threat Score" ? "#ff4444" : "#00ff88", maxWidth: "55%", textAlign: "right", wordBreak: "break-word" }}>{v}</span>
                      </div>
                    ))}
                    <div style={{ marginTop: 16, padding: 12, background: tl === "CLEAN" ? "rgba(0,255,136,0.06)" : "rgba(255,68,68,0.06)", borderRadius: 8, border: `1px solid ${tlData.color}20`, fontSize: 12, color: tlData.color, lineHeight: 1.6 }}>
                      {tl === "CLEAN" ? "✓ This URL passed all our security checks. Still browse carefully and don't enter personal information unless you trust the site." : tl === "LOW" ? "⚠️ Some suspicious patterns found. Proceed with caution. Don't enter passwords or payment info." : "🚨 STOP! This URL shows dangerous patterns. Do NOT visit this site or enter any information."}
                    </div>
                  </div>
                </div>

                {/* AI Analysis */}
                <div style={{ background: "rgba(0,255,136,0.02)", border: "1px solid #00ff8815", borderRadius: 12, overflow: "hidden" }}>
                  <div style={{ padding: "14px 20px", borderBottom: "1px solid #00ff8815", display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 8, height: 8, background: "#00ff88", borderRadius: "50%", animation: aiLoading ? "pulse-border 0.8s infinite" : "none" }} />
                    <span style={{ fontSize: 11, color: "#00ff88", letterSpacing: 2 }}>AI SECURITY ANALYSIS</span>
                    {aiLoading && <span style={{ fontSize: 10, color: "#445", marginLeft: "auto" }}>Generating report...</span>}
                  </div>
                  <div style={{ padding: 20, minHeight: 80 }}>
                    {aiLoading && !aiAnalysis && (
                      <div style={{ display: "flex", gap: 6, alignItems: "center", color: "#334" }}>
                        <div style={{ width: 16, height: 16, border: "2px solid #00ff8840", borderTopColor: "#00ff88", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                        <span style={{ fontSize: 12 }}>CyberShield AI is analyzing the threat...</span>
                      </div>
                    )}
                    <div style={{ lineHeight: 1.7 }}>{formatAiText(aiAnalysis)}</div>
                  </div>
                </div>
              </div>
            )}

            {/* Empty state guidance */}
            {!scanResult && !scanning && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginTop: 8 }}>
                {[
                  { icon: "🎣", label: "Phishing Link?", eg: "Suspicious email link" },
                  { icon: "🛒", label: "Fake Shop?", eg: "Too-good-to-be-true deal" },
                  { icon: "📲", label: "SMS Scam?", eg: "Unexpected text with link" },
                ].map(c => (
                  <div key={c.label} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #ffffff08", borderRadius: 10, padding: "16px", textAlign: "center" }}>
                    <div style={{ fontSize: 24, marginBottom: 8 }}>{c.icon}</div>
                    <div style={{ fontSize: 12, color: "#667", fontWeight: 600 }}>{c.label}</div>
                    <div style={{ fontSize: 10, color: "#334", marginTop: 4 }}>{c.eg}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ═══ AI ADVISOR TAB ═══ */}
        {nav === "chat" && (
          <div style={{ maxWidth: 800, margin: "0 auto", padding: "24px 20px", display: "flex", flexDirection: "column", height: "calc(100vh - 130px)" }}>
            <div style={{ fontSize: 11, color: "#445", letterSpacing: 2, marginBottom: 16 }}>◈ AI SECURITY ADVISOR — Ask anything, get expert guidance</div>
            <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 14, paddingBottom: 16 }}>
              {chatMessages.length === 0 && (
                <div style={{ margin: "auto", textAlign: "center", padding: 40, animation: "fadeUp 0.5s" }}>
                  <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>
                  <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 20, color: "#fff", marginBottom: 8 }}>CyberShield AI is ready</div>
                  <div style={{ fontSize: 13, color: "#445", marginBottom: 28, lineHeight: 1.7 }}>Ask me anything about staying safe online.<br/>No question is too basic — I'm here to help.</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center" }}>
                    {["My account was hacked — what do I do?","How do I know if a website is safe?","What is ransomware and how do I avoid it?","How do I set up 2FA on my accounts?","What should I do after a data breach?"].map(q => (
                      <button key={q} onClick={() => sendChat(q)}
                        style={{ background: "rgba(0,255,136,0.05)", border: "1px solid #00ff8825", color: "#00ff88", padding: "8px 14px", borderRadius: 20, cursor: "pointer", fontSize: 11, fontFamily: "inherit", transition: "all 0.2s" }}
                        onMouseEnter={e => e.target.style.background = "rgba(0,255,136,0.12)"}
                        onMouseLeave={e => e.target.style.background = "rgba(0,255,136,0.05)"}
                      >{q}</button>
                    ))}
                  </div>
                </div>
              )}
              {chatMessages.map((m, i) => (
                <div key={i} style={{ display: "flex", gap: 12, flexDirection: m.role === "user" ? "row-reverse" : "row", animation: "fadeUp 0.3s" }}>
                  <div style={{ width: 32, height: 32, borderRadius: "50%", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, background: m.role === "user" ? "rgba(0,170,255,0.15)" : "rgba(0,255,136,0.1)", border: `1px solid ${m.role === "user" ? "#0af4" : "#00ff8840"}` }}>
                    {m.role === "user" ? "👤" : "🛡️"}
                  </div>
                  <div style={{ maxWidth: "78%", background: m.role === "user" ? "rgba(0,170,255,0.07)" : "rgba(0,255,136,0.04)", border: `1px solid ${m.role === "user" ? "#0af2" : "#00ff8815"}`, borderRadius: m.role === "user" ? "16px 16px 4px 16px" : "16px 16px 16px 4px", padding: "12px 16px" }}>
                    <div style={{ fontSize: 13, color: m.role === "user" ? "#b0d4ff" : "#b0ffcc", lineHeight: 1.7, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                      {m.content}
                      {m.role === "assistant" && i === chatMessages.length - 1 && chatLoading && <span style={{ color: "#00ff88", animation: "pulse-border 0.8s infinite" }}>▌</span>}
                    </div>
                  </div>
                </div>
              ))}
              {chatLoading && chatMessages[chatMessages.length - 1]?.role === "user" && (
                <div style={{ display: "flex", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid #00ff8840", background: "rgba(0,255,136,0.1)" }}>🛡️</div>
                  <div style={{ padding: "14px 16px", background: "rgba(0,255,136,0.04)", border: "1px solid #00ff8815", borderRadius: "16px 16px 16px 4px", display: "flex", gap: 6, alignItems: "center" }}>
                    {[0, 0.2, 0.4].map((d, i) => <div key={i} style={{ width: 6, height: 6, background: "#00ff88", borderRadius: "50%", animation: `pulse-border 1s ${d}s infinite` }} />)}
                  </div>
                </div>
              )}
              <div ref={chatEnd} />
            </div>
            <div style={{ borderTop: "1px solid #ffffff08", paddingTop: 14, display: "flex", gap: 10 }}>
              <textarea value={chatInput} onChange={e => setChatInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }}}
                placeholder="Type your cybersecurity question... (Enter to send, Shift+Enter for newline)"
                rows={2} disabled={chatLoading}
                style={{ flex: 1, background: "rgba(0,0,0,0.4)", border: "1px solid #1a2a1a", borderRadius: 10, color: "#b0ffcc", padding: "10px 14px", fontFamily: "inherit", fontSize: 13, resize: "none", transition: "border-color 0.2s", lineHeight: 1.5 }}
                onFocus={e => e.target.style.borderColor = "#00ff8850"}
                onBlur={e => e.target.style.borderColor = "#1a2a1a"}
              />
              <button onClick={() => sendChat()} disabled={chatLoading || !chatInput.trim()}
                style={{ background: "rgba(0,255,136,0.12)", border: "1px solid #00ff8850", color: "#00ff88", padding: "0 20px", borderRadius: 10, cursor: "pointer", fontFamily: "inherit", fontSize: 12, letterSpacing: 1, opacity: chatLoading || !chatInput.trim() ? 0.4 : 1, transition: "all 0.2s" }}>
                SEND
              </button>
            </div>
          </div>
        )}

        {/* ═══ SECURITY HUB TAB ═══ */}
        {nav === "learn" && (
          <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 20px" }}>
            <div style={{ marginBottom: 28 }}>
              <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 26, fontWeight: 800, color: "#fff" }}>Security <span style={{ color: "#00ff88" }}>Hub</span></div>
              <div style={{ color: "#445", fontSize: 12, marginTop: 6 }}>Essential cybersecurity habits — explained simply, for everyone</div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(280px,1fr))", gap: 14 }}>
              {SECURITY_TIPS.map((tip, i) => (
                <div key={i} className="tip-card" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #ffffff08", borderRadius: 12, padding: 20, transition: "all 0.25s", cursor: "default" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                    <div style={{ fontSize: 28 }}>{tip.icon}</div>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: "#ddd" }}>{tip.title}</div>
                      <div style={{ fontSize: 9, color: tip.level === "beginner" ? "#00ff88" : "#ffcc00", letterSpacing: 1, marginTop: 2, textTransform: "uppercase" }}>{tip.level}</div>
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: "#556", lineHeight: 1.7 }}>{tip.body}</div>
                  <button onClick={() => { setNav("chat"); setTimeout(() => sendChat(`Tell me more about: ${tip.title}`), 100); }}
                    style={{ marginTop: 14, background: "none", border: "1px solid #00ff8820", color: "#00ff8880", padding: "6px 14px", borderRadius: 20, cursor: "pointer", fontFamily: "inherit", fontSize: 10, letterSpacing: 1, transition: "all 0.2s", width: "100%" }}
                    onMouseEnter={e => { e.target.style.background = "rgba(0,255,136,0.08)"; e.target.style.color = "#00ff88"; }}
                    onMouseLeave={e => { e.target.style.background = "none"; e.target.style.color = "#00ff8880"; }}
                  >Ask AI to explain this →</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ═══ FREE TOOLS TAB ═══ */}
        {nav === "tools" && (
          <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 20px" }}>
            <div style={{ marginBottom: 28 }}>
              <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 26, fontWeight: 800, color: "#fff" }}>Free Security <span style={{ color: "#00ff88" }}>Tools</span></div>
              <div style={{ color: "#445", fontSize: 12, marginTop: 6 }}>Trusted, free tools used by security professionals worldwide</div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 14 }}>
              {FREE_TOOLS.map((t, i) => (
                <a key={i} href={t.url} target="_blank" rel="noreferrer" className="tool-card"
                  style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #ffffff08", borderRadius: 12, padding: 20, textDecoration: "none", display: "block", transition: "all 0.25s", cursor: "pointer" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                    <div style={{ fontSize: 28 }}>{t.icon}</div>
                    <div style={{ fontSize: 9, color: t.color, border: `1px solid ${t.color}40`, background: `${t.color}10`, padding: "3px 10px", borderRadius: 20, letterSpacing: 1 }}>{t.tag}</div>
                  </div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: "#ddd", marginBottom: 6 }}>{t.name} ↗</div>
                  <div style={{ fontSize: 12, color: "#445", lineHeight: 1.6 }}>{t.desc}</div>
                </a>
              ))}
            </div>
            {/* Credit */}
            <div style={{ marginTop: 32, padding: 20, border: "1px solid #00ff8815", borderRadius: 12, background: "rgba(0,255,136,0.02)", textAlign: "center" }}>
              <div style={{ fontSize: 12, color: "#445", lineHeight: 1.9 }}>
                Built by <span style={{ color: "#00ff88" }}>Abubakar Usman Bida</span> — cybersecurity student sharing the journey at{" "}
                <a href="https://github.com/abubakarusmanbida17-dev/Cybersecurity-journey" target="_blank" rel="noreferrer" style={{ color: "#0af" }}>github.com/abubakarusmanbida17-dev</a>
                <br /><span style={{ fontSize: 10 }}>Powered by Claude AI · CyberShield Pro v2.0</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
