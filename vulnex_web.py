import streamlit as st
import re
from urllib.parse import urlparse
import time

# --- CONFIGURATION ---
st.set_page_config(page_title="Vulnex Link-Guard", page_icon="🛡️", layout="centered")

# --- CSS FOR PROFESSIONAL UI ---
st.markdown("""
    <style>
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #d53369 0%, #daae51 100%);
        color: white;
        font-weight: bold;
        border: none;
        height: 55px;
        font-size: 18px;
        border-radius: 12px;
    }
    .report-box {
        padding: 15px;
        border-radius: 8px;
        background-color: #262730;
        border-left: 5px solid #ff4b4b;
        margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- THREAT INTELLIGENCE DATABASE ---

# 1. FREE HOSTING (Hackers use these to host fake sites free)
FREE_HOSTING_DOMAINS = [
    '000webhostapp.com', 'herokuapp.com', 'netlify.app', 'vercel.app', 
    'pages.dev', 'firebaseapp.com', 'glitch.me', 'repl.co', 'wixsite.com', 
    'koyeb.app', 'onrender.com', 'render.com', 'railway.app', 'fly.dev',
    'duckdns.org', 'ngrok.io'
]

# 2. BRAND PROTECTION (If these words exist, domain MUST match)
PROTECTED_BRANDS = {
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'twitter': 'twitter.com',
    'paypal': 'paypal.com',
    'gmail': 'google.com',
    'google': 'google.com',
    'microsoft': 'microsoft.com',
    'netflix': 'netflix.com',
    'gtbank': 'gtbank.com',
    'zenith': 'zenithbank.com',
    'access': 'accessbankplc.com',
    'uba': 'ubagroup.com',
    'opay': 'opayweb.com',
    'palmpay': 'palmpay.com'
}

# 3. HIGH RISK TLDs (Cheap domains used by scammers)
SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.vip', '.gq', '.tk', '.ml', '.cf', '.cc', '.info']

# 4. MALICIOUS FILES
MALICIOUS_FILES = ['.exe', '.apk', '.scr', '.bat', '.sh', '.zip', '.rar']

# --- SCANNER LOGIC ---
def scan_link(link):
    risk_score = 0
    red_flags = []
    
    # Clean input
    link = link.strip()
    if not link.startswith(('http://', 'https://')):
        link = 'http://' + link
        
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        full_path = link.lower()
    except:
        return 100, ["URL is malformed or invalid"]

    # RULE 1: FREE HOSTING DETECTION (Critical for Koyeb/Vercel)
    for host in FREE_HOSTING_DOMAINS:
        if host in domain:
            risk_score += 60
            red_flags.append(f"Hosted on Free Cloud Platform '{host}' (High Risk)")

    # RULE 2: BRAND IMPERSONATION (The Facebook Fix)
    for brand, official in PROTECTED_BRANDS.items():
        # Check if brand name appears in the link (path or subdomain)
        if brand in full_path:
            # But the domain is NOT the official one
            if official not in domain:
                risk_score += 100 # INSTANT MAX RISK
                red_flags.append(f"🚨 FAKE {brand.upper()} DETECTED! (Link says '{brand}' but domain is '{domain}')")

    # RULE 3: SUSPICIOUS TLDs (The "Bad Neighborhood" Check)
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 25
        red_flags.append("Uses a Low-Reputation Domain Extension (.xyz, .top, etc)")

    # RULE 4: IP ADDRESS USAGE
    if re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", domain):
        risk_score += 50
        red_flags.append("Uses raw IP Address instead of Domain Name")

    # RULE 5: MALICIOUS FILE EXTENSIONS
    if any(full_path.endswith(ext) for ext in MALICIOUS_FILES):
        risk_score += 100
        red_flags.append("Link points to a direct MALWARE file download")

    # RULE 6: @ SYMBOL REDIRECT
    if '@' in link:
        risk_score += 30
        red_flags.append("Contains '@' symbol (Browser redirection trick)")

    # Cap score at 100
    return min(risk_score, 100), red_flags

# --- UI LAYOUT ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Zero-Trust Phishing Detection | v3.2 Paranoid Mode")

url = st.text_input("Paste Link to Scan:", placeholder="https://...")

if st.button("RUN SECURITY AUDIT"):
    if url:
        # Fake processing for cool effect
        with st.status("Analyzing Threat Vectors...", expanded=True) as status:
            time.sleep(0.5)
            st.write("🔍 Checking Hosting Infrastructure...")
            time.sleep(0.3)
            st.write("🏢 Verifying Brand Identity...")
            time.sleep(0.3)
            status.update(label="Scan Complete", state="complete", expanded=False)
        
        score, flags = scan_link(url)

        st.divider()
        
        # DISPLAY SCORE
        col1, col2 = st.columns([1, 2])
        with col1:
            color = "#00C851" # Green
            if score > 75: color = "#ff4444" # Red
            elif score > 30: color = "#ffbb33" # Orange
            
            st.markdown(f"""
                <div style="text-align: center; border: 4px solid {color}; border-radius: 50%; width: 100px; height: 100px; display: flex; align-items: center; justify-content: center;">
                    <h1 style="color: {color}; margin: 0;">{score}</h1>
                </div>
            """, unsafe_allow_html=True)

        with col2:
            if score > 75:
                st.error("🚫 **DANGEROUS LINK**")
                st.write("Do not open this. It is confirmed phishing or malware.")
            elif score > 30:
                st.warning("⚠️ **SUSPICIOUS**")
                st.write("Proceed with extreme caution.")
            else:
                st.success("✅ **SAFE TO OPEN**")
                st.write("No threats detected.")

        # DISPLAY FLAGS
        if flags:
            st.subheader("⚠️ Detected Threats:")
            for flag in flags:
                st.markdown(f'<div class="report-box">{flag}</div>', unsafe_allow_html=True)

    else:
        st.info("Paste a link above to begin.")
