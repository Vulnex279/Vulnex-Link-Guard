import streamlit as st
import re
from urllib.parse import urlparse
import time
import difflib

# --- CONFIGURATION ---
st.set_page_config(page_title="Vulnex Link-Guard", page_icon="🛡️", layout="centered")

# --- CSS FOR PROFESSIONAL UI ---
st.markdown("""
    <style>
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #1CB5E0 0%, #000851 100%);
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

# 1. FREE HOSTING DOMAINS (Hackers use these)
FREE_HOSTING_DOMAINS = [
    '000webhostapp.com', 'herokuapp.com', 'netlify.app', 'vercel.app', 
    'pages.dev', 'firebaseapp.com', 'glitch.me', 'repl.co', 'wixsite.com', 
    'koyeb.app', 'onrender.com', 'render.com', 'railway.app', 'fly.dev',
    'duckdns.org', 'ngrok.io', 'surge.sh'
]

# 2. URL SHORTENERS (Hidden Destinations) - RESTORED & VERIFIED
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 
    'rebrand.ly', 'linktr.ee', 'cutt.ly'
]

# 3. OFFICIAL BRANDS (For Clone Detection)
OFFICIAL_DOMAINS = {
    'facebook.com': ['facebook', 'facebok', 'fb-login'],
    'instagram.com': ['instagram', 'insta-login'],
    'twitter.com': ['twitter', 'x.com'],
    'paypal.com': ['paypal', 'pay-pal'],
    'google.com': ['google', 'gmail', 'g-mail'],
    'microsoft.com': ['microsoft', 'office365', 'm-soft'],
    'netflix.com': ['netflix', 'net-flix'],
    'gtbank.com': ['gtbank', 'gtb', 'gt-bank', 'gtworld'],
    'zenithbank.com': ['zenith', 'zenithbank'],
    'accessbankplc.com': ['accessbank', 'access-bank'],
    'ubagroup.com': ['uba', 'ubagroup'],
    'opayweb.com': ['opay'],
    'palmpay.com': ['palmpay']
}

# 4. SUSPICIOUS TLDs & FILES
SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.vip', '.gq', '.tk', '.ml', '.cf', '.cc', '.info', '.online', '.site']
MALICIOUS_FILES = ['.exe', '.apk', '.scr', '.bat', '.sh', '.zip', '.rar']

# --- SMART LOGIC ---
def check_similarity(domain):
    """Calculates how similar a domain is to a real bank (Fuzzy Logic)"""
    highest_ratio = 0.0
    target_site = ""
    for real_domain in OFFICIAL_DOMAINS.keys():
        ratio = difflib.SequenceMatcher(None, domain, real_domain).ratio()
        if ratio > highest_ratio:
            highest_ratio = ratio
            target_site = real_domain
    return highest_ratio, target_site

# --- MAIN SCANNER ENGINE ---
def scan_link(link):
    risk_score = 0
    red_flags = []
    
    # 1. Clean and Parse
    link = link.strip()
    if not link.startswith(('http://', 'https://')):
        link = 'http://' + link
        
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        full_path = link.lower()
    except:
        return 100, ["URL is malformed or invalid"]

    # 2. RULE: FREE HOSTING (+60)
    for host in FREE_HOSTING_DOMAINS:
        if host in domain:
            risk_score += 60
            red_flags.append(f"Hosted on Free Cloud Platform '{host}' (High Risk)")

    # 3. RULE: URL SHORTENERS (+30) -> THIS FIXES THE BIT.LY ISSUE
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            risk_score += 30
            red_flags.append(f"Uses URL Shortener '{shortener}' (Destination Hidden)")

    # 4. RULE: CLONE DETECTION (The AI Brain)
    # Only run AI if it's not already flagged as a free host (to avoid double counting)
    if risk_score < 60:
        is_official = domain in OFFICIAL_DOMAINS
        if not is_official:
            # Check Similarity (Typosquatting)
            similarity, real_site = check_similarity(domain)
            if 0.75 < similarity < 1.0:
                risk_score += 80
                red_flags.append(f"🚨 CLONE DETECTED: This site mimics '{real_site}' ({int(similarity*100)}% match)")
            
            # Check Keywords (Brand Impersonation)
            for real_site, keywords in OFFICIAL_DOMAINS.items():
                if any(k in domain for k in keywords) and real_site not in domain:
                    risk_score += 80
                    red_flags.append(f"🚨 BRAND IMPERSONATION: Link contains '{keywords[0]}' but is NOT '{real_site}'")

    # 5. RULE: SUSPICIOUS TLDs (+25)
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 25
        red_flags.append("Uses a Low-Reputation Domain Extension (.xyz, .top, etc)")

    # 6. RULE: IP ADDRESS (+50)
    if re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", domain):
        risk_score += 50
        red_flags.append("Uses raw IP Address instead of Domain Name")

    # 7. RULE: MALICIOUS FILES (+100)
    if any(full_path.endswith(ext) for ext in MALICIOUS_FILES):
        risk_score += 100
        red_flags.append("Link points to a direct MALWARE file download")

    # 8. RULE: @ SYMBOL (+30)
    if '@' in link:
        risk_score += 30
        red_flags.append("Contains '@' symbol (Browser redirection trick)")

    return min(risk_score, 100), red_flags

# --- UI LAYOUT ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Genius-Mode Phishing Detection | v4.1 Golden Edition")

url = st.text_input("Paste Link to Scan:", placeholder="e.g. http://secure-gtbank-login.com")

if st.button("RUN INTELLIGENT SCAN"):
    if url:
        with st.status("Vulnex AI is thinking...", expanded=True) as status:
            time.sleep(0.5)
            st.write("🔍 Analyzing Structure...")
            time.sleep(0.3)
            st.write("🧠 Comparing with Legitimate Banking Database...")
            time.sleep(0.4)
            status.update(label="Analysis Complete", state="complete", expanded=False)
        
        score, flags = scan_link(url)

        st.divider()
        
        col1, col2 = st.columns([1, 2])
        with col1:
            color = "#00C851" # Green
            if score > 75: color = "#ff4444" # Red
            elif score > 20: color = "#ffbb33" # Orange
            
            st.markdown(f"""
                <div style="text-align: center; border: 4px solid {color}; border-radius: 50%; width: 100px; height: 100px; display: flex; align-items: center; justify-content: center;">
                    <h1 style="color: {color}; margin: 0;">{score}</h1>
                </div>
            """, unsafe_allow_html=True)

        with col2:
            if score > 75:
                st.error("🚫 **HIGH THREAT DETECTED**")
                st.write("This link is confirmed dangerous. Do not click.")
            elif score > 20:
                st.warning("⚠️ **SUSPICIOUS ACTIVITY**")
                st.write("This link looks unusual or hidden. Proceed with caution.")
            else:
                st.success("✅ **LOOKS SAFE**")
                st.write("No direct threats found. (Always verify manually).")

        if flags:
            st.subheader("⚠️ Security Alerts:")
            for flag in flags:
                st.markdown(f'<div class="report-box">{flag}</div>', unsafe_allow_html=True)

    else:
        st.info("Paste a link to activate the AI.")

# --- FOOTER ---
st.divider()
st.markdown("<p style='text-align: center; color: grey;'>Powered by Vulnex Security | Made in Nigeria 🇳🇬</p>", unsafe_allow_html=True)
