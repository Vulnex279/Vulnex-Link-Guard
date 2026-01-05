import streamlit as st
import re
from urllib.parse import urlparse
import time
import difflib  # <--- The new Brain Module (Built-in, Safe)

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
    .smart-box {
        padding: 15px;
        border-radius: 8px;
        background-color: #262730;
        border-left: 5px solid #1CB5E0;
        margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- THREAT INTELLIGENCE DATABASE ---

FREE_HOSTING_DOMAINS = [
    '000webhostapp.com', 'herokuapp.com', 'netlify.app', 'vercel.app', 
    'pages.dev', 'firebaseapp.com', 'glitch.me', 'repl.co', 'wixsite.com', 
    'koyeb.app', 'onrender.com', 'render.com', 'railway.app', 'fly.dev',
    'duckdns.org', 'ngrok.io', 'surge.sh'
]

# The "Real" Brands we want to protect
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

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.vip', '.gq', '.tk', '.ml', '.cf', '.cc', '.info', '.online', '.site']
MALICIOUS_FILES = ['.exe', '.apk', '.scr', '.bat', '.sh', '.zip', '.rar']

# --- SMART LOGIC ---
def check_similarity(domain):
    """
    Checks if the domain looks suspiciously similar to a real bank/site.
    Returns: (Similarity Score, Real Domain it copies)
    """
    highest_ratio = 0.0
    target_site = ""
    
    # Check against every official domain we know
    for real_domain in OFFICIAL_DOMAINS.keys():
        # Get similarity ratio (0.0 to 1.0)
        ratio = difflib.SequenceMatcher(None, domain, real_domain).ratio()
        if ratio > highest_ratio:
            highest_ratio = ratio
            target_site = real_domain
            
    return highest_ratio, target_site

# --- MAIN SCANNER ---
def scan_link(link):
    risk_score = 0
    red_flags = []
    smart_warnings = [] # New list for AI detections
    
    link = link.strip()
    if not link.startswith(('http://', 'https://')):
        link = 'http://' + link
        
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        full_path = link.lower()
    except:
        return 100, ["URL is malformed or invalid"], []

    # RULE 1: FREE HOSTING
    for host in FREE_HOSTING_DOMAINS:
        if host in domain:
            risk_score += 60
            red_flags.append(f"Hosted on Free Cloud Platform '{host}' (High Risk)")

    # RULE 2: CLONE DETECTION (The New Genius Brain) 🧠
    # Only run this if it's NOT a free host (saves time)
    if risk_score < 60:
        # Check if the domain is exact match (Safe)
        is_official = domain in OFFICIAL_DOMAINS
        
        if not is_official:
            # It's not the exact real site. Is it a clone?
            similarity, real_site = check_similarity(domain)
            
            # If similarity is High (e.g. 75%+) but not exact...
            if 0.75 < similarity < 1.0:
                risk_score += 80
                red_flags.append(f"🚨 CLONE DETECTED: This site mimics '{real_site}' ({int(similarity*100)}% match)")
            
            # Also check if keywords exist (e.g. 'gtbank-update.com')
            for real_site, keywords in OFFICIAL_DOMAINS.items():
                if any(k in domain for k in keywords) and real_site not in domain:
                    risk_score += 70
                    red_flags.append(f"🚨 BRAND IMPERSONATION: Link contains '{keywords[0]}' but is NOT '{real_site}'")

    # RULE 3: SUSPICIOUS TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 25
        red_flags.append("Uses a Low-Reputation Domain Extension (.xyz, .top, etc)")

    # RULE 4: IP ADDRESS
    if re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", domain):
        risk_score += 50
        red_flags.append("Uses raw IP Address instead of Domain Name")

    # RULE 5: MALICIOUS FILES
    if any(full_path.endswith(ext) for ext in MALICIOUS_FILES):
        risk_score += 100
        red_flags.append("Link points to a direct MALWARE file download")

    # RULE 6: @ SYMBOL
    if '@' in link:
        risk_score += 30
        red_flags.append("Contains '@' symbol (Browser redirection trick)")

    return min(risk_score, 100), red_flags, smart_warnings

# --- UI LAYOUT ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Genius-Mode Phishing Detection | v4.0 AI Logic")

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
        
        score, flags, smarts = scan_link(url)

        st.divider()
        
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
                st.error("🚫 **HIGH THREAT DETECTED**")
                st.write("This link is confirmed dangerous. Do not click.")
            elif score > 30:
                st.warning("⚠️ **SUSPICIOUS ACTIVITY**")
                st.write("This link looks unusual. Proceed with caution.")
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
