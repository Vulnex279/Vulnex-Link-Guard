import streamlit as st
import re
from urllib.parse import urlparse
import time
import difflib
import requests # <--- The Forensic Tool

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
    .forensic-box {
        padding: 15px;
        border-radius: 8px;
        background-color: #1E1E1E;
        border: 1px solid #444;
        margin-bottom: 10px;
        font-family: 'Courier New', monospace;
        font-size: 14px;
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

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 
    'rebrand.ly', 'linktr.ee', 'cutt.ly'
]

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
    highest_ratio = 0.0
    target_site = ""
    for real_domain in OFFICIAL_DOMAINS.keys():
        ratio = difflib.SequenceMatcher(None, domain, real_domain).ratio()
        if ratio > highest_ratio:
            highest_ratio = ratio
            target_site = real_domain
    return highest_ratio, target_site

def get_forensic_data(url):
    """Pings the site to get Technical Details (VirusTotal Style)"""
    try:
        # 1. Force HTTPs if missing (CRITICAL FIX)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # 2. Spoof User-Agent
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=5)
        
        # 3. Get Redirect History
        chain = [url] + [r.url for r in response.history] + [response.url]
        chain = list(dict.fromkeys(chain)) # Remove duplicates
        
        # 4. Get Server Type
        server_type = response.headers.get('Server', 'Unknown/Hidden')
        
        # 5. Get Page Title
        page_title = "Unknown"
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
        if title_match:
            page_title = title_match.group(1)
            
        return {
            "status": "Success",
            "final_url": response.url,
            "chain": chain,
            "server": server_type,
            "title": page_title,
            "code": response.status_code
        }
    except Exception as e:
        return {"status": "Error", "message": str(e)}

# --- MAIN SCANNER ---
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
        return 100, ["URL is malformed or invalid"], None

    # RULE 1: FREE HOSTING
    for host in FREE_HOSTING_DOMAINS:
        if host in domain:
            risk_score += 60
            red_flags.append(f"Hosted on Free Cloud Platform '{host}' (High Risk)")

    # RULE 2: SHORTENERS
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            risk_score += 30
            red_flags.append(f"Uses URL Shortener '{shortener}' (Destination Hidden)")

    # RULE 3: AI CLONE & BRAND CHECK
    if risk_score < 60:
        is_official = domain in OFFICIAL_DOMAINS
        if not is_official:
            similarity, real_site = check_similarity(domain)
            if 0.75 < similarity < 1.0:
                risk_score += 80
                red_flags.append(f"🚨 CLONE DETECTED: This site mimics '{real_site}' ({int(similarity*100)}% match)")
            for real_site, keywords in OFFICIAL_DOMAINS.items():
                if any(k in domain for k in keywords) and real_site not in domain:
                    risk_score += 80
                    red_flags.append(f"🚨 BRAND IMPERSONATION: Link contains '{keywords[0]}' but is NOT '{real_site}'")

    # RULE 4: TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 25
        red_flags.append("Uses a Low-Reputation Domain Extension (.xyz, .top, etc)")

    # RULE 5: IP
    if re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", domain):
        risk_score += 50
        red_flags.append("Uses raw IP Address instead of Domain Name")

    # RULE 6: MALWARE FILES
    if any(full_path.endswith(ext) for ext in MALICIOUS_FILES):
        risk_score += 100
        red_flags.append("Link points to a direct MALWARE file download")

    # RULE 7: @ REDIRECT
    if '@' in link:
        risk_score += 30
        red_flags.append("Contains '@' symbol (Browser redirection trick)")

    return min(risk_score, 100), red_flags, link

# --- UI LAYOUT ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Forensic Phishing Analysis | v5.1 Stable")

url = st.text_input("Paste Link to Scan:", placeholder="e.g. facebook-secure-login.koyeb.app")

if st.button("RUN DEEP FORENSIC SCAN"):
    if url:
        with st.status("Vulnex Engine Running...", expanded=True) as status:
            st.write("🔍 Analyzing Link Structure...")
            time.sleep(0.3)
            st.write("📡 Pinging Server for Metadata...")
            forensic_data = get_forensic_data(url) 
            time.sleep(0.5)
            status.update(label="Scan Complete", state="complete", expanded=False)
        
        score, flags, cleaned_link = scan_link(url)

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
            elif score > 20:
                st.warning("⚠️ **SUSPICIOUS ACTIVITY**")
            else:
                st.success("✅ **LOOKS SAFE**")
                
            if flags:
                for flag in flags:
                    st.write(f"• {flag}")
            else:
                st.write("No basic threats found.")

        # --- FORENSIC SECTION ---
        st.write("")
        st.subheader("🕵️ Forensic Deep-Dive")
        
        with st.expander("View Technical Server Details", expanded=True):
            if forensic_data["status"] == "Success":
                st.markdown("**🔗 Redirect Chain:**")
                if len(forensic_data["chain"]) > 1:
                    for i, hop in enumerate(forensic_data["chain"]):
                        st.markdown(f"`Step {i+1}:` {hop}")
                else:
                    st.markdown(f"`Direct:` {forensic_data['final_url']}")

                st.divider()
                
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**🖥️ Server:**")
                    st.markdown(f"`{forensic_data['server']}`")
                with c2:
                    st.markdown("**📄 Title:**")
                    st.markdown(f"`{forensic_data['title']}`")
                
                st.markdown(f"**📡 Status:** `{forensic_data['code']}`")
            else:
                st.warning(f"Connection Error: {forensic_data['message']}")

    else:
        st.info("Paste a link to activate Deep Scan.")

# --- FOOTER ---
st.divider()
st.markdown("<p style='text-align: center; color: grey;'>Powered by Vulnex Security | Made in Nigeria 🇳🇬</p>", unsafe_allow_html=True)
