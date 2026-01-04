import streamlit as st
import re
from urllib.parse import urlparse
import time

# --- CONFIGURATION ---
st.set_page_config(page_title="Vulnex Link-Guard Enterprise", page_icon="🛡️", layout="centered")

# --- CUSTOM CSS FOR "HACKER" VIBE ---
st.markdown("""
    <style>
    .stButton>button {
        width: 100%;
        background: linear-gradient(45deg, #FF4B2B, #FF416C);
        color: white;
        font-weight: bold;
        border: none;
        height: 50px;
        border-radius: 8px;
    }
    .stTextInput>div>div>input {
        border: 2px solid #444;
        border-radius: 8px;
        padding: 10px;
    }
    .report-box {
        padding: 15px;
        border-radius: 10px;
        background-color: #1E1E1E;
        border: 1px solid #333;
        margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Enterprise Phishing Detection System | v3.0")

# --- DATABASE OF THREATS ---
FREE_HOSTING_DOMAINS = [
    '000webhostapp.com', 'herokuapp.com', 'netlify.app', 'vercel.app', 
    'pages.dev', 'firebaseapp.com', 'glitch.me', 'repl.co', 'wixsite.com', 
    'wordpress.com', 'blogspot.com', 'github.io', 'surge.sh', 'weebly.com'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly', 'buff.ly'
]

PANIC_WORDS = [
    'login', 'signin', 'verify', 'update', 'account', 'security', 'bank', 
    'confirm', 'free', 'bonus', 'gift', 'prize', 'wallet', 'unlock', 'support'
]

# --- THE ADVANCED SCANNER LOGIC ---
def scan_link(link):
    risk_score = 0
    red_flags = []
    
    if not link.startswith(('http://', 'https://')):
        link = 'http://' + link
        
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
    except:
        return 100, ["Invalid URL structure (Malformation detected)"]

    # CHECK 1: FREE HOSTING
    for host in FREE_HOSTING_DOMAINS:
        if host in domain:
            risk_score += 40
            red_flags.append(f"Hosted on free platform '{host}' (Banks do not use this)")

    # CHECK 2: URL SHORTENERS
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            risk_score += 20
            red_flags.append(f"Uses URL Shortener '{shortener}' (Destination Hidden)")

    # CHECK 3: IP ADDRESS
    if re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", domain):
        risk_score += 50
        red_flags.append("Uses raw IP Address instead of Domain Name")

    # CHECK 4: KEYWORDS
    found_words = [word for word in PANIC_WORDS if word in link.lower()]
    if found_words:
        risk_score += 15
        red_flags.append(f"Contains panic/lure keywords: {found_words}")

    # CHECK 5: SUBDOMAINS
    dot_count = domain.count('.')
    if dot_count > 3 and not any(h in domain for h in FREE_HOSTING_DOMAINS):
        risk_score += 20
        red_flags.append(f"Excessive subdomains detected ({dot_count} dots)")

    # CHECK 6: LENGTH
    if len(link) > 80:
        risk_score += 10
        red_flags.append("URL is suspiciously long (>80 chars)")
        
    # CHECK 7: @ SYMBOL
    if '@' in link:
        risk_score += 30
        red_flags.append("Contains '@' symbol (Browser redirection trick)")

    return min(risk_score, 100), red_flags

# --- USER INTERFACE ---
url = st.text_input("Paste a suspicious link to scan:", placeholder="e.g. http://secure-login.vercel.app...")

if st.button("INITIATE DEEP SCAN"):
    if url:
        progress_text = "Analyzing DNS records..."
        my_bar = st.progress(0, text=progress_text)

        for percent_complete in range(100):
            time.sleep(0.01)
            if percent_complete == 30:
                 my_bar.progress(percent_complete + 1, text="Checking Hosting Provider...")
            if percent_complete == 60:
                 my_bar.progress(percent_complete + 1, text="Scanning for Known Threats...")
            my_bar.progress(percent_complete + 1)
        
        score, flags = scan_link(url)
        time.sleep(0.5)
        my_bar.empty()

        st.divider()
        col1, col2 = st.columns([1, 2])
        
        with col1:
            if score > 70:
                st.markdown(f"<h1 style='color: #FF4B2B; font-size: 60px;'>{score}%</h1>", unsafe_allow_html=True)
                st.markdown("**CRITICAL RISK**")
            elif score > 30:
                st.markdown(f"<h1 style='color: #FFC300; font-size: 60px;'>{score}%</h1>", unsafe_allow_html=True)
                st.markdown("**SUSPICIOUS**")
            else:
                st.markdown(f"<h1 style='color: #00C851; font-size: 60px;'>{score}%</h1>", unsafe_allow_html=True)
                st.markdown("**SAFE**")

        with col2:
            if score > 70:
                st.error("🚫 **DANGER DETECTED**")
                st.write("This link exhibits clear signs of a phishing attack. Do not enter any personal data.")
            elif score > 30:
                st.warning("⚠️ **CAUTION ADVISED**")
                st.write("This link has suspicious traits. Verify the sender before clicking.")
            else:
                st.success("✅ **LOOKS CLEAN**")
                st.write("No standard threats detected. Always check the URL manually.")
        
        st.write("")
        st.subheader("🕵️ Forensic Analysis")
        if flags:
            for flag in flags:
                st.markdown(f'<div class="report-box"><span style="color: #FF4B2B; font-weight: bold;">[FLAG]</span> {flag}</div>', unsafe_allow_html=True)
        else:
            st.info("System scan passed. Domain structure appears legitimate.")
    else:
        st.toast("⚠️ System requires input data.")

st.divider()
st.caption("🔒 Vulnex Security Systems | Enterprise Edition")
