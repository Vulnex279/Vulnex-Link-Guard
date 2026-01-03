import streamlit as st
import re
from urllib.parse import urlparse
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Vulnex Link-Guard", page_icon="🛡️", layout="centered")

# --- CSS STYLING (To make it look like a Mobile App) ---
st.markdown("""
    <style>
    .stButton>button {
        width: 100%;
        background-color: #00ADB5;
        color: white;
        font-weight: bold;
        border-radius: 10px;
        height: 50px;
    }
    .stTextInput>div>div>input {
        border-radius: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
st.title("🛡️ VULNEX LINK-GUARD")
st.caption("Advanced Phishing & Scam Detection System | Mobile v1.0")

# --- INPUT AREA ---
url = st.text_input("Paste a suspicious link here:", placeholder="http://example.com...")

# --- THE SCANNER LOGIC ---
def scan_link(link):
    risk_score = 0
    red_flags = []

    # 1. Length Check
    if len(link) > 75:
        risk_score += 20
        red_flags.append("URL is suspiciously long (>75 chars)")

    # 2. IP Address Check
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    if re.search(ip_pattern, link):
        risk_score += 30
        red_flags.append("Direct IP Address used (High Risk)")

    # 3. Keywords Check
    suspicious_words = ['login', 'signin', 'verify', 'update', 'account', 'security', 'bank', 'confirm', 'free', 'bonus', 'gift', 'prize']
    found_words = [word for word in suspicious_words if word in link.lower()]
    if found_words:
        risk_score += 20
        red_flags.append(f"Panic/Lure keywords found: {found_words}")

    # 4. @ Symbol Check
    if '@' in link:
        risk_score += 25
        red_flags.append("Contains '@' symbol (Redirection Trick)")

    # 5. Domain Extension Check
    try:
        parsed = urlparse(link)
        domain = parsed.netloc
        suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.win', '.gq', '.tk']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_score += 15
            red_flags.append("Low-reputation domain extension")
    except:
        pass

    return risk_score, red_flags

# --- BUTTON & RESULTS ---
if st.button("SCAN LINK"):
    if url:
        with st.spinner('Accessing Vulnex Cyber-Cloud...'):
            time.sleep(1) # Fake loading effect for cool vibes
            score, flags = scan_link(url)

        st.divider()
        
        # DISPLAY RESULTS
        if score > 50:
            st.error(f"🚫 DANGER DETECTED (Risk: {score}%)")
            st.markdown("**Recommendation:** DO NOT CLICK THIS LINK.")
        elif score > 20:
            st.warning(f"⚠️ CAUTION ADVISED (Risk: {score}%)")
            st.markdown("**Recommendation:** Proceed with extreme caution.")
        else:
            st.success(f"✅ LOOKS SAFE (Risk: {score}%)")
            st.markdown("**Recommendation:** Likely safe to open.")

        # Show Details
        if flags:
            with st.expander("See Detection Details"):
                for flag in flags:
                    st.write(f"❌ {flag}")
        else:
            st.info("No obvious red flags found in structure.")
            
    else:
        st.toast("Please paste a link first!", icon="⚠️")