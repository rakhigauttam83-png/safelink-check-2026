import re
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(page_title="SafeLink Scanner", page_icon="🔗")

st.title("🔗 SafeLink Scanner")
st.markdown(
    """
    ### Scan URLs for phishing, spoofing, and suspicious redirects
    Know before you click: this tool highlights why a link may be dangerous.
    """
)
st.write("Check if a link is safe before you click")

st.info(
    "Checks for URL shorteners, punycode/homograph domains, deceptive subdomains, insecure HTTP, redirect parameters, suspicious keywords, and more."
)

url = st.text_input("Paste a link to scan:", placeholder="https://example.com")

with st.expander("Why scanning links reduces risk"):
    st.write(
        "Phishing and scam URLs often hide their real destination. "
        "This scanner makes the warning signs visible before you click."
    )

def get_hostname(url: str) -> str:
    parsed = urlparse(url if url.lower().startswith(('http://', 'https://')) else f'https://{url}')
    hostname = parsed.netloc or parsed.path
    return hostname.split(':')[0].lower()

def contains_unicode(hostname: str) -> bool:
    return bool(re.search(r'[^
