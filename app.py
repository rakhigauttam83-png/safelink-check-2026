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
    return any(ord(ch) > 127 for ch in hostname)

def is_deceptive_subdomain(hostname: str, brands: list[str]) -> bool:
    labels = hostname.split('.')
    if len(labels) <= 2:
        return False
    subdomain = '.'.join(labels[:-2])
    return any(brand in subdomain and brand not in labels[-2:] for brand in brands)

if st.button("Scan Link"):
    if url:
        risk_score = 0
        reasons = []

        suspicious_keywords = ['free', 'win', 'prize', 'gift', 'lottery', 'secure', 'login', 'verify', 'account', 'update', 'confirm']
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at', 'shorte.st']
        impersonation_brands = ['paypal', 'google', 'apple', 'amazon', 'microsoft', 'facebook', 'bank', 'secure', 'login']

        normalized_url = url.strip()
        hostname = get_hostname(normalized_url)

        if any(word in normalized_url.lower() for word in suspicious_keywords):
            risk_score += 3
            reasons.append("Contains spam or phishing keywords")
        if any(tld in normalized_url.lower() for tld in ['.tk', '.ml', '.ga', '.cf']):
            risk_score += 4
            reasons.append("Uses free or suspicious TLD")
        if normalized_url.count('-') > 2:
            risk_score += 2
            reasons.append("Too many hyphens in URL")
        if normalized_url.lower().startswith('http://'):
            risk_score += 2
            reasons.append("Uses insecure HTTP instead of HTTPS")
        if any(short in normalized_url.lower() for short in url_shorteners):
            risk_score += 4
            reasons.append("Uses a URL shortener")
        if '@' in normalized_url:
            risk_score += 3
            reasons.append("Contains @ symbol, which can hide the real destination")
        if 'xn--' in hostname:
            risk_score += 3
            reasons.append("Contains punycode in the domain")
        if contains_unicode(hostname):
            risk_score += 4
            reasons.append("Contains Unicode characters in the domain, which may be a homograph attack")
        if len(normalized_url) > 100:
            risk_score += 2
            reasons.append("URL is unusually long")
        if 'redirect=' in normalized_url.lower() or 'url=' in normalized_url.lower() or 'next=' in normalized_url.lower():
            risk_score += 2
            reasons.append("Contains a redirect parameter, which may hide the final destination")
        if '//' in normalized_url.lower().split('://', 1)[-1]:
            risk_score += 1
            reasons.append("Contains extra path separators, which is often used in phishing URLs")

        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
            risk_score += 5
            reasons.append("Uses an IP address instead of a domain")
        if hostname.count('.') > 3:
            risk_score += 2
            reasons.append("Has many subdomains, which can be suspicious")
        if is_deceptive_subdomain(hostname, impersonation_brands):
            risk_score += 3
            reasons.append("Contains a deceptive subdomain that impersonates a trusted brand")
        if any(keyword in hostname for keyword in ['secure', 'login', 'confirm', 'verify']) and hostname.count('.') > 2:
            risk_score += 2
            reasons.append("Subdomain appears designed to trick viewers into trusting the link")

        risk_score = min(risk_score, 10)

        st.divider()

        if risk_score >= 7:
            st.error("🚨 HIGH RISK - Do not click this link!")
        elif risk_score >= 4:
            st.warning("⚠️ MEDIUM RISK - Be cautious")
        else:
            st.success("✅ LOW RISK - Link appears safe")

        if reasons:
            st.write("**Detected issues:**")
            for reason in reasons:
                st.write(f"- {reason}")

        score_col, detail_col = st.columns([1, 2])
        score_col.metric("Risk Score", f"{risk_score}/10")

        if risk_score >= 7:
            detail_col.error(
                "This link is highly risky. It may be used for phishing, credential theft, malware delivery, or fraud. Do not click it unless you can verify the source exactly."
            )
        elif risk_score >= 4:
            detail_col.warning(
                "This link has multiple suspicious indicators. It may lead to a disguised or dangerous destination, so proceed carefully."
            )
        else:
            detail_col.success(
                "The link appears low risk based on the detected patterns, but always confirm the sender and destination before clicking."
            )

        st.markdown("### Why opening this link is risky")
        st.write(
            "Links with suspicious keywords, deceptive subdomains, punycode, or redirect parameters often belong to phishing or scam campaigns. "
            "They can redirect you to fake login pages, install malware, or steal personal information."
        )

        st.caption(f"Risk Score: {risk_score}/10")
    else:
        st.warning("Please enter a URL to scan")




