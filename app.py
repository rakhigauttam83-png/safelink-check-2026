import streamlit as st

st.set_page_config(page_title="SafeLink Scanner", page_icon="🔗")

st.title("🔗 SafeLink Scanner")
st.write("Check if a link is safe before you click")

url = st.text_input("Paste a link to scan:", placeholder="https://example.com")

if st.button("Scan Link"):
    if url:
        risk_score = 0
        reasons = []
        
        if any(word in url.lower() for word in ['free', 'win', 'prize', 'gift', 'lottery']):
            risk_score += 3
            reasons.append("Contains spam keywords")
        if any(tld in url.lower() for tld in ['.tk', '.ml', '.ga', '.cf']):
            risk_score += 4
            reasons.append("Uses free/suspicious domain")
        if url.count('-') > 2:
            risk_score += 2
            reasons.append("Too many hyphens in URL")
        
        st.divider()
        
        if risk_score >= 4:
            st.error("🚨 HIGH RISK - Do not click this link!")
        elif risk_score >= 2:
            st.warning("⚠️ MEDIUM RISK - Be cautious")
        else:
            st.success("✅ LOW RISK - Link appears safe")
        
        if reasons:
            st.write("**Detected issues:**")
            for reason in reasons:
                st.write(f"- {reason}")
        
        st.caption(f"Risk Score: {risk_score}/10")
    else:
        st.warning("Please enter a URL to scan")

st.caption("Built for Devpost Hackathon 2026")
