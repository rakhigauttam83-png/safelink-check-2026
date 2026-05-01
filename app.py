import streamlit as st

from safe_link_scanner import scan_url

st.set_page_config(
    page_title="Safe-Link Scanner",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded",
)

st.title("Safe-Link Scanner")
st.write("Inspect URLs for suspicious patterns, phishing indicators, and weak domain signals.")

with st.form("scanner_form"):
    url = st.text_input("Enter a URL to scan", placeholder="https://example.com")
    submitted = st.form_submit_button("Scan Link")

if submitted:
    result = scan_url(url)
    if result.is_safe:
        st.success("This link appears safe based on the scanner heuristics.")
    else:
        st.error("Potential risks found. Review the details below.")

    st.markdown("---")
    st.subheader("Scan summary")
    st.write(f"**Normalized URL:** `{result.normalized_url}`")
    st.write(f"**Danger score:** {result.danger_score}")

    if result.reasons:
        st.subheader("Detected issues")
        for reason in result.reasons:
            st.write(f"- {reason}")

    st.subheader("Checks")
    cols = st.columns(2)
    cols[0].write("**Passed checks**")
    for check in result.passed_checks:
        cols[0].write(f"- {check}")
    cols[1].write("**Failed checks**")
    for check in result.failed_checks:
        cols[1].write(f"- {check}")

    st.markdown("---")
    st.info(
        "This scanner uses static heuristics only. For production use, combine it with live threat intelligence and URL reputation APIs."
    )
