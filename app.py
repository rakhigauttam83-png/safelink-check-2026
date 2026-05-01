import base64
import importlib
import ipaddress
import json
import os
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, date, timedelta
from urllib.parse import quote, urlparse

import requests
import streamlit as st

try:
    pyzbar_module = importlib.import_module('pyzbar.pyzbar')
    qr_decode = pyzbar_module.decode
    Image = importlib.import_module('PIL.Image')
    QR_SCAN_AVAILABLE = True
except ImportError:
    qr_decode = None
    Image = None
    QR_SCAN_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    whois = None
    WHOIS_AVAILABLE = False

st.set_page_config(page_title="SafeLink Scanner", page_icon="🔗")

st.markdown(
    """
    <style>
    .app-header {
        background: linear-gradient(135deg, #0c4e8a 0%, #0079c1 100%);
        border-radius: 24px;
        padding: 28px;
        color: white;
        box-shadow: 0 18px 60px rgba(0,0,0,0.16);
        margin-bottom: 24px;
    }
    .app-header h1 { margin-bottom: 0.2rem; }
    .app-subtitle { color: #d9edf8; font-size: 1rem; margin-top: 0.4rem; }
    .card-panel {
        background: #ffffff;
        border-radius: 20px;
        padding: 22px;
        box-shadow: 0 10px 30px rgba(15, 34, 76, 0.08);
        margin-bottom: 20px;
    }
    .badge-high { background: #ff4d4f; color: white; padding: 6px 14px; border-radius: 999px; font-weight: 700; }
    .badge-medium { background: #faad14; color: white; padding: 6px 14px; border-radius: 999px; font-weight: 700; }
    .badge-low { background: #52c41a; color: white; padding: 6px 14px; border-radius: 999px; font-weight: 700; }
    .risk-summary { color: #1f3a72; font-size: 1rem; margin-top: 10px; }
    .small-note { color: #4f6d94; }
    </style>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="app-header">
        <h1>🔗 SafeLink Scanner</h1>
        <p class="app-subtitle">
            Scan URLs and QR codes for phishing, spoofing, and suspicious redirects with color-coded insights and instant feedback.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="card-panel"><strong>How it works:</strong> Detects typosquatting, suspicious redirects, SSL issues, QR/UPI scams, and VirusTotal alerts before you click.</div>',
    unsafe_allow_html=True,
)

if QR_SCAN_AVAILABLE:
    qr_file = st.file_uploader("Upload a QR code image to decode and scan", type=["png", "jpg", "jpeg", "bmp"])
    qr_camera = st.camera_input("Or use your camera to scan a QR code")
    qr_input = qr_camera if qr_camera is not None else qr_file

    if qr_input is not None:
        try:
            image = Image.open(qr_input)
            decoded_items = qr_decode(image)
            if decoded_items:
                decoded_texts = [item.data.decode('utf-8', errors='ignore') for item in decoded_items]
                st.markdown("### QR code results")
                for decoded_text in decoded_texts:
                    st.write(f"- {decoded_text}")

                decoded_url = None
                for decoded_text in decoded_texts:
                    candidate = decoded_text.strip()
                    if candidate and urlparse(candidate if urlparse(candidate).scheme else f'https://{candidate}').hostname:
                        decoded_url = candidate if urlparse(candidate).scheme else f'https://{candidate}'
                        break

                if decoded_url:
                    st.success(f"Detected URL from QR code: {decoded_url}")
                    if st.button("Load decoded URL into scanner"):
                        st.session_state.scanner_url = decoded_url
                else:
                    st.info("QR code decoded text, but no valid URL was detected.")
            else:
                st.warning("No QR code was detected in the image.")
        except Exception as exc:
            st.error(f"Unable to decode QR code image: {exc}")
else:
    st.warning("QR scan support requires pyzbar and Pillow. Install these packages to enable QR image scanning.")

url = st.text_input("Paste a link to scan:", placeholder="https://example.com", key="scanner_url")

with st.expander("Why scanning links reduces risk"):
    st.write(
        "Phishing and scam URLs often hide their real destination. "
        "This scanner makes the warning signs visible before you click."
    )

def get_hostname(url: str) -> str:
    parsed = urlparse(url if url.lower().startswith(('http://', 'https://')) else f'https://{url}')
    hostname = parsed.netloc or parsed.path
    return hostname.split(':')[0].lower()

def is_private_or_reserved_host(hostname: str) -> bool:
    if not hostname:
        return True
    lowered = hostname.lower()
    if lowered in {'localhost', '127.0.0.1', '::1'}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        pass
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family == socket.AF_INET:
                ip = ipaddress.IPv4Address(sockaddr[0])
            elif family == socket.AF_INET6:
                ip = ipaddress.IPv6Address(sockaddr[0])
            else:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return True
    except Exception:
        return True
    return False


def is_valid_url(url: str) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        return False
    if not parsed.hostname:
        return False
    if is_private_or_reserved_host(parsed.hostname):
        return False
    return True


def contains_unicode(hostname: str) -> bool:
    return any(ord(ch) > 127 for ch in hostname)

def detect_upi_qr_risk(url: str, hostname: str) -> tuple[bool, str]:
    lower_url = url.lower()
    if 'upi://' in lower_url:
        return True, "Contains a UPI deep link, which is often used in QR payment scams."

    payee_match = re.search(r'pa=([^&]+)', lower_url)
    if payee_match and '@' in payee_match.group(1):
        return True, "Contains a UPI payee identifier, which may indicate a QR payment phishing attempt."

    qr_indicators = ['@paytm', '@phonepe', '@okaxis', '@okhdfcbank', '@apl', '@ybl', '@upi', '@axis', '@ibl', '@hdfcbank', 'paytm.me']
    for indicator in qr_indicators:
        if indicator in lower_url:
            return True, "References a UPI/QR payment identifier or payment service commonly abused in phishing scams."
    return False, ""

def normalize_leetspeak(label: str) -> str:
    replacements = str.maketrans({
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '$': 's',
        '@': 'a',
    })
    return label.lower().translate(replacements)

def edit_distance(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def is_typosquatting(hostname: str, brands: list[str]) -> tuple[bool, str]:
    labels = hostname.lower().split('.')
    if len(labels) < 2:
        return False, ""
    root_label = labels[-2]
    normalized = normalize_leetspeak(root_label)
    for brand in brands:
        if normalized == brand:
            if root_label != brand:
                return True, f"The domain looks like a typo-squatted version of '{brand}.com'."
            return False, ""
        if edit_distance(normalized, brand) == 1 and normalized != brand:
            return True, f"The domain is very similar to '{brand}.com' and may be used for typosquatting."
    return False, ""

def get_domain_age_days(hostname: str) -> tuple[int | None, str]:
    if not WHOIS_AVAILABLE:
        return None, "WHOIS unavailable"
    try:
        record = whois.whois(hostname)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            created = creation_date
        elif isinstance(creation_date, date):
            created = datetime(creation_date.year, creation_date.month, creation_date.day)
        elif isinstance(creation_date, str):
            try:
                created = datetime.fromisoformat(creation_date.replace('Z', ''))
            except ValueError:
                created = None
        else:
            created = None
        if isinstance(created, datetime):
            age = (datetime.utcnow() - created).days
            return age, created.strftime('%Y-%m-%d')
    except Exception:
        pass
    return None, "unknown"

def trace_redirect_chain(url: str) -> tuple[str, list[str], str]:
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        history = [resp.url for resp in response.history]
        final_url = response.url
        return final_url, history + [final_url], ''
    except requests.RequestException as exc:
        return url, [], str(exc)


def is_redirect_chain_suspicious(original_url: str, redirect_chain: list[str]) -> bool:
    if len(redirect_chain) <= 1:
        return False
    original_host = get_hostname(original_url)
    final_host = get_hostname(redirect_chain[-1])
    if original_host == final_host:
        return False
    if original_host.startswith('www.') and original_host[4:] == final_host:
        return False
    if final_host.startswith('www.') and final_host[4:] == original_host:
        return False
    return True


def load_reported_links() -> list[dict]:
    report_path = os.path.join(os.path.dirname(__file__), 'reported_links.json')
    if not os.path.exists(report_path):
        return []
    try:
        with open(report_path, 'r', encoding='utf-8') as report_file:
            return json.load(report_file)
    except Exception:
        return []


def get_today_threat_feed(reports: list[dict]) -> tuple[int, str, int]:
    now = datetime.utcnow().date()
    today_reports = []
    for report in reports:
        reported_at = report.get('reported_at', '')
        try:
            reported_date = datetime.fromisoformat(reported_at.replace('Z', '')).date()
            if reported_date == now:
                today_reports.append(report)
        except Exception:
            continue
    if not today_reports:
        return 0, 'Unknown city', 0

    location_counts = Counter()
    for report in today_reports:
        hostname = report.get('hostname', '')
        if not hostname:
            continue
        geo_info = get_ip_geolocation(hostname)
        city = geo_info.get('city', 'Unknown') or 'Unknown'
        country = geo_info.get('country', 'Unknown') or 'Unknown'
        location_counts[f"{city}, {country}"] += 1
    top_city, top_count = location_counts.most_common(1)[0] if location_counts else ('Unknown city', 0)
    return len(today_reports), top_city, top_count


def get_screenshot_url(url: str) -> tuple[str, str]:
    try:
        safe_url = quote(url, safe='')
        preview_url = f"https://image.thum.io/get/width/1024/crop/768/{safe_url}"
        return preview_url, ''
    except Exception as exc:
        return '', str(exc)


def get_virustotal_report(url: str) -> dict:
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not api_key:
        return {'error': 'VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY in the environment.'}

    headers = {'x-apikey': api_key}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        response = requests.get(endpoint, headers=headers, timeout=12)
        if response.status_code == 404:
            submit = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url}, timeout=12)
            if not submit.ok:
                return {'error': f'VirusTotal submission failed: {submit.status_code} {submit.text}'}
            data = submit.json()
            url_id = data.get('data', {}).get('id', url_id)
            response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=12)
        if not response.ok:
            return {'error': f'VirusTotal lookup failed: {response.status_code} {response.text}'}

        data = response.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        results = data.get('last_analysis_results', {})
        total = sum(stats.values()) if stats else 0
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        flagged = [f"{engine}: {result.get('category')}" for engine, result in results.items() if result.get('category') not in {'undetected', 'harmless'}]
        return {
            'malicious': malicious,
            'suspicious': suspicious,
            'total': total,
            'flagged': flagged,
            'stats': stats,
        }
    except Exception as exc:
        return {'error': str(exc)}


def save_reported_link(url: str, hostname: str, risk_percent: int, risk_level: str, reasons: list[str]) -> bool:
    try:
        report_path = os.path.join(os.path.dirname(__file__), 'reported_links.json')
        existing = []
        if os.path.exists(report_path):
            with open(report_path, 'r', encoding='utf-8') as report_file:
                existing = json.load(report_file)
        entry = {
            'url': url,
            'hostname': hostname,
            'risk_percent': risk_percent,
            'risk_level': risk_level,
            'reasons': reasons,
            'reported_at': datetime.utcnow().isoformat() + 'Z',
        }
        if not any(item.get('url') == url for item in existing):
            existing.append(entry)
            with open(report_path, 'w', encoding='utf-8') as report_file:
                json.dump(existing, report_file, indent=2)
        return True
    except Exception:
        return False


def get_ssl_certificate_info(hostname: str) -> dict[str, str]:
    details = {
        'hostname': hostname,
        'issuer': 'unknown',
        'subject': 'unknown',
        'valid_from': 'unknown',
        'valid_to': 'unknown',
        'subject_alt_names': [],
        'error': '',
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        details['issuer'] = dict(x[0] for x in cert.get('issuer', [])) if cert.get('issuer') else 'unknown'
        details['subject'] = dict(x[0] for x in cert.get('subject', [])) if cert.get('subject') else 'unknown'
        details['valid_from'] = cert.get('notBefore', 'unknown')
        details['valid_to'] = cert.get('notAfter', 'unknown')
        details['subject_alt_names'] = cert.get('subjectAltName', [])
    except Exception as exc:
        details['error'] = str(exc)
    return details


def get_ip_geolocation(hostname: str) -> dict[str, str]:
    details = {'hostname': hostname, 'ip': 'unknown', 'country': 'unknown', 'region': 'unknown', 'city': 'unknown', 'isp': 'unknown', 'error': ''}
    try:
        ip_address = socket.gethostbyname(hostname)
        details['ip'] = ip_address
        response = requests.get(f'https://ip-api.com/json/{ip_address}', timeout=8)
        if response.ok:
            data = response.json()
            details['country'] = data.get('country', 'unknown')
            details['region'] = data.get('regionName', 'unknown')
            details['city'] = data.get('city', 'unknown')
            details['isp'] = data.get('isp', 'unknown')
        else:
            details['error'] = f'Geolocation lookup returned status {response.status_code}'
    except Exception as exc:
        details['error'] = str(exc)
    return details


def get_whois_details(hostname: str) -> dict[str, str]:
    details = {'domain': hostname, 'registrar': 'unknown', 'creation_date': 'unknown', 'expiration_date': 'unknown', 'updated_date': 'unknown', 'name_servers': [], 'status': [], 'error': ''}
    if not WHOIS_AVAILABLE:
        details['error'] = 'WHOIS package unavailable in this environment.'
        return details
    try:
        record = whois.whois(hostname)
        details['registrar'] = getattr(record, 'registrar', 'unknown') or 'unknown'
        creation_date = record.creation_date
        expiration_date = record.expiration_date
        updated_date = record.updated_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        details['creation_date'] = creation_date.strftime('%Y-%m-%d') if isinstance(creation_date, (datetime, date)) else str(creation_date)
        details['expiration_date'] = expiration_date.strftime('%Y-%m-%d') if isinstance(expiration_date, (datetime, date)) else str(expiration_date)
        details['updated_date'] = updated_date.strftime('%Y-%m-%d') if isinstance(updated_date, (datetime, date)) else str(updated_date)
        details['name_servers'] = record.name_servers if record.name_servers else []
        details['status'] = record.status if record.status else []
    except Exception as exc:
        details['error'] = str(exc)
    return details

def is_deceptive_subdomain(hostname: str, brands: list[str]) -> bool:
    labels = hostname.split('.')
    if len(labels) <= 2:
        return False
    subdomain = '.'.join(labels[:-2])
    return any(brand in subdomain and brand not in labels[-2:] for brand in brands)

reported_links = load_reported_links()
today_count, top_location, top_location_count = get_today_threat_feed(reported_links)
feed_message = (
    f"{top_location_count} phishing links blocked in {top_location} today"
    if today_count > 0
    else "No phishing links blocked today yet"
)

st.markdown("## Real-time threat feed")
feed_col1, feed_col2 = st.columns([1, 1])
feed_col1.metric("Links blocked today", today_count)
feed_col2.metric("Top impacted location", top_location)
st.success(feed_message)

if st.button("Scan Link"):
    if url:
        risk_score = 0
        reasons = []

        suspicious_keywords = ['free', 'win', 'prize', 'gift', 'lottery', 'secure', 'login', 'verify', 'account', 'update', 'confirm']
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at', 'shorte.st']
        impersonation_brands = ['paypal', 'google', 'apple', 'amazon', 'microsoft', 'facebook', 'bank', 'secure', 'login']

        normalized_url = url.strip()
        if not urlparse(normalized_url).scheme:
            normalized_url = f'https://{normalized_url}'
        if not is_valid_url(normalized_url):
            st.error("The URL is malformed, insecure, or points to a local/private network address. Please enter a public HTTPS URL.")
            st.stop()
        hostname = get_hostname(normalized_url)
        screenshot_url, screenshot_error = get_screenshot_url(normalized_url)
        vt_report = get_virustotal_report(normalized_url)

        if any(word in normalized_url.lower() for word in suspicious_keywords):
            risk_score += 3
            reasons.append("Contains spam or phishing keywords")
        upi_risk, upi_reason = detect_upi_qr_risk(normalized_url, hostname)
        if upi_risk:
            risk_score += 4
            reasons.append(upi_reason)
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

        typosquatting, typo_reason = is_typosquatting(hostname, impersonation_brands)
        if typosquatting:
            risk_score += 4
            reasons.append(typo_reason)

        age_days, age_str = get_domain_age_days(hostname)
        if age_days is not None:
            if age_days < 30:
                risk_score += 3
                reasons.append(f"Domain was registered only {age_days} days ago ({age_str}), which is a common trait of phishing sites.")
            else:
                reasons.append(f"Domain age is {age_days} days (registered {age_str}).")
        else:
            reasons.append("Domain age could not be verified from WHOIS data.")

        final_url, redirect_chain, redirect_error = trace_redirect_chain(normalized_url)
        if redirect_chain and len(redirect_chain) > 1:
            if is_redirect_chain_suspicious(normalized_url, redirect_chain):
                risk_score += 3
                reasons.append("The link follows multiple suspicious redirects, which can hide the final destination.")
                reasons.append(f"Final destination after redirect chain: {final_url}")
        elif redirect_error:
            reasons.append(f"Could not fully trace redirects: {redirect_error}")

        if isinstance(vt_report, dict) and not vt_report.get('error'):
            vt_malicious = vt_report.get('malicious', 0)
            vt_suspicious = vt_report.get('suspicious', 0)
            vt_total = vt_report.get('total', 0)
            if vt_malicious or vt_suspicious:
                risk_score += 3
                reasons.append(
                    f"VirusTotal cross-check found {vt_malicious} malicious and {vt_suspicious} suspicious flags out of {vt_total} scanners."
                )
        elif isinstance(vt_report, dict) and vt_report.get('error'):
            reasons.append(vt_report['error'])

        risk_score = min(risk_score, 10)
        risk_percent = int(risk_score * 10)
        risk_level = 'Low'
        risk_summary = 'This link appears low risk based on detected patterns.'
        if risk_percent >= 70:
            risk_level = 'High'
            risk_summary = 'This link is highly risky. It may be used for phishing, credential theft, malware delivery, or fraud.'
        elif risk_percent >= 40:
            risk_level = 'Medium'
            risk_summary = 'This link has multiple suspicious indicators. It may lead to a disguised or dangerous destination.'

        st.divider()

        st.markdown(
            f"""
            <div class="card-panel">
                <div style="display:flex; justify-content:space-between; align-items:center; gap: 16px; flex-wrap:wrap;">
                    <div>
                        <h2 style="margin:0;">Risk Score: {risk_percent}%</h2>
                        <p class="risk-summary">{risk_summary}</p>
                    </div>
                    <div class="badge-{risk_level.lower()}">{risk_level} risk</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        score_col, detail_col = st.columns([1, 2])
        score_col.metric("Risk Level", f"{risk_percent}%")
        if risk_level == 'High':
            score_col.error(f"{risk_level} risk")
        elif risk_level == 'Medium':
            score_col.warning(f"{risk_level} risk")
        else:
            score_col.success(f"{risk_level} risk")

        if risk_level == 'High':
            detail_col.error(risk_summary)
        elif risk_level == 'Medium':
            detail_col.warning(risk_summary)
        else:
            detail_col.success(risk_summary)

        if reasons:
            st.markdown("**Detected issues:**")
            for reason in reasons:
                st.markdown(f"- {reason}")

        if risk_level in {'Medium', 'High'}:
            st.markdown("### Why was this flagged?")
            st.write(
                "This link was flagged because it matches common phishing red flags such as deceptive domains, redirects, and suspicious parameters. "
                "Check the details below to understand why the scanner raised an alert."
            )
            st.write("**Common phishing red flags include:**")
            st.write("- Deceptive or typo-squatted domains")
            st.write("- Redirect chains and hidden final destinations")
            st.write("- Shortened links that hide the target page")
            st.write("- Newly registered or rapidly changing domains")
            st.write("- Suspicious keywords like login, secure, verify, or account")

            if st.button("Report this link as malicious"):
                if save_reported_link(normalized_url, hostname, risk_percent, risk_level, reasons):
                    st.success("Thanks! The link has been added to the community report database.")
                else:
                    st.error("Unable to save the report right now. Please try again later.")

        with st.expander("Website preview"):
            if screenshot_url:
                st.image(screenshot_url, caption="Generated website thumbnail preview", use_column_width=True)
            else:
                st.error(f"Screenshot preview unavailable: {screenshot_error}")

        with st.expander("Technical details"):
            st.markdown("### SSL certificate details")
            cert_info = get_ssl_certificate_info(hostname)
            if cert_info.get('error'):
                st.error(f"SSL certificate lookup failed: {cert_info['error']}")
            else:
                st.write(f"**Issuer:** {cert_info['issuer']}")
                st.write(f"**Subject:** {cert_info['subject']}")
                st.write(f"**Valid from:** {cert_info['valid_from']}")
                st.write(f"**Valid to:** {cert_info['valid_to']}")
                st.write("**Subject Alternative Names:**")
                st.write(cert_info['subject_alt_names'])

            st.markdown("### Server geolocation")
            geo_info = get_ip_geolocation(hostname)
            if geo_info.get('error'):
                st.error(f"Geolocation lookup failed: {geo_info['error']}")
            else:
                st.write(f"**IP address:** {geo_info['ip']}")
                st.write(f"**Country:** {geo_info['country']}")
                st.write(f"**Region:** {geo_info['region']}")
                st.write(f"**City:** {geo_info['city']}")
                st.write(f"**ISP:** {geo_info['isp']}")

            st.markdown("### WHOIS data")
            whois_info = get_whois_details(hostname)
            if whois_info.get('error'):
                st.error(f"WHOIS lookup failed: {whois_info['error']}")
            else:
                st.write(f"**Registrar:** {whois_info['registrar']}")
                st.write(f"**Creation date:** {whois_info['creation_date']}")
                st.write(f"**Expiration date:** {whois_info['expiration_date']}")
                st.write(f"**Last updated:** {whois_info['updated_date']}")
                st.write(f"**Name servers:** {whois_info['name_servers']}")
                st.write(f"**Status:** {whois_info['status']}")

            st.markdown("### VirusTotal scan summary")
            if isinstance(vt_report, dict) and vt_report.get('error'):
                st.error(f"VirusTotal lookup failed: {vt_report['error']}")
            else:
                st.write(f"**Malicious detections:** {vt_report.get('malicious', 0)}")
                st.write(f"**Suspicious detections:** {vt_report.get('suspicious', 0)}")
                st.write(f"**Total engines checked:** {vt_report.get('total', 0)}")
                if vt_report.get('flagged'):
                    st.write("**Flagged engines:**")
                    for flagged in vt_report['flagged'][:10]:
                        st.write(f"- {flagged}")
                    if len(vt_report['flagged']) > 10:
                        st.write(f"...and {len(vt_report['flagged']) - 10} more flagged engines.")

        st.markdown("### Why opening this link is risky")
        st.write(
            "Links with suspicious keywords, deceptive subdomains, punycode, or redirect parameters often belong to phishing or scam campaigns. "
            "They can redirect you to fake login pages, install malware, or steal personal information."
        )

        st.caption(f"Risk Score: {risk_percent}%")
    else:
        st.warning("Please enter a URL to scan")


















