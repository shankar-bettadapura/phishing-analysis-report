import re
import ipaddress
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\[(){},]+",
    re.IGNORECASE
)

_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|gov|edu|mil|int|info|biz|xyz|top|club|online|site|ru|cn|tk|pw|cc|"
    r"uk|de|fr|br|in|jp|au|ca|nl|se|no|fi|pl|cz|sk|hu|ro|bg|hr|lt|lv|ee|by|ua|kz|am|ge|az|"
    r"me|rs|al|ba|mk|md|tr|il|sa|ae|qa|kw|bh|om|ye|iq|ir|pk|bd|np|lk|mm|th|vn|ph|my|sg|id|"
    r"ng|za|eg|ma|dz|tn|ke|gh|et|tz|ug|ci|sn|cm|mz|zm|zw|rw|mw|ls|bw|na|sz|ao|cd|mg|mr|ml|"
    r"bf|ne|td|cf|cg|ga|gq|st|cv|gw|tg|bj|gn|sl|lr|gm|er|dj|km|sc|mu|re|yt|sh|ac|io|"
    r"app|dev|tech|ai|cloud|digital|media|news|blog|shop|store|pay|bank|secure|login|verify|"
    r"account|update|support|help|service)\b",
    re.IGNORECASE
)

_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


# ---------------------------------------------------------------------------
# Private IP ranges to exclude
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _extract_domain_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # If host is an IP, return None — handled by IP extractor
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return host.lower() if host else None
    except Exception:
        return None


def _clean_url(url: str) -> str:
    """Strip trailing punctuation that regex may have captured."""
    return re.sub(r"[.,;:!?)\"']+$", "", url)


def defang(value: str, ioc_type: str) -> str:
    """Defang IOCs for safe display in reports."""
    if ioc_type == "url":
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    if ioc_type in ("ip", "domain"):
        return value.replace(".", "[.]")
    return value


# ---------------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------------

def _extract_urls(text: str) -> list:
    raw = _URL_PATTERN.findall(text)
    return list(dict.fromkeys(_clean_url(u) for u in raw))


def _extract_ips(text: str) -> list:
    raw = _IP_PATTERN.findall(text)
    return list(dict.fromkeys(ip for ip in raw if _is_public_ip(ip)))


def _extract_domains_from_text(text: str, known_domains: set) -> list:
    raw = _DOMAIN_PATTERN.findall(text)
    # _DOMAIN_PATTERN returns the last group (TLD); rebuild full match
    full_domains = re.findall(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" +
        r"(?:com|net|org|io|co|gov|edu|mil|int|info|biz|xyz|top|club|online|site|ru|cn|tk|pw|cc|"
        r"uk|de|fr|br|in|jp|au|ca|nl|se|no|fi|pl|cz|sk|hu|ro|bg|hr|lt|lv|ee|by|ua|kz|am|ge|az|"
        r"me|rs|al|ba|mk|md|tr|il|sa|ae|qa|kw|bh|om|ye|iq|ir|pk|bd|np|lk|mm|th|vn|ph|my|sg|id|"
        r"ng|za|eg|ma|dz|tn|ke|gh|et|tz|ug|ci|sn|cm|mz|zm|zw|rw|mw|ls|bw|na|sz|ao|cd|mg|mr|ml|"
        r"bf|ne|td|cf|cg|ga|gq|st|cv|gw|tg|bj|gn|sl|lr|gm|er|dj|km|sc|mu|re|yt|sh|ac|io|"
        r"app|dev|tech|ai|cloud|digital|media|news|blog|shop|store|pay|bank|secure|login|verify|"
        r"account|update|support|help|service)\b",
        text, re.IGNORECASE
    )
    cleaned = []
    for d in full_domains:
        d_lower = d.lower().strip(".")
        if d_lower and d_lower not in known_domains:
            cleaned.append(d_lower)
    return list(dict.fromkeys(cleaned))


def _extract_hashes(text: str) -> list:
    sha256 = _SHA256_PATTERN.findall(text)
    sha1 = [h for h in _SHA1_PATTERN.findall(text) if h not in sha256]
    md5 = [h for h in _MD5_PATTERN.findall(text) if h not in sha256 and h not in sha1]
    return list(dict.fromkeys(sha256 + sha1 + md5))


# ---------------------------------------------------------------------------
# Main extraction entry point
# ---------------------------------------------------------------------------

def extract_iocs(email_data: dict) -> dict:
    """
    Extract all IOCs from parsed email data.

    Returns:
        {
          "urls": [{"value": ..., "defanged": ..., "source": ...}],
          "ips": [...],
          "domains": [...],
          "hashes": [...],
        }
    """
    # Build a single searchable corpus from headers + body
    header_text_parts = []
    for key, val in email_data.get("raw_headers", []):
        header_text_parts.append(str(val))
    header_text = " ".join(header_text_parts)

    body_plain = email_data.get("body", {}).get("plain", "")
    body_html = email_data.get("body", {}).get("html", "")
    full_text = f"{header_text} {body_plain} {body_html}"

    # Extract attachment hashes
    attachment_hashes = []
    for att in email_data.get("attachments", []):
        if att.get("sha256"):
            attachment_hashes.append(att["sha256"])

    # --- URLs ---
    raw_urls = _extract_urls(body_plain) + _extract_urls(body_html)
    raw_urls = list(dict.fromkeys(raw_urls))
    urls = [
        {"value": u, "defanged": defang(u, "url"), "source": "body"}
        for u in raw_urls
    ]

    # --- IPs ---
    raw_ips_body = _extract_ips(full_text)
    # Also extract from X-Originating-IP header specifically
    xip = email_data.get("headers", {}).get("x_originating_ip", "").strip("[]")
    if xip and _is_public_ip(xip) and xip not in raw_ips_body:
        raw_ips_body.insert(0, xip)
    ips = [
        {"value": ip, "defanged": defang(ip, "ip"), "source": "header" if ip == xip else "body/header"}
        for ip in list(dict.fromkeys(raw_ips_body))
    ]

    # --- Domains (from URLs + raw text, deduped) ---
    url_domains = set()
    for u in raw_urls:
        d = _extract_domain_from_url(u)
        if d:
            url_domains.add(d)

    # Sender domain
    sender_addr = email_data.get("headers", {}).get("from_address", "")
    if "@" in sender_addr:
        sender_domain = sender_addr.split("@")[-1].lower()
        url_domains.add(sender_domain)

    reply_to = email_data.get("headers", {}).get("reply_to", "")
    if "@" in reply_to:
        rt_domain = reply_to.split("@")[-1].lower()
        url_domains.add(rt_domain)

    text_domains = _extract_domains_from_text(full_text, url_domains)

    all_domains = list(url_domains) + text_domains
    seen = set()
    unique_domains = []
    for d in all_domains:
        if d and d not in seen:
            seen.add(d)
            unique_domains.append(d)

    domain_source_map = {}
    for d in list(url_domains):
        domain_source_map[d] = "url/header"
    for d in text_domains:
        if d not in domain_source_map:
            domain_source_map[d] = "body"

    domains = [
        {"value": d, "defanged": defang(d, "domain"), "source": domain_source_map.get(d, "body")}
        for d in unique_domains
    ]

    # --- Hashes ---
    body_hashes = _extract_hashes(full_text)
    all_hash_values = list(dict.fromkeys(attachment_hashes + body_hashes))
    hashes = [
        {
            "value": h,
            "defanged": h,
            "source": "attachment" if h in attachment_hashes else "body",
            "type": "SHA256" if len(h) == 64 else ("SHA1" if len(h) == 40 else "MD5"),
        }
        for h in all_hash_values
    ]

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
    }