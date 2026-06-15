import email
import email.policy
import hashlib
import re
from email.header import decode_header
from email.utils import parseaddr


def _decode_header_value(raw_value: str) -> str:
    """Decode RFC2047-encoded header values to plain text."""
    if not raw_value:
        return ""
    parts = decode_header(raw_value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def _parse_auth_results(msg) -> dict:
    """Extract SPF, DKIM, and DMARC results from Authentication-Results headers."""
    auth = {"spf": "none", "dkim": "none", "dmarc": "none"}

    auth_headers = msg.get_all("Authentication-Results") or []
    received_spf = msg.get_all("Received-SPF") or []

    combined = " ".join(auth_headers + received_spf).lower()

    for protocol in ("spf", "dkim", "dmarc"):
        for result in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
            pattern = rf"{protocol}[=\s]+{result}"
            if re.search(pattern, combined):
                auth[protocol] = result
                break

    return auth


def _parse_received_chain(msg) -> list:
    """Extract the Received header chain for hop analysis."""
    received_headers = msg.get_all("Received") or []
    hops = []
    for i, hop in enumerate(received_headers):
        hop_clean = " ".join(hop.split())
        hops.append({"hop": i + 1, "raw": hop_clean})
    return hops


def _extract_attachments(msg) -> list:
    """Extract attachment metadata and SHA256 hashes from email parts."""
    attachments = []
    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        if content_disposition and content_disposition.lower() in ("attachment", "inline"):
            filename = part.get_filename()
            if filename:
                filename = _decode_header_value(filename)
            payload = part.get_payload(decode=True)
            sha256 = hashlib.sha256(payload).hexdigest() if payload else None
            attachments.append({
                "filename": filename or "unknown",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload) if payload else 0,
                "sha256": sha256,
            })
    return attachments


def _extract_body(msg) -> dict:
    """Extract plain text and HTML body content."""
    plain = ""
    html = ""
    for part in msg.walk():
        ct = part.get_content_type()
        disposition = part.get_content_disposition()
        if disposition and "attachment" in disposition.lower():
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if ct == "text/plain" and not plain:
                plain = text
            elif ct == "text/html" and not html:
                html = text
        except Exception:
            continue
    return {"plain": plain, "html": html}


def parse_email(file_path: str) -> dict:
    """
    Parse a .eml file and return a structured dict containing:
      - headers: key email headers
      - auth: SPF/DKIM/DMARC results
      - received_chain: Received hop list
      - body: plain + HTML content
      - attachments: filename, type, size, sha256
      - raw_headers: all headers as list of (name, value) tuples
    """
    with open(file_path, "rb") as f:
        raw = f.read()

    msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    sender_raw = _decode_header_value(msg.get("From", ""))
    sender_name, sender_addr = parseaddr(sender_raw)

    reply_to_raw = _decode_header_value(msg.get("Reply-To", ""))
    _, reply_to_addr = parseaddr(reply_to_raw)

    return_path_raw = _decode_header_value(msg.get("Return-Path", ""))
    _, return_path_addr = parseaddr(return_path_raw)

    headers = {
        "from": sender_raw,
        "from_name": sender_name,
        "from_address": sender_addr,
        "reply_to": reply_to_addr or "N/A",
        "return_path": return_path_addr or "N/A",
        "to": _decode_header_value(msg.get("To", "")),
        "subject": _decode_header_value(msg.get("Subject", "")),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", msg.get("X-MimeOLE", "")),
        "x_originating_ip": msg.get("X-Originating-IP", msg.get("X-Sender-IP", "")),
        "content_type": msg.get("Content-Type", ""),
        "mime_version": msg.get("MIME-Version", ""),
    }

    raw_headers = [(k, v) for k, v in msg.items()]
    auth = _parse_auth_results(msg)
    received_chain = _parse_received_chain(msg)
    body = _extract_body(msg)
    attachments = _extract_attachments(msg)

    return {
        "headers": headers,
        "auth": auth,
        "received_chain": received_chain,
        "body": body,
        "attachments": attachments,
        "raw_headers": raw_headers,
    }