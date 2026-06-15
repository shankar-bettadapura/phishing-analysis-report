from datetime import datetime


_VERDICT_COLORS = {
    "MALICIOUS":  "#e74c3c",
    "SUSPICIOUS": "#f39c12",
    "CLEAN":      "#27ae60",
    "UNKNOWN":    "#8b949e",
}

_AUTH_COLORS = {
    "pass":       "#27ae60",
    "fail":       "#e74c3c",
    "softfail":   "#f39c12",
    "neutral":    "#8b949e",
    "permerror":  "#e74c3c",
    "temperror":  "#f39c12",
    "none":       "#484f58",
}


def _auth_badge(result: str) -> str:
    color = _AUTH_COLORS.get(result.lower(), "#484f58")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">{result.upper()}</span>'


def _verdict_badge(verdict: str) -> str:
    color = _VERDICT_COLORS.get(verdict, "#8b949e")
    return f'<span style="background:{color};color:#fff;padding:3px 10px;border-radius:3px;font-size:12px;font-weight:bold;letter-spacing:1px">{verdict}</span>'


def _overall_verdict(enriched: list) -> tuple:
    if not enriched:
        return "#484f58", "NO ENRICHMENT", "No threat intelligence enrichment was performed."
    malicious = sum(1 for r in enriched if r.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for r in enriched if r.get("verdict") == "SUSPICIOUS")
    if malicious > 0:
        return _VERDICT_COLORS["MALICIOUS"], "MALICIOUS", f"{malicious} IOC(s) confirmed malicious across multiple threat intelligence sources — immediate investigation warranted."
    if suspicious > 0:
        return _VERDICT_COLORS["SUSPICIOUS"], "SUSPICIOUS", f"{suspicious} IOC(s) flagged by one source — treat with caution and investigate further."
    return _VERDICT_COLORS["CLEAN"], "CLEAN", "No IOCs matched any threat intelligence source — low confidence of active phishing infrastructure."


def _build_header_table(headers: dict, auth: dict, received_chain: list) -> str:
    rows = ""
    fields = [
        ("From", headers.get("from", "N/A")),
        ("From Address", headers.get("from_address", "N/A")),
        ("Reply-To", headers.get("reply_to", "N/A")),
        ("Return-Path", headers.get("return_path", "N/A")),
        ("To", headers.get("to", "N/A")),
        ("Subject", headers.get("subject", "N/A")),
        ("Date", headers.get("date", "N/A")),
        ("Message-ID", headers.get("message_id", "N/A")),
        ("X-Mailer", headers.get("x_mailer", "N/A") or "N/A"),
        ("X-Originating-IP", headers.get("x_originating_ip", "N/A") or "N/A"),
    ]
    for label, value in fields:
        rows += f"""<tr><td style="width:180px;color:#8b949e;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.6px">{label}</td>
                    <td style="word-break:break-all">{value}</td></tr>"""

    # Auth row
    spf = _auth_badge(auth.get("spf", "none"))
    dkim = _auth_badge(auth.get("dkim", "none"))
    dmarc = _auth_badge(auth.get("dmarc", "none"))
    rows += f"""<tr><td style="color:#8b949e;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.6px">Authentication</td>
                <td>SPF&nbsp;{spf}&nbsp;&nbsp;DKIM&nbsp;{dkim}&nbsp;&nbsp;DMARC&nbsp;{dmarc}</td></tr>"""

    # Received chain
    if received_chain:
        hops_html = ""
        for hop in received_chain[:5]:
            raw = hop["raw"][:120] + ("..." if len(hop["raw"]) > 120 else "")
            hops_html += f'<div style="font-size:11px;color:#8b949e;margin:2px 0">Hop {hop["hop"]}: {raw}</div>'
        rows += f"""<tr><td style="color:#8b949e;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.6px;vertical-align:top;padding-top:10px">Received Chain</td>
                    <td>{hops_html}</td></tr>"""

    return f"""<table style="width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden">
               <tr><th colspan="2" style="background:#21262d;padding:12px 18px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">Email Header Analysis</th></tr>
               {rows}
               </table>"""


def _build_ioc_summary_tiles(iocs: dict, enriched: list) -> str:
    types = ["URLs", "IPs", "Domains", "Hashes"]
    counts = [len(iocs.get("urls", [])), len(iocs.get("ips", [])), len(iocs.get("domains", [])), len(iocs.get("hashes", []))]

    malicious = sum(1 for r in enriched if r.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for r in enriched if r.get("verdict") == "SUSPICIOUS")
    clean = sum(1 for r in enriched if r.get("verdict") == "CLEAN")

    def tile(label, value, color="#58a6ff"):
        return f"""<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px 22px;text-align:center;flex:1;min-width:100px">
                    <div style="font-size:28px;font-weight:bold;color:{color}">{value}</div>
                    <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px;margin-top:4px">{label}</div>
                   </div>"""

    ioc_tiles = "".join(tile(t, c) for t, c in zip(types, counts))
    verdict_tiles = (
        tile("Malicious", malicious, _VERDICT_COLORS["MALICIOUS"]) +
        tile("Suspicious", suspicious, _VERDICT_COLORS["SUSPICIOUS"]) +
        tile("Clean", clean, _VERDICT_COLORS["CLEAN"])
    )

    return f"""<div style="margin-bottom:20px">
               <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">IOC Counts</div>
               <div style="display:flex;gap:12px;flex-wrap:wrap">{ioc_tiles}</div>
               </div>
               {"" if not enriched else f'''<div>
               <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">Enrichment Results</div>
               <div style="display:flex;gap:12px;flex-wrap:wrap">{verdict_tiles}</div>
               </div>'''}"""


def _build_enrichment_table(enriched: list) -> str:
    if not enriched:
        return '<p style="color:#484f58;font-style:italic">No enrichment data — run without --no-enrichment flag to query threat intelligence feeds.</p>'

    rows = ""
    for r in enriched:
        verdict = r.get("verdict", "UNKNOWN")
        color = _VERDICT_COLORS.get(verdict, "#8b949e")
        badge = _verdict_badge(verdict)

        # Collapse source results into readable detail
        details_parts = []
        for sr in r.get("source_results", []):
            if "error" in sr:
                details_parts.append(f'<span style="color:#e74c3c">{sr["source"]}: error — {sr["error"]}</span>')
            else:
                skip = {"source", "malicious", "error"}
                kv = " | ".join(
                    f'<strong>{k.replace("_", " ").title()}</strong>: {v}'
                    for k, v in sr.items() if k not in skip
                )
                flag = "🚨" if sr.get("malicious") else "✓"
                details_parts.append(f'{flag} {sr["source"]}: {kv}')

        details = "<br>".join(details_parts) if details_parts else "No data"

        rows += f"""<tr>
            <td style="font-weight:bold;color:#c9d1d9">{r.get("ioc_type","")}</td>
            <td style="word-break:break-all;font-family:monospace;font-size:12px;color:#8b949e">{r.get("defanged","")}</td>
            <td style="color:#484f58;font-size:12px">{r.get("ioc_source","")}</td>
            <td>{badge}</td>
            <td style="font-size:12px;color:#c9d1d9;line-height:1.6">{details}</td>
        </tr>"""

    return f"""<table style="width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden">
               <thead><tr>
                 <th style="background:#21262d;padding:12px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px;width:100px">Type</th>
                 <th style="background:#21262d;padding:12px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">IOC (defanged)</th>
                 <th style="background:#21262d;padding:12px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px;width:100px">Found In</th>
                 <th style="background:#21262d;padding:12px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px;width:110px">Verdict</th>
                 <th style="background:#21262d;padding:12px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">TI Details</th>
               </tr></thead>
               <tbody>{rows}</tbody>
               </table>"""


def _build_attachments_table(attachments: list) -> str:
    if not attachments:
        return '<p style="color:#484f58;font-style:italic">No attachments detected.</p>'
    rows = ""
    for a in attachments:
        rows += f"""<tr>
            <td style="font-weight:bold">{a.get("filename","unknown")}</td>
            <td style="color:#8b949e">{a.get("content_type","")}</td>
            <td style="color:#8b949e">{a.get("size_bytes", 0):,} bytes</td>
            <td style="font-family:monospace;font-size:11px;color:#58a6ff;word-break:break-all">{a.get("sha256","N/A")}</td>
        </tr>"""
    return f"""<table style="width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden">
               <thead><tr>
                 <th style="background:#21262d;padding:10px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">Filename</th>
                 <th style="background:#21262d;padding:10px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">Type</th>
                 <th style="background:#21262d;padding:10px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">Size</th>
                 <th style="background:#21262d;padding:10px 14px;text-align:left;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.8px">SHA256</th>
               </tr></thead>
               <tbody>{rows}</tbody>
               </table>"""


def generate_html_report(email_data: dict, iocs: dict, enriched: list, org: str = "") -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    headers = email_data.get("headers", {})
    auth = email_data.get("auth", {})
    received_chain = email_data.get("received_chain", [])
    attachments = email_data.get("attachments", [])

    verdict_color, verdict_label, verdict_summary = _overall_verdict(enriched)
    header_table = _build_header_table(headers, auth, received_chain)
    summary_tiles = _build_ioc_summary_tiles(iocs, enriched)
    enrichment_table = _build_enrichment_table(enriched)
    attachments_table = _build_attachments_table(attachments)

    org_line = f" — {org}" if org else ""

    def section(title, content):
        return f"""<div style="margin-bottom:24px">
                     <h2 style="font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #21262d">{title}</h2>
                     {content}
                   </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing Analysis Report — {headers.get("subject","")}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117; color:#c9d1d9; padding:32px 24px; }}
    .container {{ max-width:1100px; margin:0 auto; }}
    table td, table th {{ padding:12px 14px; border-top:1px solid #21262d; vertical-align:top; line-height:1.5; }}
    table tr:first-child td {{ border-top:none; }}
    a {{ color:#58a6ff; }}
  </style>
</head>
<body>
<div class="container">

  <!-- Header banner -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:28px 32px;margin-bottom:20px">
    <div style="display:inline-block;background:{verdict_color};color:#fff;padding:6px 20px;border-radius:4px;font-weight:bold;font-size:13px;letter-spacing:2px;margin-bottom:14px">{verdict_label}</div>
    <div style="font-size:20px;font-weight:bold;color:#58a6ff;margin-bottom:6px;word-break:break-all">{headers.get("subject","(no subject)")}</div>
    <div style="color:#8b949e;font-size:13px">
      Phishing Analysis Report{org_line}&nbsp;&bull;&nbsp;Analysed: {timestamp}
    </div>
  </div>

  <!-- Verdict summary -->
  <div style="background:#161b22;border-left:4px solid {verdict_color};padding:14px 18px;margin-bottom:20px;border-radius:0 6px 6px 0;font-size:14px;line-height:1.6">
    {verdict_summary}
  </div>

  {section("IOC Summary", summary_tiles)}
  {section("Email Header Analysis", header_table)}
  {section("IOC Enrichment Results", enrichment_table)}
  {section("Attachments", attachments_table)}

  <!-- Analyst note -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:24px;font-size:13px;color:#8b949e;line-height:1.6">
    <strong style="color:#c9d1d9">Analyst Note</strong><br>
    This report is designed for initial triage — not definitive attribution. A CLEAN verdict reflects no current open-source reporting, not confirmed safety.
    A MALICIOUS verdict warrants escalation and contextual investigation before blocking decisions. Cross-reference findings with asset ownership, SPF/DKIM/DMARC alignment,
    and sender reputation patterns. Shared infrastructure (CDNs, cloud providers) may produce false positives.
  </div>

  <div style="text-align:center;color:#484f58;font-size:12px;margin-top:16px;padding-top:16px;border-top:1px solid #21262d">
    Phishing Analysis Report &bull; shankar-bettadapura &bull; {timestamp}
  </div>
</div>
</body>
</html>"""