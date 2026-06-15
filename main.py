import os
import sys
import argparse
from dotenv import load_dotenv
from datetime import datetime

from parsers.email_parser import parse_email
from ioc.extractor import extract_iocs
from enrichment.engine import enrich_iocs
from reports.html_report import generate_html_report
from reports.excel_report import generate_excel_report

load_dotenv()

OTX_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")


def validate_keys():
    missing = []
    if not OTX_KEY:
        missing.append("OTX_API_KEY")
    if not ABUSEIPDB_KEY:
        missing.append("ABUSEIPDB_API_KEY")
    if missing:
        print(f"[WARNING] Missing API keys: {', '.join(missing)}")
        print("          Enrichment will be partial. Add keys to .env to enable full analysis.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Analysis Report — parse email headers/body, extract IOCs, enrich against threat intel feeds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py sample_emails/phishing_sample.eml
  python main.py sample_emails/phishing_sample.eml --output reports/ --org "Acme Corp"
  python main.py sample_emails/phishing_sample.eml --no-enrichment
        """
    )
    parser.add_argument("email", help="Path to .eml file to analyse")
    parser.add_argument("--output", default="reports/", help="Output directory for reports (default: reports/)")
    parser.add_argument("--org", default="", help="Organisation name for report headers")
    parser.add_argument("--no-enrichment", action="store_true", help="Skip TI enrichment (faster, offline mode)")
    args = parser.parse_args()

    if not os.path.isfile(args.email):
        print(f"[ERROR] File not found: {args.email}")
        sys.exit(1)

    print(f"\n[*] Phishing Analysis Report")
    print(f"    File    : {args.email}")
    print(f"    Time    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    if args.org:
        print(f"    Org     : {args.org}")
    print()

    # Step 1 — Parse email
    print("[1/4] Parsing email headers and body...")
    email_data = parse_email(args.email)
    print(f"      From        : {email_data['headers'].get('from', 'N/A')}")
    print(f"      Subject     : {email_data['headers'].get('subject', 'N/A')}")
    print(f"      Auth        : SPF={email_data['auth']['spf']}  DKIM={email_data['auth']['dkim']}  DMARC={email_data['auth']['dmarc']}")

    # Step 2 — Extract IOCs
    print("\n[2/4] Extracting IOCs...")
    iocs = extract_iocs(email_data)
    total_iocs = sum(len(v) for v in iocs.values())
    print(f"      URLs    : {len(iocs['urls'])}")
    print(f"      IPs     : {len(iocs['ips'])}")
    print(f"      Domains : {len(iocs['domains'])}")
    print(f"      Hashes  : {len(iocs['hashes'])}")
    print(f"      Total   : {total_iocs} IOCs extracted")

    # Step 3 — Enrich
    enriched = []
    if not args.no_enrichment and total_iocs > 0:
        validate_keys()
        print("\n[3/4] Enriching IOCs against threat intelligence feeds...")
        enriched = enrich_iocs(iocs, OTX_KEY, ABUSEIPDB_KEY)
        malicious = sum(1 for r in enriched if r.get("verdict") == "MALICIOUS")
        suspicious = sum(1 for r in enriched if r.get("verdict") == "SUSPICIOUS")
        clean = sum(1 for r in enriched if r.get("verdict") == "CLEAN")
        print(f"      MALICIOUS  : {malicious}")
        print(f"      SUSPICIOUS : {suspicious}")
        print(f"      CLEAN      : {clean}")
    elif args.no_enrichment:
        print("\n[3/4] Enrichment skipped (--no-enrichment flag set)")
    else:
        print("\n[3/4] No IOCs found — enrichment skipped")

    # Step 4 — Reports
    print("\n[4/4] Generating reports...")
    os.makedirs(args.output, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_subject = email_data['headers'].get('subject', 'unknown')[:30]
    safe_subject = "".join(c if c.isalnum() or c in " _-" else "_" for c in safe_subject).strip().replace(" ", "_")

    base_name = f"Phishing_Report_{safe_subject}_{timestamp}"
    html_path = os.path.join(args.output, f"{base_name}.html")
    xlsx_path = os.path.join(args.output, f"{base_name}.xlsx")

    html_content = generate_html_report(email_data, iocs, enriched, args.org)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"      HTML  -> {html_path}")

    generate_excel_report(email_data, iocs, enriched, xlsx_path, args.org)
    print(f"      Excel -> {xlsx_path}")

    print(f"\n[+] Analysis complete.\n")


if __name__ == "__main__":
    main()