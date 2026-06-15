import requests
import time


_TIMEOUT = 10
_RATE_DELAY = 0.3  # seconds between API calls


def _otx_query_ip(ip: str, api_key: str) -> dict:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        r = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=_TIMEOUT)
        if r.status_code != 200:
            return {"source": "AlienVault OTX", "error": f"HTTP {r.status_code}"}
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "source": "AlienVault OTX",
            "malicious": pulse_count > 0,
            "pulse_count": pulse_count,
            "country": data.get("country_name", ""),
            "asn": data.get("asn", ""),
        }
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}


def _otx_query_domain(domain: str, api_key: str) -> dict:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        r = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=_TIMEOUT)
        if r.status_code != 200:
            return {"source": "AlienVault OTX", "error": f"HTTP {r.status_code}"}
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "source": "AlienVault OTX",
            "malicious": pulse_count > 0,
            "pulse_count": pulse_count,
        }
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}


def _abuseipdb_query(ip: str, api_key: str) -> dict:
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": api_key, "Accept": "application/json"}
        r = requests.get(url, headers=headers, params=params, timeout=_TIMEOUT)
        if r.status_code != 200:
            return {"source": "AbuseIPDB", "error": f"HTTP {r.status_code}"}
        d = r.json().get("data", {})
        confidence = d.get("abuseConfidenceScore", 0)
        return {
            "source": "AbuseIPDB",
            "malicious": confidence >= 25,
            "abuse_confidence": confidence,
            "total_reports": d.get("totalReports", 0),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "country_code": d.get("countryCode", ""),
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


def _urlhaus_query_url(url_val: str) -> dict:
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url_val},
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return {"source": "URLhaus", "error": f"HTTP {r.status_code}"}
        data = r.json()
        query_status = data.get("query_status", "")
        if query_status == "no_results":
            return {"source": "URLhaus", "malicious": False, "status": "not listed"}
        return {
            "source": "URLhaus",
            "malicious": data.get("url_status") in ("online", "unknown"),
            "url_status": data.get("url_status", "unknown"),
            "threat": data.get("threat", ""),
            "date_added": data.get("date_added", ""),
        }
    except Exception as e:
        return {"source": "URLhaus", "error": str(e)}


def _urlhaus_query_hash(hash_val: str) -> dict:
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={"sha256_hash": hash_val},
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return {"source": "URLhaus", "error": f"HTTP {r.status_code}"}
        data = r.json()
        if data.get("query_status") == "no_results":
            return {"source": "URLhaus", "malicious": False, "status": "not listed"}
        return {
            "source": "URLhaus",
            "malicious": True,
            "file_type": data.get("file_type", ""),
            "signature": data.get("signature", ""),
            "virustotal": data.get("virustotal", {}).get("result", ""),
        }
    except Exception as e:
        return {"source": "URLhaus", "error": str(e)}


def _compute_verdict(source_results: list) -> str:
    if not source_results:
        return "UNKNOWN"
    malicious_count = sum(1 for r in source_results if r.get("malicious", False) and "error" not in r)
    if malicious_count == 0:
        return "CLEAN"
    elif malicious_count == 1:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def enrich_iocs(iocs: dict, otx_key: str | None, abuseipdb_key: str | None) -> list:
    """
    Enrich extracted IOCs against OTX, AbuseIPDB, and URLhaus.

    Returns a list of enrichment result dicts, one per IOC, each containing:
      - ioc_type, value, defanged, source_results, verdict
    """
    results = []

    # --- URLs ---
    for ioc in iocs.get("urls", []):
        val = ioc["value"]
        print(f"       [URL] {val[:70]}...")
        source_results = [_urlhaus_query_url(val)]
        time.sleep(_RATE_DELAY)
        results.append({
            "ioc_type": "URL",
            "value": val,
            "defanged": ioc["defanged"],
            "ioc_source": ioc["source"],
            "source_results": source_results,
            "verdict": _compute_verdict(source_results),
        })

    # --- IPs ---
    for ioc in iocs.get("ips", []):
        val = ioc["value"]
        print(f"       [IP]  {val}")
        source_results = []
        if otx_key:
            source_results.append(_otx_query_ip(val, otx_key))
            time.sleep(_RATE_DELAY)
        if abuseipdb_key:
            source_results.append(_abuseipdb_query(val, abuseipdb_key))
            time.sleep(_RATE_DELAY)
        results.append({
            "ioc_type": "IP",
            "value": val,
            "defanged": ioc["defanged"],
            "ioc_source": ioc["source"],
            "source_results": source_results,
            "verdict": _compute_verdict(source_results),
        })

    # --- Domains ---
    for ioc in iocs.get("domains", []):
        val = ioc["value"]
        print(f"       [DOM] {val}")
        source_results = []
        if otx_key:
            source_results.append(_otx_query_domain(val, otx_key))
            time.sleep(_RATE_DELAY)
        results.append({
            "ioc_type": "Domain",
            "value": val,
            "defanged": ioc["defanged"],
            "ioc_source": ioc["source"],
            "source_results": source_results,
            "verdict": _compute_verdict(source_results),
        })

    # --- Hashes ---
    for ioc in iocs.get("hashes", []):
        val = ioc["value"]
        if ioc.get("type") != "SHA256":
            # URLhaus only supports SHA256
            results.append({
                "ioc_type": f"Hash ({ioc.get('type', 'unknown')})",
                "value": val,
                "defanged": val,
                "ioc_source": ioc["source"],
                "source_results": [{"source": "URLhaus", "malicious": False, "status": "SHA256 only"}],
                "verdict": "UNKNOWN",
            })
            continue
        print(f"       [SHA256] {val[:20]}...")
        source_results = [_urlhaus_query_hash(val)]
        time.sleep(_RATE_DELAY)
        results.append({
            "ioc_type": "Hash (SHA256)",
            "value": val,
            "defanged": val,
            "ioc_source": ioc["source"],
            "source_results": source_results,
            "verdict": _compute_verdict(source_results),
        })

    return results