from urllib.parse import urlparse
from scanner.models import ScanResult
from .scan_logic import validate_url, scan_sql_injection, scan_xss, scan_open_ports


def run_full_scan(url):
    url = validate_url(url)
    parsed = urlparse(url)
    host = parsed.hostname

    sql_result = scan_sql_injection(url)
    xss_result = scan_xss(url)
    ports_result = scan_open_ports(host)

    risks = [sql_result["risk_level"], xss_result["risk_level"], ports_result["risk_level"]]
    if "High" in risks:
        overall_risk = "High"
    elif "Medium" in risks:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    recs = []
    if sql_result["risk_level"] == "High":
        recs.append("Fix SQL injection with parameterized queries.")
    if xss_result["risk_level"] == "High":
        recs.append("Sanitize user inputs to prevent XSS.")
    if ports_result["risk_level"] in ["Medium", "High"]:
        recs.append("Close unnecessary open ports.")

    if not recs:
        recs.append("No major issues detected.")

    scan = ScanResult.objects.create(
        url=url,
        open_ports=", ".join(str(p) for p in ports_result["open_ports"]),
        sql_injection=str(sql_result),
        xss=str(xss_result),
        findings={
            "sql_injection": sql_result,
            "xss": xss_result,
            "ports": ports_result,
        },
        risk_level=overall_risk,
        recommendations="; ".join(recs),
        status="completed",
    )

    return scan
