from urllib.parse import urlparse
from scanner.models import ScanResult, UrlScanHistory
from .scan_logic import validate_url, scan_sql_injection, scan_xss, scan_open_ports
import json


def update_url_history(url, findings, scan_id, user=None):
    """Helper function to update scan history"""
    risk_level = findings.get("risk_assessment", {}).get("overall_risk_level", "Low")
    
    UrlScanHistory.objects.update_or_create(
        url=url,
        user=user,  # ✅ Now tracks per-user
        defaults={
            "last_risk_level": risk_level, 
            "last_scan_id": scan_id
        }
    )

def run_full_scan(url, user=None):
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

    # Add status field for SQL injection
    sql_result_with_status = {**sql_result, "status": sql_result.get("status", "Safe")}
    
    # Create findings structure
    findings_data = {
        "sql_injection": sql_result,
        "xss": xss_result,
        "ports": ports_result,
        "risk_assessment": {
            "overall_risk_level": overall_risk
        }
    }
    
    scan = ScanResult.objects.create(
        url=url,
        user=user,
        open_ports="\n".join(str(p) for p in ports_result["open_ports"]),
        sql_injection=json.dumps(sql_result_with_status),
        xss=json.dumps(xss_result),
        findings=findings_data,
        risk_level=overall_risk,
        recommendations="; ".join(recs),
        status="completed",
    )
    
    # Update history - NO INDENTATION ERROR, properly aligned
    update_url_history(url, findings_data, scan.id, user)

    return scan