import requests
import socket
import psutil
import concurrent.futures
import nmap
from urllib.parse import urlparse, parse_qs


def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL provided")
    return url


def scan_sql_injection(url):
    payloads = ["' OR '1'='1", "';--", "\" OR \"1\"=\"1", "' OR '1'='1' --"]
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query) or {"id": ["1"]}

    vulnerable = False
    details = []

    for param in params.keys():
        for payload in payloads:
            test_params = {k: (payload if k == param else v[0]) for k, v in params.items()}
            try:
                response = requests.get(base_url, params=test_params, timeout=10)
                if any(err in response.text.lower() for err in [
                    "sql syntax", "mysql", "syntax error", "odbc", "ora-00933", "unclosed quotation"
                ]):
                    vulnerable = True
                    details.append({"parameter": param, "payload": payload, "status": "Vulnerable"})
            except requests.RequestException:
                details.append({"parameter": param, "payload": payload, "status": "Error"})

    status = "Vulnerable" if vulnerable else "Safe"
    risk_level = "High" if vulnerable else "Low"

    return {
        "type": "SQL Injection",
        "status": status,
        "details": details if details else "No obvious injection found",
        "risk_level": risk_level,
    }


def scan_xss(url):
    test_payload = "<script>alert('XSS')</script>"
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query) or {"q": [""]}

    results = []
    for param in params.keys():
        test_params = {k: (test_payload if k == param else v[0]) for k, v in params.items()}
        try:
            response = requests.get(base_url, params=test_params, timeout=10)
            status = "Vulnerable" if test_payload in response.text else "Safe"
        except requests.RequestException:
            status = "Error - Could not test"

        results.append({"parameter": param, "status": status})

    risk_level = "High" if any(r["status"] == "Vulnerable" for r in results) else "Low"
    return {"type": "XSS", "results": results, "risk_level": risk_level}


def detect_safe_thread_count():
    return psutil.cpu_count(logical=True) * 5


def scan_single_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((host, port)) == 0:
            return port
    except Exception:
        return None
    finally:
        sock.close()
    return None


def scan_open_ports(host, ports=None):
    open_ports = []
    try:
        nm = nmap.PortScanner()
        if ports:
            port_range = ",".join(map(str, ports))
            nm.scan(host, port_range)
        else:
            nm.scan(host, arguments="-p-")

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]["state"] == "open":
                    open_ports.append(port)
    except Exception:
        if ports is None:
            ports = range(1, 1025)
        with concurrent.futures.ThreadPoolExecutor(max_workers=detect_safe_thread_count()) as executor:
            for port in executor.map(lambda p: scan_single_port(host, p), ports):
                if port:
                    open_ports.append(port)

    if len(open_ports) > 5:
        risk_level = "High"
    elif len(open_ports) > 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {"type": "Open Ports", "open_ports": open_ports, "risk_level": risk_level}
