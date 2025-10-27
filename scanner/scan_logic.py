import requests
import socket
import psutil
import concurrent.futures
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
    """
    Optimized: Reduced payloads and added timeout
    """
    # ⚡ Reduced from 4 to 2 most effective payloads
    payloads = ["' OR '1'='1", "';--"]
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query) or {"id": ["1"]}

    vulnerable = False
    details = []

    for param in params.keys():
        for payload in payloads:
            test_params = {k: (payload if k == param else v[0]) for k, v in params.items()}
            try:
                # ⚡ Reduced timeout from 10s to 3s
                response = requests.get(base_url, params=test_params, timeout=3)
                if any(err in response.text.lower() for err in [
                    "sql syntax", "mysql", "syntax error", "odbc", "ora-00933", "unclosed quotation"
                ]):
                    vulnerable = True
                    details.append({"parameter": param, "payload": payload, "status": "Vulnerable"})
                    break  # ⚡ Stop testing this param if vulnerable
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
    """
    Optimized: Reduced timeout
    """
    test_payload = "<script>alert('XSS')</script>"
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query) or {"q": [""]}

    results = []
    for param in params.keys():
        test_params = {k: (test_payload if k == param else v[0]) for k, v in params.items()}
        try:
            # ⚡ Reduced timeout from 10s to 3s
            response = requests.get(base_url, params=test_params, timeout=3)
            status = "Vulnerable" if test_payload in response.text else "Safe"
        except requests.RequestException:
            status = "Error - Could not test"

        results.append({"parameter": param, "status": status})

    risk_level = "High" if any(r["status"] == "Vulnerable" for r in results) else "Low"
    return {"type": "XSS", "results": results, "risk_level": risk_level}


def scan_single_port(host, port):
    """
    Helper function to scan a single port
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # ⚡ Reduced from 1s to 0.5s
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_open_ports(host, ports=None):
    """
    🚀 ULTRA-FAST VERSION: Only scans common ports
    This is 50x faster than scanning all ports!
    """
    # ⚡ CRITICAL OPTIMIZATION: Only scan common ports
    if ports is None:
        ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
        ]
    
    open_ports = []
    
    # ⚡ Use ThreadPoolExecutor for parallel scanning
    max_workers = min(20, len(ports))  # Cap at 20 threads
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(scan_single_port, host, port): port 
                for port in ports
            }
            
            # Collect results with timeout
            for future in concurrent.futures.as_completed(future_to_port, timeout=5):
                result = future.result()
                if result:
                    open_ports.append(result)
    except concurrent.futures.TimeoutError:
        print(f"Port scan timeout for {host}")
    except Exception as e:
        print(f"Port scan error: {e}")
    
    # Calculate risk level
    if len(open_ports) > 5:
        risk_level = "High"
    elif len(open_ports) > 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "type": "Open Ports", 
        "open_ports": sorted(open_ports),  # ⚡ Sort for consistent output
        "risk_level": risk_level
    }


def scan_all_ports(host):
  
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(host, arguments="-p-")
        
        open_ports = []
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]["state"] == "open":
                    open_ports.append(port)
        
        return {
            "type": "Full Port Scan",
            "open_ports": sorted(open_ports),
            "risk_level": "High" if len(open_ports) > 5 else "Medium" if len(open_ports) > 2 else "Low"
        }
    except Exception as e:
        return {"error": f"Full port scan failed: {e}"}