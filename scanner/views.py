# views.py
import time
import random
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse, HttpResponse
from urllib.parse import urlparse
import threading, json

from django.contrib.auth.models import User
from rest_framework import status
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import ScanResult, UrlScanHistory
from .serializers import ScanResultSerializer
from .scan_logic import scan_sql_injection, scan_xss, scan_open_ports, validate_url
from .scanner import run_full_scan
from .utils import basic_scrape_info
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer, SigninSerializer
from rest_framework.views import APIView
import traceback
from datetime import timedelta
from django.utils.timezone import now
import requests
from django.conf import settings

# -----------------------
# Helpers
# -----------------------
def generate_recommendations(sql_res, xss_res, ports_res):
    recommendations = []
    if sql_res.get("status") == "Vulnerable" or sql_res.get("risk_level") == "High":
        recommendations.append("Use parameterized queries to prevent SQL injection.")
    if xss_res.get("risk_level") == "High":
        recommendations.append("Validate and sanitize user inputs to prevent XSS attacks.")
    if ports_res.get("open_ports"):
        recommendations.append("Close unused ports to reduce attack surface.")
    return recommendations



def run_all_scans(url):

    findings = {
        "meta": {},
        "logs": [],
        "scans": {},
        "error": None
    }
    
    try:
        # Validate URL
        valid_url = validate_url(url)
        host = urlparse(valid_url).hostname
        
        findings["meta"] = {
            "url": valid_url,
            "host": host,
            "started_at": int(time.time())
        }
        
        # Define all scans
        scans_to_run = [
            {"key": "open_ports", "func": scan_open_ports, "arg": host},
            {"key": "sql_injection", "func": scan_sql_injection, "arg": valid_url},
            {"key": "xss", "func": scan_xss, "arg": valid_url},
            {"key": "scrape_info", "func": basic_scrape_info, "arg": valid_url},
        ]
        
        # Run all scans
        for task in scans_to_run:
            key, scan_func, arg = task["key"], task["func"], task["arg"]
            scan_start = time.time()
            
            try:
                result = scan_func(arg)
                print(f"[SCAN] Raw result for {key}: {result}")
                
                # Normalize results
                if not isinstance(result, dict):
                    if key == "open_ports":
                        result = {"open_ports": result}
                    elif key == "scrape_info":
                        result = {"data": result}
                    else:
                        result = {"status": result}
                
                findings["scans"][key] = result
                findings["logs"].append({
                    "step": key,
                    "time": int(time.time()),
                    "duration_ms": int((time.time() - scan_start) * 1000),
                    "status": "ok"
                })
                
            except Exception as e:
                findings["scans"][key] = {"error": str(e)}
                findings["logs"].append({
                    "step": key,
                    "time": int(time.time()),
                    "duration_ms": int((time.time() - scan_start) * 1000),
                    "status": "error",
                    "error": str(e)
                })
                print(f"[SCAN] ❌ {key} scan failed: {e}")
        
        # Calculate risk assessment
        sql_result = findings["scans"].get("sql_injection", {})
        xss_result = findings["scans"].get("xss", {})
        ports_result = findings["scans"].get("open_ports", {})
        
        def get_risk_level(obj):
            return obj.get("risk_level") or obj.get("status") or "Unknown"
        
        risk_levels = [
            get_risk_level(sql_result), 
            get_risk_level(xss_result), 
            get_risk_level(ports_result)
        ]
        risk_order = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}
        overall_risk = max(risk_levels, key=lambda r: risk_order.get(r, 0))
        
        findings["risk_assessment"] = {
            "risk_levels": risk_levels,
            "overall_risk": overall_risk,
            "recommendations": generate_recommendations(sql_result, xss_result, ports_result)
        }
        
        findings["meta"]["completed_at"] = int(time.time())
        findings["meta"]["total_duration_ms"] = int((time.time() - findings["meta"]["started_at"]) * 1000)
        
    except Exception as e:
        findings["error"] = str(e)
        findings["logs"].append({
            "step": "fatal_error",
            "time": int(time.time()),
            "error": str(e)
        })
        print(f"[SCAN] 🚨 Fatal error: {e}\n{traceback.format_exc()}")
    
    return findings


def save_scan_results(scan_id, findings):
    """
    SAVING FUNCTION - Handles all database operations.
    Call this ONCE after run_all_scans() completes.
    """
    try:
        scan = ScanResult.objects.get(id=scan_id)
        
        # Check if there was an error
        if findings.get("error"):
            scan.status = f"error: {findings['error']}"
            scan.findings = findings
            scan.save()
            return
        
        # Extract results from the new structure
        scans = findings.get("scans", {})
        sql_result = scans.get("sql_injection", {})
        xss_result = scans.get("xss", {})
        ports_result = scans.get("open_ports", {})
        risk_assessment = findings.get("risk_assessment", {})
        
        # Update all fields at once
        scan.url = findings["meta"]["url"]
        scan.open_ports = "\n".join(map(str, ports_result.get("open_ports", [])))
        scan.sql_injection = json.dumps(sql_result)
        scan.xss = json.dumps(xss_result)
        scan.risk_level = risk_assessment.get("overall_risk", "Unknown")
        scan.recommendations = "\n".join(risk_assessment.get("recommendations", []))
        scan.status = "completed"
        scan.findings = findings
        
        # Single save operation
        scan.save()
        
        print(f"[SCAN-{scan_id}] ✅ Results saved successfully (Risk: {scan.risk_level})")
        
    except Exception as e:
        print(f"[SCAN-{scan_id}] 🚨 Failed to save results: {e}\n{traceback.format_exc()}")
        try:
            scan = ScanResult.objects.get(id=scan_id)
            scan.status = f"error: save failed - {e}"
            scan.save()
        except:
            pass


def run_scan_and_save(scan_id, url):
   
    print(f"✅ run_scan_and_save CALLED for scan_id={scan_id}, url={url}")
    
    try:
        # Update status to running
        scan = ScanResult.objects.get(id=scan_id)
        scan.status = "running"
        scan.save()
        
        # Run all scans (no database operations here - FAST!)
        findings = run_all_scans(url)
        
        # Save everything in one go (ONE database write)
        save_scan_results(scan_id, findings)
        
        return findings
        
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"[SCAN-{scan_id}] 🚨 Fatal error: {e}\n{error_trace}")
        
        try:
            scan = ScanResult.objects.get(id=scan_id)
            scan.status = f"error: fatal - {e}"
            scan.findings = {
                "error": str(e), 
                "logs": [{
                    "step": "fatal", 
                    "time": int(time.time()), 
                    "error": str(e)
                }]
            }
            scan.save()
        except Exception as save_e:
            print(f"[SCAN-{scan_id}] 🚨 Could not save error status: {save_e}")
        
        return {"error": f"A fatal error occurred: {e}"}


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_scan_result(request):
    url = request.data.get('url')
    if not url:
        return Response({'error': 'URL is required'}, status=400)


    scan = ScanResult.objects.create(
        url=url,
        status="pending",
        user=request.user
    )

    threading.Thread(target=run_scan_and_save, args=(scan.id, url), daemon=True).start()

    return Response({
        "scan_id": scan.id,   
        "message": f"Scanning {url} started. Poll /results/{scan.id}/ for updates."
    }, status=202)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_scan_results(request):
    
    scan = ScanResult.objects.all().order_by('-created_at').first()
    if not scan:
        return Response({"error": "No scans found"}, status=404)

    serializer = ScanResultSerializer(scan)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_scan_result_by_id(request, scan_id):
  
    try:
        scan = ScanResult.objects.get(id=scan_id)
        serializer = ScanResultSerializer(scan)
        return Response(serializer.data)
    except ScanResult.DoesNotExist:
        return Response({"error": "Scan not found"}, status=404)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_view(request):
    
    url = request.GET.get("url")
    if not url:
        return JsonResponse({"error": "URL parameter missing"}, status=400)

    try:
        valid_url = validate_url(url)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

    host = urlparse(valid_url).hostname
    results = {
        "sql_injection": scan_sql_injection(valid_url),
        "xss": scan_xss(valid_url),
        "open_ports": scan_open_ports(host),
        "scrape_info": basic_scrape_info(valid_url)
    }
    return JsonResponse(results)


@api_view(["POST"])
@permission_classes([AllowAny])
def signup(request):
    # Verify CAPTCHA first
    captcha_token = request.data.get('captcha')
    if not captcha_token:
        return Response(
            {"error": "CAPTCHA verification is required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Verify CAPTCHA with Google
    captcha_verification = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': captcha_token,
        }
    )
    
    captcha_result = captcha_verification.json()
    if not captcha_result.get('success'):
        return Response(
            {"error": "CAPTCHA verification failed"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response(
            {"message": "User created successfully", **tokens},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user
    return Response({
        "id": user.id,
        "email": user.email  
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def signin(request):

    captcha_token = request.data.get('captcha')
    
    
    if captcha_token:
        try:
            captcha_verification = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': settings.RECAPTCHA_SECRET_KEY,
                    'response': captcha_token,
                }
            )
            
            captcha_result = captcha_verification.json()
            if not captcha_result.get('success'):
                return Response(
                    {"error": "CAPTCHA verification failed"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return Response(
                {"error": "CAPTCHA verification error"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    
    serializer = SigninSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        tokens = get_tokens_for_user(user)
        return Response({"message": "Login successful", **tokens})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def search_scan_results(request):
    query = request.GET.get("query", "").strip()
    if not query:
        return Response([])

    results = ScanResult.objects.filter(
        url__icontains=query
    ) | ScanResult.objects.filter(
        risk_level__icontains=query
    ) | ScanResult.objects.filter(
        recommendations__icontains=query
    )

    serializer = ScanResultSerializer(results, many=True)
    return Response(serializer.data)




@api_view(['GET'])
@permission_classes([IsAuthenticated])  
def findings(request):
    """
    Returns findings filtered by timeframe OR specific scan_id
    """
    try:
        scan_id = request.GET.get('scan_id', None)
        timeframe = request.GET.get('timeframe', '30d')
        show_all = request.GET.get('show_all', 'false').lower() == 'true'
        
        # If scan_id provided, return only that scan
        if scan_id:
            scans = ScanResult.objects.filter(
                user=request.user,
                id=scan_id,
                status='completed'
            )
        else:
            # Filter by timeframe
            if timeframe == '1w':
                cutoff = now() - timedelta(days=7)
            elif timeframe == '2d':
                cutoff = now() - timedelta(days=2)
            else:
                cutoff = now() - timedelta(days=30)
              
            scans = ScanResult.objects.filter(
                user=request.user,   
                created_at__gte=cutoff,
                status='completed'
            ).order_by('-created_at')

        findings_list = []

        for scan in scans:
            vulnerabilities = []
            
            # Parse SQL Injection
            try:
                if scan.sql_injection:
                    sql_data = json.loads(scan.sql_injection) if isinstance(scan.sql_injection, str) else scan.sql_injection
                    if sql_data.get('status') == 'Vulnerable':
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'recommendation': (
                                "Implement parameterized queries or prepared statements to prevent SQL injection attacks. "
                                "Use ORM frameworks that automatically sanitize inputs. "
                                "Apply principle of least privilege to database accounts and avoid using admin credentials in application code. "
                                "Enable Web Application Firewall (WAF) rules to detect and block SQL injection attempts."
                            )
                        })
            except:
                pass
            
            # Parse XSS
            try:
                if scan.xss:
                    xss_data = json.loads(scan.xss) if isinstance(scan.xss, str) else scan.xss
                    vulnerable_xss = [r for r in xss_data.get('results', []) if r.get('status') == 'Vulnerable']
                    if vulnerable_xss:
                        params = [r.get('parameter', 'unknown') for r in vulnerable_xss]
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'affected_params': params,
                            'recommendation': (
                                "Sanitize and encode all user-supplied data before rendering in HTML, JavaScript, or CSS contexts. "
                                "Implement Content Security Policy (CSP) headers to restrict script execution. "
                                "Use modern frameworks (React, Vue, Angular) that automatically escape outputs. "
                                f"Vulnerable parameters detected: {', '.join(params)}. "
                                "Enable HTTPOnly and Secure flags on all cookies to prevent session hijacking."
                            )
                        })
            except:
                pass
            
            # Parse Open Ports
            try:
                if scan.open_ports:
                    ports_list = [p.strip() for p in scan.open_ports.split('\n') if p.strip()] if isinstance(scan.open_ports, str) else scan.open_ports
                    port_count = len([p for p in ports_list if p])
                    
                    if port_count > 0:
                        severity = 'High' if port_count > 5 else 'Medium' if port_count > 2 else 'Low'
                        
                        # Professional recommendation based on severity
                        if severity == 'High':
                            recommendation = (
                                f"Critical: {port_count} open ports detected, increasing attack surface significantly. "
                                "Immediately close all unnecessary ports using host-based firewalls (iptables, Windows Firewall). "
                                "Review running services and disable those not required for business operations. "
                                "Implement network segmentation and place sensitive services behind VPN or bastion hosts. "
                                "Enable port knocking or implement a zero-trust network architecture."
                            )
                        elif severity == 'Medium':
                            recommendation = (
                                f"Warning: {port_count} open ports detected. "
                                "Review each open port and ensure only essential services are exposed. "
                                "Apply firewall rules to restrict access to trusted IP addresses only. "
                                "Ensure all exposed services are running the latest patched versions. "
                                "Consider implementing port scanning detection and alerting mechanisms."
                            )
                        else:
                            recommendation = (
                                f"Notice: {port_count} open port(s) detected. "
                                "Verify that exposed services are intentional and properly secured. "
                                "Ensure strong authentication is enabled on all accessible services. "
                                "Regularly audit open ports and close any that are no longer needed. "
                                "Monitor logs for suspicious connection attempts."
                            )
                        
                        vulnerabilities.append({
                            'type': 'Open Ports',
                            'severity': severity,
                            'port_count': port_count,
                            'recommendation': recommendation
                        })
            except:
                pass
            if show_all:
                for vuln in vulnerabilities:
                    findings_list.append({
                        'id': f"{scan.id}-{vuln['type'].lower().replace(' ', '-')}",
                        'scan_id': scan.id,  # ✅ ADD THIS
                        'url': scan.url,
                        'vulnerability': vuln['type'],
                        'severity': vuln['severity'],
                        'recommendation': vuln['recommendation'],
                        'scan_date': scan.created_at.isoformat()
                    })
                
                if not vulnerabilities:
                    findings_list.append({
                        'id': scan.id,
                        'scan_id': scan.id,  # ✅ ADD THIS
                        'url': scan.url,
                        'vulnerability': 'No Issues Found',
                        'severity': 'Low',
                        'recommendation': 'No vulnerabilities detected.',
                        'scan_date': scan.created_at.isoformat()
                    })
            else:
                if vulnerabilities:
                    severity_order = {'High': 3, 'Medium': 2, 'Low': 1}
                    most_critical = max(vulnerabilities, key=lambda v: severity_order.get(v['severity'], 0))
                    
                    findings_list.append({
                        'id': scan.id,
                        'scan_id': scan.id,  # ✅ ADD THIS
                        'url': scan.url,
                        'vulnerability': most_critical['type'],
                        'severity': most_critical['severity'],
                        'recommendation': most_critical['recommendation'],
                        'scan_date': scan.created_at.isoformat(),
                        'total_issues': len(vulnerabilities)
                    })
                else:
                    findings_list.append({
                        'id': scan.id,
                        'scan_id': scan.id,  # ✅ ADD THIS
                        'url': scan.url,
                        'vulnerability': 'No Issues Found',
                        'severity': 'Low',
                        'recommendation': 'No vulnerabilities detected.',
                        'scan_date': scan.created_at.isoformat(),
                        'total_issues': 0
                    })
        
        return Response(findings_list)
        
    except Exception as e:
        print(f"Error in findings: {e}")
        import traceback
        traceback.print_exc()
        return Response({"error": "Failed to fetch findings"}, status=500)
           
          


# Usage from frontend:
# /api/findings/                    → Shows 1 finding per scan (most critical)
# /api/findings/?show_all=true     → Shows all vulnerabilities separately    
# In your Django view
# class FindingsView(APIView):
#     permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # ✅ Filter by user
        findings = findings.objects.filter(user=request.user)
        serializer = FindingSerializer(findings, many=True)
        return Response(serializer.data)
    
def update_url_history(url, findings, scan_id):
    risk_level = findings["risk_assessment"]["overall_risk_level"]
    UrlScanHistory.objects.update_or_create(
        url=url,
        defaults={"last_risk_level": risk_level, "last_scan_id": scan_id}
    )
