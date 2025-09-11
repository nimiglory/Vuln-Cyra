# views.py
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

from .models import ScanResult
from .serializers import ScanResultSerializer
from .scanner import scan_sql_injection, scan_xss, scan_open_ports, validate_url
from .utils import basic_scrape_info


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


def run_scan_and_save(scan_id, url):
    """Background worker for scanning and saving results to DB."""
    try:
        scan = ScanResult.objects.get(id=scan_id)

        valid_url = validate_url(url)
        host = urlparse(valid_url).hostname

        # Perform scans
        ports_result = scan_open_ports(host)
        sql_result = scan_sql_injection(valid_url)
        xss_result = scan_xss(valid_url)
        scrape_info = basic_scrape_info(valid_url)

        # Combine findings
        findings = {
            "sql_injection": sql_result,
            "xss": xss_result,
            "open_ports": ports_result,
            "scrape_info": scrape_info,
        }

        # Risk & recommendations
        risk_levels = [
            sql_result.get("risk_level", "Low"),
            xss_result.get("risk_level", "Low"),
            ports_result.get("risk_level", "Low"),
        ]
        risk_order = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}
        overall_risk = max(risk_levels, key=lambda r: risk_order.get(r, 0))

        recommendations = generate_recommendations(sql_result, xss_result, ports_result)

        # Update scan result
        scan.url = valid_url
        scan.open_ports = "\n".join(map(str, ports_result.get("open_ports", [])))
        scan.sql_injection = json.dumps(sql_result)
        scan.xss = json.dumps(xss_result)
        scan.findings = findings
        scan.risk_level = overall_risk
        scan.recommendations = "\n".join(recommendations)
        scan.save()

    except Exception as e:
        try:
            scan.status = f"error: {str(e)}"
            scan.save()
        except:
            pass


# -----------------------
# API Views
# -----------------------
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_scan_result(request):
    """Create a scan entry and run scan in background."""
    url = request.data.get('url')
    if not url:
        return Response({'error': 'URL is required'}, status=400)

    scan = ScanResult.objects.create(url=url)
    threading.Thread(target=run_scan_and_save, args=(scan.id, url), daemon=True).start()

    return Response({
        "message": f"Scanning {url} in the background. Use /results/ to fetch results."
    }, status=202)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_scan_results(request):
    """Get the latest scan result only (no ID required)."""
    scan = ScanResult.objects.all().order_by('-created_at').first()
    if not scan:
        return Response({"error": "No scans found"}, status=404)

    serializer = ScanResultSerializer(scan)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_view(request):
    """Quick scan endpoint (on-demand, no DB save)."""
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


@api_view(['POST'])
@permission_classes([AllowAny])  # Anyone can signup
def signup(request):
    """Register a new user with password validation."""
    username = request.data.get('username')
    password = request.data.get('password')
    if not username or not password:
        return Response({"error": "Username and password required"}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"error": "Username already taken"}, status=400)

    try:
        validate_password(password)
    except ValidationError as e:
        return Response({"error": list(e.messages)}, status=400)

    User.objects.create_user(username=username, password=password)
    return Response({"message": "User created successfully"}, status=201)


def home(request):
    """Simple test view."""
    if request.user.is_authenticated:
        return HttpResponse(f"🎉 You are logged in as: {request.user.username}")
    return HttpResponse("⚠️ You are not logged in. Try /accounts/google/login/")
