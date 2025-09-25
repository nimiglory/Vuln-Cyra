# views.py
import time
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
from .scan_logic import scan_sql_injection, scan_xss, scan_open_ports, validate_url
from .scanner import run_full_scan
from .utils import basic_scrape_info
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer, SigninSerializer
import traceback
from datetime import timedelta
from django.utils.timezone import now

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
    """
    Runs all checks, logs each step, and saves partial results after each check.
    The main logic is consolidated to loop through defined scans, handle errors for
    each, and then process the combined results.
    """
    print(f"✅ run_scan_and_save CALLED for scan_id={scan_id}, url={url}")
    scan = None  # Initialize scan to None for the outer error handler
    findings = {}

    try:
        # ---------- 1. INITIAL SETUP AND URL VALIDATION ----------
        scan = ScanResult.objects.get(id=scan_id)
        scan.status = "running"
        scan.save()

        start_ts = time.time()
        print(f"[SCAN-{scan_id}] Starting scan for {url}")

        # URL validation is critical, so it's handled separately.
        # If it fails, we stop immediately.
        try:
            valid_url = validate_url(url)
            host = urlparse(valid_url).hostname
            print(f"[SCAN-{scan_id}] Validated URL: {valid_url}, Host: {host}")
        except Exception as e:
            msg = f"URL validation failed: {e}"
            print(f"[SCAN-{scan_id}] ❌ {msg}")
            scan.status = f"error: invalid url - {e}"
            scan.findings = {"error": msg}
            scan.save()
            return {"error": msg} # Return the error response

        # Prepare findings structure and save so frontend sees progress
        findings = {
            "meta": {"url": valid_url, "host": host, "started_at": int(start_ts)},
            "logs": []
        }
        scan.findings = findings
        scan.save()

        def persist_step(key, result_obj):
            """Helper to save partial results and log the step."""
            nonlocal scan, findings
            findings[key] = result_obj
            log_entry = {
                "step": key,
                "time": int(time.time()),
                "note": "ok" if "error" not in (result_obj or {}) else "error"
            }
            findings.setdefault("logs", []).append(log_entry)
            scan.findings = findings
            scan.save()
            print(f"[SCAN-{scan_id}] Persisted step: {key}")

        # ---------- 2. DEFINE AND RUN ALL SCANS IN A LOOP ----------
        scans_to_run = [
            {"key": "open_ports",    "func": scan_open_ports,    "arg": host},
            {"key": "sql_injection", "func": scan_sql_injection, "arg": valid_url},
            {"key": "xss",           "func": scan_xss,           "arg": valid_url},
            {"key": "scrape_info",   "func": basic_scrape_info,  "arg": valid_url},
        ]

        results = {} # This will hold the response for each individual scan
        for task in scans_to_run:
            key, scan_func, arg = task["key"], task["func"], task["arg"]
            try:
                # Execute the scan function
                result = scan_func(arg)
                print(f"[SCAN-{scan_id}] Raw result for {key}: {result}")
                # Normalize results to always be a dictionary
                if not isinstance(result, dict):
                    if key == "open_ports":
                        result = {"open_ports": result}
                    elif key == "scrape_info":
                         result = {"data": result}
                    else:
                        result = {"status": result}
            except Exception as e:
                # If a specific scan fails, record the error and continue
                result = {"error": str(e)}
                print(f"[SCAN-{scan_id}] ❌ {key} scan failed: {e}")

            results[key] = result  # Store the individual response
            persist_step(key, result) # Save progress for the frontend

        # ---------- 3. FINALIZE, CALCULATE RISK, AND SAVE ----------
        # Extract results safely using .get() with a default empty dict
        sql_result = results.get("sql_injection", {})
        xss_result = results.get("xss", {})
        ports_result = results.get("open_ports", {})

        def rl(obj):
            return obj.get("risk_level") or obj.get("status") or "Unknown"

        risk_levels = [rl(sql_result), rl(xss_result), rl(ports_result)]
        risk_order = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}
        overall_risk = max(risk_levels, key=lambda r: risk_order.get(r, 0))

        recommendations = generate_recommendations(sql_result, xss_result, ports_result)

        findings["risk_assessment"] = {
            "risk_levels": risk_levels,
            "overall_risk": overall_risk,
            "recommendations": recommendations
        }

        # Update the main ScanResult object fields
        scan.url = valid_url
        scan.open_ports = "\n".join(map(str, ports_result.get("open_ports", [])))
        scan.sql_injection = json.dumps(sql_result)
        scan.xss = json.dumps(xss_result)
        scan.risk_level = overall_risk
        scan.recommendations = "\n".join(recommendations)
        scan.status = "completed"
        scan.findings = findings
        scan.save()

        print(f"[SCAN-{scan_id}] ✅ Scan finished (Overall risk: {overall_risk})")

        # Return the final, complete findings dictionary
        return findings

    except Exception as e:
        # This is a fatal error catch (e.g., database connection failed)
        error_trace = traceback.format_exc()
        print(f"[SCAN-{scan_id}] 🚨 Fatal error during scan process: {e}\n{error_trace}")
        if scan:
            try:
                scan.status = f"error: fatal - {e}"
                findings["error"] = str(e)
                findings.setdefault("logs", []).append({"step": "fatal", "time": int(time.time()), "error": str(e)})
                scan.findings = findings
                scan.save()
            except Exception as save_e:
                print(f"[SCAN-{scan_id}] 🚨 Could not even save fatal error status: {save_e}")
        # Return a final error response
        return {"error": f"A fatal error occurred: {e}"}




def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }

# -----------------------
# API Views
# -----------------------


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_scan_result(request):
    url = request.data.get('url')
    if not url:
        return Response({'error': 'URL is required'}, status=400)

    # ✅ Create scan with pending status
    scan = ScanResult.objects.create(url=url, status="pending")

    threading.Thread(target=run_scan_and_save, args=(scan.id, url), daemon=True).start()

    return Response({
        "scan_id": scan.id,   # ✅ frontend can track with ID
        "message": f"Scanning {url} started. Poll /results/{scan.id}/ for updates."
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
def get_scan_result_by_id(request, scan_id):
    """Poll scan result by ID"""
    try:
        scan = ScanResult.objects.get(id=scan_id)
        serializer = ScanResultSerializer(scan)
        return Response(serializer.data)
    except ScanResult.DoesNotExist:
        return Response({"error": "Scan not found"}, status=404)



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


@api_view(["POST"])
@permission_classes([AllowAny])
def signup(request):
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
        "email": user.email  # that's it, since you only use email
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def signin(request):
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
@permission_classes([IsAuthenticated])  # ✅ same as your other scan views
def findings(request):
    timeframe = request.GET.get("timeframe", None)
    queryset = ScanResult.objects.all()

    if timeframe:
        today = now()

        if timeframe == "30d":
            queryset = queryset.filter(created_at__gte=today - timedelta(days=30))
        elif timeframe == "1w":
            queryset = queryset.filter(created_at__gte=today - timedelta(weeks=1))
        elif timeframe == "2d":
            queryset = queryset.filter(created_at__gte=today - timedelta(days=2))
        elif timeframe == "last":
            queryset = queryset.order_by("-created_at")[:1]

    serializer = ScanResultSerializer(queryset, many=True)
    return Response(serializer.data)