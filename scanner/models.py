from django.db import models
from django.contrib.auth.models import User  

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="scans", null=True, blank=True)
    url = models.URLField()
    open_ports = models.TextField(blank=True, null=True)
    sql_injection = models.TextField(blank=True, null=True)  
    xss = models.TextField(blank=True, null=True)            
    findings = models.JSONField(blank=True, null=True)       
    risk_level = models.CharField(max_length=50, blank=True, null=True)
    recommendations = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, default="pending")  
    updated_at = models.DateTimeField(auto_now=True)   
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"{self.url} - {self.status}"

    def __str__(self):
        return self.url

class UrlScanHistory(models.Model):
    url = models.URLField(unique=True)
    last_risk_level = models.CharField(max_length=10)
    last_scan_id = models.UUIDField()
    updated_at = models.DateTimeField(auto_now=True)
