from django.db import models

class ScanResult(models.Model):
    url = models.URLField()
    open_ports = models.TextField(blank=True, null=True)
    sql_injection = models.TextField(blank=True, null=True)  # JSON string
    xss = models.TextField(blank=True, null=True)            # JSON string
    findings = models.JSONField(blank=True, null=True)       # Summary with detailed scan results
    risk_level = models.CharField(max_length=50, blank=True, null=True)
    recommendations = models.TextField(blank=True, null=True)
    # status = models.CharField(max_length=20, default="pending") 
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index added here

    def __str__(self):
        return self.url
