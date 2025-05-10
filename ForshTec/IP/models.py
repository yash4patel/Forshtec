from django.db import models
from django.contrib.postgres.fields import JSONField
from django.utils import timezone


class IPAddress(models.Model):
    """
    Represents an IP address analyzed by VirusTotal
    """
    ip = models.CharField(max_length=100,unique=True)

class IPAnalysis(models.Model):
    """
    Main analysis results for an IP address
    """
    ip = models.ForeignKey(IPAddress, on_delete=models.CASCADE, related_name='analyses')
    created_at = models.DateTimeField(auto_now_add=True)

    
    # Network information
    as_owner = models.CharField(max_length=255, blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    continent = models.CharField(max_length=2, blank=True, null=True)
    country = models.CharField(max_length=2, blank=True, null=True)
    jarm = models.CharField(max_length=92, blank=True, null=True)
    network = models.CharField(max_length=100, blank=True, null=True)
    regional_internet_registry = models.CharField(max_length=50, blank=True, null=True)
    
    # Reputation data
    reputation = models.IntegerField(default=0)
    
    # Analysis stats
    harmless_count = models.IntegerField(default=0)
    malicious_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    undetected_count = models.IntegerField(default=0)
    timeout_count = models.IntegerField(default=0)
    
    # Community votes
    total_votes_harmless = models.IntegerField(default=0)
    total_votes_malicious = models.IntegerField(default=0)
    
    # Raw data storage
    tags = models.JSONField(default=list)
    # raw_data = models.JSONField(blank=True, null=True)


    def __str__(self):
        return f"Analysis of {self.ip} at {self.analysis_date}"

class IPAnalysisResult(models.Model):
    """
    Individual engine results from an IP analysis
    """
    analysis = models.ForeignKey(IPAnalysis, on_delete=models.CASCADE, related_name='results')
    engine_name = models.CharField(max_length=100)
    category = models.CharField(max_length=50, blank=True, null=True)
    result = models.CharField(max_length=255, blank=True, null=True)
    method = models.CharField(max_length=50, blank=True, null=True)
    
    def __str__(self):
        return f"{self.engine_name}: {self.result or 'No result'}"

class IPCertificate(models.Model):
    """
    SSL/TLS certificates associated with an IP address
    """
    analysis = models.ForeignKey(IPAnalysis, on_delete=models.CASCADE, related_name='certificates')
    certificate_data = models.JSONField()  # Stores the complete certificate object
    
    # Common fields for easy access
    thumbprint = models.CharField(max_length=64, blank=True, null=True)
    thumbprint_sha256 = models.CharField(max_length=64, blank=True, null=True)
    serial_number = models.CharField(max_length=100, blank=True, null=True)
    issuer = models.JSONField(blank=True, null=True)
    subject = models.JSONField(blank=True, null=True)
    validity_not_before = models.DateTimeField(blank=True, null=True)
    validity_not_after = models.DateTimeField(blank=True, null=True)
    version = models.CharField(max_length=10, blank=True, null=True)
    signature_algorithm = models.CharField(max_length=50, blank=True, null=True)
    size = models.IntegerField(blank=True, null=True)
    