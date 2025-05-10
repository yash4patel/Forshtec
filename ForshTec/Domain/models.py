from django.db import models

class Domain(models.Model):
    domain_name = models.TextField(unique=True, db_column='domain_name')
    
    def __str__(self):
        return self.domain_name

class DomainAnalysis(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='analyses')
    creation_date = models.DateTimeField(null=True, blank=True)
    last_update_date = models.DateTimeField(null=True, blank=True)
    last_analysis_date = models.DateTimeField(null=True, blank=True)
    harmless_count = models.IntegerField(default=0)
    malicious_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    undetected_count = models.IntegerField(default=0)
    timeout_count = models.IntegerField(default=0)
    total_count = models.IntegerField(default=0)

class DomainAnalysisResult(models.Model):
    analysis = models.ForeignKey(DomainAnalysis, on_delete=models.CASCADE, related_name='results')
    engine_name = models.TextField()
    category = models.TextField(null=True, blank=True)
    result = models.TextField(null=True, blank=True)
    method = models.TextField(null=True, blank=True)

class DomainDNSRecord(models.Model):
    analysis = models.ForeignKey(DomainAnalysis, on_delete=models.CASCADE, related_name='dns_records')
    record_type = models.TextField()
    record_value = models.TextField()

class DomainCertificate(models.Model):
    analysis = models.ForeignKey(DomainAnalysis, on_delete=models.CASCADE, related_name='certificates')
    signature_algorithm = models.TextField()
    certificate_date = models.DateTimeField()

class SubjectAlternativeName(models.Model):
    certificate = models.ForeignKey(DomainCertificate, on_delete=models.CASCADE, related_name='sans')
    name = models.TextField()

class DomainCategory(models.Model):
    analysis = models.ForeignKey(DomainAnalysis, on_delete=models.CASCADE, related_name='categories')
    category = models.TextField()