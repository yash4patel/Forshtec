from django.db import models

# Create your models here.

class File(models.Model):
    """Represents a file analyzed by VirusTotal"""
    sha256 = models.TextField(unique=True)
    md5 = models.TextField(null=True, blank=True)
    meaningful_name = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'file'

    def __str__(self):
        return self.meaningful_name or self.sha256[:10]

class FileAnalysis(models.Model):
    """Analysis results for a specific file"""
    file = models.ForeignKey(
        File, 
        on_delete=models.CASCADE,
        db_column='file_id'
    )
    analysis_date = models.DateTimeField()
    first_submission_date = models.DateTimeField(null=True, blank=True)
    last_analysis_date = models.DateTimeField(null=True, blank=True)
    last_submission_date = models.DateTimeField(null=True, blank=True)
    times_submitted = models.IntegerField(null=True, blank=True)
    reputation = models.IntegerField(null=True, blank=True)
    harmless_count = models.IntegerField(null=True, blank=True)
    malicious_count = models.IntegerField(null=True, blank=True)
    suspicious_count = models.IntegerField(null=True, blank=True)
    undetected_count = models.IntegerField(null=True, blank=True)
    timeout_count = models.IntegerField(null=True, blank=True)
    total_votes_harmless = models.IntegerField(null=True, blank=True)
    total_votes_malicious = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = 'file_analysis'

    def __str__(self):
        return f"Analysis {self.id} for {self.file}"

class FileAnalysisResult(models.Model):
    """Individual engine results for a file analysis"""
    analysis = models.ForeignKey(
        FileAnalysis, 
        on_delete=models.CASCADE,
        db_column='analysis_id',
        related_name='results'
    )
    engine_name = models.TextField()
    category = models.TextField(null=True, blank=True)
    result = models.TextField(null=True, blank=True)
    engine_version = models.TextField(null=True, blank=True)
    engine_update = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'file_analysis_result'

    def __str__(self):
        return f"{self.engine_name} - {self.result or self.category}"

class FileSigmaAnalysis(models.Model):
    """Sigma rule analysis results for files"""
    analysis = models.ForeignKey(
        FileAnalysis, 
        on_delete=models.CASCADE,
        db_column='analysis_id',
        related_name='sigma_analyses'
    )
    rule_id = models.TextField(null=True, blank=True)
    rule_title = models.TextField(null=True, blank=True)
    rule_description = models.TextField(null=True, blank=True)
    severity = models.TextField(null=True, blank=True)
    source = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'file_sigma_analysis'

    def __str__(self):
        return f"{self.rule_title} ({self.severity})"