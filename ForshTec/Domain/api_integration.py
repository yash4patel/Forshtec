import requests
from django.conf import settings
import datetime
from .models import Domain, DomainAnalysis, DomainAnalysisResult, DomainCategory, DomainCertificate, DomainDNSRecord, SubjectAlternativeName

class VirusTotalClient:
    def __init__(self):
        self.headers = {
            "accept": "application/json",
            "x-apikey": settings.VIRUSTOTAL_API_KEY
        }
        self.base_url = "https://www.virustotal.com/api/v3/domains"

    def _make_request(self, domain_name):
        """
        Make API request to VirusTotal for domain information
        
        Important: domain_name should be a fully qualified domain name, not a filter string
        """
        # Ensure this is a valid domain name, not a filter term
        if '/' in domain_name or '?' in domain_name:
            raise VirusTotalAPIError(f"Invalid domain name: {domain_name}")
            
        url = f"{self.base_url}/{domain_name}"
        try:
            res = requests.get(url, headers=self.headers)
            res.raise_for_status()
            return res.json()
        except requests.exceptions.RequestException as e:
            raise VirusTotalAPIError(f"Request failed: {e}")

    def _process_analysis_results(self, report, analysis_results):
        for engine_name, result in analysis_results.items():
            DomainAnalysisResult.objects.create(
                analysis=report,
                engine_name=engine_name,
                category=result.get("category"),
                result=result.get("result"),
                method=result.get("method"),
            )

    def _process_dns_records(self, report, dns_records):
        for record in dns_records:
            DomainDNSRecord.objects.create(
                analysis=report,
                record_type=record.get("type"),
                record_value=record.get("value"),
            )

    def _process_certificate(self, report, cert_data, cert_date):
        if not cert_data:
            return
            
        certificate_instance = DomainCertificate.objects.create(
            analysis=report,
            signature_algorithm=cert_data.get("cert_signature", {}).get("signature_algorithm"),
            certificate_date=datetime.datetime.fromtimestamp(cert_date) if cert_date else None,
        )

        for san_name in cert_data.get('extensions', {}).get('subject_alternative_name', []):
            SubjectAlternativeName.objects.create(
                certificate=certificate_instance,
                name=san_name
            )

    def _process_categories(self, report, categories):
        if not categories:
            return
            
        for source, category in categories.items():
            DomainCategory.objects.create(
                analysis=report,
                category=category,
            )

    def get_domain_report(self, domain_name):
        """
        Get domain report from VirusTotal API
        
        Parameters:
        - domain_name: a valid domain name like "example.com"
        
        Returns:
        - DomainAnalysis object with related data or None if not found
        """
        try:
            # Sanitize the domain name input
            domain_name = domain_name.strip().lower()
            
            json_data = self._make_request(domain_name)
            data = json_data.get("data", {}).get("attributes", {})
            
            if not data:
                return None
                
            domain_obj, _ = Domain.objects.get_or_create(domain_name=domain_name)
            
            report = DomainAnalysis.objects.create(
                domain=domain_obj,
                last_analysis_date=datetime.datetime.fromtimestamp(data.get("last_analysis_date", 0)) if data.get("last_analysis_date") else None,
                malicious_count=data.get("last_analysis_stats", {}).get("malicious", 0),
                total_count=sum(data.get("last_analysis_stats", {}).values()) if data.get("last_analysis_stats") else 0,
                creation_date=datetime.datetime.fromtimestamp(data.get("creation_date", 0)) if data.get("creation_date") else None,
                last_update_date=datetime.datetime.fromtimestamp(data.get("last_modification_date", 0)) if data.get("last_modification_date") else None,
                harmless_count=data.get("total_votes", {}).get("harmless", 0),
                suspicious_count=data.get("last_analysis_stats", {}).get("suspicious", 0),
                undetected_count=data.get("last_analysis_stats", {}).get("undetected", 0),
                timeout_count=data.get("last_analysis_stats", {}).get("timeout", 0),
            )

            self._process_analysis_results(report, data.get("last_analysis_results", {}))
            self._process_dns_records(report, data.get("last_dns_records", []))
            self._process_certificate(report, data.get("last_https_certificate"), data.get("last_https_certificate_date"))
            self._process_categories(report, data.get("categories"))

            return report

        except Exception as e:
            raise VirusTotalProcessingError(f"Error processing domain report: {e}")


class VirusTotalAPIError(Exception):
    """Custom exception for API errors"""
    pass


class VirusTotalProcessingError(Exception):
    """Custom exception for data processing errors"""
    pass