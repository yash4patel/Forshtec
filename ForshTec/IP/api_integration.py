import requests
from django.conf import settings
from datetime import datetime
from .models import IPAddress, IPAnalysis, IPAnalysisResult, IPCertificate

class VirusTotalIPClient:
    """
    Handles all VirusTotal IP address operations including:
    - Fetching data from VirusTotal API
    - Saving data to database
    """
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def get_ip_report(self, ip_address):
        """Fetch IP report from VirusTotal"""
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"VirusTotal API error: {str(e)}")
            return None

    def save_ip_data(self, ip_address):
        """Main method to fetch and save IP data"""
        ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)
        vt_data = self.get_ip_report(ip_address)
        
        if not vt_data or 'data' not in vt_data:
            return None
        
        return self._create_analysis(ip_obj, vt_data)

    def _create_analysis(self, ip_obj, vt_data):
        """Create analysis record and related data"""
        attributes = vt_data['data']['attributes']
        
        analysis = IPAnalysis.objects.create(
            ip=ip_obj,
            as_owner=attributes.get('as_owner'),
            asn=attributes.get('asn'),
            continent=attributes.get('continent'),
            country=attributes.get('country'),
            jarm=attributes.get('jarm'),
            network=attributes.get('network'),
            regional_internet_registry=attributes.get('regional_internet_registry'),
            reputation=attributes.get('reputation', 0),
            harmless_count=attributes.get('last_analysis_stats', {}).get('harmless', 0),
            malicious_count=attributes.get('last_analysis_stats', {}).get('malicious', 0),
            suspicious_count=attributes.get('last_analysis_stats', {}).get('suspicious', 0),
            undetected_count=attributes.get('last_analysis_stats', {}).get('undetected', 0),
            timeout_count=attributes.get('last_analysis_stats', {}).get('timeout', 0),
            total_votes_harmless=attributes.get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=attributes.get('total_votes', {}).get('malicious', 0),
            tags=attributes.get('tags', []),
            raw_data=vt_data
        )

        self._save_analysis_results(analysis, attributes)
        self._save_certificates(analysis, attributes)
        
        return analysis

    def _save_analysis_results(self, analysis, attributes):
        """Save engine analysis results"""
        if 'last_analysis_results' in attributes:
            for engine_name, result in attributes['last_analysis_results'].items():
                IPAnalysisResult.objects.create(
                    analysis=analysis,
                    engine_name=engine_name,
                    category=result.get('category'),
                    result=result.get('result'),
                    method=result.get('method')
                )

    def _save_certificates(self, analysis, attributes):
        """Save SSL certificates if available"""
        if 'last_https_certificate' in attributes:
            cert_data = attributes['last_https_certificate']
            IPCertificate.objects.create(
                analysis=analysis,
                certificate_data=cert_data,
                thumbprint=cert_data.get('thumbprint'),
                thumbprint_sha256=cert_data.get('thumbprint_sha256'),
                serial_number=cert_data.get('serial_number'),
                issuer=cert_data.get('issuer'),
                subject=cert_data.get('subject'),
                validity_not_before=self._parse_cert_date(cert_data, 'not_before'),
                validity_not_after=self._parse_cert_date(cert_data, 'not_after'),
                version=cert_data.get('version'),
                signature_algorithm=cert_data.get('signature_algorithm'),
                size=cert_data.get('size')
            )

    def _parse_cert_date(self, cert_data, field):
        """Parse certificate date fields"""
        if not cert_data.get('validity'):
            return None
        try:
            return datetime.strptime(
                cert_data['validity'][field],
                '%Y-%m-%d %H:%M:%S'
            )
        except (ValueError, KeyError):
            return None