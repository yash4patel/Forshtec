import requests
import time
from django.utils import timezone
from django.core.files.storage import default_storage
from django.core.cache import cache
from .models import File, FileAnalysis, FileAnalysisResult, FileSigmaAnalysis

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def submit_file(self, file_path, original_filename):
        """Submit file to VirusTotal for analysis"""
        url = f"{self.base_url}/files"
        
        with open(default_storage.path(file_path), 'rb') as file:
            files = {'file': (original_filename, file)}
            response = requests.post(url, files=files, headers=self.headers)
            return response

    def get_analysis_report(self, file_id, max_attempts=10):
        """Poll VirusTotal for analysis results"""
        analysis_url = f"{self.base_url}/analyses/{file_id}"
        cache_key = f"virustotal_analysis_{file_id}"
        cached_result = cache.get(cache_key)

        if cached_result:
            return cached_result

        print(analysis_url)
        
        for attempt in range(max_attempts):
            # url = "https://www.virustotal.com/api/v3/analyses/ODA2MWVlOGEyZGYzNjMxYTY4MmQ4NmRjOWZhYjIxMTU6MTc0Njc4NDExNg%3D%3D"
            response = requests.get(analysis_url, headers=self.headers)
            # print(response)
            data = response.json()
            if response.status_code == 200:
                cache.set(cache_key, data)
                return data
            # print(data)
            # time.sleep(delay)
            return data
            
        
        raise TimeoutError("VirusTotal analysis timed out")

    def save_analysis_results(self, file_id, report, original_filename):
        """Save VirusTotal analysis results to database"""
        attributes = report['data']['attributes']
        
        # Create or update File record
        file_obj, created = File.objects.update_or_create(
            sha256=file_id,
            defaults={
                'md5': attributes.get('md5'),
                'meaningful_name': original_filename,
                # 'size': attributes.get('size'),
                # 'type_description': attributes.get('type_description'),
                # 'vhash': attributes.get('vhash')
            }
        )
        # print(file_obj)
        
        # Create FileAnalysis record
        analysis = FileAnalysis.objects.create(
            file=file_obj,
            analysis_date=timezone.now(),
            first_submission_date=self.parse_vt_timestamp(attributes.get('first_submission_date')),
            last_analysis_date=self.parse_vt_timestamp(attributes.get('last_analysis_date')),
            last_submission_date=self.parse_vt_timestamp(attributes.get('last_submission_date')),
            times_submitted=attributes.get('times_submitted'),
            reputation=attributes.get('reputation'),
            harmless_count=attributes.get('last_analysis_stats', {}).get('harmless', 0),
            malicious_count=attributes.get('last_analysis_stats', {}).get('malicious', 0),
            suspicious_count=attributes.get('last_analysis_stats', {}).get('suspicious', 0),
            undetected_count=attributes.get('last_analysis_stats', {}).get('undetected', 0),
            timeout_count=attributes.get('last_analysis_stats', {}).get('timeout', 0),
            total_votes_harmless=attributes.get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=attributes.get('total_votes', {}).get('malicious', 0),
        )
        
        # Save engine results
        self._save_engine_results(analysis, attributes.get('last_analysis_results', {}))
        
        # Save sigma analysis results
        self._save_sigma_results(analysis, attributes.get('sigma_analysis_results', []))
        
        return analysis

    def _save_engine_results(self, analysis, results):
        """Save individual engine results"""
        for engine_name, result in results.items():
            FileAnalysisResult.objects.create(
                analysis=analysis,
                engine_name=engine_name,
                category=result.get('category'),
                result=result.get('result'),
                engine_version=result.get('engine_version'),
                engine_update=result.get('engine_update'),
                method=result.get('method'),
            )

    def _save_sigma_results(self, analysis, sigma_results):
        """Save sigma rule analysis results"""
        for sigma_result in sigma_results:
            FileSigmaAnalysis.objects.create(
                analysis=analysis,
                rule_id=sigma_result.get('rule_id'),
                rule_title=sigma_result.get('rule_title'),
                rule_description=sigma_result.get('rule_description'),
                severity=sigma_result.get('rule_level'),
                source=sigma_result.get('rule_source'),
            )

    @staticmethod
    def parse_vt_timestamp(timestamp):
        """Convert VirusTotal timestamp to datetime"""
        if timestamp:
            return timezone.datetime.fromtimestamp(timestamp)
        return None