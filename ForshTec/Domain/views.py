from django.http import JsonResponse
from django.core.cache import cache
from django.utils import timezone
from django.db import DatabaseError
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from .models import Domain, DomainAnalysis
# from .serializers import DomainAnalysisSerializer
from .serializers import (
    DomainSerializer, 
    DomainAnalysisSerializer,
    DomainAnalysisResultSerializer,
    DomainDNSRecordSerializer,
    DomainCertificateSerializer,
    DomainCategorySerializer,
    SubjectAlternativeNameSerializer
)
from .api_integration import VirusTotalClient, VirusTotalAPIError, VirusTotalProcessingError
import logging
from rest_framework.response import Response
from rest_framework import status


logger = logging.getLogger(__name__)


class DomainReportView(APIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vt_client = VirusTotalClient()

    def get(self, request, domain_name):
        try:
            if not domain_name or domain_name == 'None':
                return self._error_response('Domain name is required', 400)
            
            cache_key = f'virustotal_report_{domain_name}'
            cached_data = cache.get(cache_key)
            
            if cached_data is not None:
                return JsonResponse({'status': 'success', 'data': cached_data})
            
            domain_obj, created = Domain.objects.get_or_create(domain_name=domain_name)
            
            recent_report = self._get_recent_report(domain_obj)
            
            if recent_report:
                return self._serialize_and_cache_response(recent_report, cache_key)
            
            new_report = self.vt_client.get_domain_report(domain_name)
            if new_report:
                return self._serialize_and_cache_response(new_report, cache_key)
            
            return self._error_response('Could not fetch domain data', 404)
        
        except DatabaseError as e:
            logger.error(f"Database error: {str(e)}")
            return self._error_response(f'Database operation failed: {str(e)}', 500)
        except (VirusTotalAPIError, VirusTotalProcessingError) as e:
            logger.error(f"VirusTotal error: {str(e)}")
            return self._error_response(f'VirusTotal operation failed: {str(e)}', 503)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return self._error_response(str(e), 500)

    def _get_recent_report(self, domain_obj):
        return DomainAnalysis.objects.filter(
            domain=domain_obj,
            last_update_date__gte=timezone.now() - timezone.timedelta(hours=24)
        ).order_by('-last_update_date').first()

    def _serialize_and_cache_response(self, report, cache_key):
        serializer = DomainAnalysisSerializer(report)
        data = serializer.data
        cache.set(cache_key, data, 86400)
        return JsonResponse({'status': 'success', 'data': data})

    def _error_response(self, message, status_code):
        return JsonResponse({
            'status': 'error',
            'message': message
        }, status=status_code)
    

class DatabaseDomainView(APIView):
    """
    API endpoint to retrieve domain data from local database
    """
    def _prepare_complete_response(self, domain, analysis):
        """
        Prepare a comprehensive response with domain and all related data.
        """
        # Serialize domain
        domain_data = DomainSerializer(domain).data
        
        # Serialize analysis
        analysis_data = DomainAnalysisSerializer(analysis).data
        
        # Serialize analysis results
        results_data = DomainAnalysisResultSerializer(
            analysis.results.all(), many=True
        ).data
        
        # Serialize DNS records
        dns_data = DomainDNSRecordSerializer(
            analysis.dns_records.all(), many=True
        ).data
        
        # Serialize certificates with their SANs
        certificates = []
        for cert in analysis.certificates.all():
            cert_data = DomainCertificateSerializer(cert).data
            sans = SubjectAlternativeNameSerializer(
                cert.sans.all(), many=True
            ).data
            cert_data['subject_alternative_names'] = sans
            certificates.append(cert_data)
        
        # Serialize categories
        categories_data = DomainCategorySerializer(
            analysis.categories.all(), many=True
        ).data
        
        # Compile complete response
        return {
            'domain': domain_data,
            'analysis': analysis_data,
            'analysis_results': results_data,
            'dns_records': dns_data,
            'certificates': certificates,
            'categories': categories_data
        }

    def get(self, request, domain_name=None):
        try:
            # Validate input
            if not domain_name:
                return Response(
                    {'status': 'error', 'message': 'Domain name is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check cache first
            cache_key = f'domain_db_data_{domain_name}'
            cached_data = cache.get(cache_key)
            
            if cached_data is not None:
                return Response({'status': 'success', 'source': 'cache', 'data': cached_data})
            
            # Try to get domain from database
            try:
                domain = Domain.objects.get(domain_name=domain_name)
            except Domain.DoesNotExist:
                return Response(
                    {'status': 'error', 'message': 'Domain not found in database'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get the latest analysis with all related data
            analysis = DomainAnalysis.objects.filter(
                domain=domain
            ).prefetch_related(
                'results',
                'dns_records',
                'certificates',
                'certificates__sans',
                'categories'
            ).order_by('-last_update_date').first()
            
            if not analysis:
                return Response(
                    {'status': 'error', 'message': 'No analysis data found for this domain'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Prepare response data
            response_data = self._prepare_complete_response(domain, analysis)
            
            # Cache the result
            cache.set(cache_key, response_data, 3600)  # Cache for 1 hour
            
            return Response({'status': 'success', 'source': 'database', 'data': response_data})
            
        except Exception as e:
            logger.error(f"Error in DatabaseDomainView: {str(e)}")
            return Response(
                {'status': 'error', 'message': f'An error occurred: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DomainFilterView(APIView):
    """
    API endpoint to filter and list domains from database
    """
    def get(self, request):
        try:
            # Get query parameters
            domain_name = request.query_params.get('domain_name')
            malicious_threshold = request.query_params.get('malicious_threshold')
            from_date = request.query_params.get('from_date')
            to_date = request.query_params.get('to_date')
            category = request.query_params.get('category')
            
            # Start with all domains
            domains = Domain.objects.all()
            
            # Apply domain name filter if provided
            if domain_name:
                domains = domains.filter(domain_name__icontains=domain_name)
            
            # Apply other filters to get domains with analysis matching criteria
            if any([malicious_threshold, from_date, to_date, category]):
                # Prepare a queryset of domain IDs that match our criteria
                analysis_query = DomainAnalysis.objects.all()
                
                if malicious_threshold:
                    threshold = int(malicious_threshold)
                    analysis_query = analysis_query.filter(malicious_count__gte=threshold)
                
                if from_date:
                    analysis_query = analysis_query.filter(last_update_date__gte=from_date)
                
                if to_date:
                    analysis_query = analysis_query.filter(last_update_date__lte=to_date)
                
                if category:
                    analysis_query = analysis_query.filter(
                        categories__category__icontains=category
                    ).distinct()
                
                # Get unique domain IDs
                domain_ids = analysis_query.values_list('domain_id', flat=True).distinct()
                domains = domains.filter(id__in=domain_ids)
            
            # Prefetch the latest analysis for each domain
            domains = domains.prefetch_related('analyses')
            
            # Serialize and return
            domain_data = []
            for domain in domains:
                domain_dict = DomainSerializer(domain).data
                
                # Get the latest analysis
                latest_analysis = domain.analyses.order_by('-last_update_date').first()
                if latest_analysis:
                    domain_dict['latest_analysis'] = DomainAnalysisSerializer(latest_analysis).data
                    
                domain_data.append(domain_dict)
            
            return Response({
                'status': 'success',
                'count': len(domain_data),
                'filters': {
                    'domain_name': domain_name,
                    'malicious_threshold': malicious_threshold,
                    'from_date': from_date,
                    'to_date': to_date,
                    'category': category
                },
                'data': domain_data
            })
            
        except ValidationError as e:
            return Response(
                {'status': 'error', 'message': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error in DomainFilterView: {str(e)}")
            return Response(
                {'status': 'error', 'message': f'An error occurred: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )