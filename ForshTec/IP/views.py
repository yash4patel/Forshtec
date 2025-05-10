from django.core.cache import cache
from django.utils import timezone
from django.db import DatabaseError
from requests.exceptions import RequestException
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import IPAddress, IPAnalysis
from .api_integration import VirusTotalIPClient
from .serializers import IPAnalysisSerializer,IPAddressSerializer,IPAnalysisResultSerializer,IPCertificateSerializer

class IPAddressView(APIView):
    """
    Single endpoint for IP address analysis with caching
    """
    def get(self, request, ip_address):
        try:
            if not ip_address:
                return Response(
                    {'error': 'IP address is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            cache_key = f'virustotal_ip_report_{ip_address}'
            cached_data = cache.get(cache_key)
            
            if cached_data is not None:
                return Response({
                    'status': 'success',
                    'source': 'cache',
                    'data': cached_data
                })
            
            ip_obj, created = IPAddress.objects.get_or_create(ip=ip_address)
            
            # Check for recent analysis (within 24 hours)
            recent_analysis = IPAnalysis.objects.filter(
                ip=ip_obj,
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).order_by('-created_at').first()
            
            if recent_analysis:
                serializer = IPAnalysisSerializer(recent_analysis)
                data = serializer.data
                cache.set(cache_key, data, 86400)  # Cache for 24 hours
                return Response({
                    'status': 'success',
                    'source': 'database',
                    'data': data
                })
            
            # Fetch new data from VirusTotal
            client = VirusTotalIPClient()
            analysis = client.save_ip_data(ip_address)
            
            if not analysis:
                return Response(
                    {'error': 'Failed to fetch IP data from VirusTotal'},
                    status=status.HTTP_502_BAD_GATEWAY
                )
            
            serializer = IPAnalysisSerializer(analysis)
            data = serializer.data
            cache.set(cache_key, data, 86400)
            
            return Response({
                'status': 'success',
                'source': 'virustotal',
                'data': data
            })
            
        except DatabaseError as e:
            return Response(
                {'error': 'Database operation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except RequestException as e:
            return Response(
                {'error': 'VirusTotal API connection failed'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
  
class IPAddressDBView(APIView):
    
    def _prepare_response_data(self, ip_obj, analysis):
        """Prepare complete response data with all related objects"""
        # Serialize IP address
        ip_data = IPAddressSerializer(ip_obj).data
        
        # Serialize analysis
        analysis_data = IPAnalysisSerializer(analysis).data
        
        # Serialize all engine results
        results_data = IPAnalysisResultSerializer(
            analysis.results.all(), many=True
        ).data
        
        # Serialize all certificates
        certificates_data = IPCertificateSerializer(
            analysis.certificates.all(), many=True
        ).data
        
        return {
            'ip_address': ip_data,
            'analysis': analysis_data,
            'engine_results': results_data,
            'certificates': certificates_data
        }

    def get(self, request, ip_address):
        try:
            if not ip_address:
                return Response(
                    {'status': 'error', 'message': 'IP address is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check cache first
            cache_key = f'ip_db_full_{ip_address}'
            cached_data = cache.get(cache_key)
            
            if cached_data:
                return Response({
                    'status': 'success',
                    'source': 'cache',
                    'data': cached_data
                })
            
            # Get IP object or return 404
            ip_obj = get_object_or_404(IPAddress, ip=ip_address)
            
            # Get the latest analysis with all related data
            analysis = IPAnalysis.objects.filter(
                ip=ip_obj
            ).prefetch_related(
                'results',
                'certificates'
            ).order_by('-created_at').first()
            
            if not analysis:
                return Response(
                    {'status': 'error', 'message': 'No analysis found for this IP'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Prepare complete response
            response_data = self._prepare_response_data(ip_obj, analysis)
            
            # Cache for 1 hour
            cache.set(cache_key, response_data, 3600)
            
            return Response({
                'status': 'success',
                'source': 'database',
                'data': response_data
            })
            
        except Exception as e:
            return Response(
                {'status': 'error', 'message': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )