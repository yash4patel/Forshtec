from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from .serializers import FileAnalysisSerializer,FileSerializer,FileAnalysisResultSerializer,FileSigmaAnalysisSerializer
from .api_integration import VirusTotalAPI
from .models import File,FileAnalysis
from django.conf import settings
from django.db import models


# Initialize VirusTotal API client
vt_api = VirusTotalAPI(settings.VIRUSTOTAL_API_KEY)

class FileUploadAnalysisView(APIView):
    """
    API endpoint for uploading files to VirusTotal for analysis
    """
    
    def post(self, request, format=None):
        # Check if file was provided in the request
        if 'file' not in request.FILES:
            return Response(
                {'error': 'No file provided'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        print(uploaded_file)
        
        try:
            # Step 1: Save file temporarily
            temp_path = default_storage.save(f'tmp/{uploaded_file.name}', ContentFile(uploaded_file.read()))
            # print(temp_path)
            # Step 2: Submit to VirusTotal
            vt_response = vt_api.submit_file(temp_path, uploaded_file.name)
            # print(vt_response)
            if vt_response.status_code != 200:
                return Response(
                    {'error': 'VirusTotal API error', 'details': vt_response.text},
                    status=status.HTTP_502_BAD_GATEWAY
                )
            
            analysis_data = vt_response.json()
            # print(analysis_data)
            file_id = analysis_data['data']['id']
            
            # Step 3: Get analysis report
            report = vt_api.get_analysis_report(file_id)
            # print(report)
            
            # Step 4: Save to database
            analysis = vt_api.save_analysis_results(file_id, report, uploaded_file.name)
            
            # Clean up temporary file
            default_storage.delete(temp_path)
            
            # Return serialized response
            serializer = FileAnalysisSerializer(analysis)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print(e)



class DatabaseFileView(APIView):
    """
    API endpoint to retrieve file analysis data from local database
    """
    def _prepare_complete_response(self, file_obj, analysis):
        """
        Prepare a comprehensive response with file and all related data.
        """
        # Serialize file
        file_data = FileSerializer(file_obj).data
        
        # Serialize analysis
        analysis_data = FileAnalysisSerializer(analysis).data
        
        # Serialize analysis results
        results_data = FileAnalysisResultSerializer(
            analysis.results.all(), many=True
        ).data
        
        # Serialize sigma analysis results
        sigma_data = FileSigmaAnalysisSerializer(
            analysis.sigma_analyses.all(), many=True
        ).data
        
        # Compile complete response
        return {
            'file': file_data,
            'analysis': analysis_data,
            'analysis_results': results_data,
            'sigma_analysis': sigma_data
        }

    def get(self, request, file_hash=None):
        try:
            # Validate input
            if not file_hash:
                return Response(
                    {'status': 'error', 'message': 'File hash (SHA256 or MD5) is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check cache first
            cache_key = f'file_db_data_{file_hash}'
            cached_data = cache.get(cache_key)
            
            if cached_data is not None:
                return Response({
                    'status': 'success', 
                    'source': 'cache', 
                    'data': cached_data
                })
            
            # Try to get file from database (check both SHA256 and MD5)
            try:
                file_obj = File.objects.get(
                    models.Q(sha256=file_hash) | models.Q(md5=file_hash)
                )
            except File.DoesNotExist:
                return Response(
                    {'status': 'error', 'message': 'File not found in database'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            except File.MultipleObjectsReturned:
                # Handle case where same hash exists in both fields
                file_obj = File.objects.filter(
                    models.Q(sha256=file_hash) | models.Q(md5=file_hash)
                ).first()
            
            # Get the latest analysis with all related data
            analysis = FileAnalysis.objects.filter(
                file=file_obj
            ).prefetch_related(
                'results',         
                'sigma_analyses' 
            ).order_by('-analysis_date').first()
            
            if not analysis:
                return Response(
                    {'status': 'error', 'message': 'No analysis data found for this file'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Prepare response data
            response_data = self._prepare_complete_response(file_obj, analysis)
            
            # Cache the result
            cache.set(cache_key, response_data, 3600)  # Cache for 1 hour
            
            return Response({
                'status': 'success', 
                'source': 'database', 
                'data': response_data
            })
            
        except Exception as e:
            return Response(
                {'status': 'error', 'message': f'An error occurred: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )