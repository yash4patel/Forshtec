from rest_framework import serializers
# from Domain.models import VirusTotal,VirusTotalAnalysis,VirusTotalAnalysisResult,VirusTotalCategory,VirusTotalCertificate,VirusTotalDNSRecord
from .models import DomainCategory,Domain,DomainAnalysis,DomainAnalysisResult,DomainCertificate,DomainDNSRecord,SubjectAlternativeName
class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = '__all__'
class DomainAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainAnalysis
        fields = '__all__'

class DomainAnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainAnalysisResult
        fields = '__all__'

class DomainDNSRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainDNSRecord
        fields = '__all__'

class DomainCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainCertificate
        fields = '__all__'

class DomainCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainCategory
        fields = '__all__'


class SubjectAlternativeNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubjectAlternativeName
        fields = '__all__'