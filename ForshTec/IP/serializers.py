from rest_framework import serializers
from .models import IPAddress, IPAnalysis, IPAnalysisResult, IPCertificate

class IPAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPAddress
        fields = '__all__'

class IPAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPAnalysis
        fields = '__all__'

class IPAnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPAnalysisResult
        fields = '__all__'

class IPCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPCertificate
        fields = '__all__'
