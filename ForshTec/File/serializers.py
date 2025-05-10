from rest_framework import serializers
from .models import File, FileAnalysis, FileAnalysisResult, FileSigmaAnalysis

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = '__all__'

class FileAnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileAnalysisResult
        fields = '__all__'


class FileSigmaAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileSigmaAnalysis
        fields = '__all__'


class FileAnalysisSerializer(serializers.ModelSerializer):
    results = FileAnalysisResultSerializer(many=True, read_only=True)
    sigma_analyses = FileSigmaAnalysisSerializer(many=True, read_only=True)

    class Meta:
        model = FileAnalysis
        fields = '__all__'


class DetailSerializer(serializers.ModelSerializer):
    analyses = FileAnalysisSerializer(many=True, read_only=True)

    class Meta:
        model = File
        fields = '__all__'
