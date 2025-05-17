from pydantic import BaseModel,Field
from typing import List, Optional,Dict,Any
from datetime import datetime

class SubjectAlternativeNameBase(BaseModel):
    id: int
    certificate_id: int
    name: str

    class Config:
        orm_mode = True

class DomainCertificateBase(BaseModel):
    id: int
    analysis_id: int
    signature_algorithm: Optional[str] = None
    certificate_date: Optional[datetime] = None
    sans: List[SubjectAlternativeNameBase] = []

    class Config:
        orm_mode = True

class DomainDNSRecordBase(BaseModel):
    id: int
    analysis_id: int
    record_type: Optional[str] = None
    record_value: Optional[str] = None

    class Config:
        orm_mode = True

class DomainAnalysisResultBase(BaseModel):
    id: int
    analysis_id: int
    engine_name: Optional[str] = None
    category: Optional[str] = None
    result: Optional[str] = None
    method: Optional[str] = None

    class Config:
        orm_mode = True

class DomainCategoryBase(BaseModel):
    id: int
    analysis_id: int
    category: Optional[str] = None

    class Config:
        orm_mode = True

class DomainAnalysisBase(BaseModel):
    id: int
    domain_id: int
    creation_date: Optional[datetime] = None
    last_update_date: Optional[datetime] = None
    last_analysis_date: Optional[datetime] = None
    harmless_count: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    timeout_count: int = 0
    total_count: int = 0

    results: List[DomainAnalysisResultBase] = []
    dns_records: List[DomainDNSRecordBase] = []
    certificates: List[DomainCertificateBase] = []
    categories: List[DomainCategoryBase] = []

    class Config:
        orm_mode = True

class DomainBase(BaseModel):
    id: int
    domain_name: str
    analyses: List[DomainAnalysisBase] = []

    class Config:
        orm_mode = True


class DomainIdResponse(BaseModel):
    id: int

class DomainNameResponse(BaseModel):
    domain_name: str



# ======================
# IP Address Models
# ======================

class IPAnalysisResultBase(BaseModel):
    id: int
    analysis_id: int 
    engine_name: str
    category: Optional[str] = None
    result: Optional[str] = None
    method: Optional[str] = None

    class Config:
        orm_mode = True

class IPCertificateBase(BaseModel):
    id: int
    analysis_id: int 
    certificate_data: Dict[str, Any]
    thumbprint: Optional[str] = None
    thumbprint_sha256: Optional[str] = None
    serial_number: Optional[str] = None
    issuer: Optional[Dict[str, Any]] = None
    subject: Optional[Dict[str, Any]] = None
    validity_not_before: Optional[datetime] = None
    validity_not_after: Optional[datetime] = None
    version: Optional[str] = None
    signature_algorithm: Optional[str] = None
    size: Optional[int] = None

    class Config:
        orm_mode = True

class IPAnalysisBase(BaseModel):
    id: int
    ip_id: int
    created_at: datetime
    as_owner: Optional[str] = None
    asn: Optional[int] = None
    continent: Optional[str] = None
    country: Optional[str] = None
    jarm: Optional[str] = None
    network: Optional[str] = None
    regional_internet_registry: Optional[str] = None
    reputation: int = 0
    harmless_count: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    timeout_count: int = 0
    total_votes_harmless: int = 0
    total_votes_malicious: int = 0
    tags: List[str] = []

    # Relationships
    results: List[IPAnalysisResultBase] = []
    certificates: List[IPCertificateBase] = []

    class Config:
        orm_mode = True

class IPAddressBase(BaseModel):
    id: int
    ip: str
    analyses: List[IPAnalysisBase] = []

    class Config:
        orm_mode = True

class IPAddressResponse(IPAddressBase):
    id: int
    ip: str
    analyses: List[IPAnalysisBase] = []  # Now includes full nested structure

    class Config:
        from_attributes = True
# ======================
# Combined Response Models
# ======================

class FullDomainResponse(DomainNameResponse):
    analyses: List[DomainAnalysisBase]

class IP(BaseModel):
    ip: str 


# ===========================
# File
# ============================

# Base Models
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

class FileBase(BaseModel):
    sha256: str
    meaningful_name: Optional[str] = None

class FileCreate(FileBase):
    pass

class File(FileBase):
    id: int
    
    class Config:
        from_attributes = True

class FileAnalysisBase(BaseModel):
    analysis_date: datetime
    first_submission_date: Optional[datetime] = None
    last_analysis_date: Optional[datetime] = None
    last_submission_date: Optional[datetime] = None
    times_submitted: Optional[int] = None
    reputation: Optional[int] = None
    harmless_count: Optional[int] = None
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    undetected_count: Optional[int] = None
    timeout_count: Optional[int] = None
    total_votes_harmless: Optional[int] = None
    total_votes_malicious: Optional[int] = None

class FileAnalysisCreate(FileAnalysisBase):
    file_id: int

class FileAnalysis(FileAnalysisBase):
    id: int
    file: File
    
    class Config:
        from_attributes = True

class FileAnalysisResultBase(BaseModel):
    engine_name: str
    category: Optional[str] = None
    result: Optional[str] = None
    engine_version: Optional[str] = None
    engine_update: Optional[str] = None

class FileAnalysisResultCreate(FileAnalysisResultBase):
    analysis_id: int

class FileAnalysisResult(FileAnalysisResultBase):
    id: int
    
    class Config:
        from_attributes = True

class FileSigmaAnalysisBase(BaseModel):
    rule_id: Optional[str] = None
    rule_title: Optional[str] = None
    rule_description: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None

class FileSigmaAnalysisCreate(FileSigmaAnalysisBase):
    analysis_id: int

class FileSigmaAnalysis(FileSigmaAnalysisBase):
    id: int
    
    class Config:
        from_attributes = True

# Response models for API endpoints
class FileAnalysisResponse(FileAnalysis):
    results: List[FileAnalysisResult] = []
    sigma_analyses: List[FileSigmaAnalysis] = []

class FileWithAnalyses(File):
    analyses: List[FileAnalysisResponse] = []


