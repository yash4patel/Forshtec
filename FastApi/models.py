# ---------------------------
# File: models.py
# ---------------------------
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey,JSON,Text
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


#Domain

class Domain(Base):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, index=True)
    analyses = relationship("DomainAnalysis", back_populates="domain")

class DomainAnalysis(Base):
    __tablename__ = 'domain_analyses'
    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey('domains.id'))
    creation_date = Column(DateTime)
    last_update_date = Column(DateTime)
    last_analysis_date = Column(DateTime)
    harmless_count = Column(Integer, default=0)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    undetected_count = Column(Integer, default=0)
    timeout_count = Column(Integer, default=0)
    total_count = Column(Integer, default=0)
    
    domain = relationship("Domain", back_populates="analyses")
    results = relationship("DomainAnalysisResult", back_populates="analysis")
    dns_records = relationship("DomainDNSRecord", back_populates="analysis")
    certificates = relationship("DomainCertificate", back_populates="analysis")
    categories = relationship("DomainCategory", back_populates="analysis")

class DomainAnalysisResult(Base):
    __tablename__ = 'domain_analysis_results'
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('domain_analyses.id'))
    engine_name = Column(String)
    category = Column(String)
    result = Column(String)
    method = Column(String)
    
    analysis = relationship("DomainAnalysis", back_populates="results")

class DomainDNSRecord(Base):
    __tablename__ = 'domain_dns_records'
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('domain_analyses.id'))
    record_type = Column(String)
    record_value = Column(String)
    
    analysis = relationship("DomainAnalysis", back_populates="dns_records")

class DomainCertificate(Base):
    __tablename__ = 'domain_certificates'
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('domain_analyses.id'))
    signature_algorithm = Column(String)
    certificate_date = Column(DateTime)
    
    analysis = relationship("DomainAnalysis", back_populates="certificates")
    sans = relationship("SubjectAlternativeName", back_populates="certificate")

class SubjectAlternativeName(Base):
    __tablename__ = 'subject_alternative_names'
    id = Column(Integer, primary_key=True, index=True)
    certificate_id = Column(Integer, ForeignKey('domain_certificates.id'))
    name = Column(String)
    
    certificate = relationship("DomainCertificate", back_populates="sans")

class DomainCategory(Base):
    __tablename__ = 'domain_categories'
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('domain_analyses.id'))
    category = Column(String)
    
    analysis = relationship("DomainAnalysis", back_populates="categories")

# IP
class IPAddress(Base):
    """
    Represents an IP address analyzed by VirusTotal
    """
    __tablename__ = "ip_address"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(100), unique=True, nullable=False)
    analyses = relationship("IPAnalysis", back_populates="ip",cascade="all, delete-orphan")


class IPAnalysis(Base):
    """
    Main analysis results for an IP address
    """
    __tablename__ = "ip_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_id = Column(Integer, ForeignKey("ip_address.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Network information
    as_owner = Column(String(255), nullable=True)
    asn = Column(Integer, nullable=True)
    continent = Column(String(2), nullable=True)
    country = Column(String(2), nullable=True)
    jarm = Column(String(92), nullable=True)
    network = Column(String(100), nullable=True)
    regional_internet_registry = Column(String(50), nullable=True)

    # Reputation data
    reputation = Column(Integer, default=0)

    # Analysis stats
    harmless_count = Column(Integer, default=0)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    undetected_count = Column(Integer, default=0)
    timeout_count = Column(Integer, default=0)

    # Community votes
    total_votes_harmless = Column(Integer, default=0)
    total_votes_malicious = Column(Integer, default=0)

    # Raw data storage
    tags = Column(JSON, default=list)

    # Relationships
    ip = relationship("IPAddress", back_populates="analyses")
    results = relationship("IPAnalysisResult", back_populates="analysis", cascade="all, delete-orphan")
    certificates = relationship("IPCertificate", back_populates="analysis", cascade="all, delete-orphan")


class IPAnalysisResult(Base):
    """
    Individual engine results from an IP analysis
    """
    __tablename__ = "ip_analysis_result"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("ip_analysis.id", ondelete="CASCADE"), nullable=False)
    engine_name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=True)
    result = Column(String(255), nullable=True)
    method = Column(String(50), nullable=True)

    analysis = relationship("IPAnalysis", back_populates="results")



class IPCertificate(Base):
    """
    SSL/TLS certificates associated with an IP address
    """
    __tablename__ = "ip_certificate"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("ip_analysis.id", ondelete="CASCADE"), nullable=False)
    certificate_data = Column(JSON, nullable=False)  # Stores the complete certificate object

    # Common fields for easy access
    thumbprint = Column(String(64), nullable=True)
    thumbprint_sha256 = Column(String(64), nullable=True)
    serial_number = Column(String(100), nullable=True)
    issuer = Column(JSON, nullable=True)
    subject = Column(JSON, nullable=True)
    validity_not_before = Column(DateTime, nullable=True)
    validity_not_after = Column(DateTime, nullable=True)
    version = Column(String(10), nullable=True)
    signature_algorithm = Column(String(50), nullable=True)
    size = Column(Integer, nullable=True)

    analysis = relationship("IPAnalysis", back_populates="certificates")

class File(Base):
    """Represents a file analyzed by VirusTotal"""
    __tablename__ = 'file'

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String, unique=True, index=True)
    meaningful_name = Column(String, nullable=True)

    analyses = relationship("FileAnalysis", back_populates="file")

    def __repr__(self):
        return f"<File(id={self.id}, sha256={self.sha256[:10]}...)>"

class FileAnalysis(Base):
    """Analysis results for a specific file"""
    __tablename__ = 'file_analysis'

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey('file.id'))
    analysis_date = Column(DateTime)
    first_submission_date = Column(DateTime, nullable=True)
    last_analysis_date = Column(DateTime, nullable=True)
    last_submission_date = Column(DateTime, nullable=True)
    times_submitted = Column(Integer, nullable=True)
    reputation = Column(Integer, nullable=True)
    harmless_count = Column(Integer, nullable=True)
    malicious_count = Column(Integer, nullable=True)
    suspicious_count = Column(Integer, nullable=True)
    undetected_count = Column(Integer, nullable=True)
    timeout_count = Column(Integer, nullable=True)
    total_votes_harmless = Column(Integer, nullable=True)
    total_votes_malicious = Column(Integer, nullable=True)

    file = relationship("File", back_populates="analyses")
    results = relationship("FileAnalysisResult", back_populates="analysis")
    sigma_analyses = relationship("FileSigmaAnalysis", back_populates="analysis")

    def __repr__(self):
        return f"<FileAnalysis(id={self.id}, file_id={self.file_id})>"

class FileAnalysisResult(Base):
    """Individual engine results for a file analysis"""
    __tablename__ = 'file_analysis_result'

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('file_analysis.id'))
    engine_name = Column(String)
    category = Column(String, nullable=True)
    result = Column(String, nullable=True)
    engine_version = Column(String, nullable=True)
    engine_update = Column(String, nullable=True)

    analysis = relationship("FileAnalysis", back_populates="results")

    def __repr__(self):
        return f"<FileAnalysisResult(id={self.id}, engine={self.engine_name})>"

class FileSigmaAnalysis(Base):
    """Sigma rule analysis results for files"""
    __tablename__ = 'file_sigma_analysis'

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey('file_analysis.id'))
    rule_id = Column(String, nullable=True)
    rule_title = Column(String, nullable=True)
    rule_description = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    source = Column(String, nullable=True)

    analysis = relationship("FileAnalysis", back_populates="sigma_analyses")

    def __repr__(self):
        return f"<FileSigmaAnalysis(id={self.id}, rule={self.rule_title})>"