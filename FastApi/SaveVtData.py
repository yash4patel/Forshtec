import models, schemas
from sqlalchemy.orm import Session
from datetime import datetime, timedelta


async def save_vt_data_to_db_domain(vt_data: dict, domain_name: str, db: Session):
    try:
        domain = db.query(models.Domain).filter(
            models.Domain.domain_name == domain_name
        ).first()
        
        if not domain:
            domain = models.Domain(domain_name=domain_name)
            db.add(domain)
            db.commit()
            db.refresh(domain)

        attrs = vt_data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        analysis = models.DomainAnalysis(
            domain_id=domain.id,
            creation_date=datetime.fromtimestamp(attrs.get('creation_date', 0)) if attrs.get('creation_date') else None,
            last_update_date=datetime.fromtimestamp(attrs.get('last_modification_date', 0)) if attrs.get('last_modification_date') else None,
            last_analysis_date=datetime.fromtimestamp(attrs.get('last_analysis_date', 0)) if attrs.get('last_analysis_date') else None,
            harmless_count=stats.get('harmless', 0),
            malicious_count=stats.get('malicious', 0),
            suspicious_count=stats.get('suspicious', 0),
            undetected_count=stats.get('undetected', 0),
            timeout_count=stats.get('timeout', 0),
            total_count=sum(stats.values()) if stats else 0
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        # Save related data
        for engine_name, result in attrs.get('last_analysis_results', {}).items():
            db.add(models.DomainAnalysisResult(
                analysis_id=analysis.id,
                engine_name=engine_name,
                category=result.get('category'),
                result=result.get('result'),
                method=result.get('method')
            ))

        for record in attrs.get('last_dns_records', []):
            db.add(models.DomainDNSRecord(
                analysis_id=analysis.id,
                record_type=record.get('type'),
                record_value=record.get('value')
            ))

        cert_data = attrs.get('last_https_certificate')
        cert_date = attrs.get('last_https_certificate_date')
        if cert_data:
            cert = models.DomainCertificate(
                analysis_id=analysis.id,
                signature_algorithm=cert_data.get('cert_signature', {}).get('signature_algorithm'),
                certificate_date=datetime.fromtimestamp(cert_date) if cert_date else None
            )
            db.add(cert)
            db.commit()
            db.refresh(cert)

            for san in cert_data.get('extensions', {}).get('subject_alternative_name', []):
                db.add(models.SubjectAlternativeName(
                    certificate_id=cert.id,
                    name=san
                ))

        for source, category in attrs.get('categories', {}).items():
            db.add(models.DomainCategory(
                analysis_id=analysis.id,
                category=category
            ))

        db.commit()
        return analysis

    except Exception as e:
        db.rollback()



async def save_vt_data_to_db_ip(vt_data: dict, ip: str, db: Session):
    try:
        # Extract main data attributes
        attributes = vt_data.get('data', {}).get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        results = attributes.get('last_analysis_results', {})
        certificates = attributes.get('certificates', [])
        network_info = attributes.get('network')

        # Create or update IP Address
        ip_obj = db.query(models.IPAddress).filter_by(ip=ip).first()
        if not ip_obj:
            ip_obj = models.IPAddress(ip=ip)
            db.add(ip_obj)
            db.commit()

        # Create IP Analysis
        analysis = models.IPAnalysis(
            ip_id=ip_obj.id,
            created_at=datetime.utcnow(),
            as_owner=attributes.get('as_owner'),
            asn=attributes.get('asn'),
            continent=attributes.get('continent'),
            country=attributes.get('country'),
            jarm=attributes.get('jarm'),
            network=network_info,
            regional_internet_registry=attributes.get('regional_internet_registry'),
            reputation=attributes.get('reputation', 0),
            harmless_count=analysis_stats.get('harmless', 0),
            malicious_count=analysis_stats.get('malicious', 0),
            suspicious_count=analysis_stats.get('suspicious', 0),
            undetected_count=analysis_stats.get('undetected', 0),
            timeout_count=analysis_stats.get('timeout', 0),
            total_votes_harmless=attributes.get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=attributes.get('total_votes', {}).get('malicious', 0),
            tags=attributes.get('tags', [])
        )
        db.add(analysis)
        db.commit()

        # Add analysis results
        for engine_name, result in results.items():
            db.add(models.IPAnalysisResult(
                analysis_id=analysis.id,
                engine_name=engine_name,
                category=result.get('category'),
                result=result.get('result'),
                method=result.get('method')
            ))

        # Add certificates
        for cert in certificates:
            cert_attributes = cert.get('attributes', {})
            db_cert = models.IPCertificate(
                analysis_id=analysis.id,
                certificate_data=cert,
                thumbprint=cert_attributes.get('thumbprint'),
                thumbprint_sha256=cert_attributes.get('thumbprint_sha256'),
                serial_number=cert_attributes.get('serial_number'),
                issuer=cert_attributes.get('issuer'),
                subject=cert_attributes.get('subject'),
                validity_not_before=datetime.utcfromtimestamp(cert_attributes.get('validity_not_before', 0)),
                validity_not_after=datetime.utcfromtimestamp(cert_attributes.get('validity_not_after', 0)),
                version=cert_attributes.get('version'),
                signature_algorithm=cert_attributes.get('signature_algorithm'),
                size=cert_attributes.get('size')
            )
            db.add(db_cert)
            db.commit()

            # Add Subject Alternative Names
            sans = cert_attributes.get('subject_alternative_name', [])
            for san in sans:
                db.add(models.SubjectAlternativeName(
                    certificate_id=db_cert.id,
                    name=san
                ))

        db.commit()
        return ip_obj

    except Exception as e:
        db.rollback()
        raise

def save_vt_data_to_db_file(vt_data: dict, file_id: str, filename: str, db: Session):
    """
    Save VirusTotal file analysis data into the database.
    Handles duplicate file entries and includes proper error handling.
    """
    # try:
    # print(vt_data)
    attributes = vt_data.get('data', {}).get('attributes', {})
    analysis_stats = attributes.get('stats', {})
    results = attributes.get('results', {})
    sigma_results = attributes.get('sigma_analysis_results', [])

    # Check if file already exists
    file_record = db.query(models.File).filter_by(sha256=file_id).first()
    
    if not file_record:
        # Create new file record if it doesn't exist
        file_record = models.File(
            sha256=file_id,
            meaningful_name=filename,
            
        )
        # print(file_record)
        db.add(file_record)
        db.commit()
        db.refresh(file_record)
    else:
        # Update existing file record if needed
        if file_record.meaningful_name != filename:
            file_record.meaningful_name = filename
            db.commit()
            db.refresh(file_record)

    # Create FileAnalysis record
    analysis = models.FileAnalysis(
        file_id=file_record.id,
        analysis_date=datetime.now(),
        first_submission_date=datetime.fromtimestamp(attributes.get('first_submission_date')) if attributes.get('first_submission_date') else None,
        last_analysis_date=datetime.fromtimestamp(attributes.get('last_analysis_date')) if attributes.get('last_analysis_date') else None,
        last_submission_date=datetime.fromtimestamp(attributes.get('last_submission_date')) if attributes.get('last_submission_date') else None,
        times_submitted=attributes.get('times_submitted'),
        reputation=attributes.get('reputation'),
        harmless_count=analysis_stats.get('harmless', 0),
        malicious_count=analysis_stats.get('malicious', 0),
        suspicious_count=analysis_stats.get('suspicious', 0),
        undetected_count=analysis_stats.get('undetected', 0),
        timeout_count=analysis_stats.get('timeout', 0),
        total_votes_harmless=attributes.get('total_votes', {}).get('harmless', 0),
        total_votes_malicious=attributes.get('total_votes', {}).get('malicious', 0)
    )
    # print(analysis)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # Save engine results
    for engine_name, result in results.items():
        db.add(models.FileAnalysisResult(
            analysis_id=analysis.id,
            engine_name=engine_name,
            category=result.get('category'),
            result=result.get('result'),
            engine_version=result.get('engine_version'),
            engine_update=result.get('engine_update'),
            # method=result.get('method')
        ))

    # Save sigma analysis results
    for sigma_result in sigma_results:
        db.add(models.FileSigmaAnalysis(
            analysis_id=analysis.id,
            rule_id=sigma_result.get('rule_id'),
            rule_title=sigma_result.get('rule_title'),
            rule_description=sigma_result.get('rule_description'),
            severity=sigma_result.get('rule_level'),
            source=sigma_result.get('rule_source')
        ))

    # Save file tags if they exist in the model
    if hasattr(models, 'FileTag'):
        for tag in attributes.get('tags', []):
            db.add(models.FileTag(
                analysis_id=analysis.id,
                tag=tag
            ))

    db.commit()
    print(file_record)
    return file_record

    # except Exception as e:
        # db.rollback()
        