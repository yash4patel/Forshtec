

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional,List
import models, schemas
from database import SessionLocal, engine
from fastapi import Depends, HTTPException, Query

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/get/domain/{domain_name}", response_model=schemas.DomainBase)
async def get_domain_by_name(
    domain_name: str,
    db: Session = Depends(get_db)
):
    try:
        domain = db.query(models.Domain).filter(models.Domain.domain_name == domain_name).first()
    except Exception as e:
        print("Error encountered:", e)

    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # return {'domain_name': domain.domain_name}
    return domain

@app.get("/get/ip/{ip}", response_model=schemas.IPAddressResponse)
async def get_ip(
    ip: str,
    db: Session = Depends(get_db)
):
    # print("yash")
    try:
        ip_obj = db.query(models.IPAddress).filter(models.IPAddress.ip == ip).first()
        print(ip_obj)
    except Exception as e:
        print("Error encountered:", e)

    if ip_obj is None:
        raise HTTPException(status_code=404, detail="ip not found")
    
    # return {'ip': ip_obj.ip}
    return ip_obj

@app.get("/get/file/{file_hash}", response_model=schemas.FileAnalysisBase)
async def get_file_report(
    file_hash: str,
    db: Session = Depends(get_db)
):
    """
    Retrieve a file report by its hash (SHA256/MD5) with analysis data.
    """
    try:
        print("yash")
        # Check if the file exists in the database
        file_obj = db.query(models.File).filter(
            (models.File.sha256 == file_hash) 
        ).first()

        if not file_obj:
            raise HTTPException(status_code=404, detail="File not found")

        # Fetch the latest analysis for the file
        analysis = db.query(models.FileAnalysis).filter(
            models.FileAnalysis.file_id == file_obj.id
        ).order_by(models.FileAnalysis.analysis_date.desc()).first()

        if not analysis:
            raise HTTPException(
                status_code=404, detail="No analysis data found for this file"
            )
        print(analysis)
        return analysis

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An error occurred while fetching file report: {str(e)}"
        )