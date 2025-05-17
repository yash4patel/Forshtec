from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File as FastAPIFile
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse,JSONResponse
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import shutil
import os
import uuid
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from database import SessionLocal, engine
import models, schemas
from vt_client import VirusTotalClient
from SaveVtData import save_vt_data_to_db_domain, save_vt_data_to_db_ip, save_vt_data_to_db_file

# Load environment variables
load_dotenv()

# Create uploads directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize FastAPI and Jinja2 templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Rate limit exceeded handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests. Please try again later."},
    )
# Create DB tables
models.Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get VT client
def get_vt_client():
    return VirusTotalClient(api_key=os.getenv('API_KEY'))

# ------------------------------------
# GET: Domain Analysis
# ------------------------------------
@app.get("/domain/{domain_name}", response_model=schemas.DomainAnalysisBase)
@limiter.limit("4/minute")
@limiter.limit("500/day")
async def get_domain(
    domain_name: str,
    request: Request,
    db: Session = Depends(get_db),
    vt_client: VirusTotalClient = Depends(get_vt_client)
):
    try:
        vt_data = await vt_client.get_domain_report(domain_name)
        analysis = await save_vt_data_to_db_domain(vt_data, domain_name, db)
        # print(analysis.domain_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="No analysis available")

        return analysis

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ------------------------------------
# GET: IP Analysis
# ------------------------------------
@app.get("/ip/{ip}", response_model=schemas.IPAddressBase)
@limiter.limit("4/minute")
@limiter.limit("500/day")
async def get_ip(
    ip: str,
    request:Request,
    db: Session = Depends(get_db),
    vt_client: VirusTotalClient = Depends(get_vt_client)
):
    try:
        vt_data = await vt_client.get_ip_report(ip)
        ip_obj = await save_vt_data_to_db_ip(vt_data, ip, db)

        if not ip_obj:
            raise HTTPException(status_code=404, detail="No analysis available")

        # return {"ip": ip_obj.ip}
        return ip_obj

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ------------------------------------
# GET: HTML Upload Form
# ------------------------------------
@app.get("/file/upload", response_class=HTMLResponse)
@limiter.limit("4/minute")
@limiter.limit("500/day")
def upload_form(request: Request):
    return templates.TemplateResponse("upload_file.html", {"request": request})

# ------------------------------------
# POST: Upload File and Submit to VT
# ------------------------------------
@app.post("/file/file-id/")
@limiter.limit("4/minute")
@limiter.limit("500/day")
async def handle_file_upload(
    request:Request,
    file: UploadFile = FastAPIFile(...),
    vt_client: VirusTotalClient = Depends(get_vt_client),
    db: Session = Depends(get_db)
):
    try:
        # Save uploaded file to disk
        filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Submit file to VirusTotal
        response = await vt_client.submit_file(file_path, file.filename)
        file_id = response["data"]["id"]

        # Poll and get analysis report from VT
        analysis_result = await vt_client.get_file_report(file_id)
        
        # Save analysis result to DB
        saved_file = save_vt_data_to_db_file(analysis_result,file_id, file.filename, db)
        # print(saved_file)
        if not saved_file:
            raise HTTPException(status_code=500, detail="Failed to save analysis result")

        return {
            "file_id": file_id,
            "message": "File submitted and analysis saved",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))