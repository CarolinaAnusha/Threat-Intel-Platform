from fastapi import APIRouter, UploadFile, File

from app.models.schemas import AnalyzeThreatRequest
from app.routers.analyze import analyze_threat
from app.models.database import SessionLocal
from app.services.file_parser import FileParser

router = APIRouter(prefix="/api", tags=["Upload"])

parser = FileParser()


@router.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = parser.parse(file)

    request = AnalyzeThreatRequest(
        input_type="file",
        content=content,
        options={
            "mitre_mapping": True,
            "generate_rules": True,
            "risk_scoring": True
        }
    )

    db = SessionLocal()

    try:
        result = await analyze_threat(request, db)
        result["filename"] = file.filename
        return result
    finally:
        db.close()