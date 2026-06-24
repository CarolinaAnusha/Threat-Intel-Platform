from fastapi import APIRouter
from fastapi import UploadFile
from fastapi import File

from app.services.file_parser import FileParser
from app.services.ioc_extractor import IOCExtractor

router = APIRouter(
    prefix="/api",
    tags=["Upload"]
)

parser = FileParser()
extractor = IOCExtractor()


@router.post("/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...)
):

    content = parser.parse(file)

    iocs = extractor.extract(content)

    return {
        "filename": file.filename,
        "content_length": len(content),
        "iocs": iocs
    }