from fastapi import APIRouter

from app.models.schemas import ExtractIOCRequest, ExtractIOCResponse
from app.services.ioc_extractor import IOCExtractor
from app.services.enrichment import EnrichmentService
from app.models.enrichment_schema import EnrichmentResponse
from app.models.schemas import RiskRequest
from app.services.risk_scorer import RiskScorer
from datetime import datetime
from app.models.schemas import AnalyzeThreatRequest
from app.agents.report_writer import ReportWriter
from app.agents.detection_engineer import DetectionEngineer

router = APIRouter(prefix="/api", tags=["Analysis"])

extractor = IOCExtractor()
enrichment_service = EnrichmentService()
risk_scorer = RiskScorer()
report_writer = ReportWriter()
detection_engineer = DetectionEngineer()

@router.post("/extract-iocs", response_model=ExtractIOCResponse)
async def extract_iocs(request: ExtractIOCRequest):
    iocs = extractor.extract(request.content)

    return {
        "total_iocs": len(iocs),
        "iocs": iocs,
    }

@router.get(
    "/enrich/{cve_id}",
    response_model=EnrichmentResponse
)
async def enrich_cve(cve_id: str):

    result = enrichment_service.enrich_cve(cve_id)

    return {
        "data": result
    }

@router.post("/risk")
async def calculate_risk(request: RiskRequest):
    iocs = extractor.extract(request.content)

    enriched_cves = []

    for ioc in iocs:
        if ioc["type"] == "cve":
            enriched = enrichment_service.enrich_cve(ioc["value"])
            if enriched:
                enriched_cves.append(enriched)

    risk = risk_scorer.calculate(enriched_cves, iocs)

    return {
        "iocs": iocs,
        "enrichment": enriched_cves,
        "risk": risk
    }

@router.post("/analyze")
async def analyze_threat(request: AnalyzeThreatRequest):
    iocs = extractor.extract(request.content)

    enriched_cves = []

    for ioc in iocs:
        if ioc["type"] == "cve":
            enriched = enrichment_service.enrich_cve(ioc["value"])
            if enriched:
                enriched_cves.append(enriched)

    risk = risk_scorer.calculate(enriched_cves, iocs)
    ai_report = report_writer.generate(
    request.content,
    iocs,
    {"cves": enriched_cves},
    risk
    )
    detection_rules = detection_engineer.generate(
    iocs,
    risk["risk_level"]
    )
    analysis_id = "TI-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")

    return {
        "analysis_id": analysis_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_type": request.input_type,
        "iocs": iocs,
        "enrichment": {
            "cves": enriched_cves
        },
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_factors": risk["risk_factors"],
        "ai_report": ai_report,
        "detection_rules": detection_rules
    }