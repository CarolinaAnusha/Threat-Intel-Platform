from fastapi import APIRouter
import json

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
from app.agents.mitre_mapper import MITREMapper
from fastapi import Depends
from sqlalchemy.orm import Session
from app.models.database import SessionLocal
from app.models.analysis import Analysis
from app.services.graph_builder import GraphBuilder

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter(prefix="/api", tags=["Analysis"])

extractor = IOCExtractor()
enrichment_service = EnrichmentService()
risk_scorer = RiskScorer()
report_writer = ReportWriter()
detection_engineer = DetectionEngineer()
mitre_mapper = MITREMapper()
graph_builder = GraphBuilder()

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
async def analyze_threat(request: AnalyzeThreatRequest, db: Session = Depends(get_db)):
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
    mitre_mapping = mitre_mapper.map(request.content)
    relationship_graph = graph_builder.build(
    iocs,
    {"cves": enriched_cves}
    )
    analysis_id = "TI-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")

    response = {
        "analysis_id": analysis_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_type": request.input_type,
        "iocs": iocs,
        "enrichment": {
        "cves": enriched_cves
        },
        "mitre_mapping": mitre_mapping,
        "relationship_graph": relationship_graph,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_factors": risk["risk_factors"],
        "ai_report": ai_report,
        "detection_rules": detection_rules
    }

    analysis_record = Analysis(
        analysis_id=analysis_id,
        input_type=request.input_type,
        content=request.content,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        created_at=response["timestamp"],
        full_result=json.dumps(response)
    )

    db.add(analysis_record)
    db.commit()

    return response

@router.get("/analyses")
async def get_analyses(db: Session = Depends(get_db)):
    records = db.query(Analysis).order_by(Analysis.id.desc()).all()

    return {
        "total": len(records),
        "analyses": [
            {
                "analysis_id": item.analysis_id,
                "input_type": item.input_type,
                "input_preview": item.content[:80],
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "created_at": item.created_at
            }
            for item in records
        ]
    }


@router.get("/analyses/{analysis_id}")
async def get_analysis_by_id(analysis_id: str, db: Session = Depends(get_db)):
    item = db.query(Analysis).filter(Analysis.analysis_id == analysis_id).first()

    if not item:
        return {
            "error": "Analysis not found"
        }

    if item.full_result:
        return json.loads(item.full_result)

    return {
        "analysis_id": item.analysis_id,
        "input_type": item.input_type,
        "content": item.content,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "created_at": item.created_at
    }
