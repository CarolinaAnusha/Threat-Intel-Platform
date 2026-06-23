from typing import List, Optional
from pydantic import BaseModel, Field


class ExtractIOCRequest(BaseModel):
    content: str = Field(..., min_length=1)


class IOCResponse(BaseModel):
    type: str
    value: str
    confidence: float


class ExtractIOCResponse(BaseModel):
    total_iocs: int
    iocs: List[IOCResponse]

class RiskRequest(BaseModel):
    content: str = Field(..., min_length=1)

class AnalyzeOptions(BaseModel):
    mitre_mapping: bool = True
    generate_rules: bool = True
    risk_scoring: bool = True

class AnalyzeThreatRequest(BaseModel):
    input_type: str = "text"
    content: str = Field(..., min_length=1)
    options: Optional[AnalyzeOptions] = AnalyzeOptions()