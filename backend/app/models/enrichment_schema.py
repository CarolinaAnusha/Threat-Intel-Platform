from typing import List, Optional

from pydantic import BaseModel


class CVEEnrichmentResponse(BaseModel):
    id: str
    cvss: float
    severity: str
    description: str
    exploit_available: bool
    malware_families: List[str]
    threat_actors: List[str]


class EnrichmentResponse(BaseModel):
    data: Optional[CVEEnrichmentResponse]