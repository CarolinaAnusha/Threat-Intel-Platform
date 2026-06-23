import json
from pathlib import Path


class EnrichmentService:

    def __init__(self):
        data_path = Path(__file__).parent.parent / "data" / "cves.json"

        with open(data_path, "r", encoding="utf-8") as file:
            self.cves = json.load(file)

    def enrich_cve(self, cve_id: str):

        for cve in self.cves:

            if cve["id"].lower() == cve_id.lower():
                return cve

        return None