import json
from pathlib import Path


class MITREMapper:

    def __init__(self):
        file_path = (
            Path(__file__).parent.parent /
            "data" /
            "mitre_attack.json"
        )

        with open(file_path, "r", encoding="utf-8") as file:
            self.techniques = json.load(file)

    def map(self, text):
        text = text.lower()

        matches = []

        for technique in self.techniques:

            confidence = 0

            for keyword in technique["keywords"]:

                if keyword.lower() in text:
                    confidence += 25

            if confidence > 0:

                matches.append({
                    "tactic": technique["tactic"],
                    "technique": technique["technique"],
                    "technique_id": technique["technique_id"],
                    "confidence": min(confidence, 100)
                })

        return matches