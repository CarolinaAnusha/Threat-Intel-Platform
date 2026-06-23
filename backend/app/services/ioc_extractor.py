import re
from typing import Dict, List


class IOCExtractor:
    def __init__(self):
        self.patterns = {
            "ipv4": r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
            "url": r"https?://[^\s,]+",
            "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
            "cve": r"\bCVE-\d{4}-\d{4,7}\b",
            "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        }

    def extract(self, text: str) -> List[Dict]:
        if not text or not text.strip():
            return []

        results = []
        seen = set()

        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)

            for value in matches:
                value = value.strip().rstrip(".,;)")
                key = (ioc_type, value.lower())

                if key in seen:
                    continue

                if ioc_type == "domain" and self._is_domain_false_positive(value, text):
                    continue

                seen.add(key)

                results.append(
                    {
                        "type": ioc_type,
                        "value": value,
                        "confidence": self._confidence(ioc_type, value),
                    }
                )

        return results

    def _confidence(self, ioc_type: str, value: str) -> float:
        confidence_map = {
            "ipv4": 0.95,
            "url": 0.95,
            "email": 0.9,
            "md5": 0.95,
            "sha1": 0.95,
            "sha256": 0.95,
            "cve": 1.0,
            "domain": 0.85,
        }

        return confidence_map.get(ioc_type, 0.75)

    def _is_domain_false_positive(self, value: str, text: str) -> bool:
        lower_value = value.lower()

        if lower_value.startswith("http"):
            return True

        if "@" in lower_value:
            return True

        common_false_positives = {
            "example.com",
            "localhost.localdomain",
        }

        if lower_value in common_false_positives:
            return True

        return False