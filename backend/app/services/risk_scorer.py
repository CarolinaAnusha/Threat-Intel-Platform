class RiskScorer:
    def calculate(self, enrichment_items, iocs):
        score = 0
        factors = []

        for item in enrichment_items:
            if not item:
                continue

            cvss = item.get("cvss", 0)

            if cvss > 9:
                score += 30
                factors.append({"factor": "CVSS > 9 Critical Vulnerability", "score": 30})
            elif 7 <= cvss <= 9:
                score += 20
                factors.append({"factor": "CVSS 7-9 High Vulnerability", "score": 20})
            elif 4 <= cvss < 7:
                score += 10
                factors.append({"factor": "CVSS 4-7 Medium Vulnerability", "score": 10})

            if item.get("exploit_available"):
                score += 25
                factors.append({"factor": "Public Exploit Available", "score": 25})

            if item.get("malware_families"):
                score += 15
                factors.append({
                    "factor": f"Malware Associated: {', '.join(item.get('malware_families'))}",
                    "score": 15
                })

            if item.get("threat_actors"):
                score += 10
                factors.append({
                    "factor": f"Known Threat Actor: {', '.join(item.get('threat_actors'))}",
                    "score": 10
                })

        suspicious_iocs = [
            ioc for ioc in iocs
            if ioc["type"] in ["domain", "ipv4", "url", "hash", "md5", "sha1", "sha256"]
        ]

        if suspicious_iocs:
            score += 8
            factors.append({"factor": "Suspicious IOC Reputation", "score": 8})

        score = min(score, 100)

        return {
            "risk_score": score,
            "risk_level": self._level(score),
            "risk_factors": factors
        }

    def _level(self, score):
        if score <= 30:
            return "low"
        if score <= 60:
            return "medium"
        if score <= 80:
            return "high"
        return "critical"