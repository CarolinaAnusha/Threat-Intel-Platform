class RiskScorer:
    def calculate(self, enrichment_items, iocs):
        score = 0
        factors = []

        ioc_counts = {
            "domain": 0,
            "ipv4": 0,
            "url": 0,
            "email": 0,
            "md5": 0,
            "sha1": 0,
            "sha256": 0,
            "cve": 0,
        }

        for ioc in iocs:
            ioc_type = ioc.get("type")
            if ioc_type in ioc_counts:
                ioc_counts[ioc_type] += 1

        if ioc_counts["domain"] > 0:
            points = min(ioc_counts["domain"] * 6, 18)
            score += points
            factors.append({"factor": "Suspicious Domain Indicator", "score": points})

        if ioc_counts["ipv4"] > 0:
            points = min(ioc_counts["ipv4"] * 5, 15)
            score += points
            factors.append({"factor": "Suspicious IP Indicator", "score": points})

        if ioc_counts["url"] > 0:
            points = min(ioc_counts["url"] * 7, 21)
            score += points
            factors.append({"factor": "Suspicious URL Indicator", "score": points})

        if ioc_counts["email"] > 0:
            points = min(ioc_counts["email"] * 4, 12)
            score += points
            factors.append({"factor": "Suspicious Email Indicator", "score": points})

        hash_count = ioc_counts["md5"] + ioc_counts["sha1"] + ioc_counts["sha256"]
        if hash_count > 0:
            points = min(hash_count * 8, 24)
            score += points
            factors.append({"factor": "Malware Hash Indicator", "score": points})

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
            elif cvss > 0:
                score += 5
                factors.append({"factor": "Low Severity CVE Present", "score": 5})

            if item.get("exploit_available"):
                score += 25
                factors.append({"factor": "Public Exploit Available", "score": 25})

            malware_families = item.get("malware_families", [])
            if malware_families:
                score += 15
                factors.append({
                    "factor": f"Malware Associated: {', '.join(malware_families)}",
                    "score": 15
                })

            threat_actors = item.get("threat_actors", [])
            if threat_actors:
                score += 10
                factors.append({
                    "factor": f"Known Threat Actor: {', '.join(threat_actors)}",
                    "score": 10
                })

        if len(iocs) >= 3:
            score += 8
            factors.append({"factor": "Multiple Correlated IOCs", "score": 8})

        if score == 0 and iocs:
            score = 5
            factors.append({"factor": "Unclassified Suspicious Indicator", "score": 5})

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