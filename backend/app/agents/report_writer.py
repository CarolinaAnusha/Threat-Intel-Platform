import json

from app.agents.ai_client import AIClient


class ReportWriter:
    def __init__(self):
        self.ai_client = AIClient()

    def generate(self, content, iocs, enrichment, risk):
        ai_result = self._generate_with_ai(content, iocs, enrichment, risk)

        if ai_result:
            return ai_result

        return self._fallback_report(content, iocs, enrichment, risk)

    def _generate_with_ai(self, content, iocs, enrichment, risk):
        system_prompt = """
You are an expert SOC analyst and threat intelligence report writer.
Generate concise, professional, actionable cyber threat intelligence.
Return ONLY valid JSON.
Do not include markdown.
"""

        user_prompt = f"""
Analyze this threat intelligence context and return JSON with exactly these keys:
summary, analyst_assessment, attack_scenario, business_impact, immediate_actions, long_term_remediation, monitoring.

Threat text:
{content}

Extracted IOCs:
{json.dumps(iocs, indent=2)}

Enrichment:
{json.dumps(enrichment, indent=2)}

Risk:
{json.dumps(risk, indent=2)}

Required JSON format:
{{
  "summary": "2-3 sentence overview",
  "attack_scenario": "step-by-step exploitation scenario",
  "business_impact": "business consequences",
  "immediate_actions": ["action1", "action2", "action3", "action4"],
  "long_term_remediation": ["fix1", "fix2", "fix3", "fix4"],
  "analyst_assessment": "AI analyst confidence and reasoning in 2-3 sentences",
  "monitoring": ["watch1", "watch2", "watch3", "watch4"]
}}
"""

        result = self.ai_client.generate_json(system_prompt, user_prompt)

        if not result:
            return None

        required_keys = [
            "summary",
            "attack_scenario",
            "business_impact",
            "immediate_actions",
            "long_term_remediation",
            "analyst_assessment",
            "monitoring",
        ]

        for key in required_keys:
            if key not in result:
                return None

        return result

    def _fallback_report(self, content, iocs, enrichment, risk):
        content_lower = content.lower()
        cves = enrichment.get("cves", [])

        cve_names = [cve["id"] for cve in cves]
        malware = []
        actors = []

        for cve in cves:
            malware.extend(cve.get("malware_families", []))
            actors.extend(cve.get("threat_actors", []))

        domains = [ioc["value"] for ioc in iocs if ioc["type"] == "domain"]
        ips = [ioc["value"] for ioc in iocs if ioc["type"] == "ipv4"]
        urls = [ioc["value"] for ioc in iocs if ioc["type"] == "url"]
        emails = [ioc["value"] for ioc in iocs if ioc["type"] == "email"]
        hashes = [
            ioc["value"]
            for ioc in iocs
            if ioc["type"] in ["md5", "sha1", "sha256"]
        ]

        threat_type = self._detect_threat_type(content_lower, cve_names, hashes)

        return {
            "summary": self._summary(
                threat_type,
                risk,
                domains,
                ips,
                urls,
                emails,
                hashes,
                cve_names,
                malware,
                actors,
            ),
            "attack_scenario": self._attack_scenario(
                threat_type,
                domains,
                ips,
                urls,
                emails,
                hashes,
                cve_names,
                content_lower,
            ),
            "business_impact": self._business_impact(threat_type, risk),
            "immediate_actions": self._immediate_actions(
                domains,
                ips,
                urls,
                emails,
                hashes,
                cve_names,
                threat_type,
            ),
            "long_term_remediation": self._long_term_remediation(threat_type, cve_names),
            "analyst_assessment": self._analyst_assessment(threat_type, risk, domains, ips, cve_names, malware, actors),
            "monitoring": self._monitoring(
                domains,
                ips,
                urls,
                emails,
                hashes,
                malware,
                threat_type,
            ),
        }

    def _detect_threat_type(self, content, cves, hashes):
        if "ransomware" in content or "lockbit" in content or "blackcat" in content:
            return "ransomware"
        if "phishing" in content or "credential" in content or "login" in content:
            return "credential phishing"
        if "lateral movement" in content or "persistence" in content:
            return "post-compromise activity"
        if cves:
            return "vulnerability exploitation"
        if hashes:
            return "malware artifact"
        return "suspicious infrastructure"

    def _summary(
        self,
        threat_type,
        risk,
        domains,
        ips,
        urls,
        emails,
        hashes,
        cves,
        malware,
        actors,
    ):
        indicators = []

        if domains:
            indicators.append(f"{len(domains)} domain indicator(s)")
        if urls:
            indicators.append(f"{len(urls)} URL indicator(s)")
        if ips:
            indicators.append(f"{len(ips)} IP indicator(s)")
        if emails:
            indicators.append(f"{len(emails)} email indicator(s)")
        if hashes:
            indicators.append(f"{len(hashes)} file hash indicator(s)")
        if cves:
            indicators.append(f"{len(cves)} CVE reference(s)")

        indicator_text = ", ".join(indicators) if indicators else "limited indicators"

        context = []
        if cves:
            context.append(f"notable vulnerability exposure involving {', '.join(cves)}")
        if malware:
            context.append(f"malware association with {', '.join(sorted(set(malware)))}")
        if actors:
            context.append(f"possible threat actor association with {', '.join(sorted(set(actors)))}")

        context_text = "; ".join(context) if context else "no confirmed malware or actor attribution"

        return (
            f"This case appears to involve {threat_type} and is assessed as "
            f"{risk['risk_level'].upper()} with a score of {risk['risk_score']}/100. "
            f"The analysis identified {indicator_text}. Additional context shows {context_text}."
        )

    def _attack_scenario(
        self,
        threat_type,
        domains,
        ips,
        urls,
        emails,
        hashes,
        cves,
        content,
    ):
        if threat_type == "credential phishing":
            landing = urls[0] if urls else (domains[0] if domains else "a suspicious login page")
            return (
                f"An attacker may lure users to {landing} using phishing messages or fake login prompts. "
                "Victims could submit credentials, allowing the attacker to access cloud accounts, "
                "bypass normal workflows, and attempt follow-on activity such as mailbox abuse or lateral movement."
            )

        if threat_type == "ransomware":
            infra = ", ".join(domains + ips) if domains or ips else "identified infrastructure"
            return (
                f"The adversary may use {infra} for staging, command-and-control, or payload delivery. "
                "After initial access, the attacker may escalate privileges, move laterally, disable recovery controls, "
                "and deploy ransomware to disrupt business operations."
            )

        if threat_type == "vulnerability exploitation":
            cve_text = ", ".join(cves) if cves else "a known exposed vulnerability"
            return (
                f"The attacker may exploit {cve_text} against internet-facing infrastructure. "
                "Successful exploitation could provide remote access, enable web shell deployment, "
                "or create a foothold for credential theft and internal reconnaissance."
            )

        if threat_type == "malware artifact":
            hash_text = ", ".join(hashes[:2])
            return (
                f"The observed file hash indicator(s) {hash_text} suggest suspicious or malicious binary activity. "
                "The file may execute payload logic, connect to external infrastructure, or support persistence on the endpoint."
            )

        return (
            "The indicators suggest suspicious infrastructure requiring validation. "
            "The activity may represent early-stage reconnaissance, phishing preparation, or command-and-control setup."
        )

    def _business_impact(self, threat_type, risk):
        if threat_type == "credential phishing":
            return (
                "Potential impact includes account takeover, unauthorized mailbox access, data exposure, "
                "fraudulent transactions, and abuse of trusted user identities."
            )

        if threat_type == "ransomware":
            return (
                "Potential impact includes encryption of business-critical systems, downtime, data theft, "
                "recovery cost, reputational damage, and regulatory exposure."
            )

        if threat_type == "vulnerability exploitation":
            return (
                "Potential impact includes unauthorized access to exposed services, web shell deployment, "
                "privilege escalation, data compromise, and service disruption."
            )

        if threat_type == "malware artifact":
            return (
                "Potential impact includes endpoint compromise, credential theft, persistence, data staging, "
                "or communication with external attacker-controlled infrastructure."
            )

        if risk["risk_level"] in ["high", "critical"]:
            return (
                "The activity may lead to unauthorized access, incident response escalation, and operational disruption."
            )

        return (
            "Current impact appears limited, but the indicators should be validated and monitored for escalation."
        )

    def _immediate_actions(self, domains, ips, urls, emails, hashes, cves, threat_type):
        actions = []

        for domain in domains[:3]:
            actions.append(f"Block or sinkhole domain {domain} at DNS, proxy, and email security layers.")

        for url in urls[:3]:
            actions.append(f"Block URL {url} and search proxy logs for historical access.")

        for ip in ips[:3]:
            actions.append(f"Review and block outbound connections to {ip} where appropriate.")

        for email in emails[:3]:
            actions.append(f"Search mail logs for messages involving {email} and quarantine related emails.")

        for file_hash in hashes[:3]:
            actions.append(f"Hunt endpoints for file hash {file_hash} and isolate affected hosts if found.")

        for cve in cves[:3]:
            actions.append(f"Validate exposure and patch or mitigate assets affected by {cve}.")

        if threat_type == "credential phishing":
            actions.append("Reset credentials for affected users and review MFA prompts and sign-in anomalies.")
        elif threat_type == "ransomware":
            actions.append("Isolate suspected systems and verify backup integrity before recovery activity.")
        else:
            actions.append("Create a SOC case and correlate the indicators across endpoint, DNS, proxy, and SIEM logs.")

        return actions[:6]

    def _long_term_remediation(self, threat_type, cves):
        items = [
            "Maintain centralized logging across endpoint, identity, DNS, proxy, and firewall telemetry.",
            "Tune SIEM detections using confirmed indicators and observed ATT&CK techniques.",
        ]

        if threat_type == "credential phishing":
            items.extend([
                "Enforce phishing-resistant MFA for privileged and high-risk users.",
                "Improve email security controls, domain impersonation detection, and user awareness training.",
            ])
        elif threat_type == "ransomware":
            items.extend([
                "Implement ransomware recovery playbooks, immutable backups, and least-privilege access controls.",
                "Strengthen endpoint detection coverage for privilege escalation and lateral movement behavior.",
            ])
        elif cves:
            items.extend([
                "Improve patch management SLAs for critical and externally exposed vulnerabilities.",
                "Maintain external attack surface monitoring for exposed services and vulnerable assets.",
            ])
        else:
            items.extend([
                "Create threat intelligence watchlists for suspicious infrastructure and recurring indicators.",
                "Review network egress filtering and suspicious destination alerting policies.",
            ])

        return items[:5]

    def _monitoring(self, domains, ips, urls, emails, hashes, malware, threat_type):
        items = []

        for domain in domains[:3]:
            items.append(f"Monitor DNS, proxy, and EDR telemetry for connections to {domain}.")

        for url in urls[:3]:
            items.append(f"Search historical proxy logs for access to {url}.")

        for ip in ips[:3]:
            items.append(f"Monitor firewall and NetFlow logs for outbound traffic to {ip}.")

        for email in emails[:3]:
            items.append(f"Monitor mail gateway logs for sender or reply-to activity involving {email}.")

        for file_hash in hashes[:3]:
            items.append(f"Hunt EDR telemetry for file hash {file_hash}.")

        for family in sorted(set(malware))[:3]:
            items.append(f"Monitor endpoint behavior associated with {family} tradecraft.")

        if threat_type == "credential phishing":
            items.append("Monitor identity logs for impossible travel, MFA fatigue, and unusual mailbox rules.")
        elif threat_type == "ransomware":
            items.append("Monitor for mass file modification, shadow copy deletion, and suspicious privilege escalation.")
        else:
            items.append("Monitor for repeated connections, new related domains, and suspicious authentication patterns.")

        return items[:6]
    
    def _analyst_assessment(self, threat_type, risk, domains, ips, cves, malware, actors):
        evidence = []

        if domains:
            evidence.append(f"suspicious domain activity involving {', '.join(domains[:2])}")
        if ips:
            evidence.append(f"network communication with {', '.join(ips[:2])}")
        if cves:
            evidence.append(f"vulnerability exposure involving {', '.join(cves[:2])}")
        if malware:
            evidence.append(f"malware association with {', '.join(sorted(set(malware))[:2])}")
        if actors:
            evidence.append(f"possible actor linkage to {', '.join(sorted(set(actors))[:2])}")

        evidence_text = "; ".join(evidence) if evidence else "limited but suspicious indicators"

        return (
            f"AI assessment: This activity is consistent with {threat_type}. "
            f"The confidence is {self._confidence_label(risk['risk_score'])} based on {evidence_text}. "
            f"Recommended priority is {risk['risk_level'].upper()} triage."
        )

    def _confidence_label(self, score):
        if score >= 80:
            return "high"
        if score >= 50:
            return "moderate"
        return "low-to-moderate"