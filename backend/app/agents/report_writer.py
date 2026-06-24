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
summary, attack_scenario, business_impact, immediate_actions, long_term_remediation, monitoring.

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
            "monitoring",
        ]

        for key in required_keys:
            if key not in result:
                return None

        return result

    def _fallback_report(self, content, iocs, enrichment, risk):
        cves = enrichment.get("cves", [])

        cve_names = [cve["id"] for cve in cves]
        malware = []
        actors = []

        for cve in cves:
            malware.extend(cve.get("malware_families", []))
            actors.extend(cve.get("threat_actors", []))

        domains = [ioc["value"] for ioc in iocs if ioc["type"] == "domain"]
        ips = [ioc["value"] for ioc in iocs if ioc["type"] == "ipv4"]

        return {
            "summary": self._summary(risk, cve_names, malware, actors),
            "attack_scenario": self._attack_scenario(domains, ips, cve_names),
            "business_impact": self._business_impact(risk),
            "immediate_actions": self._immediate_actions(domains, ips, cve_names),
            "long_term_remediation": [
                "Implement MFA for high-risk user groups.",
                "Improve email and web filtering controls.",
                "Maintain a strict patch management SLA for critical CVEs.",
                "Run phishing awareness and incident response training.",
            ],
            "monitoring": self._monitoring(domains, ips, malware),
        }

    def _summary(self, risk, cves, malware, actors):
        return (
            f"This threat is assessed as {risk['risk_level'].upper()} "
            f"with a risk score of {risk['risk_score']}/100. "
            f"The analysis identified {', '.join(cves) if cves else 'no known CVE'}, "
            f"with links to {', '.join(malware) if malware else 'no known malware'} "
            f"and {', '.join(actors) if actors else 'no known threat actor'}."
        )

    def _attack_scenario(self, domains, ips, cves):
        return (
            "An attacker may use the identified infrastructure "
            f"{', '.join(domains + ips) if domains or ips else 'from the report'} "
            f"alongside {', '.join(cves) if cves else 'available weaknesses'} "
            "to gain initial access, harvest credentials, or stage follow-on activity."
        )

    def _business_impact(self, risk):
        if risk["risk_level"] == "critical":
            return (
                "Successful exploitation could lead to credential theft, unauthorized access, "
                "ransomware deployment, operational disruption, and regulatory exposure."
            )

        if risk["risk_level"] == "high":
            return (
                "Successful exploitation could cause service disruption, data exposure, "
                "and increased incident response workload."
            )

        return (
            "The current indicators suggest limited impact, but continued monitoring is recommended."
        )

    def _immediate_actions(self, domains, ips, cves):
        actions = []

        for domain in domains:
            actions.append(f"Block domain {domain} at DNS/proxy level.")

        for ip in ips:
            actions.append(f"Block IP {ip} at firewall or proxy level.")

        for cve in cves:
            actions.append(f"Validate exposure and patch systems affected by {cve}.")

        actions.append("Create a SOC ticket and monitor related alerts.")

        return actions

    def _monitoring(self, domains, ips, malware):
        items = []

        for domain in domains:
            items.append(f"Monitor DNS and proxy logs for connections to {domain}.")

        for ip in ips:
            items.append(f"Search SIEM logs for outbound traffic to {ip}.")

        for family in malware:
            items.append(f"Monitor endpoint telemetry for behavior associated with {family}.")

        items.append("Watch for unusual authentication attempts and lateral movement.")

        return items