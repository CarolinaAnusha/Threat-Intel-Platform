class DetectionEngineer:
    def generate(self, iocs, risk_level):
        domains = [ioc["value"] for ioc in iocs if ioc["type"] == "domain"]
        ips = [ioc["value"] for ioc in iocs if ioc["type"] == "ipv4"]
        hashes = [ioc["value"] for ioc in iocs if ioc["type"] in ["md5", "sha1", "sha256"]]

        return {
            "sigma": self._sigma(domains, ips, risk_level),
            "yara": self._yara(domains, ips, hashes, risk_level),
            "splunk": self._splunk(domains, ips),
            "sentinel": self._sentinel(domains, ips),
            "elastic": self._elastic(domains, ips)
        }

    def _sigma(self, domains, ips, risk_level):
        domain_lines = "\n".join([f"      - '{d}'" for d in domains]) or "      - 'no-domain-detected'"
        ip_lines = "\n".join([f"      - '{ip}'" for ip in ips]) or "      - 'no-ip-detected'"

        return f"""title: Suspicious Communication With Threat Infrastructure
status: experimental
description: Detects communication with extracted threat intelligence indicators
author: Threat Intelligence Platform
logsource:
  category: proxy
detection:
  selection_domain:
    url|contains:
{domain_lines}
  selection_ip:
    dst_ip:
{ip_lines}
  condition: selection_domain or selection_ip
falsepositives:
  - Security research
  - Sandbox testing
level: {risk_level}
tags:
  - attack.initial_access
  - attack.t1566
"""

    def _yara(self, domains, ips, hashes, risk_level):
        strings = []

        for index, domain in enumerate(domains):
            strings.append(f'    $domain{index+1} = "{domain}"')

        for index, ip in enumerate(ips):
            strings.append(f'    $ip{index+1} = "{ip}"')

        for index, hash_value in enumerate(hashes):
            strings.append(f'    $hash{index+1} = "{hash_value}"')

        if not strings:
            strings.append('    $placeholder = "no-iocs-detected"')

        return f"""rule Threat_Intel_Detected_Infrastructure
{{
  meta:
    description = "Detects artifacts from analyzed threat intelligence"
    threat_level = "{risk_level}"
    author = "Threat Intelligence Platform"

  strings:
{chr(10).join(strings)}

  condition:
    any of them
}}"""

    def _splunk(self, domains, ips):
        domain_query = " OR ".join([f'url="*{d}*"' for d in domains])
        ip_query = " OR ".join([f'dest_ip="{ip}"' for ip in ips])
        combined = " OR ".join([q for q in [domain_query, ip_query] if q])

        return f"""index=proxy ({combined})
| stats count by src_ip, url, dest_ip
| sort -count"""

    def _sentinel(self, domains, ips):
        domain_conditions = " or ".join([f'DestinationHostName contains "{d}"' for d in domains])
        ip_conditions = " or ".join([f'DestinationIP == "{ip}"' for ip in ips])
        combined = " or ".join([c for c in [domain_conditions, ip_conditions] if c])

        return f"""CommonSecurityLog
| where {combined}
| summarize Count=count() by SourceIP, DestinationHostName, DestinationIP"""

    def _elastic(self, domains, ips):
        should_items = []

        for domain in domains:
            should_items.append({"match": {"url.domain": domain}})

        for ip in ips:
            should_items.append({"match": {"destination.ip": ip}})

        return {
            "query": {
                "bool": {
                    "should": should_items
                }
            }
        }