class DetectionEngineer:
    def generate(self, iocs, risk_level):
        domains = [ioc["value"] for ioc in iocs if ioc["type"] == "domain"]
        ips = [ioc["value"] for ioc in iocs if ioc["type"] == "ipv4"]
        urls = [ioc["value"] for ioc in iocs if ioc["type"] == "url"]
        emails = [ioc["value"] for ioc in iocs if ioc["type"] == "email"]
        hashes = [
            ioc["value"]
            for ioc in iocs
            if ioc["type"] in ["md5", "sha1", "sha256"]
        ]
        cves = [ioc["value"] for ioc in iocs if ioc["type"] == "cve"]

        return {
            "sigma": self._sigma(domains, ips, urls, emails, hashes, cves, risk_level),
            "yara": self._yara(domains, ips, urls, hashes, cves, risk_level),
            "splunk": self._splunk(domains, ips, urls, emails, hashes, cves),
            "sentinel": self._sentinel(domains, ips, urls, emails, hashes, cves),
            "elastic": self._elastic(domains, ips, urls, emails, hashes, cves)
        }

    def _sigma(self, domains, ips, urls, emails, hashes, cves, risk_level):
        selections = []
        conditions = []

        if domains:
            lines = "\n".join([f"      - '{domain}'" for domain in domains])
            selections.append(f"""  selection_domain:
    url|contains:
{lines}""")
            conditions.append("selection_domain")

        if urls:
            lines = "\n".join([f"      - '{url}'" for url in urls])
            selections.append(f"""  selection_url:
    url|contains:
{lines}""")
            conditions.append("selection_url")

        if ips:
            lines = "\n".join([f"      - '{ip}'" for ip in ips])
            selections.append(f"""  selection_ip:
    dst_ip:
{lines}""")
            conditions.append("selection_ip")

        if emails:
            lines = "\n".join([f"      - '{email}'" for email in emails])
            selections.append(f"""  selection_email:
    sender|contains:
{lines}""")
            conditions.append("selection_email")

        if hashes:
            lines = "\n".join([f"      - '{hash_value}'" for hash_value in hashes])
            selections.append(f"""  selection_hash:
    hash:
{lines}""")
            conditions.append("selection_hash")

        if cves:
            lines = "\n".join([f"      - '{cve}'" for cve in cves])
            selections.append(f"""  selection_cve:
    message|contains:
{lines}""")
            conditions.append("selection_cve")

        if not selections:
            selections.append("""  selection_placeholder:
    message|contains:
      - 'no-indicators-detected'""")
            conditions.append("selection_placeholder")

        tags = self._sigma_tags(domains, urls, emails, hashes, cves)

        return f"""title: Threat Intelligence Indicator Match
id: ti-generated-indicator-match
status: experimental
description: Detects activity matching indicators extracted from analyzed threat intelligence.
author: Threat Intelligence Platform
logsource:
  product: proxy
  category: network_connection
detection:
{chr(10).join(selections)}
  condition: {' or '.join(conditions)}
falsepositives:
  - Security research activity
  - Malware sandbox detonation
  - Internal threat hunting validation
level: {risk_level}
tags:
{chr(10).join([f"  - {tag}" for tag in tags])}
"""

    def _sigma_tags(self, domains, urls, emails, hashes, cves):
        tags = []

        if domains or urls or emails:
            tags.extend(["attack.initial_access", "attack.t1566"])

        if cves:
            tags.extend(["attack.initial_access", "attack.t1190"])

        if hashes:
            tags.extend(["attack.execution", "attack.t1204"])

        if not tags:
            tags.append("attack.discovery")

        return tags

    def _yara(self, domains, ips, urls, hashes, cves, risk_level):
        strings = []

        for index, domain in enumerate(domains, start=1):
            strings.append(f'    $domain{index} = "{domain}" nocase')

        for index, url in enumerate(urls, start=1):
            strings.append(f'    $url{index} = "{url}" nocase')

        for index, ip in enumerate(ips, start=1):
            strings.append(f'    $ip{index} = "{ip}"')

        for index, cve in enumerate(cves, start=1):
            strings.append(f'    $cve{index} = "{cve}" nocase')

        for index, hash_value in enumerate(hashes, start=1):
            strings.append(f'    $hash{index} = "{hash_value}" nocase')

        if not strings:
            strings.append('    $placeholder = "no-iocs-detected"')

        condition = "any of them"

        if hashes and (domains or ips or urls):
            condition = "any of ($hash*) or any of ($domain*) or any of ($url*) or any of ($ip*)"
        elif hashes:
            condition = "any of ($hash*)"
        elif domains or ips or urls:
            condition = "any of ($domain*) or any of ($url*) or any of ($ip*)"

        return f"""rule TI_Generated_Indicator_Detection
{{
  meta:
    description = "Detects artifacts derived from threat intelligence analysis"
    threat_level = "{risk_level}"
    author = "Threat Intelligence Platform"
    generated_for = "SOC triage and malware hunting"

  strings:
{chr(10).join(strings)}

  condition:
    {condition}
}}"""

    def _splunk(self, domains, ips, urls, emails, hashes, cves):
        conditions = []

        for domain in domains:
            conditions.append(f'url="*{domain}*"')
            conditions.append(f'dest_host="*{domain}*"')

        for url in urls:
            conditions.append(f'url="*{url}*"')

        for ip in ips:
            conditions.append(f'dest_ip="{ip}"')
            conditions.append(f'destination_ip="{ip}"')

        for email in emails:
            conditions.append(f'sender="*{email}*"')
            conditions.append(f'src_user="*{email}*"')

        for hash_value in hashes:
            conditions.append(f'file_hash="{hash_value}"')
            conditions.append(f'process_hash="{hash_value}"')

        for cve in cves:
            conditions.append(f'"{cve}"')

        if not conditions:
            conditions.append('"no-indicators-detected"')

        return f"""index=* ({' OR '.join(conditions)})
| eval detection_source="threat_intelligence_platform"
| stats count min(_time) as first_seen max(_time) as last_seen values(index) as indexes by src_ip, dest_ip, url, dest_host, file_hash, user
| convert ctime(first_seen) ctime(last_seen)
| sort -count"""

    def _sentinel(self, domains, ips, urls, emails, hashes, cves):
        clauses = []

        for domain in domains:
            clauses.append(f'DestinationHostName contains "{domain}"')
            clauses.append(f'Url contains "{domain}"')

        for url in urls:
            clauses.append(f'Url contains "{url}"')

        for ip in ips:
            clauses.append(f'DestinationIP == "{ip}"')
            clauses.append(f'RemoteIP == "{ip}"')

        for email in emails:
            clauses.append(f'SenderFromAddress contains "{email}"')
            clauses.append(f'Account contains "{email}"')

        for hash_value in hashes:
            clauses.append(f'SHA256 == "{hash_value}"')
            clauses.append(f'MD5 == "{hash_value}"')
            clauses.append(f'FileHash == "{hash_value}"')

        for cve in cves:
            clauses.append(f'Message contains "{cve}"')

        if not clauses:
            clauses.append('Message contains "no-indicators-detected"')

        return f"""union isfuzzy=true CommonSecurityLog, DeviceNetworkEvents, DeviceFileEvents, EmailEvents
| where {' or '.join(clauses)}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by DeviceName, SourceIP, DestinationIP, DestinationHostName, Url, FileName, Account
| order by Count desc"""

    def _elastic(self, domains, ips, urls, emails, hashes, cves):
        should_items = []

        for domain in domains:
            should_items.append({"wildcard": {"url.domain": f"*{domain}*"}})
            should_items.append({"wildcard": {"destination.domain": f"*{domain}*"}})

        for url in urls:
            should_items.append({"wildcard": {"url.full": f"*{url}*"}})

        for ip in ips:
            should_items.append({"term": {"destination.ip": ip}})
            should_items.append({"term": {"source.ip": ip}})

        for email in emails:
            should_items.append({"wildcard": {"email.from.address": f"*{email}*"}})
            should_items.append({"wildcard": {"user.email": f"*{email}*"}})

        for hash_value in hashes:
            should_items.append({"term": {"file.hash.md5": hash_value}})
            should_items.append({"term": {"file.hash.sha1": hash_value}})
            should_items.append({"term": {"file.hash.sha256": hash_value}})

        for cve in cves:
            should_items.append({"match_phrase": {"message": cve}})

        if not should_items:
            should_items.append({"match_phrase": {"message": "no-indicators-detected"}})

        return {
            "query": {
                "bool": {
                    "minimum_should_match": 1,
                    "should": should_items
                }
            }
        }