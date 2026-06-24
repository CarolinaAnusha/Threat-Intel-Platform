class GraphBuilder:
    def build(self, iocs, enrichment):
        nodes = []
        edges = []
        seen_nodes = set()

        def add_node(node_id, label, node_type):
            if node_id not in seen_nodes:
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type
                })
                seen_nodes.add(node_id)

        def add_edge(source, target, relationship):
            edges.append({
                "source": source,
                "target": target,
                "label": relationship
            })

        for ioc in iocs:
            add_node(ioc["value"], ioc["value"], ioc["type"])

        cves = enrichment.get("cves", [])

        for cve in cves:
            cve_id = cve["id"]
            add_node(cve_id, cve_id, "cve")

            for ioc in iocs:
                if ioc["type"] in ["domain", "ipv4", "url"]:
                    add_edge(ioc["value"], cve_id, "associated_with")

            for malware in cve.get("malware_families", []):
                add_node(malware, malware, "malware")
                add_edge(cve_id, malware, "linked_to")

            for actor in cve.get("threat_actors", []):
                add_node(actor, actor, "threat_actor")
                add_edge(cve_id, actor, "attributed_to")

        return {
            "nodes": nodes,
            "edges": edges
        }