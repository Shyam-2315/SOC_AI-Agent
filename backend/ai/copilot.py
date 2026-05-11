from app.db.client import alerts_collection, incidents_collection


async def _collect_alerts(query: dict):
    alerts = []
    async for alert in alerts_collection.find(query).sort("timestamp", -1).limit(100):
        alert["_id"] = str(alert["_id"])
        alerts.append(alert)
    return alerts


async def process_soc_query(
    query: str,
    organization_id: str,
):
    query = query.lower()
    organization_query = {
        "organization_id": organization_id,
    }

    if "summary" in query or "summaries" in query or "overview" in query:
        total_alerts = await alerts_collection.count_documents(organization_query)
        critical_alerts = await alerts_collection.count_documents({
            **organization_query,
            "severity": {
                "$regex": "^critical$",
                "$options": "i",
            },
        })
        open_incidents = await incidents_collection.count_documents({
            **organization_query,
            "status": "open",
        })

        top_ips = {}
        async for alert in alerts_collection.find(organization_query).limit(1000):
            ip_address = alert.get("ip_address")
            if ip_address:
                top_ips[ip_address] = top_ips.get(ip_address, 0) + 1

        return {
            "query_type": "soc_summary",
            "summary": {
                "total_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "open_incidents": open_incidents,
                "top_dangerous_ips": sorted(
                    top_ips.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:5],
            },
        }

    if "critical" in query:
        return {
            "query_type": "critical_alerts",
            "results": await _collect_alerts({
                **organization_query,
                "severity": {
                    "$regex": "^critical$",
                    "$options": "i",
                },
            }),
        }

    if "malware" in query:
        return {
            "query_type": "malware_alerts",
            "results": await _collect_alerts({
                **organization_query,
                "event_type": "malware",
            }),
        }

    if "ransomware" in query:
        return {
            "query_type": "ransomware_alerts",
            "results": await _collect_alerts({
                **organization_query,
                "event_type": "ransomware",
            }),
        }

    if "mitre" in query:
        mitre_data = []
        async for alert in alerts_collection.find(organization_query).limit(100):
            mitre_data.append({
                "event_type": alert.get("event_type"),
                "technique": alert.get("mitre_technique"),
                "tactic": alert.get("mitre_tactic"),
            })

        return {
            "query_type": "mitre_analysis",
            "results": mitre_data,
        }

    if "dangerous ip" in query:
        ip_stats = {}
        async for alert in alerts_collection.find(organization_query).limit(1000):
            ip = alert.get("ip_address")
            if not ip:
                continue
            ip_stats[ip] = ip_stats.get(ip, 0) + 1

        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return {
            "query_type": "dangerous_ips",
            "results": sorted_ips,
        }

    return {
        "message": "Query not understood",
    }
