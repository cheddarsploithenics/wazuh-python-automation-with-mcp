import json
from pathlib import Path

import requests

from datetime import datetime, timedelta, timezone

WAZUH_URL = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "J8s6E*n.R9n38LOJERz1n2Cb3vVNfuxe"

ALERTS_FILE = Path("/var/ossec/logs/alerts/alerts.json")

requests.packages.urllib3.disable_warnings()


def get_token():
    response = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    response.raise_for_status()
    return response.json()["data"]["token"]


def get_headers():
    token = get_token()
    return {"Authorization": f"Bearer {token}"}


def get_agents():
    response = requests.get(
        f"{WAZUH_URL}/agents",
        headers=get_headers(),
        verify=False
    )
    response.raise_for_status()
    return response.json()["data"]["affected_items"]


def get_offline_agents():
    agents = get_agents()
    return [
        agent for agent in agents
        if agent.get("status", "").lower() != "active"
    ]


def get_high_severity_alerts(minimum_level=10, limit=20):
    alerts = []

    if not ALERTS_FILE.exists():
        return alerts

    with ALERTS_FILE.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            level = alert.get("rule", {}).get("level", 0)

            if level >= minimum_level:
                alerts.append(alert)

    return alerts[-limit:]

def get_recent_alert_count(hours=24):
    if not ALERTS_FILE.exists():
        return {
            "hours": hours,
            "total_alerts": 0,
            "high_severity_alerts": 0
        }

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    total_alerts = 0
    high_severity_alerts = 0

    with ALERTS_FILE.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp_raw = alert.get("timestamp")
            if not timestamp_raw:
                continue

            try:
                alert_time = datetime.fromisoformat(
                    timestamp_raw.replace("Z", "+00:00")
                )
            except ValueError:
                continue

            if alert_time >= cutoff:
                total_alerts += 1

                level = alert.get("rule", {}).get("level", 0)
                if level >= 10:
                    high_severity_alerts += 1

    return {
        "hours": hours,
        "total_alerts": total_alerts,
        "high_severity_alerts": high_severity_alerts
    }


def generate_daily_soc_report():
    agents = get_agents()
    offline_agents = get_offline_agents()
    high_alerts = get_high_severity_alerts(minimum_level=10, limit=20)
    recent_counts = get_recent_alert_count(hours=24)

    active_agents = [
        agent for agent in agents
        if agent.get("status", "").lower() == "active"
    ]

    lines = []

    lines.append("Wazuh Daily SOC Report")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now()}")
    lines.append("")

    lines.append("Agent Summary")
    lines.append("-" * 60)
    lines.append(f"Total Agents: {len(agents)}")
    lines.append(f"Active Agents: {len(active_agents)}")
    lines.append(f"Inactive Agents: {len(offline_agents)}")
    lines.append("")

    lines.append("Recent Alert Summary")
    lines.append("-" * 60)
    lines.append(f"Alert Window: Last {recent_counts['hours']} hours")
    lines.append(f"Total Alerts: {recent_counts['total_alerts']}")
    lines.append(f"High Severity Alerts: {recent_counts['high_severity_alerts']}")
    lines.append("")

    lines.append("Inactive Agents")
    lines.append("-" * 60)

    if offline_agents:
        for agent in offline_agents:
            lines.append(
                f"ID: {agent.get('id')} | "
                f"Name: {agent.get('name')} | "
                f"IP: {agent.get('ip', 'N/A')} | "
                f"Status: {agent.get('status')}"
            )
    else:
        lines.append("No inactive agents found.")

    lines.append("")
    lines.append("High Severity Alerts")
    lines.append("-" * 60)

    if high_alerts:
        for alert in high_alerts:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})

            lines.append(f"Time: {alert.get('timestamp')}")
            lines.append(f"Agent: {agent.get('name', 'N/A')}")
            lines.append(f"Rule ID: {rule.get('id')}")
            lines.append(f"Level: {rule.get('level')}")
            lines.append(f"Description: {rule.get('description')}")
            lines.append("-" * 60)
    else:
        lines.append("No high-severity alerts found.")

    return "\n".join(lines)