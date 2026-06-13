import json
import requests
from pathlib import Path
from datetime import datetime

wazuh_url = "https://localhost:55000"
wazuh_user = "wazuh"
wazuh_pass = "J8s6E*n.R9n38LOJERz1n2Cb3vVNfuxe"

alerts_file = Path("/var/ossec/logs/alerts/alerts.json")
output_file = Path("daily_soc_report.txt")

requests.packages.urllib3.disable_warnings()


def get_token():
    response = requests.post(
        f"{wazuh_url}/security/user/authenticate",
        auth=(wazuh_user, wazuh_pass),
        verify=False
    )
    response.raise_for_status()
    return response.json()["data"]["token"]


def get_agents():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{wazuh_url}/agents",
        headers=headers,
        verify=False
    )
    response.raise_for_status()
    return response.json()["data"]["affected_items"]


def get_high_alerts(minimum_level=10, limit=20):
    alerts = []

    if not alerts_file.exists():
        return alerts

    with alerts_file.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            level = alert.get("rule", {}).get("level", 0)

            if level >= minimum_level:
                alerts.append(alert)

    return alerts[-limit:]


agents = get_agents()
high_alerts = get_high_alerts()

active_agents = [a for a in agents if a.get("status", "").lower() == "active"]
inactive_agents = [a for a in agents if a.get("status", "").lower() != "active"]

report_lines = []

report_lines.append("Wazuh Daily SOC Report")
report_lines.append("=" * 60)
report_lines.append(f"Generated: {datetime.now()}")
report_lines.append("")

report_lines.append("Agent Summary")
report_lines.append("-" * 60)
report_lines.append(f"Total Agents: {len(agents)}")
report_lines.append(f"Active Agents: {len(active_agents)}")
report_lines.append(f"Inactive Agents: {len(inactive_agents)}")
report_lines.append("")

if inactive_agents:
    report_lines.append("Inactive Agents")
    report_lines.append("-" * 60)

    for agent in inactive_agents:
        report_lines.append(
            f"ID: {agent.get('id')} | "
            f"Name: {agent.get('name')} | "
            f"IP: {agent.get('ip', 'N/A')} | "
            f"Status: {agent.get('status')}"
        )

    report_lines.append("")

report_lines.append("High Severity Alerts")
report_lines.append("-" * 60)

if high_alerts:
    for alert in high_alerts:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        report_lines.append(f"Time: {alert.get('timestamp')}")
        report_lines.append(f"Agent: {agent.get('name', 'N/A')}")
        report_lines.append(f"Rule ID: {rule.get('id')}")
        report_lines.append(f"Level: {rule.get('level')}")
        report_lines.append(f"Description: {rule.get('description')}")
        report_lines.append("-" * 60)
else:
    report_lines.append("No high-severity alerts found.")

output_file.write_text("\n".join(report_lines))

print(f"Report created: {output_file.resolve()}")