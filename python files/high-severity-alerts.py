import json
from pathlib import Path

alerts_file = Path("/var/ossec/logs/alerts/alerts.json")
minimum_level = 10
limit = 20

print("\nHigh Severity Alerts")
print("=" * 70)

if not alerts_file.exists():
    print(f"Alerts file not found: {alerts_file}")
    raise SystemExit(1)

matches = []

with alerts_file.open("r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule = alert.get("rule", {})
        level = rule.get("level", 0)

        if level >= minimum_level:
            matches.append(alert)

for alert in matches[-limit:]:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    print(f"Time: {alert.get('timestamp')}")
    print(f"Agent: {agent.get('name', 'N/A')}")
    print(f"Agent ID: {agent.get('id', 'N/A')}")
    print(f"Rule ID: {rule.get('id')}")
    print(f"Level: {rule.get('level')}")
    print(f"Description: {rule.get('description')}")
    print("-" * 70)

if not matches:
    print("No high-severity alerts found.")