from wazuh_client import get_agents, get_offline_agents, get_high_severity_alerts

print("Agents:")
for agent in get_agents():
    print(agent.get("id"), agent.get("name"), agent.get("status"))

print("\nOffline Agents:")
offline_agents = get_offline_agents()

if offline_agents:
    for agent in offline_agents:
        print(agent.get("id"), agent.get("name"), agent.get("status"))
else:
    print("All agents are active.")

print("\nHigh Severity Alerts:")
alerts = get_high_severity_alerts()

if alerts:
    for alert in alerts:
        print(alert.get("timestamp"), alert.get("rule", {}).get("description"))
else:
    print("No high-severity alerts found.")