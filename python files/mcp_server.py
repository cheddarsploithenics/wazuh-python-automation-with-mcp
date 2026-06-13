from mcp.server.fastmcp import FastMCP

from wazuh_client import (
    get_agents,
    get_offline_agents,
    get_high_severity_alerts,
    get_recent_alert_count as get_alerts_count,
    generate_daily_soc_report as generate_report,
)

mcp = FastMCP("wazuh-soc-mcp")


@mcp.tool()
def list_agents() -> list:
    """List all Wazuh agents with ID, name, IP, and status."""
    agents = get_agents()

    return [
        {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip", "N/A"),
            "status": agent.get("status"),
        }
        for agent in agents
    ]


@mcp.tool()
def list_offline_agents() -> list:
    """List Wazuh agents that are not active."""
    agents = get_offline_agents()

    return [
        {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip", "N/A"),
            "status": agent.get("status"),
        }
        for agent in agents
    ]


@mcp.tool()
def list_high_severity_alerts(minimum_level: int = 10, limit: int = 10) -> list:
    """List recent high-severity Wazuh alerts."""
    alerts = get_high_severity_alerts(
        minimum_level=minimum_level,
        limit=limit
    )

    results = []

    for alert in alerts:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        results.append(
            {
                "timestamp": alert.get("timestamp"),
                "agent": agent.get("name", "N/A"),
                "agent_id": agent.get("id", "N/A"),
                "rule_id": rule.get("id"),
                "level": rule.get("level"),
                "description": rule.get("description"),
            }
        )

    return results

@mcp.tool()
def get_agent_health_summary():
    agents = get_agents()

    total_agents = len(agents)

    active_agents = [
        a for a in agents
        if a.get("status", "").lower() == "active"
    ]

    offline_agents = [
        a for a in agents
        if a.get("status", "").lower() != "active"
    ]

    return {
        "total_agents": total_agents,
        "active_agents": len(active_agents),
        "offline_agents": len(offline_agents),
        "offline_agent_names": [
            agent.get("name")
            for agent in offline_agents
        ]
    }

@mcp.tool()
def get_recent_alert_count(hours: int = 24) -> dict:
    """Get the number of Wazuh alerts from the last specified number of hours."""
    return get_alerts_count(hours=hours)


@mcp.tool()
def generate_daily_soc_report() -> str:
    """Generate a daily SOC report from Wazuh agent and alert data."""
    return generate_report()

if __name__ == "__main__":
    mcp.run()