@mcp.tool()
def get_recent_alert_count_tool(hours: int = 24) -> dict:
    """Get the number of Wazuh alerts from the last specified number of hours."""
    return get_recent_alert_count(hours=hours)


@mcp.tool()
def generate_daily_soc_report_tool() -> str:
    """Generate a daily SOC report from Wazuh agent and alert data."""
    return generate_daily_soc_report()