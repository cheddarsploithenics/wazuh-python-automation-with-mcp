Wazuh Python Automation with MCP

Overview

This project demonstrates the integration of Wazuh SIEM, Python automation, and Model Context Protocol (MCP) to create an AI-assisted Security Operations Center (SOC) workflow.

The solution automates common security monitoring tasks including agent inventory management, endpoint health monitoring, offline agent detection, high-severity alert analysis, and daily SOC reporting. Through MCP integration, these security functions can be queried and executed using natural language through AI tools such as GitHub Copilot.

The goal of this project was to reduce manual SOC tasks while improving visibility into endpoint security and security event data.

---

Features: Agent Inventory Management

- Retrieves Wazuh agent information through the Wazuh REST API
- Displays:
  - Agent ID
  - Hostname
  - IP Address
  - Connection Status

Offline Agent Detection

- Identifies agents that are no longer active
- Highlights systems requiring investigation or remediation

High Severity Alert Monitoring

- Parses Wazuh alert logs
- Filters alerts above a configurable severity threshold
- Displays:
  - Alert timestamp
  - Agent information
  - Rule ID
  - Severity level
  - Alert description

Daily SOC Reporting

- Generates consolidated security reports
- Includes:
  - Agent health summary
  - Offline endpoints
  - Alert statistics
  - High severity findings

MCP Integration

- Exposes Wazuh monitoring functions as MCP tools
- Enables AI assistants to:
  - Query agent health
  - Review offline systems
  - Generate SOC reports
  - Analyze alert activity

---

Architecture

```text
Wazuh Manager
      |
      v
Wazuh REST API
      |
      v
wazuh_client.py
      |
      +--------------------+
      |                    |
      v                    v
SOC Reporting       Alert Analysis
      |
      v
MCP Server
      |
      v
GitHub Copilot / AI Assistant
```

---

Project Structure

```text
wazuh-python-automation/
│
├── wazuh_client.py
├── mcp_server.py
│
├── agent-inventory.py
├── offline-agents.py
├── high-severity-alerts.py
├── soc-report.py
│
├── test.py
├── test_client.py
│
├── .env
└── README.md
```

---

Core Components

wazuh_client.py

Centralized module responsible for:

- Authentication
- Token management
- API communication
- Agent retrieval
- Alert processing
- SOC report generation

All monitoring scripts and MCP tools utilize this module.

---

mcp_server.py

Creates a FastMCP server and exposes Wazuh functionality as AI-accessible tools.

Example tools:

- `list_agents`
- `list_offline_agents`
- `list_high_severity_alerts`
- `get_agent_health_summary`
- `get_recent_alert_count`
- `generate_daily_soc_report`

---

Agent Inventory Script

Queries the Wazuh API and displays all registered agents and their current status.

**Purpose:**

- Asset visibility
- Endpoint tracking
- Agent validation

---

Offline Agent Monitoring

Identifies agents that are disconnected, inactive, or pending.

**Purpose:**

- Endpoint health monitoring
- Security coverage validation
- Troubleshooting

---

High Severity Alert Monitoring

Reads Wazuh alert logs and identifies critical security events.

**Purpose:**

- Threat visibility
- Incident triage
- Vulnerability identification

---

Daily SOC Reporting

Generates a consolidated report containing:

- Agent statistics
- Offline systems
- Alert counts
- High severity findings

**Purpose:**

- Daily security reviews
- SOC reporting
- Operational visibility

---

Example MCP Usage

Natural language requests can be submitted through GitHub Copilot:

```text
Use the get_agent_health_summary tool from wazuh-soc-mcp.
```

```text
Generate a daily SOC report.
```

```text
Show me all offline agents.
```

```text
List high severity alerts.
```

The MCP server automatically executes the appropriate Python functions and returns the results.

---

Technologies Used

- Python 3
- Wazuh SIEM
- Wazuh REST API
- FastMCP
- GitHub Copilot
- JSON
- REST APIs
- Linux

---

Security Considerations

This repository has been sanitized for public release.

Sensitive information removed includes:

- API tokens
- Authentication credentials
- Internal IP addresses
- Organization-specific hostnames
- Security event details

Environment variables should be used to store all secrets and credentials.

---

Future Enhancements

Planned improvements include:

- Email-based SOC report delivery
- Alert trend analysis
- MITRE ATT&CK mapping
- Dashboard generation
- Vulnerability summary reporting
- Incident ticket creation
- Integration with additional SIEM platforms

---

Key Outcomes

This project demonstrates:

- Security automation using Python
- Wazuh API integration
- SIEM data processing
- MCP server development
- AI-assisted security operations
- Security reporting automation
- SOC workflow enhancement

---

Conclusion

This project demonstrates how traditional SIEM monitoring can be enhanced through Python automation and AI integration. By combining Wazuh, Python, MCP, and GitHub Copilot, security data can be accessed through natural language while reducing manual effort associated with routine SOC monitoring and reporting activities.
