import requests

wazuh_url = "https://localhost:55000"
wazuh_user = "wazuh"
wazuh_pass = "J8s6E*n.R9n38LOJERz1n2Cb3vVNfuxe"

requests.packages.urllib3.disable_warnings()

auth_response = requests.post(
    f"{wazuh_url}/security/user/authenticate",
    auth=(wazuh_user, wazuh_pass),
    verify=False
)

auth_response.raise_for_status()
token = auth_response.json()["data"]["token"]

headers = {
    "Authorization": f"Bearer {token}"
}

agents_response = requests.get(
    f"{wazuh_url}/agents",
    headers=headers,
    verify=False
)

agents_response.raise_for_status()
agents = agents_response.json()["data"]["affected_items"]

print("Wazuh Agent Inventory")
print("---------------------")

for agent in agents:
    print(
        f"ID: {agent.get('id')} | "
        f"Name: {agent.get('name')} | "
        f"IP: {agent.get('ip', 'N/A')} | "
        f"Status: {agent.get('status')}"
    )