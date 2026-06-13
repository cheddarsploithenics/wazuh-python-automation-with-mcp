import requests

url = "https://localhost:55000"
user = "wazuh"
password = "J8s6E*n.R9n38LOJERz1n2Cb3vVNfuxe"

requests.packages.urllib3.disable_warnings()

auth_response = requests.post(
    f"{url}/security/user/authenticate",
    auth=(user, password),
    verify=False
)

print(auth_response.status_code)
print(auth_response.text)