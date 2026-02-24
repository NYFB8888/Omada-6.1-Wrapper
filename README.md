# Omada-6.1-Wrapper
A lightweight Python wrapper for the Omada 6.01 OpenAPI, providing a simple interface for interacting with Omada Controller 6.01 endpoints.


Simple usage
<pre>
from omada_api.omada_api import Omada
import json


def extract_ip(item):
    # Case 1: client-style record
    if "ip" in item and isinstance(item["ip"], str):
        return [item["ip"]]

    # Case 2: dns/dhcp-style record
    if "ipAddresses" in item and isinstance(item["ipAddresses"], list):
        # Filter out non-string values just in case
        return [ip for ip in item["ipAddresses"] if isinstance(ip, str)]

    # Case 3: no IP found
    return []

def normalize(records):
    out = []
    for item in records:
        ips = extract_ip(item)
        for ip in ips:
            out.append({**item, "ip": ip})
    return out

def get(data, keys, default=None):
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
        if current is None:
            return default
    return current

omada = Omada(
    baseurl="https://xxx.xxxx.xxx.xxx",
    username="admin",
    password="password",
    site='MySite',
    client_id="xxxxxxxxxxxxxx",
    client_secret="xxxxxx",
    omada_id="xxxxxxxxxxxxxxxxxxxxxx",
    debug =False,
    verify=False
)


api=f"/openapi/v2/{omada.omadac_id}/sites/{omada.site_id}/clients"
clients = omada.Commad(omada.mod.POST,api)['data']

api=f"/openapi/v1/{omada.omadac_id}/sites/{omada.site_id}/setting/lan/dns"
dns = omada.Commad(omada.mod.GET,api)['data']

api=f"/openapi/v1/{omada.omadac_id}/sites/{omada.site_id}/setting/service/dhcp"
dhcp = omada.Commad(omada.mod.GET,api)['data']

dns_by_ip = {item["ip"]: item for item in normalize(dns)}
dhcp_by_ip = {item["ip"]: item for item in normalize(dhcp)}
clients_by_ip = {item["ip"]: item for item in normalize(clients)}

all_ips = set(dns_by_ip) | set(dhcp_by_ip) | set(clients_by_ip)

merged = []
for ip in all_ips:
    merged.append({
        "ip": ip,
        "dns": dns_by_ip.get(ip),
        "dhcp": dhcp_by_ip.get(ip),
        "client": clients_by_ip.get(ip)
    })

for counter,f in enumerate( merged, start=1):
    try:
        #print(f['dns'].keys())
        pass
    except:
        pass
    res = f"IP {get(f,['ip'], default=""):>15}  DNS {get(f,['dns', 'ip'], default=''):>15}   {get(f,['dns', 'name'], default=''):>36}   DHCP{get(f,['dhcp', 'ip'], default=''):>15}  {get(f,['dhcp', 'name'], default=''):>24}    CLIENT{get(f,['client','ip'], default=""):>15}  {get(f,['client','name'], default=""):>18}  "
    print(res)

omada.Logout()

</pre>

