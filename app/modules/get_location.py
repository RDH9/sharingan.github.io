
import requests
import ipaddress
from app.models import database, models
import json

# returns a string or none
def validate(ip_addr: str):
    if ip_addr is None or not isinstance(ip_addr, str):
        return None
    data = ip_addr.strip()
    try:
        address = ipaddress.ip_address(data)
    except ValueError as e:
        print(f"error reading ip address. {e}")
        return None
    if address.is_private or address.is_multicast or address.is_unspecified or address.is_link_local or address.is_loopback or address.is_reserved:
        return None
    return str(address)

#returns a dict or none
def get_location(ip_addr: str):
    try:
        address = validate(ip_addr)
        if address is None:
            return None
        url = f"http://ip-api.com/json/{address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        results = response.json()
        if not isinstance(results, dict):
            print("unexpected JSON format from API. Expected Dict.")
            return None
        return results
    except requests.Timeout:
        print("timeout error")
        return None
    except requests.exceptions.JSONDecodeError:
        print("JSON is invalid!")
        return None
    except requests.RequestException:
        print("network error")
        return None
    
def geo_to_finding(get_geo_result):
    findings = []
    if get_geo_result is None or not isinstance(get_geo_result, dict):
        return []
    if get_geo_result.get("status") == "success":
        data = {"country": get_geo_result.get("country"), "region": get_geo_result.get("regionName"), "city": get_geo_result.get("city"), "isp": get_geo_result.get("isp"), "org": get_geo_result.get("org"), "as": get_geo_result.get("as"), "query" : get_geo_result.get("query")}
        serialized_data = json.dumps(data)
        findings.append({"module_source": "geo-location", "data_type": "location details", "data": serialized_data, "source": "ip-api"})
    return findings
   
def full_geo_lookup(ip_addr: str):
    data = get_location(ip_addr)
    findings = geo_to_finding(data)
    with database.SessionLocal() as session:
        inv = models.Investigation(name="geo-location", target=ip_addr)
        for f in findings:
            find = models.Finding(module_source=f["module_source"], data_type=f["data_type"], data=f["data"], source=f["source"])
            inv.inv.append(find)
        session.add(inv)
        session.commit()
        

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        