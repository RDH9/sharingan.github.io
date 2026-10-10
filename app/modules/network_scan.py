import nmap
import ipaddress
import json
from app.models import database, models

def validate_ip(ip_addr: str):
    result = {}
    if ip_addr is None or not isinstance(ip_addr, str):
        result["valid"] = False
        result["address"] = None
        result["scope"] = None
        result["reason"] = "No ip address"
        return result
    data = ip_addr.strip()
    try:
        address = ipaddress.ip_address(data)
    except ValueError:
        result["valid"] = False
        result["address"] = None
        result["scope"] = None
        result["reason"] = "invalid text"
        return result
    if address.is_multicast or address.is_unspecified or address.is_link_local or address.is_loopback or address.is_reserved or address.version != 4:
        result["valid"] = False
        result["address"] = str(address)
        result["scope"] = None
        result["reason"] = "invalid ip address"
        return result
    elif address.is_global:
        result["valid"] = True
        result["address"] = str(address)
        result["scope"] = "external"
    elif address.is_private:
        result["valid"] = True
        result["address"] = str(address)
        result["scope"] = "internal"
    elif address in ipaddress.ip_network("100.64.0.0/10"):
        result["valid"] = False
        result["address"] = str(address)
        result["scope"] = None
        result["reason"] = "shared address space"
        return result
    return result

    
def network_scan(ip_addr: str):
    valid_ip = validate_ip(ip_addr)
    try:
        if not isinstance(valid_ip, dict) or not valid_ip.get("valid"):
            return None
        nm = nmap.PortScanner()
        result = nm.scan(valid_ip["address"], "21-8080", arguments="-sV --version-light -T3 --reason -n")
        return result
    except nmap.PortScannerError:
        print("portscanner error")
        return None

def parse_scan_result(scan_result):
    result = {}
    hosts = scan_result.get("scan", {})
    for ip, value in hosts.items():
        host_data = {
            "target": ip,
            "host_state": value["status"]["state"],
            "hosts_reason": value["status"].get("reason"),
            "ports": []
        }
        
        for port, port_info in value.get("tcp", {}).items():
            service = port_info["name"]
            port_state = port_info["state"]
            port_data = {
                "port": port,
                "protocol": "tcp",
                "state": port_info.get("state"),
                "service": port_info.get("name"),
                "product": port_info.get("version"),
                "reason": port_info.get("reason"),
                "cpe": port_info.get("cpe")
            }
            host_data["ports"].append(port_data)
        result = host_data
    return result

def nmap_to_findings(parsed_data):
    serialized_data = json.dumps(parsed_data)
    findings = []
    findings.append({"module_source": "nmap", "data_type": "host_info", "data": serialized_data, "source": "nmap network scan"})
    return findings

def full_nmap_scan(ip_addr: str):
    data = network_scan(ip_addr)
    if data is None:
        return None
    parse_data = parse_scan_result(data)
    if not isinstance(parse_data, dict) or not parse_data.get("target"):
        return None
    findings = nmap_to_findings(parse_data)
    with database.SessionLocal() as session:
        inv = models.Investigation(name="network_scan", target=parse_data["target"])
        for f in findings:
            find = models.Finding(module_source=f["module_source"], data_type=f["data_type"], data=f["data"], source=f["source"])
            inv.inv.append(find)
        session.add(inv)
        session.commit()
