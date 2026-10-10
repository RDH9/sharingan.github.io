import nmap
import ipaddress

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
    for ip, value in scan_result.items():
        result["target"] = ip
        result["host_state"] = state = value["status"]["state"]["reason"]
        
        for port, port_info in value.get("tcp", {}).items():
            service = port_info["name"]
            port_state = port_info["state"]