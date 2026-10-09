import whois
import streamlit as st
from app.models import database, models
import dns.resolver
import json, requests

#WHOIS
def get_whois_info(domain: str):
    try:
        info = whois.whois(domain)
        return info
    except Exception as e:
        print(f"Error retrieving WHOIS information. {e}")
        return None


def whois_to_findings(whois_result):
    try:
        findings = []
        fields = ["domain_name", "registrar", "updated_date", "creation_date", "expiration_date", "name_servers", "status", "emails", "dnssec", "org", "country"]
        for f in fields:
            value = getattr(whois_result, f, None)
            if value is None:
                continue
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            #key dict
            findings.append({"module_source": "whois", "data_type": f, "data": str(value), "source": "whois lookup"})
        return findings
    except Exception as e:
        print(f"Error retrieving WHOIS information: {e}")
        return None

#DNS
def get_dns_records(domain: str):
    records = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SOA", "SRV"]
    findings = {}
    for r in records:
        try:
            data = dns.resolver.resolve(domain, r)
            # converts collection of dns objects into clean strings. and saves them in a dict.
            findings[r] = [str(d) for d in data]
        except (dns.resolver.NoAnswer):
            print(f"Didn't find record {r}")
        except (dns.resolver.NXDOMAIN):
            print(f"The domain {domain} doesn't exist.")
        except Exception as e:
            print("Error!")
    return findings

def dns_to_findings(dns_result):
    findings = []
    try:
        for record_type, data in dns_result.items():
            for d in data:
                findings.append({"module_source": "DNS", "data_type": record_type, "data": str(d), "source": "dns lookup"})
        return findings
    except Exception as e:
        print("Error!")

def get_subdomains(domain: str):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for x in data:
                names = x.get('name_value', '').split('\n')
                for name in names:
                    n = name.replace('*.', '')
                    subdomains.add(n)
            return sorted(list(subdomains))
        else:
            return []
    except Exception as e:
        print(f"Error getting subdomains data. {e}")
        return []

def subdomains_to_findings(subdomain_result):
    findings = []
    try:
        for d in subdomain_result:
            findings.append({"module_source": "subdomain enum", "data_type": "subdomain", "data": str(d), "source": "crt.sh"})
        return findings
    except Exception as e:
        print(f"Error with subdomains: {e}")

#full domain lookup function
def full_domain_lookup(domain: str):
    data = get_whois_info(domain)
    findings = whois_to_findings(data)
    data_2 = get_dns_records(domain)
    findings_2 = dns_to_findings(data_2)
    data_3 = get_subdomains(domain)
    findings_3 = subdomains_to_findings(data_3)
    all_findings = findings + findings_2 + findings_3
    with database.SessionLocal() as session:
        inv = models.Investigation(name=domain, target=domain)
        for f in all_findings:
            find = models.Finding(module_source=f["module_source"], data_type=f["data_type"], data=f["data"], source=f["source"])
            inv.inv.append(find)
        session.add(inv)
        session.commit()
