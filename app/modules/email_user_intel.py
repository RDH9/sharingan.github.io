from xposedornot import XposedOrNot, NotFoundError, ValidationError
from app.models import database, models
import streamlit as st

def breach_check(user_in :str):
    try:
        xon = XposedOrNot()
        result = xon.check_email(user_in, include_details=True) 
        if result.status == "fail":
            return None 
        return result
    except NotFoundError:
        return None

    except ValidationError:
        return None

def to_findings(breach_result):
    findings = []
    breaches = breach_result.breaches
    for breach in breaches:
        findings.append({"module_source": "xposedornot", "data_type": "breach", "data": str(breach), "source": "xposedornot"})
    return findings

def full_breach_lookup(email: str):
    data = breach_check(email)
    findings = to_findings(data)
    with database.SessionLocal() as session:
        inv = models.Investigation(name = email, target = email)
        for f in findings:
            find = models.Finding(module_source=f["module_source"], data_type=f["data_type"], data=f["data"], source=f["source"])
            inv.inv.append(find)
        session.add(inv)
        session.commit()
    

