import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from models import database, models
from app.modules import domain_intel, email_user_intel, get_location, meta_data
import streamlit as st
from sqlalchemy import select

#title
with st.container(gap = "xxsmall"):
    st.title(":red[Sharingan]")
    st.subheader("A OSINT Hub.")
    st.divider()

tab1, tab2, tab3, tab4, tab5 = st.tabs(["DOMAIN","BREACH","GEOLOCATION","EXIF METADATA","TBA"])

#Full domain lookup
with tab1:
    st.header("Full Domain Lookup")
    with st.container(horizontal=False):
        inp = st.text_input("Enter the domain", type="url")
        if st.button("search", width="stretch"):
            domain_intel.full_domain_lookup(inp)

    with database.SessionLocal() as session1:
        data = session1.execute(select(models.Investigation)).scalars().all()
        for d in data:
            #loops through the investigation findings
            finding_rows = [{"module": f.module_source, "data_type": f.data_type, "data": f.data} for f in d.inv]
            st.table(finding_rows)

#email breach
with tab2:
    st.header("Check for data breach")
    with st.container(horizontal=False):
        inp = st.text_input("Enter the email", type="email")
        if st.button("Enter Email", width="stretch"):
            results = email_user_intel.breach_check(inp)
            if results is None:
                st.info("No breaches found!")
            email_user_intel.full_breach_lookup(inp)
    with database.SessionLocal() as session2:
        data2 = session2.execute(select(models.Investigation)).scalars().all()
        for d in data2:
            findings_rows2 = [{"module": f.module_source, "data_type": f.data_type, "data": f.data} for f in d.inv]
            st.table(findings_rows2)
            
#geo-location
with tab3:
    st.header("Get Geo-Location")
    with st.container():
        inp = st.text_input("Enter IP Address")
        if st.button("Enter IP", width="stretch"):
            get_location.full_geo_lookup(inp)
    with database.SessionLocal() as session3:
        data3 = session3.execute(select(models.Investigation)).scalars().all()
        for d in data3:
            finding_rows3 = [{"module": f.module_source, "data_type": f.data_type, "data": f.data} for f in d.inv]
            st.table(finding_rows3)
            
#img metadata
with tab4:
    st.header("EXIF Metadata")
    with st.container():
        user_img = st.file_uploader("Choose a file", type="image", accept_multiple_files=True)
        meta_data.full_image_lookup(user_img)
    with database.SessionLocal() as session4:
        data4 = session4.execute(select(models.Investigation)).scalars().all()
        for d in data4:
            finding_rows4 = [{"module": f.module_source, "data_type": f.data_type, "data": f.data} for f in d.inv]
            st.table(finding_rows4)
        
        