#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from utils.Util import list_vendors, c_year, c_month, write_file, get_file_form_links,load_json

def get_palo_data():
    file_name = "raw/PaloAlto-CVE-%s-%s.xml" % (c_year, c_month)
    file = 'raw/cve'

    links = []
    cve_all = {}
    file_index = 0

    try:
        resp = requests.get(list_vendors['PALO'])
        if resp.status_code == 200:
            write_file(file_name, resp)

        mytree = ET.parse(file_name)
        root = mytree.getroot()
        for x in root[0].findall('item'):
            st = str(x.find('link').text)
            n = st.split('m/')
            link = n[0] + 'm/json/' + n[1]
            links.append(link)
        # print(len(links))

        get_file_form_links(links, file, file_index, 'json')

        for i in range(len(links)):
            cve = load_json(file + str(i) + '.json')
            # for cve in json_string:
            cve_d = {}
            cve_d['id'] = cve["CVE_data_meta"]["ID"]
            # print(cve_d['id'])
            try:
                cve_d["impact"] = cve["impact"]["cvss"]["baseScore"]
            except:
                cve_d["impact"] = 0.0

            try:
                cve_d["vector"] = cve["impact"]["cvss"]["attackVector"]
            except:
                cve_d["vector"] = "LOCAL"

            try:
                cve_d["severity"] = cve["impact"]["cvss"]["baseSeverity"]
                cve_d["cvss"] = cve["impact"]["cvss"]
            except:
                cve_d["severity"] = "MEDIUM"
                cve_d["cvss"] = {
                    "version": "3.1",
                    "vectorString": "",
                    "attackVector": "LOCAL",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "LOW",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "LOW",
                    "baseScore": 0.0,
                    "baseSeverity": "LOW"
                }

            try:
                cve_d["references"] = cve["references"]["reference_data"]
            except:
                cve_d["references"] = []

            # vendor
            vendor = []
            product = []
            cpe = []
            try:
                for node in cve["affects"]["vendor"]["vendor_data"]:
                    vendor = node['vendor_name']
            except:
                pass
            cve_d["cpe"] = cpe
            cve_d["product"] = product
            cve_d["vendor"] = vendor
            try:
                desc = []
                for d in cve["description"]["description_data"]:
                    desc.append(d["value"])
                cve_d["description"] = desc

            except:

                cve_d["description"] = []
            cve_d["created"] = cve["CVE_data_meta"]["DATE_PUBLIC"]
            cve_d["last_modified"] = cve["CVE_data_meta"]["DATE_PUBLIC"]

            cve_d['link'] = "[]"
            cve_all[cve_d["id"]] = cve_d
        return cve_all
    except:
        print('Error In PaloAlto Feed')