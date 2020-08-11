#!/usr/bin/env python3
import requests
from utils.Util import list_vendors, c_year, c_month, write_file,load_json


def get_redhat_data():
    file_name = "raw/REDHAT-CVE-%s-%s.json" % (c_year, c_month)
    cve_all = {}
    # Writing from response to local
    try:
        resp = requests.get(list_vendors['REDHAT'])
        if resp.status_code == 200:
            write_file(file_name, resp)

        json_string = load_json(file_name)
        for cve in json_string:
            cve_d = {}
            cve_d["id"] = cve["CVE"]
            try:
                cve_d["impact"] = cve["cvss3_score"]
            except:
                cve_d["impact"] = 0.0

            try:
                cve_d["vector"] = cve["cvss3_scoring_vector"]
            except:
                cve_d["vector"] = "LOCAL"

            try:
                cve_d["severity"] = cve["severity"]
                cve_d["cvss"] = ""
            except:
                cve_d["severity"] = "MEDIUM"
                cve_d["cvss"] = ""
            try:
                cve_d["references"] = []
            except:
                cve_d["references"] = []
            # vendor
            vendor = []
            product = []
            cpe = []

            cve_d["cpe"] = cpe
            cve_d["product"] = product
            cve_d["vendor"] = vendor
            try:
                cve_d["description"] = cve['bugzilla_description']

            except:

                cve_d["description"] = []
            cve_d["created"] = cve["public_date"]
            cve_d["last_modified"] = ""
            try:
                cve_d['link'] = cve['resource_url']
            except:
                cve_d['link'] = []
            cve_all[cve_d["id"]] = cve_d

        return cve_all
    except:
        print('Error In RedHat Feed')