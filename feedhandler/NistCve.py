#!/usr/bin/env python3

import requests
import gzip
from cpe import CPE
import simplejson as json
from utils.Util import c_year, c_month, list_vendors, write_file


def get_nist_cve():

    file_name = "raw/NIST-CVE-%s-%s.json.gz" % (c_year, c_month)
    cve_all = {}
    try:
        resp = requests.get(list_vendors['NIST'])
        if resp.status_code == 200:
            write_file(file_name, resp)
        # Reading the file through json
        with gzip.open(file_name, "rb") as out_json:
            json_obj = out_json.read()
            json_string = json.loads(json_obj)

        for cve in json_string["CVE_Items"]:
            cve_d = {}
            cve_d["id"] = cve["cve"]["CVE_data_meta"]["ID"]
            try:
                cve_d["impact"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            except:
                cve_d["impact"] = 0.0

            try:
                cve_d["vector"] = cve["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
            except:
                cve_d["vector"] = "LOCAL"

            try:
                cve_d["severity"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                cve_d["cvss"] = cve["impact"]["baseMetricV3"]["cvssV3"]
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
                cve_d["references"] = cve["cve"]["references"]["reference_data"]
            except:
                cve_d["references"] = []
            # vendor
            vendor = []
            product = []
            cpe = []
            try:
                for node in cve["configurations"]["nodes"]:
                    # ~ print(node)
                    for match in node["cpe_match"]:
                        vuln = match["vulnerable"]
                        if vuln == True:
                            cpe_parse = CPE(match["cpe23Uri"])
                            for v in cpe_parse.get_vendor():
                                if v not in vendor:
                                    vendor.append(v)
                            for p in cpe_parse.get_product():
                                if p not in product:
                                    product.append(p)
                            cpe.append(node["cpe_match"])
            except:
                pass
            cve_d["cpe"] = cpe
            cve_d["product"] = product
            cve_d["vendor"] = vendor
            try:
                desc = []
                for d in cve["cve"]["description"]["description_data"]:
                    desc.append(d["value"])
                cve_d["description"] = desc

            except:

                cve_d["description"] = []
            cve_d["created"] = cve["publishedDate"]
            cve_d["last_modified"] = cve["lastModifiedDate"]

            cve_d['link'] = "[]"
            cve_all[cve_d["id"]] = cve_d
        return cve_all
    except:
        print('Error In NIST Feed')
