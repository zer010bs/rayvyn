#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET
from utils.Util import list_vendors, c_year, c_month, write_file, get_file_form_links


# still to do! gotta get rid of over-lapping code

def get_orc_data():
    file_name = "raw/ORACLE-CVE-%s-%s.xml" % (c_year, c_month)
    file = 'raw/cve'
    links = []
    cve_all = {}
    file_index = 0

    try:
        resp = requests.get(list_vendors['ORACLE'])
        if resp.status_code == 200:
            write_file(file_name, resp)

        my_sub_tree = ET.parse(file_name)
        sub_root = my_sub_tree.getroot()
        print(sub_root)
        for vul in sub_root.findall('{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability'):
            cve_d = {}
            try:
                cve_d["id"] = vul.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}CVE').text
            except:
                cve_d["id"] = None
            try:
                scr = vul.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}CVSSScoreSets')[0]
            except:
                scr = ""
            try:
                ref = vul.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}References')[0]
                cve_d['description'] = ref.find(
                    '{http://www.icasi.org/CVRF/schema/vuln/1.1}Description').text
            except:
                cve_d['description'] = ""
            try:
                cve_d["impact"] = scr.find(
                    '{http://www.icasi.org/CVRF/schema/vuln/1.1}BaseScore').text
                # print(scr.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}BaseScoreV3').text)
            except:
                cve_d["impact"] = 0.0

            try:
                cve_d["vector"] = scr.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}Vector').text
            except:
                cve_d["vector"] = "LOCAL"

            for date in sub_root.findall('{http://www.icasi.org/CVRF/schema/vuln/1.1}DocumentTracking'):
                try:
                    cve_d['last_modified'] = date.find(
                        '{http://www.icasi.org/CVRF/schema/vuln/1.1}CurrentReleaseDate').text
                    cve_d['created'] = date.find(
                        '{http://www.icasi.org/CVRF/schema/vuln/1.1}InitialReleaseDate').text
                except:
                    cve_d['last_modified'] = ""
                    cve_d['created'] = ""
            for url in sub_root.findall('{http://www.icasi.org/CVRF/schema/vuln/1.1}DocumentReferences')[0]:
                try:
                    cve_d['link'] = url.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}URL').text
                except:
                    cve_d['link'] = "[]"

            cve_d['severity'] = ""
            cve_d['references'] = ""
            cve_d['cpe'] = ""
            cve_d['vendor'] = ""
            cve_d['cvss'] = ""
            cve_d['product'] = ""
            if cve_d['id'] is not None:
                cve_all[cve_d["id"]] = cve_d
        return cve_all
    except:
        print('Oracle Feed Error')
