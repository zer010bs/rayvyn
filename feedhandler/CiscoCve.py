#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from utils.Util import list_vendors, c_year, c_month, write_file, get_file_form_links


def get_cisco_data():
    file_name = "raw/CISCO-CVE-%s-%s.xml" % (c_year, c_month)
    file = 'raw/cve'
    links = []
    cve_all = {}
    file_index = 0

    try:
        resp = requests.get(list_vendors['CISCO'])
        if resp.status_code == 200:
            write_file(file_name, resp)

        mytree = ET.parse(file_name)
        root = mytree.getroot()
        for x in root[0].findall('item'):
            links.append(x.find('link').text)

        get_file_form_links(links, file, file_index, 'xml')

        for i in range(len(links)):
            cve_d = {}
            my_sub_tree = ET.parse(file + str(i) + '.xml')
            sub_root = my_sub_tree.getroot()

            for vul in sub_root.findall('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}Vulnerability'):

                try:
                    cve_d["id"] = vul.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}CVE').text
                except:
                    cve_d["id"] = None
                try:
                    scr = vul.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}CVSSScoreSets')[0]
                except:
                    scr = ""
                try:
                    ref = vul.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}References')[0]
                    cve_d['description'] = ref.find(
                        '{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}Description').text
                except:
                    cve_d['description'] = ""
                try:
                    cve_d["impact"] = scr.find(
                        '{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}BaseScoreV3').text
                    # print(scr.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}BaseScoreV3').text)
                except:
                    cve_d["impact"] = 0.0

                try:
                    cve_d["vector"] = scr.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln}VectorV3').text
                except:
                    cve_d["vector"] = "LOCAL"

            for date in sub_root.findall('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}DocumentTracking'):
                try:
                    cve_d['last_modified'] = date.find(
                        '{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}CurrentReleaseDate').text
                    cve_d['created'] = date.find(
                        '{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}InitialReleaseDate').text
                except:
                    cve_d['last_modified'] = ""
                    cve_d['created'] = ""
            for url in sub_root.findall('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}DocumentReferences')[0]:
                try:
                    cve_d['link'] = url.find('{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}URL').text
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
    except :
        print('Error In Cisco Feed')