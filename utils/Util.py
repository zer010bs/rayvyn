#!/usr/bin/env python3
import time
import simplejson as json
import requests

# __LINK__ = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz'
list_vendors = {"NIST": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
                "CISCO": "https://tools.cisco.com/security/center/cvrf_20.xml",
                'PALO': 'https://security.paloaltonetworks.com/rss.xml',
                'REDHAT': 'https://access.redhat.com/hydra/rest/securitydata/cve.json',
                'ORACLE': 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/5115881.xml'}

time_stamp = time.localtime(time.time())
c_year = time.strftime("%Y", time_stamp)
c_month = time.strftime("%m", time_stamp)
c_dt = time.strftime("%Y-%m-%d %H:%M", time_stamp)

keys = list(list_vendors.keys())


# file_index = 0

def write_file(file_name, resp):
    with open(file_name, "wb") as ow:
        for chunk in resp:
            ow.write(chunk)


def show_output(processed, new_added, changed, critical):
    print(str(processed) + ' Entries Processed | ' + str(new_added) + ' New Entries| ' + str(
        changed) + ' Changed | ' + str(critical) + ' Critical')
    print(str(new_added) + ' Comitted')
    print('=======================================')


def get_crit_desc(cve_d, feed):
    desc = ""
    if cve_d:
        for cve in cve_d:
            # this the magic sauce

            desc = desc + "\n [RVN]  %12s | %s %s | CVSS: %s | Severity: %s  |\n" % (
                cve_d[cve]["id"], cve_d[cve]["vendor"], cve_d[cve]["product"], cve_d[cve]["impact"],
                cve_d[cve]["severity"])
            desc = desc + " Feed  : %s\n" % ("".join(feed))
            #print(cve_d[cve]['feed'])
            if cve_d[cve]["vendor"] == "":
                desc = desc + " Vendors  : Not Available\n"
            else:
                desc = desc + " Vendors  : %s\n" % ("".join(cve_d[cve]["vendor"]))
            desc = desc + " Products : %s \n" % (" ".join(cve_d[cve]["product"]))
            try:
                desc = desc + " Vector   : %s \n" % (cve_d[cve]["cvss"]["attackVector"])
            except:
                desc = desc + " Vector   : Not Available\n"
            desc = desc + " Desc     : %s \n" % ("".join(cve_d[cve]["description"]))
            desc = desc + " CVSS     : %s\n" % (cve_d[cve]["cvss"])
            try:
                desc = desc + " Advisory Link     : %s \n" % (cve_d[cve]["link"])
            except:
                desc = desc + " Advisory Link     :  Not Available \n"

        return desc
        # print(keys[0])


def show_all_crit_ids(cve_list):
    print('\nAll Critical Cves with Ids are listed  below ')
    print(cve_list)


def show_all_change_ids(cve_list):
    print('\nAll Changed Cves with Ids are listed below')
    print(cve_list)


def get_file_form_links(links, file, file_index, format):
    for i in links:
        cve_response = requests.get(i)
        if cve_response.status_code == 200:
            write_file(file + str(file_index) + '.' + str(format), cve_response)
            file_index += 1
            time.sleep(float(cve_response.elapsed.seconds))


def check_for_critical(cve_all, cve_d, critical, critical_cves, critical_cves_list,vendor):
    try:
        if (float(cve_all[cve_d]["impact"]) >= 7.5 or cve_all[cve_d]["severity"] in ('CRITICAL', 'HIGH')) \
                and (cve_all[cve_d]["cvss"]["attackVector"] == "NETWORK"
                     and cve_all[cve_d]["cvss"]["userInteraction"] == "NONE" and cve_all[cve_d]["cvss"][
                         "privilegesRequired"] == "NONE"):
            critical += 1
            critical_cves[cve_all[cve_d]['id']] = cve_all[cve_d]
            #critical_cves[cve_all[cve_d]['feed'] = cve_all[vendor]
            critical_cves_list.append(cve_all[cve_d]['id'])
    except:
        if float(cve_all[cve_d]["impact"]) >= 7.5:
            critical_cves[cve_all[cve_d]['id']] = cve_all[cve_d]
            critical += 1
            critical_cves_list.append(cve_all[cve_d]['id'])

    return critical


def load_json(file):
    with open(file, "rb") as out_json:
        json_obj = out_json.read()
        json_string = json.loads(json_obj)
        return json_string
