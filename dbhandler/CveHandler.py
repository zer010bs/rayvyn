#!/usr/bin/env python3

from Model import db
from Model import Cve, History
from feedhandler.NistCve import get_nist_cve
from feedhandler.CiscoCve import get_cisco_data
from feedhandler.PaloAltoCve import get_palo_data
from feedhandler.RedhatCve import get_redhat_data
import time
from utils.Util import show_output, get_crit_desc,show_all_change_ids,show_all_crit_ids,check_for_critical
from alertHandlers.EmailAlert import send_alert
import simplejson as json


def add_all_to_db():

    critical_cves_list = []
    changed_cves_list = []
    critical_cves = {}
    cric_desc = []
    curr_vendor = ""

    cve_data = {'nist': get_nist_cve(), 'cisco': get_cisco_data(), 'paloalto': get_palo_data(), 'redhat': get_redhat_data()}

    # debugging only
    #~ cve_data = {'nist': get_nist_cve() }
    for vendor in cve_data:
        print('Adding data from ' + str(vendor).capitalize())
        curr_vendor = str(vendor).capitalize()
        cve_all = cve_data[vendor]

        new_added = 0
        changed = 0
        critical = 0
        try:
            for cve_d in cve_all:
                i_no = db.session.query(Cve).filter(Cve.cve_id == cve_all[cve_d]["id"], Cve.active == 1, Cve.list_vendors == str(vendor)).first()
                if i_no:
                    if i_no.last_modified == cve_all[cve_d]["last_modified"]:  # same cve
                        continue
                    else:
                        try:
                            prev_date = History(i_no.last_modified, i_no.id)
                            # print(cve_all[cve_d]["lastModifiedDate"])
                            i_no.last_modified = cve_all[cve_d]["last_modified"]
                            #print("[-] CVE is changed %s" % cve_all[cve_d]["id"])
                            db.session.add(prev_date)
                            changed += 1
                            changed_cves_list.append(cve_all[cve_d]["id"])
                        except:
                            #print('couldnt add')
                            continue
                else:
                    # print('adding')

                    new_item = Cve(
                        cve_id=cve_all[cve_d]["id"],
                        created=cve_all[cve_d]['created'],
                        last_modified=cve_all[cve_d]["last_modified"],
                        description=json.dumps(cve_all[cve_d]["description"]),
                        severity=cve_all[cve_d]["severity"],
                        impact=cve_all[cve_d]["impact"],
                        raw="",
                        active=1,
                        references=json.dumps(cve_all[cve_d]["references"]),
                        vector=cve_all[cve_d]["vector"],
                        vendor=json.dumps(cve_all[cve_d]["vendor"]),
                        product=json.dumps(cve_all[cve_d]["product"]),
                        cpe=json.dumps(cve_all[cve_d]["cpe"]),
                        cvss=json.dumps(cve_all[cve_d]["cvss"]),
                        list_vendors=str(vendor),
                        advisory_link=cve_all[cve_d]['link']
                    )
                    db.session.add(new_item)
                    new_added += 1

                critical = check_for_critical(cve_all, cve_d, critical, critical_cves, critical_cves_list, str(vendor))
                #print(critical_cves[cve_d]['feed'])
               # cric_desc.append("".join(get_crit_desc(critical_cves, str(vendor).capitalize())))
            processed = len(cve_all)
            db.session.commit()
            show_output(processed, new_added, changed, critical)
        except:
            print('\n + Endpoint Error + for ' + str(vendor) + '\n')
    #print(str(cric_desc))
    if len(critical_cves_list) >= 1:
        show_all_crit_ids(critical_cves_list)
    if len(changed_cves_list) >= 1:
        show_all_change_ids(changed_cves_list)
    if len(critical_cves) >= 1:
        try:
          send_alert(get_crit_desc(critical_cves, ''), len(critical_cves))
        except:
          print('Cves Commited to database but not sent')
    else:
        print('No Critical Cve to send')
    time.sleep(0.5)
