#!/usr/bin/env python3
from dbhandler.CveHandler import add_all_to_db
from feedhandler.RedhatCve import get_redhat_data
from feedhandler.OracleCve import get_orc_data

from utils.Util import c_dt

#get_cisco_data()
print('----------------------')
print(c_dt)
print('Collecting Data...')
#send_alert("",1)
#get_palo_data()
#print(get_forti_data())
#get_orc_data()
add_all_to_db()

#print(get_redhat_data())
#get_nist_cve()
#print(get_crit_desc(get_cisco_data()))
