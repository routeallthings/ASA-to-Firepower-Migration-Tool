#!/usr/bin/env python
'''
---AUTHOR---
Name: Matt Cross
Email: routeallthings@gmail.com

---PREREQ---
INSTALL CISCOCONFPARSE (pip install ciscoconfparse==1.2.38)
INSTALL REQUESTS (pip install requests)

---VERSION---
VERSION 1.3
Currently Implemented Features
- Import of Network Objects
- Import of Network Object Groups* (Except groups inside groups)
- Import of Ports
- Import of Port Groups


Features planned in the near future
- NAT
- Routes
- Import of ACL
- Import of Network groups inside Network groups

'''

'''IMPORT MODULES'''
import getpass
import os
import re
try:
	import requests
except ImportError:
	requestsinstallstatus = fullpath = raw_input ('Requests module is missing, would you like to automatically install? (Y/N): ')
	if "Y" in requestsinstallstatus or "y" in requestsinstallstatus or "yes" in requestsinstallstatus or "Yes" in requestsinstallstatus or "YES" in requestsinstallstatus:
		os.system('python -m pip install requests')
		import requests
	else:
		print "You selected an option other than yes. Please be aware that this script requires the use of Requests. Please install manually and retry"
		sys.exit()
from requests.auth import HTTPDigestAuth
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import sys
import csv
import urllib2
import time

try: 
	from ciscoconfparse import CiscoConfParse
except ImportError:
	ciscoconfparseinstallstatus = fullpath = raw_input ('CiscoConfParse module is missing, would you like to automatically install? (Y/N): ')
	if "Y" in ciscoconfparseinstallstatus or "y" in ciscoconfparseinstallstatus or "yes" in ciscoconfparseinstallstatus or "Yes" in ciscoconfparseinstallstatus or "YES" in ciscoconfparseinstallstatus:
		os.system('python -m pip install CiscoConfParse')
		from ciscoconfparse import CiscoConfParse
	else:
		print "You selected an option other than yes. Please be aware that this script requires the use of CiscoConfParse. Please install manually and retry"
		sys.exit()
'''GLOBAL VARIABLES'''

fullpath = raw_input ('Enter the file path of the ASA config: ')
importnetworkobjectsq = raw_input ('Do you want to import Network Objects? (Y/N): ')
importserviceobjectsq = raw_input ('Do you want to import Port Objects? (Y/N): ')
'''importaclq = raw_input ('Do you want to import ACL rules? IN DEVELOPMENT (Y/N): ')'''
importaclq = 'N'
if "Y" in importaclq or "y" in importaclq or "yes" in importaclq or "Yes" in importaclq or "YES" in importaclq:
	importaclnameq = ('Enter a name for the ACL that will show up in Firepower Management Center: ')
fullpath = raw_input ('Enter the file path of the ASA config: ')
fmcpathfull = raw_input ('Enter the IP address of the destination FMC: ')
fmcpath = "https://" + fmcpathfull
fmcuser = raw_input ('Enter the username of the destination FMC: ')
fmcpassword = getpass.getpass('Enter the password of the destination FMC: ')
debugmode = raw_input ('Debug Mode? (Y/N): ') 
csvpath = 'https://raw.githubusercontent.com/routeallthings/ASA-to-Firepower-Migration-Tool/master/PortList.csv'

'''NOT IMPLEMENTED'''
'''importnatq = raw_input ('Do you want to import NAT rules (Y/N): ')'''


'''##### BEGIN SCRIPT #####'''
'''Print Variables in Debug'''
if debugmode == 'Y' or debugmode == 'y':
	print ""
	print "BEGIN -- GLOBAL VARIABLES"
	print "ImportNetworkObjectsq = " + importnetworkobjectsq
	print "ImportServiceObjectsq = " + importserviceobjectsq
	print "ImportACLq = " + importaclq
	print "ImportACLnameq = " + importaclnameq
	print "Fullpath = " + (fullpath.encode('string-escape'))
	print "FMCpath = " + fmcpath
	print "FMCuser = " + fmcuser
	print "FMCpassword = " + fmcpassword
	print "END -- GLOBAL VARIABLES"
	print ""
'''	print "ImportNATq = " + importnatq '''

'''Firepower MGMT Connect '''
fmctokenurl = "https://" + fmcpath + "/api/fmc_platform/v1/auth/generatetoken"
headers = {'Content-Type': 'application/json'}
fmc_api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
fmc_auth_url = fmcpath + fmc_api_auth_path
try:
    # Download SSL certificates from your FMC first and provide its path for verification.
    r = requests.post(fmc_auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(fmcuser,fmcpassword), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        print(auth_headers)
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
headers['X-auth-access-token']=auth_token

fmcnetobjecturl = fmcpath + "/api/fmc_config/v1/domain/default/object/networks"
if (fmcnetobjecturl[-1] == '/'):
    fmcnetobjecturl = fmcnetobjecturl[:-1]
fmchostsobjecturl = fmcpath + "/api/fmc_config/v1/domain/default/object/hosts"
if (fmchostsobjecturl[-1] == '/'):
    fmchostsobjecturl = fmchostsobjecturl[:-1]
fmcrangesobjecturl = fmcpath + "/api/fmc_config/v1/domain/default/object/ranges"
if (fmcrangesobjecturl[-1] == '/'):
    fmcrangesobjecturl = fmcrangesobjecturl[:-1]
fmcnetobjectgroupurl = fmcpath + "/api/fmc_config/v1/domain/default/object/networkgroups"
if (fmcnetobjectgroupurl[-1] == '/'):
    fmcnetobjectgroupurl = fmcnetobjectgroupurl[:-1]
fmcportobjecturl = fmcpath + "/api/fmc_config/v1/domain/default/object/protocolportobjects"
if (fmcportobjecturl[-1] == '/'):
    fmcportobjecturl = fmcportobjecturl[:-1]
fmcportsurl = fmcpath + "/api/fmc_config/v1/domain/default/object/ports"
if (fmcportsurl[-1] == '/'):
    fmcportsurl = fmcportsurl[:-1]
fmcportgroupurl = fmcpath + "/api/fmc_config/v1/domain/default/object/portobjectgroups"
if (fmcportgroupurl[-1] == '/'):
    fmcportgroupurl = fmcportgroupurl[:-1]
fmcaccesspolicyurl = fmcpath + "/api/fmc_config/v1/domain/default/policy/accesspolicies"
if (fmcaccesspolicyurl[-1] == '/'):
    fmcaccesspolicyurl = fmcaccesspolicyurl[:-1]
fmczoneobjecturl = fmcpath + "/api/fmc_config/v1/domain/default/object/securityzones"
if (fmczoneobjecturl[-1] == '/'):
    fmczoneobjecturl = fmczoneobjecturl[:-1]

	
'''Create Regex Matches'''
ipv4_address = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
	
''' Loading Network Objects and Groups '''
asaconfig = CiscoConfParse(fullpath)
objectnetwork = asaconfig.find_objects(r"^object network")
objectnetworkgroup = asaconfig.find_objects(r"^object-group network")
objectservice = asaconfig.find_objects(r"^object service")
objectservicegroup = asaconfig.find_objects(r"^object-group service")
objectprotocolgroup = asaconfig.find_objects(r"^object-group protocol")
aclinterfacelist = asaconfig.find_objects(r"^access-group")


'''SECTION: Import Object Network '''
if "Y" in importnetworkobjectsq or "y" in importnetworkobjectsq or "yes" in importnetworkobjectsq or "Yes" in importnetworkobjectsq or "YES" in importnetworkobjectsq:
	for specificobjectnetwork in objectnetwork:
		objectnetwork_before = specificobjectnetwork.text
		objectnetworkname = objectnetwork_before[len('object network '):]
		objectnetworkname = objectnetworkname.lstrip()
		for objectnetworkchild in specificobjectnetwork.children:
			objectnetworkchild_before = objectnetworkchild.text
			if "host" in objectnetworkchild_before:
				objectnetworkip = objectnetworkchild_before[len('host '):]
				objectnetworkip = objectnetworkip.lstrip()
			if "range" in objectnetworkchild_before:
				objectnetworkip = objectnetworkchild_before[len('range '):]
				objectnetworkip = objectnetworkip.lstrip()
			if "subnet" in objectnetworkchild_before:
				objectnetworkip_b1 = objectnetworkchild_before[len('subnet '):]
				objectnetworkip_b1 = objectnetworkip_b1.lstrip()
				objectnetworkip_network = objectnetworkip_b1.split(" ")[:1][0]
				if ipv4_address.match(objectnetworkip_network):
					'''Match IPv4 against a regex and convert the subnet portion to CIDR for the import process'''
					objectnetworkip_subnet = objectnetworkip_b1.split(" ")[1:][0]
					objectnetworkip_cidr = sum([bin(int(x)).count("1") for x in objectnetworkip_subnet.split(".")])
					objectnetworkip = objectnetworkip_network + "/" + str(objectnetworkip_cidr)
				else:
					'''For all matches on IPv6 as its only a single line'''
					objectnetworkip = objectnetworkip_network
			if "description" in objectnetworkchild_before:
				objectnetworkdescription = objectnetworkchild_before[len('description '):]
				objectnetworkdescription = objectnetworkdescription.lstrip()
			if not "description" in objectnetworkchild_before:
				objectnetworkdescription = "Imported Object"
		fmcpostdata = {
			"name" : objectnetworkname,
			"description" : objectnetworkdescription,
			"value" : objectnetworkip
		}
		try:
			r = requests.post(fmcnetobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.post(fmcnetobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
				status_code = r.status_code
			resp = r.text
			if status_code == 201 or status_code == 202:
				print ("The following object was successfully imported: " + fmcpostdata["name"])
			else :
				r.raise_for_status()
				print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
		except requests.exceptions.HTTPError as err:
			if status_code == 400:
				print "Object " + objectnetworkname + " might already exist. Error code 400"
			else :
				print ("Error in connection to the server: "+str(err))	
		finally:
			if r : r.close()
		if debugmode == 'Y' or debugmode == 'y':	
			print " "
			print "Object Network Name " + objectnetworkname
			print "Object Network IP " + objectnetworkip
			print "Object Network Description " + objectnetworkdescription
			print " "
	'''SECTION: Import Object Network Group '''
	'''Get list of existing objects'''
	try:
		r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Network Objects Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''get host objects and merge into primary list to get uuid'''
	try:
		r = requests.get(fmchostsobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmchostsobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Host objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Hosts Objects Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Host objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''get ranges objects and merge into primary list to get uuid'''
	try:
		r = requests.get(fmcrangesobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcrangesobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Range objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Range Objects Successful."
			#print("GET successful. Response data --> ")
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Range objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()

	for specificobjectnetworkgroup in objectnetworkgroup:
		objectnetworkgroup_objectlist = []
		objectnetworkgroup_literallist = []
		objectnetworkgroup_before = specificobjectnetworkgroup.text
		objectnetworkgroupname = objectnetworkgroup_before[len('object network-group '):]
		objectnetworkgroupname = objectnetworkgroupname.lstrip()
		for objectnetworkgroupchild in specificobjectnetworkgroup.children:
			objectnetworkgroupchild_b1 = objectnetworkgroupchild.text
			objectnetworkgroupchild_b2 = objectnetworkgroupchild_b1.replace("network-object ", "")
			if "object" in objectnetworkgroupchild_b2:
				objectnetworkgroupchild_name = objectnetworkgroupchild_b2[len('object '):]
				objectnetworkgroupchild_name = objectnetworkgroupchild_name.lstrip()
				try:
					objectnetworkgroupchild_id = next(item for item in objectnetworkgroup_fullobjectlist if item.get("name") == objectnetworkgroupchild_name.lower() or item.get("name") == objectnetworkgroupchild_name.upper() or item.get("name") == objectnetworkgroupchild_name)
					objectnetworkgroupchild_type = objectnetworkgroupchild_id['type']
				except:
					print "Error in locating UUID for " + objectnetworkgroupchild_name
				try:
					objectnetworkgroupchild_uuid = next(item for item in objectnetworkgroup_fullobjectlist if item.get("name") == objectnetworkgroupchild_name.lower() or item.get("name") == objectnetworkgroupchild_name.upper() or item.get("name") == objectnetworkgroupchild_name)
					objectnetworkgroupchild_id = objectnetworkgroupchild_uuid['id']
				except:
					print "Error in locating UUID for " + objectnetworkgroupchild_name
				objectnetworkgroupchild_set = {
				   "type": objectnetworkgroupchild_type,
				   "name": objectnetworkgroupchild_name,
				   "id": objectnetworkgroupchild_id
				}
				try:
					objectnetworkgroup_objectlist.append(objectnetworkgroupchild_set)
				except NameError:
					objectnetworkgroup_objectlist = []
					objectnetworkgroup_objectlist.append(objectnetworkgroupchild_set)
			if "host" in objectnetworkgroupchild_b2:
				objectnetworkgroupchild_value = objectnetworkgroupchild_b2[len('host '):]
				objectnetworkgroupchild_value = objectnetworkgroupchild_value.lstrip()
				objectnetworkgroupchild_set = {
				   "type": "host",
				   "value": objectnetworkgroupchild_value
				}
				try:
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
				except NameError:
					objectnetworkgroup_literallist = []
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
			if re.match(r"^ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} ",objectnetworkgroupchild_b2) : 
				objectnetworkgroupchild_b3 = objectnetworkgroupchild_b2.lstrip()
				objectnetworkgroupchild_network = objectnetworkgroupchild_b3.split(" ")[:1][0]
				objectnetworkgroupchild_subnet = objectnetworkgroupchild_b3.split(" ")[1:][0]
				objectnetworkgroupchild_cidr = sum([bin(int(x)).count("1") for x in objectnetworkgroupchild_subnet.split(".")])
				objectnetworkgroupchild_value = objectnetworkgroupchild_network + "/" + str(objectnetworkgroupchild_cidr)
				objectnetworkgroupchild_set = {
				   "type": "Network",
				   "value": objectnetworkgroupchild_value
				}
				try:
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
				except NameError:
					objectnetworkgroup_literallist = []
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
			if re.match(r"^ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",objectnetworkgroupchild_b2) : 
				objectnetworkgroupchild_value = objectnetworkgroupchild_b2.lstrip()
				objectnetworkgroupchild_set = {
				   "type": "Network",
				   "value": objectnetworkgroupchild_value
				}
				try:
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
				except NameError:
					objectnetworkgroup_literallist = []
					objectnetworkgroup_literallist.append(objectnetworkgroupchild_set)
		fmcpostdata_b = {
			"name" : objectnetworkgroupname,
			"type" : "Network",
			"objects": objectnetworkgroup_objectlist,
			"literals": objectnetworkgroup_literallist
		}
		fmcpostdata = json.dumps(fmcpostdata_b)
		try:
			r = requests.post(fmcnetobjectgroupurl, data=fmcpostdata, headers=headers, verify=False);
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.post(fmcnetobjectgroupurl, data=fmcpostdata, headers=headers, verify=False);
				status_code = r.status_code
			resp = r.text
			if status_code == 201 or status_code == 202:
				print ("The following object group was successfully imported: " + objectnetworkgroupname)
			else :
				r.raise_for_status()
				print ("Error occurred in importing the following object: " + objectnetworkgroupname + " Post error was " +resp)
		except requests.exceptions.HTTPError as err:
			if status_code == 400:
				print "Object " + objectnetworkgroupname + " might already exist or is referencing a missing object. Error code 400"
			else :
				print ("Error in connection to the server: "+str(err))	
		finally:
			if r : r.close()
		if debugmode == 'Y' or debugmode == 'y':	
			print " "
			print "Object Network Group Name " + objectnetworkgroupname
			print " "
			print "Object Network Group POST " + fmcpostdata
			print " "
else:
	print "You have selected not to import network objects, skipping step"
'''SECTION: Import Object Services'''
if "Y" in importserviceobjectsq or "y" in importserviceobjectsq or "yes" in importserviceobjectsq or "Yes" in importserviceobjectsq or "YES" in importserviceobjectsq:
	for specificobjectservice in objectservice:
		objectservice_before = specificobjectservice.text
		objectservicename = objectservice_before[len('object service'):]
		objectservicename = objectservicename.lstrip()
		for objectservicechild in specificobjectservice.children:
			objectservicechild_before = objectservicechild.text
			objectservicechild_b1 = objectservicechild_before[len(' service '):]
			objectservicechild_b1 = objectservicechild_b1.lstrip()
			objectservicechild_protocol = objectservicechild_b1.split(" ")[:1][0]
			if re.match(r"\d+",objectservicechild_protocol) :
				print " "
				print "Import custom service object manually as API doesnt support this function"
				print "Object name is " + objectservicename
				print " "
			else :
				objectservicechild_singleport = None
				objectservicechild_firstport = None
				objectservicechild_lastport = None
				objectservicechild_direction = objectservicechild_b1.split(" ")[1:][0]
				objectservicechild_amountofport = objectservicechild_b1.split(" ")[2:][0]
				if objectservicechild_amountofport in ["eq"]:
					objectservicechild_singleport = objectservicechild_b1.split(" ")[3:][0]
				if objectservicechild_amountofport in ["range"]:
					objectservicechild_firstport = objectservicechild_b1.split(" ")[3:][0]
					objectservicechild_lastport = objectservicechild_b1.split(" ")[4:][0]
				if not objectservicechild_singleport == None:
						objectservicechild_port = objectservicechild_singleport
				if not objectservicechild_firstport == None:
						objectservicechild_port = objectservicechild_firstport + "-" + objectservicechild_lastport
				if "description" in objectservicechild_before:
					objectservicedescription = objectservicechild_before[len('description '):]
					objectservicedescription = objectservicedescription.lstrip()
				if not "description" in objectservicechild_before:
					objectservicedescription = "Imported Object"
				if re.match(r"^[a-zA-Z]*$",objectservicechild_port):
					'''Load CSV of known ports'''
					try:
						csvdownload = urllib2.urlopen(csvpath)
						defaultports = csv.DictReader(csvdownload)
					except:
						print ""
						print "Could not load the default CSV port file"
						print "Format is name, protocol (TCP, UDP, TCP and UDP), Port, Description)"
					objectservicechild_convertedport = next(ports for ports in defaultports if ports['name'] == objectservicechild_port)
					objectservicechild_port = objectservicechild_convertedport['port']
				fmcpostdata = {
					"name" : objectservicename,
					"description" : objectservicedescription,
					"port" : objectservicechild_port,
					"protocol" : objectservicechild_protocol,
					"type" : "ProtocolPortObject"
				}
		try:
			r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
				status_code = r.status_code
			resp = r.text
			if status_code == 201 or status_code == 202:
				print ("The following service object was successfully imported: " + fmcpostdata["name"])
			else :
				r.raise_for_status()
				print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
		except requests.exceptions.HTTPError as err:
			if status_code == 400:
				print "Object " + objectservicename + " might already exist. Error code 400"
			else :
				print ("Error in connection to the server: "+str(err))	
		finally:
			if r : r.close()
		if debugmode == 'Y' or debugmode == 'y':	
			print " "
			print "Object service Name " + objectservicename
			print "Object service Port " + objectservicechild_port
			print "Object service Protocol " + objectservicechild_protocol
			print "Object service Description " + objectservicedescription
			print " "

	'''SECTION: Import Object Service Group '''

	'''Get list of existing objects'''
	try:
		r = requests.get(fmcportsurl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcportsurl, headers=headers, verify=False)
			status_code = r.status_code
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Service objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Service Objects Successful."
			#print("GET successful. Response data --> ")		
			
			try:
				objectservicegroup_fullobjectlist.extend(items)
			except NameError:
				objectservicegroup_fullobjectlist = []
				objectservicegroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
		
	for specificobjectservicegroup in objectservicegroup:
		objectservicegroup_before = specificobjectservicegroup.text
		objectservicegroupname = objectservicegroup_before.split(" ")[2:][0]
		try:
			objectservicegroupprotocol = objectservicegroup_before.split(" ")[3:][0]
		except:
			if debugmode == 'Y' or debugmode == 'y':
					print " "
					print "NOT A PROTOCOL"
					print " "
		for objectservicegroupchild in specificobjectservicegroup.children:
			objectservicegroupchild_b0 = objectservicegroupchild.text
			objectservicegroupchild_b1 = objectservicegroupchild_b0.split(" ")[1:][0]
			objectservicegroupchild_b2 = objectservicegroupchild_b0.split(" ")[2:][0]
			'''Port Object'''
			if "port-object" in objectservicegroupchild_b1:
				objectservicechild_singleport = None
				objectservicechild_firstport = None
				objectservicechild_lastport = None
				objectservicechild_protocol = objectservicegroupprotocol
				objectservicechild_amountofport = objectservicegroupchild_b0.split(" ")[2:][0]
				if objectservicechild_amountofport in ["eq"]:
					objectservicechild_singleport = objectservicegroupchild_b0.split(" ")[3:][0]
				if objectservicechild_amountofport in ["range"]:
					objectservicechild_firstport = objectservicegroupchild_b0.split(" ")[3:][0]
					objectservicechild_lastport = objectservicegroupchild_b0.split(" ")[4:][0]
				if not objectservicechild_singleport == None:
					objectservicechild_port = objectservicechild_singleport
				if not objectservicechild_firstport == None:
					objectservicechild_port = objectservicechild_firstport + "-" + objectservicechild_lastport
				objectservicedescription = "Imported Object"
				if re.match(r"^[a-zA-Z]*$",objectservicechild_port):
					'''Load CSV of known ports'''
					try:
						csvdownload = urllib2.urlopen(csvpath)
						defaultports = csv.DictReader(csvdownload)
					except:
						print ""
						print "Could not load the default CSV port file"
						print "Format is name, protocol (TCP, UDP, TCP and UDP), Port, Description)"
					objectservicechild_convertedport = next(ports for ports in defaultports if ports['name'] == objectservicechild_port)
					objectservicechild_port = objectservicechild_convertedport['port']
				objectservicename = objectservicechild_protocol + objectservicechild_port
				fmcpostdata = {
					"name" : objectservicename,
					"description" : objectservicedescription,
					"port" : objectservicechild_port,
					"protocol" : objectservicechild_protocol,
					"type" : "ProtocolPortObject"
				}
				try:
					r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
					status_code = r.status_code
					if (status_code == 429):
						print "API is currently being rate-limited. Pausing for 60 seconds."
						time.sleep(60)
						r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
						status_code = r.status_code
					resp = r.text
					if status_code == 201 or status_code == 202:
						print ("The following service object was successfully imported: " + fmcpostdata["name"])
					else :
						r.raise_for_status()
						print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
				except requests.exceptions.HTTPError as err:
					if status_code == 400:
						print "Object " + objectservicename + " might already exist. Error code 400"
					else :
						print ("Error in connection to the server: "+str(err))	
				finally:
					if r : r.close()
					if debugmode == 'Y' or debugmode == 'y':	
						print " "
						print "Object service Name " + objectservicename
						print "Object service Port " + objectservicechild_port
						print "Object service Protocol " + objectservicechild_protocol
						print "Object service Description " + objectservicedescription
						print " "
				try:
					r = requests.get(fmcportsurl, headers=headers, verify=False)
					status_code = r.status_code
					if (status_code == 429):
						print "API is currently being rate-limited. Pausing for 60 seconds."
						time.sleep(60)
						r = requests.get(fmcportsurl, headers=headers, verify=False)
						status_code = r.status_code
					objectservicegroup_fullobjectlist = []
					if (status_code == 200):
						resp = r.text
						resp_nonjson = json.loads(resp)
						resp_next = resp_nonjson['paging']
						resp_page = resp_next['pages']
						try:
								items = resp_nonjson["items"]
						except:
							if debugmode == 'Y' or debugmode == 'y':
								print "No Service objects Detected"
								print " "
						if resp_page > 1 :
							resp_nextpage = resp_next['next']
							for page in resp_nextpage:
								page = json.dumps(page)
								page = page.strip('"')
								r = requests.get(page, headers=headers, verify=False)
								resp_nextcontent = r.text
								resp_nextcontent_nonjson = json.loads(resp_nextcontent)
								resp_nextcontent_items = resp_nextcontent_nonjson["items"]
								items.extend(resp_nextcontent_items)
						if debugmode == 'Y' or debugmode == 'y':
								print "GET Service Objects Successful."
							#print("GET successful. Response data --> ")		
						try:
							objectservicegroup_fullobjectlist.extend(items)
						except NameError:
							objectservicegroup_fullobjectlist = []
							objectservicegroup_fullobjectlist.extend(items)
					else:
						#r.raise_for_status()
						print("Error occurred in GET --> "+resp + " i --> " + str(i))
				except requests.exceptions.HTTPError as err:
					print ("Error in connection --> "+str(err))
				finally:
					if r : r.close()
				try:
					objectservicegroupchild_id = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicename.lower() or item.get("name") == objectservicename.upper() or item.get("name") == objectservicename)
					objectservicegroupchild_type = objectservicegroupchild_id['type']
				except:
					print "Error in locating UUID for " + objectservicename
				try:
					objectservicegroupchild_uuid = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicename.lower() or item.get("name") == objectservicename.upper() or item.get("name") == objectservicename)
					objectservicegroupchild_id = objectservicegroupchild_uuid['id']
				except:
					print "Error in locating UUID for " + objectservicename
				objectservicegroupchild_set = {
				"type": objectservicegroupchild_type,
				"name": objectservicename,
				"id": objectservicegroupchild_id
				}
				try:
					objectservicegroup_objectlist.append(objectservicegroupchild_set)
				except NameError:
					objectservicegroup_objectlist = []
					objectservicegroup_objectlist.append(objectservicegroupchild_set)
			'''Service Object'''
			if "service-object" in objectservicegroupchild_b1:
				if "object" in objectservicegroupchild_b2:
					objectservicegroupchild_name = objectservicegroupchild_b0.split(" ")[3:][0]
					try:
						objectservicegroupchild_id = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicegroupchild_name.lower() or item.get("name") == objectservicegroupchild_name.upper() or item.get("name") == objectservicegroupchild_name)
						objectservicegroupchild_type = objectservicegroupchild_id['type']
					except:
						print "Error in locating UUID for " + objectservicegroupchild_name
					try:
						objectservicegroupchild_uuid = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicegroupchild_name.lower() or item.get("name") == objectservicegroupchild_name.upper() or item.get("name") == objectservicegroupchild_name)
						objectservicegroupchild_id = objectservicegroupchild_uuid['id']
					except:
						print "Error in locating UUID for " + objectservicegroupchild_name
					objectservicegroupchild_set = {
					"type": objectservicegroupchild_type,
					"name": objectservicegroupchild_name,
					"id": objectservicegroupchild_id
					}
					try:
						objectservicegroup_objectlist.append(objectservicegroupchild_set)
					except NameError:
						objectservicegroup_objectlist = []
						objectservicegroup_objectlist.append(objectservicegroupchild_set)
				if "tcp" in objectservicegroupchild_b2 or "udp" in objectservicegroupchild_b2:
					'''Create First Port'''
					objectservicechild_singleport = None
					objectservicechild_firstport = None
					objectservicechild_lastport = None
					objectservicechild_protocol = objectservicegroupchild_b0.split(" ")[2:][0]
					objectservicechild_direction = objectservicegroupchild_b0.split(" ")[3:][0]
					objectservicechild_amountofport = objectservicegroupchild_b0.split(" ")[4:][0]
					if objectservicechild_amountofport in ["eq"]:
						objectservicechild_singleport = objectservicegroupchild_b0.split(" ")[5:][0]
					if objectservicechild_amountofport in ["range"]:
						objectservicechild_firstport = objectservicegroupchild_b0.split(" ")[5:][0]
						objectservicechild_lastport = objectservicegroupchild_b0.split(" ")[6:][0]
					if not objectservicechild_singleport == None:
						objectservicechild_port = objectservicechild_singleport
					if not objectservicechild_firstport == None:
						objectservicechild_port = objectservicechild_firstport + "-" + objectservicechild_lastport
					objectservicedescription = "Imported Object"
					if re.match(r"^[a-zA-Z]*$",objectservicechild_port):
						'''Load CSV of known ports'''
						try:
							csvdownload = urllib2.urlopen(csvpath)
							defaultports = csv.DictReader(csvdownload)
						except:
							print ""
							print "Could not load the default CSV port file"
							print "Format is name, protocol (TCP, UDP, TCP and UDP), Port, Description)"
						objectservicechild_convertedport = next(ports for ports in defaultports if ports['name'] == objectservicechild_port)
						objectservicechild_port = objectservicechild_convertedport['port']
					objectservicename = objectservicechild_protocol + objectservicechild_port
					fmcpostdata = {
						"name" : objectservicename,
						"description" : objectservicedescription,
						"port" : objectservicechild_port,
						"protocol" : objectservicechild_protocol,
						"type" : "ProtocolPortObject"
					}
					try:
						r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
						status_code = r.status_code
						if (status_code == 429):
							print "API is currently being rate-limited. Pausing for 60 seconds."
							time.sleep(60)
							r = requests.post(fmcportobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
							status_code = r.status_code
						resp = r.text
						if status_code == 201 or status_code == 202:
							print ("The following service object was successfully imported: " + fmcpostdata["name"])
						else :
							r.raise_for_status()
							print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
					except requests.exceptions.HTTPError as err:
						if status_code == 400:
							print "Object " + objectservicename + " might already exist. Error code 400"
						else :
							print ("Error in connection to the server: "+str(err))	
					finally:
						if r : r.close()
					if debugmode == 'Y' or debugmode == 'y':	
						print " "
						print "Object service Name " + objectservicename
						print "Object service Port " + objectservicechild_port
						print "Object service Protocol " + objectservicechild_protocol
						print "Object service Description " + objectservicedescription
						print " "
					try:
						r = requests.get(fmcportsurl, headers=headers, verify=False)
						status_code = r.status_code
						if (status_code == 429):
							print "API is currently being rate-limited. Pausing for 60 seconds."
							time.sleep(60)
							r = requests.get(fmcportsurl, headers=headers, verify=False)
							status_code = r.status_code
						objectservicegroup_fullobjectlist = []
						if (status_code == 200):
							resp = r.text
							resp_nonjson = json.loads(resp)
							resp_next = resp_nonjson['paging']
							resp_page = resp_next['pages']
							try:
									items = resp_nonjson["items"]
							except:
								if debugmode == 'Y' or debugmode == 'y':
									print "No Service objects Detected"
									print " "
							if resp_page > 1 :
								resp_nextpage = resp_next['next']
								for page in resp_nextpage:
									page = json.dumps(page)
									page = page.strip('"')
									r = requests.get(page, headers=headers, verify=False)
									resp_nextcontent = r.text
									resp_nextcontent_nonjson = json.loads(resp_nextcontent)
									resp_nextcontent_items = resp_nextcontent_nonjson["items"]
									items.extend(resp_nextcontent_items)
							if debugmode == 'Y' or debugmode == 'y':
									print "GET Service Objects Successful."
								#print("GET successful. Response data --> ")		
							try:
								objectservicegroup_fullobjectlist.extend(items)
							except NameError:
								objectservicegroup_fullobjectlist = []
								objectservicegroup_fullobjectlist.extend(items)
						else:
							#r.raise_for_status()
							print("Error occurred in GET --> "+resp + " i --> " + str(i))
					except requests.exceptions.HTTPError as err:
						print ("Error in connection --> "+str(err))
					finally:
						if r : r.close()
					try:
						objectservicegroupchild_id = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicename.lower() or item.get("name") == objectservicename.upper() or item.get("name") == objectservicename)
						objectservicegroupchild_type = objectservicegroupchild_id['type']
					except:
						print "Error in locating UUID for " + objectservicename
					try:
						objectservicegroupchild_uuid = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == objectservicename.lower() or item.get("name") == objectservicename.upper() or item.get("name") == objectservicename)
						objectservicegroupchild_id = objectservicegroupchild_uuid['id']
					except:
						print "Error in locating UUID for " + objectservicename
					objectservicegroupchild_set = {
					"type": objectservicegroupchild_type,
					"name": objectservicename,
					"id": objectservicegroupchild_id
					}
					try:
						objectservicegroup_objectlist.append(objectservicegroupchild_set)
					except NameError:
						objectservicegroup_objectlist = []
						objectservicegroup_objectlist.append(objectservicegroupchild_set)
		fmcpostdata_b = {
		"objects": objectservicegroup_objectlist,
		"name": objectservicegroupname,
		"type": "PortObjectGroup"
		}
		fmcpostdata = json.dumps(fmcpostdata_b)
		try:
			r = requests.post(fmcportgroupurl, data=fmcpostdata, headers=headers, verify=False);
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.post(fmcportgroupurl, data=fmcpostdata, headers=headers, verify=False);
				status_code = r.status_code
			resp = r.text
			if status_code == 201 or status_code == 202:
				print ("The following object group was successfully imported: " + objectservicegroupname)
			else :
				r.raise_for_status()
				print ("Error occurred in importing the following object: " + objectservicegroupname + " Post error was " +resp)
		except requests.exceptions.HTTPError as err:
			if status_code == 400:
				print "Object " + objectservicegroupname + " might already exist or is referencing a missing object. Error code 400"
			else :
				print ("Error in connection to the server: "+str(err))	
		finally:
			if r : r.close()
		if debugmode == 'Y' or debugmode == 'y':	
			print " "
			print "Object Service Group Name " + objectservicegroupname
			print " "
			print "Object Service Group POST " + fmcpostdata
			print " "
		'''Clear Variables in Loop'''
		objectservicegroup_objectlist = []
else:
	print "You have selected not to import port/service objects, skipping step"
'''SECTION: IMPORT OF ACL'''
if "Y" in importaclq or "y" in importaclq or "yes" in importaclq or "Yes" in importaclq or "YES" in importaclq:
	'''Create ACL'''
	fmcpostdata = {
					"name" : importaclnameq,
					"type" : "AccessPolicy",
					"defaultAction": {
						"action": "BLOCK"
					}
		}
	try:
		r = requests.post(fmcaccesspolicyurl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.post(fmcaccesspolicyurl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
			status_code = r.status_code
		resp = r.text
		if status_code == 201 or status_code == 202:
			print ("The new access policy was successfully created: " + fmcpostdata["name"])
		else :
			r.raise_for_status()
			print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
	except requests.exceptions.HTTPError as err:
		if status_code == 400:
			print "The access policy " + importaclnameq + " already exists. Error code 400. Please delete and rerun this script"
			'''sys.exit()'''
		else :
			print ("Error in connection to the server: "+str(err))	
	finally:
			if r : r.close()
	if debugmode == 'Y' or debugmode == 'y':	
		print " "
		print "Zone object name " + importaclnameq
		print " "
	'''Get UUID and add into post for access policy later'''
	try:
		r = requests.get(fmcaccesspolicyurl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcaccesspolicyurl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Access Policies Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Access Policies Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Access Policies Detected"
					print " "
			# Extract the numbers from the items whose name starts with importaclnameq and keep adding them to allEntries
			try:
				acl_fullacllist.extend(items)
			except NameError:
				acl_fullacllist = []
				acl_fullacllist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	fmcaccesspolicy_uuid_b = next(item for item in acl_fullacllist if item.get("name") == importaclnameq.lower() or item.get("name") == importaclnameq.upper() or item.get("name") == importaclnameq)
	fmcaccesspolicyid = fmcaccesspolicy_uuid_b['id']
	fmcaccessrulesurl = fmcpath + "/api/fmc_config/v1/domain/default/policy/accesspolicies/" + fmcaccesspolicyid + "/accessrules"
	if (fmcaccessrulesurl[-1] == '/'):
		fmcaccessrulesurl = fmcaccessrulesurl[:-1]
	'''Refresh Object Lists'''
	'''Get Network Objects'''
	try:
		r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Network Objects Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get Host Objects and merge list with Network Objects'''
	try:
		r = requests.get(fmchostsobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmchostsobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Host objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Hosts Objects Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Host objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get Range Objects and merge list with Network Objects'''
	try:
		r = requests.get(fmcrangesobjecturl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcrangesobjecturl, headers=headers, verify=False)
			status_code = r.status_code
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Range objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Range Objects Successful."
			#print("GET successful. Response data --> ")
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Range objects Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get Network Object Groups and merge with Host Objects'''
	try:
		r = requests.get(fmcnetobjectgroupurl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcnetobjectgroupurl, headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network object groups Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Network Object Groups Successful."
			#print("GET successful. Response data --> ")		
			try:
				json_resp = json.loads(resp)
				items = json_resp["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network Object Groups Detected"
					print " "
			# Extract the numbers from the items whose name starts with objectnetworkgroupchild_name and keep adding them to allEntries
			try:
				objectnetworkgroup_fullobjectlist.extend(items)
			except NameError:
				objectnetworkgroup_fullobjectlist = []
				objectnetworkgroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get Port Objects'''
	try:
		r = requests.get(fmcportsurl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcportsurl, headers=headers, verify=False)
			status_code = r.status_code
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Service objects Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Service Objects Successful."
			#print("GET successful. Response data --> ")		
			
			try:
				objectservicegroup_fullobjectlist.extend(items)
			except NameError:
				objectservicegroup_fullobjectlist = []
				objectservicegroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get Port Object Groups and merge with Port Objects'''
	try:
		r = requests.get(fmcportgroupurl, headers=headers, verify=False)
		status_code = r.status_code
		if (status_code == 429):
			print "API is currently being rate-limited. Pausing for 60 seconds."
			time.sleep(60)
			r = requests.get(fmcportgroupurl, headers=headers, verify=False)
			status_code = r.status_code
		if (status_code == 200):
			resp = r.text
			resp_nonjson = json.loads(resp)
			resp_next = resp_nonjson['paging']
			resp_page = resp_next['pages']
			try:
					items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Service Object Groups Detected"
					print " "
			if resp_page > 1 :
				resp_nextpage = resp_next['next']
				for page in resp_nextpage:
					page = json.dumps(page)
					page = page.strip('"')
					r = requests.get(page, headers=headers, verify=False)
					resp_nextcontent = r.text
					resp_nextcontent_nonjson = json.loads(resp_nextcontent)
					resp_nextcontent_items = resp_nextcontent_nonjson["items"]
					items.extend(resp_nextcontent_items)
			if debugmode == 'Y' or debugmode == 'y':
				print "GET Service Object Groups Successful."
			#print("GET successful. Response data --> ")		
			try:
				objectservicegroup_fullobjectlist.extend(items)
			except NameError:
				objectservicegroup_fullobjectlist = []
				objectservicegroup_fullobjectlist.extend(items)
		else:
			#r.raise_for_status()
			print("Error occurred in GET --> "+resp + " i --> " + str(i))
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r : r.close()
	'''Get interfaces with ACLs attached and add as zone objects'''
	for aclinterface in aclinterfacelist:
		aclinterface_before = aclinterface.text
		aclinterfacename = aclinterface_before.split(" ")[4:][0]
		'''Create Zone Object'''
		fmcpostdata = {
					"name" : aclinterfacename,
					"description" : "Imported interface name",
					"interfaceMode" : "ROUTED",
					"type" : "SecurityZone"
		}
		try:
			r = requests.post(fmczoneobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.post(fmczoneobjecturl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
				status_code = r.status_code
			resp = r.text
			if status_code == 201 or status_code == 202:
				print ("The new zone object was successfully created: " + fmcpostdata["name"])
			else :
				r.raise_for_status()
				print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
		except requests.exceptions.HTTPError as err:
			if status_code == 400:
				print "Zone object " + aclinterfacename + " might already exist. Error code 400"
			if status_code == 500:
				print "Zone object " + aclinterfacename + " might already exist. Error code 500"
			else :
				print ("Error in connection to the server: "+str(err))	
		finally:
			if r : r.close()
		if debugmode == 'Y' or debugmode == 'y':	
			print " "
			print "Zone object name " + aclinterfacename
			print " "
		'''Get Zone UUID'''
		try:
			r = requests.get(fmczoneobjecturl, headers=headers, verify=False)
			status_code = r.status_code
			if (status_code == 429):
				print "API is currently being rate-limited. Pausing for 60 seconds."
				time.sleep(60)
				r = requests.get(fmczoneobjecturl, headers=headers, verify=False)
				status_code = r.status_code
			resp = r.text
			if (status_code == 200):
				resp = r.text
				resp_nonjson = json.loads(resp)
				resp_next = resp_nonjson['paging']
				resp_page = resp_next['pages']
				try:
						items = resp_nonjson["items"]
				except:
					if debugmode == 'Y' or debugmode == 'y':
						print "No Zone objects Detected"
						print " "
				if resp_page > 1 :
					resp_nextpage = resp_next['next']
					for page in resp_nextpage:
						page = json.dumps(page)
						page = page.strip('"')
						r = requests.get(page, headers=headers, verify=False)
						status_code = r.status_code
						if (status_code == 429):
							print "API is currently being rate-limited. Pausing for 60 seconds."
							time.sleep(60)
							r = requests.get(page, headers=headers, verify=False)
						resp_nextcontent = r.text
						resp_nextcontent_nonjson = json.loads(resp_nextcontent)
						resp_nextcontent_items = resp_nextcontent_nonjson["items"]
						items.extend(resp_nextcontent_items)
				if debugmode == 'Y' or debugmode == 'y':
					print "GET Zone Objects Successful."
				#print("GET successful. Response data --> ")		
				try:
					json_resp = json.loads(resp)
					items = json_resp["items"]
				except:
					if debugmode == 'Y' or debugmode == 'y':
						print "No zone objects detected"
						print " "
				# Extract the numbers from the items whose name starts with zoneobjects_fulllist and keep adding them to allEntries
				try:
					zoneobjects_fulllist.extend(items)
				except NameError:
					zoneobjects_fulllist = []
					zoneobjects_fulllist.extend(items)
			else:
				#r.raise_for_status()
				print("Error occurred in GET --> "+resp + " i --> " + str(i))
		except requests.exceptions.HTTPError as err:
			print ("Error in connection --> "+str(err))
		finally:
			if r : r.close()
		aclinterfacename_uuid_b = next(item for item in zoneobjects_fulllist if item.get("name") == aclinterfacename.lower() or item.get("name") == aclinterfacename.upper() or item.get("name") == aclinterfacename)
		aclinterfacenameid = aclinterfacename_uuid_b['id']
		'''Add objects into created ACL'''
		aclname = aclinterface_before.split(" ")[1:][0]
		acldirection = aclinterface_before.split(" ")[2:][0]
		if "in" in acldirection:
			aclcategory = aclinterfacename + "-> ANY"
			sourceZones = {
				"objects": [
					{
						"name": aclinterfacename,
						"id": aclinterfacenameid,
						"type": "SecurityZone"
					}
				]
			}
		if "out" in acldirection:
			aclcategory = aclinterfacename + "<- ANY"
			destinationZones = {
				"objects": [
					{
						"name": aclinterfacename,
						"id": aclinterfacenameid,
						"type": "SecurityZone"
					}
				]
			}
		aclinterfaceentries = asaconfig.find_objects(r"^access-list " + aclname)
		for entry in aclinterfaceentries:
			''' objectnetworkgroup_fullobjectlist objectservicegroup_fullobjectlist '''
			fmcpostdata = []
			status_code = []
			destinationport = []
			sourcenetworks = []
			destinationnetworks = []
			fullentrytext = entry.text
			entryaction = fullentrytext.split(" ")[3:][0]
			'''Create Port Objects'''
			entry_b0 = fullentrytext.split(" ")[4:]
			entry_b0 = " ".join(entry_b0)
			entry_porttype = entry_b0.split(" ")[:1][0]
			if "ip" in entry_porttype:
				entry_b0 = entry_b0.split(" ")[1:]
				entry_b0 = " ".join(entry_b0)
			if "object" in entry_porttype:
				entry_portname = entry_b0.split(" ")[1:][0]
				try:
					entry_portname_uuid = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == entry_portname.lower() or item.get("name") == entry_portname.upper() or item.get("name") == entry_portname)
				except:
					print "Error when attempting to import the object " + entry_portname + ". Please make sure the object is in place by either importing using this script or manually creating"
					'''sys.exit()'''
				entry_portsource = entry_portname_uuid['id']
				destinationport = {
				"type": "ProtocolPortObject",
				"protocol": "0",
				"name": entry_portname,
				"id": entry_portsource
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if "tcp" in entry_porttype:
				entry_portnumber = entry_b0.split(" ")[1:][0]
				destinationport = {
				"type": "ProtocolPortObject",
				"protocol": "6",
				"value" : entry_portnumber
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if "udp" in entry_porttype:
				entry_portnumber = entry_b0.split(" ")[1:][0]
				destinationport = {
				"type": "ProtocolPortObject",
				"protocol": "17",
				"value" : entry_portnumber
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if "icmp" in entry_porttype:
				entry_portnumber = entry_b0.split(" ")[1:][0]
				destinationport = {
				"type": "ProtocolPortObject",
				"protocol": "1",
				"value" : entry_portnumber
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if destinationport == [] and not "ip" in entry_porttype:
				print entry_porttype + " is currently not supported. Please manually create this rule"
				break
			'''Create Source Networks'''
			entry_sourcenettype = entry_b0.split(" ")[:1][0]
			if "any" in entry_sourcenettype:
				entry_b0 = entry_b0.split(" ")[1:]
				entry_b0 = " ".join(entry_b0)
			if "object" in entry_sourcenettype:
				entrynetworkobject_name = entry_b0.split(" ")[1:][0]
				try:
					entrynetworkobject_uuid = next(item for item in objectnetworkgroup_fullobjectlist if item.get("name") == entrynetworkobject_name.lower() or item.get("name") == entrynetworkobject_name.upper() or item.get("name") == entrynetworkobject_name)
				except:
					print "Error when attempting to import the object " + entrynetworkobject_name + ". Please make sure the object is in place by either importing using this script or manually creating"
					'''sys.exit()'''
				entrynetworkobject_source = entrynetworkobject_uuid['id']
				sourcenetworks = {
				"type": "Network",
				"name": entrynetworkobject_name,
				"id": entrynetworkobject_source
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if "host" in entry_sourcenettype:
				entrysourceportobject_port = entry_b0.split(" ")[1:][0]
				sourcenetworks = {
				"type": "Network",
				"value" : entrysourceportobject_port
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if re.match(r"^ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} ",entry_sourcenettype): 
				objectnetworkgroupchild_network = entry_b0.split(" ")[:1][0]
				objectnetworkgroupchild_subnet = entry_b0.split(" ")[1:][0]
				objectnetworkgroupchild_cidr = sum([bin(int(x)).count("1") for x in objectnetworkgroupchild_subnet.split(".")])
				objectnetworkgroupchild_value = objectnetworkgroupchild_network + "/" + str(objectnetworkgroupchild_cidr)
				sourcenetworks = {
				   "type": "Network",
				   "value": objectnetworkgroupchild_value
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if sourcenetworks == [] and not "any" in entry_sourcenettype:
				print entry_sourcenettype + " is currently not supported. Please manually create this rule"
				break
			'''Create Destination Networks'''
			entry_destnettype = entry_b0.split(" ")[:1][0]
			if "any" in entry_destnettype:
				entry_b0 = entry_b0.split(" ")[1:]
				entry_b0 = " ".join(entry_b0)
			if "object" in entry_destnettype:
				entrynetworkobject_name = entry_b0.split(" ")[1:][0]
				try:
					entrynetworkobject_uuid = next(item for item in objectservicegroup_fullobjectlist if item.get("name") == entrynetworkobject_name.lower() or item.get("name") == entrynetworkobject_name.upper() or item.get("name") == entrynetworkobject_name)
				except:
					print "Error when attempting to import the object " + entrynetworkobject_name + ". Please make sure the object is in place by either importing using this script or manually creating"
					break
				entrynetworkobject_source = entrynetworkobject_uuid['id']
				destinationnetworks = {
				"type": "Network",
				"name": entrynetworkobject_name,
				"id": entrynetworkobject_source
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if "host" in entry_destnettype:
				entrysourceportobject_port = entry_b0.split(" ")[1:][0]
				destinationnetworks = {
				"type": "Network",
				"value" : entrysourceportobject_port
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if re.match(r"^ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} ",entry_destnettype): 
				objectnetworkgroupchild_network = entry_b0.split(" ")[:1][0]
				objectnetworkgroupchild_subnet = entry_b0.split(" ")[1:][0]
				objectnetworkgroupchild_cidr = sum([bin(int(x)).count("1") for x in objectnetworkgroupchild_subnet.split(".")])
				objectnetworkgroupchild_value = objectnetworkgroupchild_network + "/" + str(objectnetworkgroupchild_cidr)
				destinationnetworks = {
				   "type": "Network",
				   "value": objectnetworkgroupchild_value
				}
				entry_b0 = entry_b0.split(" ")[2:]
				entry_b0 = " ".join(entry_b0)
			if destinationnetworks == [] and not "any" in entry_destnettype:
				print entry_destnettype + " is currently not supported. Please manually create this rule"
				break
			'''Additional Parameters'''
			if "permit" in entryaction:
				action = "ALLOW"
			else:
				action = "BLOCK"
			if "inactive" in entry_b0:
				enabled = "false"
			else:
				enabled = "true"
			'''Create JSON'''
			fmcpostdata = {
			"action": action,
			"enabled": enabled,
			"type": "AccessRule",
			"name": aclinterfacename + "_PermitAll",
			"destinationPorts": destinationport,
			"sourceNetworks": sourcenetworks,
			"destionationNetworks": destinationnetworks,
			"sendEventsToFMC": "true",
			"sourceZones": sourceZones,
			"logFiles": "false",
			"logBegin": "true",
			"logEnd": "true"
			}
			if not fmcpostdata == []:
				try:
					r = requests.post(fmcaccessrulesurl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
					status_code = r.status_code
					if (status_code == 429):
						print "API is currently being rate-limited. Pausing for 60 seconds."
						time.sleep(60)
						r = requests.post(fmcaccessrulesurl, data=json.dumps(fmcpostdata), headers=headers, verify=False);
						status_code = r.status_code
					resp = r.text
					if status_code == 201 or status_code == 202:
						print ("The following ACL was successfully imported: " + fmcpostdata["name"])
					else :
						r.raise_for_status()
						print ("Error occurred in importing the following object: " + fmcpostdata["name"] + " Post error was " +resp)
				except requests.exceptions.HTTPError as err:
					if status_code == 400:
						print "ACL Entry " + fmcpostdata["name"] + " might already exist. Error code 400"
					else :
						print ("Error in connection to the server: "+str(err))	
				finally:
					if r : r.close()
				if debugmode == 'Y' or debugmode == 'y':	
					print " "
					print "Full ACL Entry = " + fullentrytext
					if status_code == 201 or status_code == 202:
						print "Import Status = Imported"
					if not status_code == 201 or status_code == 202:
						print "Import Status = Not Imported"
					print " "		
else:
	print "You have selected not to import the ACL, skipping step"