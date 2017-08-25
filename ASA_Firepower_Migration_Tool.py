#!/usr/bin/env python
'''
---AUTHOR---
Name: Matt Cross
Email: routeallthings@gmail.com

---PREREQ---
INSTALL CISCOCONFPARSE (pip install ciscoconfparse==1.2.38)

---VERSION---
VERSION 1.2
Currently Implemented Features
- Import of Network Objects
- Import of Network Object Groups* (Except groups inside groups)
- Import of Ports
- Import of Port Groups

Features planned in the near future
- Auto update of script
- Auto install of CISCOCONFPARSE if missing

Fixed from 1.1
- Rest response to parse next page for id
- Some variable names can be used with both upper/lower case characters

'''

'''IMPORT MODULES'''
import getpass
import os
import re
from ciscoconfparse import CiscoConfParse
import requests
from requests.auth import HTTPDigestAuth
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import sys
import csv
import urllib2

'''GLOBAL VARIABLES'''

fullpath = raw_input ('Enter the file path of the ASA config: ')
fmcpathfull = raw_input ('Enter the IP address of the destination FMC: ')
fmcpath = "https://" + fmcpathfull
fmcuser = raw_input ('Enter the username of the destination FMC: ')
fmcpassword = getpass.getpass('Enter the password of the destination FMC: ')
debugmode = raw_input ('Debug Mode? (Y/N): ') 

csvpath = 'https://raw.githubusercontent.com/routeallthings/ASA-to-Firepower-Migration-Tool/master/PortList.csv'

'''##### BEGIN SCRIPT #####'''
'''Print Variables in Debug'''
if debugmode == 'Y' or debugmode == 'y':
	print ""
	print "BEGIN -- GLOBAL VARIABLES"
	print "Fullpath = " + (fullpath.encode('string-escape'))
	print "FMCpath = " + fmcpath
	print "FMCuser = " + fmcuser
	print "FMCpassword = " + fmcpassword
	print "END -- GLOBAL VARIABLES"
	print ""
'''	print "ImportNATq = " + importnatq '''
'''	print "ImportACLq = " + importaclq '''

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

	
'''Create Regex Matches'''
ipv4_address = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
	
''' Loading Network Objects and Groups '''
asaconfig = CiscoConfParse(fullpath)
objectnetwork = asaconfig.find_objects(r"^object network")
objectnetworkgroup = asaconfig.find_objects(r"^object-group network")
objectservice = asaconfig.find_objects(r"^object service")
objectservicegroup = asaconfig.find_objects(r"^object-group service")
objectprotocolgroup = asaconfig.find_objects(r"^object-group protocol")


''' Object Network '''
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
'''Object Network Group '''
'''Get list of existing objects'''
try:
	r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
	status_code = r.status_code
	resp = r.text
	if (status_code == 200):
		resp = r.text
		resp_nonjson = json.loads(resp)
		resp_next = resp_nonjson['paging']
		resp_page = resp_next['pages']
		if resp_page > 1 :
			resp_nextpage = resp_next['next']
			try:
				items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Network objects Detected"
					print " "
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
	resp = r.text
	if (status_code == 200):
		resp = r.text
		resp_nonjson = json.loads(resp)
		resp_next = resp_nonjson['paging']
		resp_page = resp_next['pages']
		if resp_page > 1 :
			resp_nextpage = resp_next['next']
			try:
				items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Host objects Detected"
					print " "
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
	if (status_code == 200):
		resp = r.text
		resp_nonjson = json.loads(resp)
		resp_next = resp_nonjson['paging']
		resp_page = resp_next['pages']
		if resp_page > 1 :
			resp_nextpage = resp_next['next']
			try:
				items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Range objects Detected"
					print " "
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

''' Object service '''
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

'''Object Service Group '''

'''Get list of existing objects'''
try:
	r = requests.get(fmcportsurl, headers=headers, verify=False)
	status_code = r.status_code
	if (status_code == 200):
		resp = r.text
		resp_nonjson = json.loads(resp)
		resp_next = resp_nonjson['paging']
		resp_page = resp_next['pages']
		if resp_page > 1 :
			resp_nextpage = resp_next['next']
			try:
				items = resp_nonjson["items"]
			except:
				if debugmode == 'Y' or debugmode == 'y':
					print "No Service objects Detected"
					print " "
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
				objectservicegroup_fullobjectlist = []
				if (status_code == 200):
					resp = r.text
					resp_nonjson = json.loads(resp)
					resp_next = resp_nonjson['paging']
					resp_page = resp_next['pages']
					if resp_page > 1 :
						resp_nextpage = resp_next['next']
						try:
							items = resp_nonjson["items"]
						except:
							if debugmode == 'Y' or debugmode == 'y':
								print "No Service objects Detected"
								print " "
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
					objectservicegroup_fullobjectlist = []
					if (status_code == 200):
						resp = r.text
						resp_nonjson = json.loads(resp)
						resp_next = resp_nonjson['paging']
						resp_page = resp_next['pages']
						if resp_page > 1 :
							resp_nextpage = resp_next['next']
							try:
								items = resp_nonjson["items"]
							except:
								if debugmode == 'Y' or debugmode == 'y':
									print "No Service objects Detected"
									print " "
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
			