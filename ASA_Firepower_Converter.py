#!/usr/bin/env python
'''NOTES'''
'''INSTALL CISCOCONFPARSE (pip install ciscoconfparse==1.2.38)'''

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

'''GLOBAL VARIABLES'''

fullpath = raw_input ('Enter the filename of the ASA config: ')
'''fullpath = os.path.normpath(fullpathinput)'''
fmcpathfull = raw_input ('Enter the IP address of the destination FMC: ')
fmcpath = "https://" + fmcpathfull
fmcuser = raw_input ('Enter the username of the destination FMC: ')
fmcpassword = getpass.getpass('Enter the password of the destination FMC: ')
'''importnatq = raw_input ('Do you want to import NAT rules (Y/N): ')'''
'''importaclq = raw_input ('Do you want to import ACL rules (Y/N): ')'''
debugmode = raw_input ('Debug Mode? (Y/N): ') 

'''TESTONLY
fullpath = os.path.normpath("C:/TFTP-Root/asa.cfg")
fmcpath = "https://192.168.45.45"
fmcuser = "admin"
fmcpassword = "Password1"
debugmode = "y"
keep'''

fmctokenurl = "https://" + fmcpath + "/api/fmc_platform/v1/auth/generatetoken"


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
        '''sys.exit()'''
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    '''sys.exit()'''
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

''' Actual Scripts '''
asaconfig = CiscoConfParse(fullpath)
objectnetwork = asaconfig.find_objects(r"^object network")
objectnetworkgroup = asaconfig.find_objects(r"^object-group network")
objectservice = asaconfig.find_objects(r"^object service")
objectservicegroup = asaconfig.find_objects(r"^object-group service")
objectprotocolgroup = asaconfig.find_objects(r"^object-group protocol")
''' Object Network '''
for specificobjectnetwork in objectnetwork:
	objectnetwork_before = specificobjectnetwork.text
	objectnetworkname = objectnetwork_before.strip("object network ")
	for objectnetworkchild in specificobjectnetwork.children:
		objectnetworkchild_before = objectnetworkchild.text
		if "host" in objectnetworkchild_before:
			objectnetworkip = objectnetworkchild_before.strip("host ")
		if "range" in objectnetworkchild_before:
			objectnetworkip = objectnetworkchild_before.strip("range ")
		if "subnet" in objectnetworkchild_before:
			objectnetworkip_b1 = objectnetworkchild_before.strip("subnet ")
			objectnetworkip_network = objectnetworkip_b1.split(" ")[:1][0]
			objectnetworkip_subnet = objectnetworkip_b1.split(" ")[1:][0]
			objectnetworkip_cidr = sum([bin(int(x)).count("1") for x in objectnetworkip_subnet.split(".")])
			objectnetworkip = objectnetworkip_network + "/" + str(objectnetworkip_cidr)
		if "description" in objectnetworkchild_before:
			objectnetworkdescription = objectnetworkchild_before.strip("description ")
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
''' Object Network Group '''

'''Get list of existing objects'''
try:
	r = requests.get(fmcnetobjecturl, headers=headers, verify=False)
	status_code = r.status_code
	resp = r.text
	if (status_code == 200):
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
	resp = r.text
	if (status_code == 200):
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
	objectnetworkgroupname = objectnetworkgroup_before.strip("object network-group ")
	
	for objectnetworkgroupchild in specificobjectnetworkgroup.children:
		objectnetworkgroupchild_b1 = objectnetworkgroupchild.text
		objectnetworkgroupchild_b2 = objectnetworkgroupchild_b1.replace("network-object ", "")
		if "object" in objectnetworkgroupchild_b2:
			objectnetworkgroupchild_name = objectnetworkgroupchild_b2.strip("object ")
			try:
				objectnetworkgroupchild_id = next(item for item in objectnetworkgroup_fullobjectlist if item.get("name") == objectnetworkgroupchild_name)
				objectnetworkgroupchild_type = objectnetworkgroupchild_id['type']
			except:
				print "Error in locating UUID for " + objectnetworkgroupchild_name
			try:
				objectnetworkgroupchild_uuid = next(item for item in objectnetworkgroup_fullobjectlist if item.get("name") == objectnetworkgroupchild_name)
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
			objectnetworkgroupchild_value = objectnetworkgroupchild_b2.strip("host ")
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