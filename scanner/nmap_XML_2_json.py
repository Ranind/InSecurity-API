#python 3

#
#	imports
#

# standard
import os
import requests
import sys
import json
from libnmap.parser import NmapParser
from xml.parsers import expat
import urllib.request

#settings
ERROR_STRING = "ERROR"

def default_value(value_type):
	if value_type == str:
		return ""
	if value_type == int:
		return -1
	if value_type == float:
		return -1.0
	if value_type == bool:
		return ""

	print("type not found:%s" % str(value_type))


def return_json_value(obj, expected_type):
	global default_value
	try:

		return_value = obj

		if callable(obj):
			return_value = obj()

		if type(return_value) == expected_type:
			return return_value

		raise ValueError(ERROR_STRING)
	except:
		return default_value(expected_type)

def write_json(fname, dict):

	if os.path.exists(fname):
		os.remove(fname)

	with open(fname, 'w') as dump:
		json.dump(dict, dump, indent=2)


def CPE_to_dict_CVE_list(CPE_string):
	dest_port = 443
	api = 'https://cve.circl.lu:%s/api/cvefor/%s'
	url = api%(dest_port, CPE_string.lower())

	request = urllib.request.Request(url)
	request.add_header('Version', '1.1')
	request.add_header('Accept',  '*/json')
	response = urllib.request.urlopen(request)

	try:
		content = json.loads(response.read().decode("utf-8"))
		if content.get("status") != "success":
			raise Exception()
	except Exception as e:
		print (e)
		raise Exception("Failed API CVE lookup for CPE string: %s" % CPE_string)

	full_response_json = content.get("data")

	CVE_list = []
	for c in full_response_json:
		CVE = {}

		CVE['Vuln_ID'] = return_json_value(c['id'], str)
		CVE['Summary'] = return_json_value(c['summary'], str)
		CVE['CVSS_Severity'] = return_json_value(float(c['cvss']), float)

		CVE_list.append(CVE)

	return CVE_list

#libnmap.object.cpe
def CPE_object_to_dict(libnmap_CPE_obj):
	global default_value

	service_CPE_list = {
		'cpeString' : default_value(str),
		'getProduct' : default_value(str), 
		'getUpdate' : default_value(str),
		'getVendor' : default_value(str),
		'getVersion' : default_value(str),
		'isApplication' : default_value(bool),
		'isHardware' : default_value(bool),
		'isOperatingSystem' : default_value(bool)
	}

	if hasattr(libnmap_CPE_obj, 'cpestring'):
		service_CPE_list['cpeString'] = return_json_value(libnmap_CPE_obj.cpestring, str)
	else:
		service_CPE_list['cpeString'] = return_json_value(libnmap_CPE_obj, str)

	if hasattr(libnmap_CPE_obj, 'getProduct'):
		service_CPE_list['getProduct'] = return_json_value(libnmap_CPE_obj.getProduct, str)

	if hasattr(libnmap_CPE_obj, 'getUpdate'):
		service_CPE_list['getUpdate'] = return_json_value(libnmap_CPE_obj.getUpdate, str)

	if hasattr(libnmap_CPE_obj, 'getVendor'):
		service_CPE_list['getVendor'] = return_json_value(libnmap_CPE_obj.getVendor, str)

	if hasattr(libnmap_CPE_obj, 'getVersion'):
		service_CPE_list['getVersion'] = return_json_value(libnmap_CPE_obj.getVersion, str)

	if hasattr(libnmap_CPE_obj, 'is_application'):
		service_CPE_list['isApplication'] = return_json_value(libnmap_CPE_obj.is_application, bool)	

	if hasattr(libnmap_CPE_obj, 'is_hardware'):
		service_CPE_list['isHardware'] = return_json_value(libnmap_CPE_obj.is_hardware, bool)	

	if hasattr(libnmap_CPE_obj, 'is_operating_system'):
		service_CPE_list['isOperatingSystem'] = return_json_value(libnmap_CPE_obj.is_operating_system, bool)	

	return service_CPE_list


# convert nmap xml output to json object for payload
def xmlf_to_payload(xml_fname):

	global ERROR_STRING
	try:
		#parse data
		report = NmapParser.parse_fromfile(xml_fname) #NmapParse module is opening the XML file
	except:
		print ("Error with nmap XML format")
		return ERROR_STRING


	#global Report dict
	Report = {}
	Report['Devices'] = []

	### host information (Device)
	for _host in report.hosts:

		Device = {
			'Vulnerability_Score' : default_value(int),
			'IP' : return_json_value(_host.ipv4, str), 			#_host.ipv6 
			'MAC_Address' :  return_json_value(_host.mac,str),
			'Vendor' : return_json_value(_host.vendor,str),
			'host_CPE_list' : [], 								#fill bellow
			'host_CVE_list' : [],								#fill bellow
			'Services' : [],									#fill bellow
			'Identification_Accuracy' : default_value(int)		#fill bellow

		}

		#
		# host CPE list
		#
		host_cpe_list = []
		for c in _host.os_match_probabilities():
			host_cpe_list.extend(c.get_cpe())
		host_cpe_list = list(set(host_cpe_list))
		Device['host_CPE_list'] = [CPE_object_to_dict(c) for c in host_cpe_list]


		#
		# host CVE list
		#
		for c in Device['host_CPE_list']:
			Device['host_CVE_list'].append(CPE_to_dict_CVE_list(c['cpeString']))

		#
		#	Services
		#
		for s in _host.services:

			Service={
				'port': return_json_value(s.port,int), 
				'banner': return_json_value(s.banner,str), 
				'protocol':return_json_value(s.protocol, str), 
				'name': return_json_value(s.service, str),
				'state': return_json_value(s.state,str),
				'reason': return_json_value(s.reason,str),
				'service_CPE_list': [],
				'service_CVE_list': []
			}


			if s.cpelist:
				#
				# serivce CPE list
				#
				for c in s.cpelist:
					Service['service_CPE_list'].append(CPE_object_to_dict(c))

				#
				# serivce CVE list
				#
				for c in Service['service_CPE_list']:
					Service['service_CVE_list'].extend(CPE_to_dict_CVE_list(c['cpeString']))


			Device['Services'].append(Service)
	
		Report['Devices'].append(Device)

	return Report 



"""
									run program
"""

if __name__ == "__main__":
	print(xmlf_to_payload("../example.xml"))

