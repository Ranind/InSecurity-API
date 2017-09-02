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


def write_json(fname, dict):

	if os.path.exists(fname):
		os.remove(fname)

	with open(fname, 'w') as dump:
		json.dump(dict, dump, indent=2)


def CPE_to_dict_CVE_list(CPE_string):
	dest_port = 443
	api = 'https://cve.circl.lu:%s/api/cvefor/%s'

	request = urllib.request.Request(api%(dest_port, CPE_string.lower()))
	request.add_header('Version', '1.1')
	request.add_header('Accept',  '*/json')
	response = urllib.request.urlopen(request)

	try:
		content = json.loads(response.read().decode("utf-8"))
		if content.get("status") != "success":
			raise Exception()
	except Exception as e:
		print(e)
		raise Exception("Couldn't fetch the info for %s" % CPE_string)

	full_response_json = json.loads(json.dumps(content.get("data")))

	CVE_list = []
	for c in full_response_json:
		CVE = {}

		CVE['Vuln_ID'] = c['id'] or ""
		CVE['Summary'] = c['summary'] or ""
		CVE['CVSS_Severity'] = float(c['cvss'])

		CVE_json = json.dumps(CVE)
		CVE_list.append(CVE_json)

	return json.loads(json.dumps(CVE_list))

#libnmap.object.cpe
def CPE_object_to_dict(libnmap_CPE_obj):

	if type(libnmap_CPE_obj) == str:
		service_CPE_list = {
			'cpeString' : libnmap_CPE_obj,
			'getProduct' : "", 
			'getUpdate' : "",
			'getVendor' : "",
			'getVersion' : "",
			'isApplication' : "",
			'isHardware' : "",
			'isOperatingSystem' : ""
		}
		return service_CPE_list

	#assert type(libnmap_CPE_obj) == libnmap.objects.cpe.CPE

	service_CPE_list = {
		'cpeString' : libnmap_CPE_obj.cpestring or "",
		'getProduct' : "",  #.getProduct() or ""
		'getUpdate' : "",	#.getUpdate() or ""
		'getVendor' : "",	#.getVendor() or ""
		'getVersion' : "",	#.getVersion() or ""
		'isApplication' : libnmap_CPE_obj.is_application() or "",
		'isHardware' : libnmap_CPE_obj.is_hardware() or "",
		'isOperatingSystem' : libnmap_CPE_obj.is_operating_system() or ""
	}

	return service_CPE_list


# convert nmap xml output to json object for payload
def xmlf_to_payload(xml_fname):

	try:
		#parse data
		report = NmapParser.parse_fromfile(xml_fname) #NmapParse module is opening the XML file
	except:
		print ("error nmap xml format")
		return ERROR_STRING


	#global Report dict
	Report = {}


	Report['Devices'] = []


	### host information (Device)
	for _host in report.hosts:

		Device = {
			'Vulnerability_Score' : -1,
			'IP' : _host.ipv4, #_host.ipv6 
			'MAC_Address' :  _host.mac,
			'Vendor' : _host.vendor,
			'host_CPE_list' : [], 			#fill bellow
			'host_CVE_list' : [],			#fill bellow
			'Services' : [],				#fill bellow
			'Identification_Accuracy' : -1	#fill bellow

		}

		#
		# host CPE list
		#
		cpeList = []
		for c in _host.os_match_probabilities():
			cpeList = c.get_cpe()

		cpeList = list(set(cpeList))
		if len(cpeList) > 0:
			for c in cpeList:
				Device['host_CPE_list'].append(CPE_object_to_dict(c))

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
				'port':s.port, 
				'banner':s.banner, 
				'protocol':s.protocol, 
				'name':s.service,
				'state':s.state,
				'reason':s.reason,
				'service_CPE_list': [],
				'service_CVE_list': []
			}

			if s.cpelist:

				#service_CPE_list
				for c in s.cpelist:
					Service['service_CPE_list'].append(CPE_object_to_dict(c))

				#service_CVE_list
				for c in Service['service_CPE_list']:
					Service['service_CVE_list'].extend(CPE_to_dict_CVE_list(c['cpeString']))

			Device['Services'].append(Service)

			print (Service)

		Report['Devices'].append(Device)

	return Report 



"""
									run program
"""

if __name__ == "__main__":
	xmlf_to_payload("../example.xml")


