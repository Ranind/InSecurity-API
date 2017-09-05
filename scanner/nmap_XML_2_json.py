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
import re
import math

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

def read_json(fname):
	with open(fname) as f:    
	    data = json.load(f)
	return data

def get_public_ip():
	urls = ['http://ip.dnsexit.com',
							'http://ifconfig.me/ip',
							'http://ipecho.net/plain',
							'http://checkip.dyndns.org/plain',
							'http://whatismyipaddress.com/',
							'http://websiteipaddress.com/WhatIsMyIp',
							'http://getmyipaddress.org/',
							'http://www.my-ip-address.net/',
							'http://myexternalip.com/raw',
							'http://www.canyouseeme.org/',
							'http://www.trackip.net/',
							'http://icanhazip.com/',
							'http://www.iplocation.net/',
							'http://www.howtofindmyipaddress.com/',
							'http://www.ipchicken.com/',
							'http://whatsmyip.net/',
							'http://www.ip-adress.com/',
							'http://checkmyip.com/',
							'http://www.tracemyip.org/',
							'http://www.lawrencegoetz.com/programs/ipinfo/',
							'http://www.findmyip.co/',
							'http://ip-lookup.net/',
							'http://www.dslreports.com/whois',
							'http://www.mon-ip.com/en/my-ip/',
							'http://www.myip.ru',
							'http://ipgoat.com/',
							'http://www.myipnumber.com/my-ip-address.asp',
							'http://www.whatsmyipaddress.net/',
							'http://formyip.com/',
							'https://check.torproject.org/',
							'http://www.displaymyip.com/',
							'http://www.bobborst.com/tools/whatsmyip/',
							'http://checkip.dyndns.com/',
							'http://myexternalip.com/',
							'http://www.ip-adress.eu/',
							'http://www.infosniper.net/',
							'https://wtfismyip.com/text',
							'http://ipinfo.io/',
							'http://httpbin.org/ip',
							'https://diagnostic.opendns.com/myip']
	public_ip = ""
	error_msg = "Error in get_public_ip"

	for url in urls:
		public_ip = extract_ip_from_response(fetch(url,error_msg,is_json=False))
		if public_ip != "": return public_ip
	return ""


def extract_ip_from_response(response):
	try:
		regx = re.search(
			'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
			response)
		ip = regx.group(0)
		if len(ip) > 0:
			return ip
		return ''
	except Exception:
		return ''

def fetch(url, error_msg, is_json=True):
	request = urllib.request.Request(url)
	request.add_header('Version', '1.1')
	request.add_header('Accept',  '*/json')
	request.add_header('User-agent',
						  "Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0")

	response = urllib.request.urlopen(request)

	if is_json:
		try:
			content = json.loads(response.read().decode("utf-8"))
			if content.get("status") != "success":
				raise Exception()
		except Exception as e:
			print (e)
			raise Exception(error_msg)

		return content.get("data")

	else: 

		content = response.read()

		try:
			content = content.decode('UTF-8')
		except UnicodeDecodeError:
			content = content.decode('ISO-8859-1')

		return content

def CPE_to_dict_CVE_list(CPE_string):
	dest_port = 443
	api = 'https://cve.circl.lu:%s/api/cvefor/%s'
	url = api%(dest_port, CPE_string.lower())

	error_msg = "Failed API CVE lookup for CPE string: %s" % CPE_string
	full_response_json = fetch(url, error_msg)

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

# *temporary method*
# run nmap command and output to xml file
def run_nmap_cmd(nmap_cmd, output_xml_path):
	global ERROR_STRING
	try:
		#run scan
		os.system('sudo nmap ' + nmap_cmd + ' -oX ' + output_xml_path)
	except: 
		print (sys.exc_info()[0])
		print ("error: f:nmap_XML_json.py: failed to run nmap_command")
		return ERROR_STRING

#read in nmap scan from xml file with NmapParser from libnmap library
def libnmap_parse_XML(xml_path):
	global ERROR_STRING
	try:
		#parse data
		return NmapParser.parse_fromfile(xml_path) #NmapParse module is opening the XML file
	except:
		print ("Error with nmap XML format in file: %s" % xml_path)
		return ERROR_STRING

def libnmap_host_2_device_schema(_host):
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
		Device['host_CVE_list'].extend(CPE_to_dict_CVE_list(c['cpeString']))

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

	return Device

# convert nmap xml output to json object for payload
def parse_nmap_output(private_xml_path, public_xml_path):

	# Update global python dict, "Report"
	global Report

	#
	# private nmap scan parsing
	#
	scan = libnmap_parse_XML(private_xml_path)

	### host information (Report.Devices)
	for _host in scan.hosts:
		Device = libnmap_host_2_device_schema(_host)
		Report['Devices'].append(Device)

	#
	# public nmap scan parsing
	#
	scan = libnmap_parse_XML(public_xml_path)

	### router information (Report.Router)
	_router = scan.hosts[0]
	Router = libnmap_host_2_device_schema(_router)
	Router['publicIP'] = get_public_ip()
	Report['Router'] = Router

def device_vulnerability_score(cvsss, number_open_filtered_ports):
	w = 70.0
	k = 5	#scaler for open services
	v = sum(cvsss)
	p = number_open_filtered_ports

	fv = 0
	if v > 0: fv = math.log(v)

	gv = 0
	if p > 0: gv = k*math.log(p)

	score = w / (w + fv + gv)

	return score

def network_vulnerability_score(router_score, device_scores, number_of_devices):
	r = router_score
	d = device_scores
	n = number_of_devices
	w = 15 #weight of router compared to a single device

	if n != 0:
		return ((w*r + n*(sum(d)))/(w + n))*100
	return r*100

def grade(percentage):
	#A: 90-100
	#B: 80-89
	#C: 70-79
	#D: 60-69
	#F: <60

	if percentage > 90:
	    return "A"
	elif 80 <= percentage < 90:
	    return "B"
	elif 70 <= percentage < 80:
	    return "B"
	elif 60 <= percentage < 70:
	    return "C"
	else:
	    return "F"


# extract list of device cvss scores
def calc_vuln_scores_grade():
	global Report

	#
	# Device vulnerability Scores
	#

	device_scores = []
	for d in Report['Devices']:
		device_cvsss = []
		number_of_services = 0

		for cve in d['host_CVE_list']:
			if type(cve) == dict:
				device_cvsss.append(cve['CVSS_Severity'])

		for service in d['Services']:
			for cve in service['service_CVE_list']:
				if type(cve) == dict:
					device_cvsss.append(cve['CVSS_Severity'])
			number_of_services += 1

		device_score = device_vulnerability_score(device_cvsss, number_of_services)

		# set Device 'Vulnerability_Score' in Report
		d['Vulnerability_Score'] = device_score

		device_scores.append(device_score)


	#
	#	Router vulnerability Score
	#

	router_cvsss = []
	number_of_services = 0

	for cve in Report['Router']['host_CVE_list']:
		if type(cve) == dict:
			router_cvsss.append(cve['CVSS_Severity'])

	for service in Report['Router']['Services']:
		for cve in service['service_CVE_list']:
			if type(cve) == dict:
				router_cvsss.append(cve['CVSS_Severity'])
		number_of_services += 1

	router_score = device_vulnerability_score(router_cvsss, number_of_services)

	# set Router 'Vulnerability_Score' in Report
	Report['Router']['Vulnerability_Score'] = router_score


	#
	#	Network vulnerability Score
	#

	network_score = network_vulnerability_score(router_score, device_scores, len(Report['Devices']))
	network_grade = grade(network_score)

	# set Network 'Vulnerability_Score' and Vulnerability_Grade' in Report
	Report['Vulnerability_Score'] = network_score
	Report['Vulnerability_Grade'] = network_grade

"""
									run program
"""

#
# settings
#

ERROR_STRING = "ERROR"

#
# global variables
#

Report = {
	'scanType' : default_value(str),
	'Vulnerability_Score' : default_value(str),
	'Vulnerability_Grade' : default_value(str),
	'Wireless_Security_Protocols' : [],
	'Router' : {},
	'Devices' : []
}

PUBLIC_XMLF_PATH = '../public_example.xml'
PRIVATE_XMLF_PATH = '../example.xml'


if __name__ == "__main__":
	global Report
	global PUBLIC_XMLF_PATH
	global PRIVATE_XMLF_PATH

	#*temporary*
	#public_ip = get_public_ip()
	#run_nmap_cmd('-A %s' % public_ip, PUBLIC_XMLF_PATH)

	#parse_nmap_output(PRIVATE_XMLF_PATH, PUBLIC_XMLF_PATH)

	#*temporary*
	#write_json('../stage2_json.json', Report)
	Report = read_json('../stage2_json.json')

	calc_vuln_scores_grade()





