#python 3

from libnmap.parser import NmapParser
#from xml.parsers import expat
from usefull_methods import *

#
#
#       parse_nmap_output Methods
#
#

#read in nmap scan from xml file with NmapParser from libnmap library
def libnmap_parse_XML(xml_path):
    global ERROR_STRING
    try:
        #parse data
        return NmapParser.parse_fromfile(xml_path) #NmapParse module is opening the XML file
    except Exception as e:
        print (e)
        print ("Error with nmap XML format in file: %s" % xml_path)
        return ERROR_STRING


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


def libnmap_host_2_device_schema(_host):
    Device = {
        'Vulnerability_Score' : default_value(int),
        'IP' : return_json_value(_host.ipv4, str),                      #_host.ipv6
        'MAC_Address' :  return_json_value(_host.mac,str),
        'Vendor' : return_json_value(_host.vendor,str),
        'host_CPE_list' : [],                                                           #fill bellow
        'host_CVE_list' : [],                                                           #fill bellow
        'Services' : [],                                                                        #fill bellow
        'Identification_Accuracy' : default_value(int)          #fill bellow
    }

    #
    # host CPE list
    #
    host_cpe_list = []
    for c in _host.os_match_probabilities():
        host_cpe_list.extend(c.get_cpe())
    host_cpe_list = list(set(host_cpe_list))
    Device['host_CPE_list'] = [CPE_object_to_dict(c) for c in host_cpe_list]

    """
    #
    # host CVE list
    #
    for c in Device['host_CPE_list']:
            Device['host_CVE_list'].extend(CPE_to_dict_CVE_list(c['cpeString']))
    """

    #
    #   Services
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

            """
            #
            # serivce CVE list
            #
            for c in Service['service_CPE_list']:
                    Service['service_CVE_list'].extend(CPE_to_dict_CVE_list(c['cpeString']))
            """

        Device['Services'].append(Service)

    return Device

# convert nmap xml output to json object for payload
def parse_nmap_output(private_xml_path, public_xml_path):
    log_activity('\tParsing scan output')

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
