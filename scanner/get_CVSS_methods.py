#python 3

from usefull_methods import *

#
#
#       get_cves Methods
#
#

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

def get_cves():
    log_activity('\tFinding CVEs')
    
    global Report

    #
    # Device CVEs
    #
    for Device in Report['Devices']:
        #
        # host CVE list
        #
        for CPE in Device['host_CPE_list']:
            Device['host_CVE_list'].extend(
                    CPE_to_dict_CVE_list(CPE['cpeString']))

        #
        #       Services
        #
        for Service in Device['Services']:
            #
            # serivce CVE list
            #
            for CPE in Service['service_CPE_list']:
                Service['service_CVE_list'].extend(
                        CPE_to_dict_CVE_list(CPE['cpeString']))
    #
    #       Router CVEs
    #
    # in router : host CVE list
    for CPE in Report['Router']['host_CPE_list']:
        Report['Router']['host_CVE_list'].extend(
                CPE_to_dict_CVE_list(CPE['cpeString']))

        #
        #       Router Services
        #
        for Service in Report['Router']['Services']:
            #
            # serivce CVE list
            #
            for CPE in Service['service_CPE_list']:
                Service['service_CVE_list'].extend(
                        CPE_to_dict_CVE_list(CPE['cpeString']))