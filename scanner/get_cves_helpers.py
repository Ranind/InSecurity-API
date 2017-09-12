# python3

from shared_functions import *


def count_cpes(data):
    total_cpes = 0

    # Device CPES
    for Device in data['Devices']:
        total_cpes += len(Device['host_CPE_list'])
        for Service in Device['Services']:
            total_cpes += len(Service['service_CPE_list'])

    # Router (host) CVEs
    total_cpes += len(data['Router']['host_CPE_list'])

    # Router Services and corresponding CVEs
    for Service in data['Router']['Services']:
        total_cpes += len(Service['service_CPE_list'])

    return total_cpes


def cpe_to_dict_cve_list(cpe_string):
    dest_port = 443
    api = 'https://cve.circl.lu:%s/api/cvefor/%s'
    url = api % (dest_port, cpe_string.lower())

    error_msg = "Failed API CVE lookup for CPE string: %s" % cpe_string
    full_response_json = fetch(url, error_msg)

    cve_list = []

    for c in full_response_json:
        cve_list.append({
            'Vuln_ID': return_json_value(c['id'], str),
            'Summary': return_json_value(c['summary'], str),
            'CVSS_Severity': return_json_value(float(c['cvss']), float)
        })

    return cve_list
