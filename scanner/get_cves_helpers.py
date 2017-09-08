# python3

from shared_functions import *


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
