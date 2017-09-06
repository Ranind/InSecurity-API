# python3

import math


def device_vulnerability_score(cvsss, number_open_filtered_ports):
    w = 70.0
    k = 5   # scale factor for open services
    v = sum(cvsss)
    p = number_open_filtered_ports

    fv = 0
    if v > 0:
        fv = math.log(v)

    gv = 0
    if p > 0:
        gv = k*math.log(p)

    score = w / (w + fv + gv)

    return score


def network_vulnerability_score(router_score, device_scores, number_of_devices):
    r = router_score
    d = device_scores
    n = number_of_devices
    w = 15  # weight of router compared to a single device

    if n != 0:
        return ((w*r + sum(d))/(w + n))*100
    else:
        return r*100


def grade(percentage):
    # A: 90-100
    # B: 80-89
    # C: 70-79
    # D: 60-69
    # F: <60

    if percentage >= 90:
        return "A"
    elif 80 <= percentage < 90:
        return "B"
    elif 70 <= percentage < 80:
        return "C"
    elif 60 <= percentage < 70:
        return "D"
    else:
        return "F"


def cal_device_vuln_score(device):
    device_cvsss = []
    number_of_services = 0

    for cve in device['host_CVE_list']:
        if type(cve) == dict:
            device_cvsss.append(cve['CVSS_Severity'])

    for service in device['Services']:
        for cve in service['service_CVE_list']:
            if type(cve) == dict:
                device_cvsss.append(cve['CVSS_Severity'])
        number_of_services += 1

    device_score = device_vulnerability_score(device_cvsss, number_of_services)

    return device_score
