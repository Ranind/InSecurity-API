# TODO: Use the correct import for python 3, add any pip steps to provision.sh
import MySQLdb
import subprocess
import re

from .parse_nmap_helpers import *
from .get_cves_helpers import *
from .calc_vuln_scores_grades_helpers import *

db_connection = MySQLdb.connect(host='localhost', user='api', passwd='password', db='InSecurity')
data = []
scan_id = int(sys.argv[1])
public_ip = None
gateway_ip = None

# TODO: Determine appropriate weights
progress_weights = {
    'prep': 5,
    'nmap_public': 5,
    'nmap_private': 5,
    'parse': 5,
    'cves': 5,
    'scores': 5,
    'report': 5
}
cumulative_progress = 0
incremental_progress = 0


def run_nmap(args, scan):
    """
    nmap_args - list of args to give nmap

    Return temp XML file paths
    """
    log_activity('\tScanning ' + scan + ' network')

    xml_path = 'nmap_results_%s_%s.xml' % (scan, scan_id)
    nmap_cmd = ['nmap'] + args + ['-oX', xml_path]
    nmap = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE)

    while True:
        # TODO: parse this for progress
        line = nmap.stdout.readline()
        if not line:
            break

    xml_abs_path = os.path.abspath(xml_path)

    return xml_abs_path


def get_gateway():
    """
    Return the default gateway of the host calling this function
    """
    log_activity('\tDetermining gateway')

    route = subprocess.Popen(['route', '-n'], stdout=subprocess.PIPE)
    output = subprocess.check_output(['awk', 'FNR == 3 {print $2}'], stdin=route.stdout)
    route.wait()

    return output.decode('UTF-8').rstrip()


def get_public_ip():
    log_activity('\tDetermining public ip address')

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
            'https://diagnostic.opendns.com/myip'
            ]

    error_msg = "Error in get_public_ip"
    regex = re.compile(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    for url in urls:
        groups = regex.search(fetch(url, error_msg, is_json=False))

        if groups is not None:
            ip = groups.group(0)

            if len(ip) > 0:
                return ip

    return False


def parse_nmap_output(private_xml_path, public_xml_path):
    log_activity('\tParsing scan output')

    # Update global python dict, "Report"
    global data

    # private nmap scan parsing
    scan = libnmap_parse_xml(private_xml_path)

    # host information (Report.Devices)
    for _host in scan.hosts:
        device = libnmap_host_to_device_schema(_host)
        data['Devices'].append(device)

    # public nmap scan parsing
    scan = libnmap_parse_xml(public_xml_path)

    # router information (Report.Router)
    router = libnmap_host_to_device_schema(scan.hosts[0])
    router['publicIP'] = get_public_ip()
    data['Router'] = router


def calc_vuln_scores_grades():
    global data

    log_activity('\tCalculating vulnerability scores and vulnerability grades')

    # Device vulnerability Scores
    device_scores = []
    for device in data['Devices']:
        device_score = cal_device_vuln_score(device)

        # set Device 'Vulnerability_Score' in Report
        device['Vulnerability_Score'] = device_score
        device_scores.append(device_score)

    # Router vulnerability Score
    router_score = cal_device_vuln_score(data['Router'])

    # set Router 'Vulnerability_Score' in Report
    data['Router']['Vulnerability_Score'] = router_score

    # Network vulnerability Score
    network_score = network_vulnerability_score(router_score, device_scores, len(data['Devices']))
    network_grade = grade(network_score)

    # set Network 'Vulnerability_Score' and Vulnerability_Grade' in Report
    data['Vulnerability_Score'] = network_score
    data['Vulnerability_Grade'] = network_grade


def get_cves():
    log_activity('\tFinding CVEs')

    global data

    # Device CVEs
    for Device in data['Devices']:
        # Host CVEs
        for CPE in Device['host_CPE_list']:
            Device['host_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))

        # Services CVEs
        for Service in Device['Services']:
            for CPE in Service['service_CPE_list']:
                Service['service_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))

    # Router (host) CVEs
    for CPE in data['Router']['host_CPE_list']:
        data['Router']['host_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))

    # Router Services and corresponding CVEs
    for Service in data['Router']['Services']:
        for CPE in Service['service_CPE_list']:
            Service['service_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))


def create_report():
    log_activity('\tConverting data format')
    return ''


def log_activity(log_string):
    global scan_id
    global db_connection

    c = db_connection.cursor()

    c.execute("INSERT INTO ActivityLog (id, message) VALUES (%d, %s)", (scan_id, log_string))

    print(log_string)


def update_progress(job, job_percentage):
    global progress_weights
    global cumulative_progress
    global incremental_progress
    global scan_id

    current_progress = int(progress_weights[job] * job_percentage + cumulative_progress)

    # Percentage increased, update database to reflect current progress & update counter
    if current_progress > incremental_progress:
        c = db_connection.cursor()

        c.execute("UPDATE Scan SET progress=%d WHERE id=%d;", (current_progress, scan_id))

        incremental_progress = current_progress

    # Job completed, update cumulative_progress
    if job_percentage == 100:
        cumulative_progress = incremental_progress


def main():
    global scan_id
    global public_ip
    global gateway_ip

    # Find data needed for scans
    log_activity('Preparing for scan:')
    public_ip = get_public_ip()
    gateway_ip = get_gateway()

    # Scan the network and parse the results
    log_activity('Starting scan (ID = ' + scan_id + '):')
    # TODO: Pass proper arguments
    parse_nmap_output(run_nmap([], 'private'), run_nmap([], 'public'))

    # Enrich the scan results
    log_activity('Enriching scan results:')
    get_cves()
    calc_vuln_scores_grades()

    # Dump the final results to the database
    log_activity('Generating report:')
    create_report()

    log_activity('Scan completed')

if __name__ == "__main__":
    main()
