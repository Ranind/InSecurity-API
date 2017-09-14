import MySQLdb
import subprocess
import re
import json
import time

from parse_nmap_helpers import *
from get_cves_helpers import *
from calc_vuln_scores_grades_helpers import *

db_connection = MySQLdb.connect(host='localhost', user='api', passwd='password', db='InSecurity')
data = {}
scan_id = int(sys.argv[1])
public_ip = None
gateway_ip = None
network = None

# TODO: Determine appropriate weights
progress_weights = {
    'prep': 5,
    'nmap_public': 25,
    'nmap_private': 25,
    'parse': 5,
    'cves': 30,
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

    xml_path = '/tmp/nmap_results_%s_%s.xml' % (scan, scan_id)
    nmap_cmd = ['nmap', '-v'] + args + ['-oX', xml_path]
    nmap = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE)

    # TODO: Increment shouldn't be hard coded here, should be
    #       dependent on nmap args/scan type
    progress_increment = .1
    progress = 0
    # Parse output from nmap looking for the lines beginning with:
    # "Initiating _____" to increase progress for each scan.
    # with -T4 -A, there should be 10 separate scans
    while True:
        line = nmap.stdout.readline().decode('UTF-8')
        if not line:
            break
        if line.startswith('Initiating'):
            progress += progress_increment
            update_progress('nmap_%s' % scan, progress)

    xml_abs_path = os.path.abspath(xml_path)

    return xml_abs_path


def get_gateway():
    """
    Return the default gateway of the host calling this function
    """
    log_activity('\tDetermining gateway')

    route = subprocess.Popen(['ip', 'route', 'show'], stdout=subprocess.PIPE)
    output = subprocess.check_output(['awk', 'FNR == 1 {print $3}'], stdin=route.stdout)
    route.wait()

    return output.decode('UTF-8').rstrip()


def get_network():
    """
    Return the network for this host in CIDR notation
    """
    log_activity('\tDetermining gateway')

    route = subprocess.Popen(['ip', 'route', 'show'], stdout=subprocess.PIPE)
    output = subprocess.check_output(['awk', 'FNR == 2 {print $1}'], stdin=route.stdout)
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
    global data

    log_activity('\tParsing scan output')

    data['Devices'] = []

    # private nmap scan parsing
    scan = libnmap_parse_xml(private_xml_path)

    # host information (Report.Devices)
    for _host in scan.hosts:
        device = libnmap_host_to_device_schema(_host)
        data['Devices'].append(device)

    # public nmap scan parsing
    scan = libnmap_parse_xml(public_xml_path)

    # router information (Report.Router)
    if len(scan.hosts) > 0:
        router = libnmap_host_to_device_schema(scan.hosts[0])
    else:
        router = libnmap_host_to_device_schema(None)
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
    global data

    log_activity('\tFinding CVEs')

    progress = 0
    progress_increment = 1 / count_cpes(data)

    # Device CVEs
    for Device in data['Devices']:
        # Host CVEs
        for CPE in Device['host_CPE_list']:
            Device['host_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))
            progress += progress_increment
            update_progress('cves', progress)

        # Services CVEs
        for Service in Device['Services']:
            for CPE in Service['service_CPE_list']:
                Service['service_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))
                progress += progress_increment
                update_progress('cves', progress)

    # Router (host) CVEs
    for CPE in data['Router']['host_CPE_list']:
        data['Router']['host_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))
        progress += progress_increment
        update_progress('cves', progress)

    # Router Services and corresponding CVEs
    for Service in data['Router']['Services']:
        for CPE in Service['service_CPE_list']:
            Service['service_CVE_list'].extend(cpe_to_dict_cve_list(CPE['cpeString']))
            progress += progress_increment
            update_progress('cves', progress)

def consolidate_router_scans():
    global data
    global public_ip
    global gateway_ip

    # set router publicIP
    data['Router']['publicIP'] = public_ip

    # move router internal scan from device section of report to router section of report
    for i, Device in enumerate(data['Devices']):

        # match
        if Device['IP'] == gateway_ip:

            data['Router']['IP'] = gateway_ip
            
            data['Router']['MAC_Address'] = Device['MAC_Address']
            data['Router']['Vendor'] = Device['Vendor']
            break


def create_report():
    global data
    global scan_id
    global db_connection

    log_activity('\tConverting data format')

    c = db_connection.cursor()

    # Add device IPs to the devices table
    for d in data['Devices']:
        c.execute("INSERT INTO Devices (id, ip) VALUES (%s, %s)", (scan_id, d['IP']))
    db_connection.commit()

    # Insert report into database and update scan metadata
    r_json = str(json.dumps(data))
    c.execute("UPDATE Scan SET status='Completed', completed=CURRENT_TIMESTAMP, progress=100, report=%s WHERE id=%s;", (r_json, scan_id))
    db_connection.commit()


def log_activity(log_string):
    global scan_id
    global db_connection

    c = db_connection.cursor()

    c.execute("INSERT INTO ActivityLog (id, message) VALUES (%s, %s)", (scan_id, log_string))
    db_connection.commit()

    print(log_string)


def update_progress(job, job_percentage):
    """
    Update global progress, given the current job, and current job's percentage.
    Percentage should be between 0 - 1.
    """
    global progress_weights
    global cumulative_progress
    global incremental_progress
    global scan_id

    current_progress = int(progress_weights[job] * job_percentage + cumulative_progress)

    # Percentage increased, update database to reflect current progress & update counter
    if current_progress > incremental_progress:
        c = db_connection.cursor()

        c.execute("UPDATE Scan SET progress=%s WHERE id=%s;", (current_progress, scan_id))
        db_connection.commit()

        incremental_progress = current_progress

    # Job completed, update cumulative_progress
    if job_percentage == 1:
        cumulative_progress = incremental_progress


def main():
    global scan_id
    global public_ip
    global gateway_ip

    # Find data needed for scans
    log_activity('Preparing for scan:')
    update_progress('prep', 0)
    public_ip = get_public_ip()
    update_progress('prep', .33)
    gateway_ip = get_gateway()
    update_progress('prep', .67)
    network = get_network()
    update_progress('prep', 1)

    # Scan the network and parse the results
    log_activity('Starting scan (ID = %d):' % scan_id)

    private_xml_path = run_nmap(['-T4', '-A', network], 'private')
    update_progress('nmap_private', 1)

    public_xml_path = run_nmap(['-T4', '-A', public_ip], 'public')
    update_progress('nmap_public', 1)

    parse_nmap_output(private_xml_path, public_xml_path)
    update_progress('parse', 1)

    # Enrich the scan results
    log_activity('Enriching scan results:')

    get_cves()
    update_progress('cves', 1)

    consolidate_router_scans()
    calc_vuln_scores_grades()
    update_progress('scores', 1)

    # Dump the final results to the database
    log_activity('Generating report:')
    create_report()

    log_activity('Scan completed')

if __name__ == "__main__":
    main()
