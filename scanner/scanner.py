import sys
import MySQLdb

from usefull_methods import *
from parse_nmap_output_methods import parse_nmap_output
from get_CVSS_methods import get_cves
from calculate_vulnerability_methods import calc_vuln_scores_grade
from get_publicIP_methods import get_public_ip
#import get_gateway

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
    log_activity('\tDetermining gateway')
    return '127.0.0.1'


def create_report():
    log_activity('\tConverting data format')
    return ''


#***moved to "usefull_methods.py"
#def log_activity(log_string):
#    pass


def update_progress(job, subpercentage):
    pass


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
    parse_nmap_output(run_nmap([], 'public',), run_nmap([], 'private'))

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
