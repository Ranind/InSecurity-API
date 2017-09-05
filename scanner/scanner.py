import sys
import MySQLdb

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
    log_activity('\tScanning ' + scan + ' network')
    return '/path/to/output'


def parse_nmap_output(private_path, public_path):
    log_activity('\tParsing scan output')
    pass


def get_cves():
    log_activity('\tFinding CVEs')
    pass


def calc_vuln_scores_grades():
    log_activity('\tCalculating vulnerability scores and vulnerability grades')
    pass


def get_public_ip():
    log_activity('\tDetermining public ip address')
    return '127.0.0.1'


def get_gateway():
    log_activity('\tDetermining gateway')
    return '127.0.0.1'


def create_report():
    log_activity('\tConverting data format')
    return ''


def log_activity(log_string):
    pass


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
    parse_nmap_output(run_nmap([]), run_nmap([]))

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
