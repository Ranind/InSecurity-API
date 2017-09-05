import os
import subprocess

scan_id = '1'

def run_nmap(nmap_args):
    """
    nmap_args - list of args to give nmap

    Return temp XML file paths
    """
    xml_path = 'nmap_results_%s.xml' % scan_id
    nmap_cmd = ['nmap'] + nmap_args + ['-oX', xml_path]
    nmap = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE)

    while True:
        # TODO: parse this for progress
        line = nmap.stdout.readline()
        if not line:
            break

    xml_abs_path = os.path.abspath(xml_path)
    return xml_abs_path


run_nmap(['127.0.0.1'])
