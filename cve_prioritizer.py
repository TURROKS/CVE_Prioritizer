#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import argparse
import json
import os
import re
import threading

from dotenv import load_dotenv

from scripts.constants import LOGO
from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.helpers import worker
from scripts.helpers import cve_trends

load_dotenv()

# argparse setup
parser = argparse.ArgumentParser(description="CVE Prioritizer", epilog='Happy Patching',
                                 usage='cve_prioritizer.py -c CVE-XXXX-XXXX')
parser.add_argument('-c', '--cve', type=str, help='Unique CVE-ID', required=False, metavar='')
parser.add_argument('-d', '--demo', help='Top 10 CVEs of the last 7days from cvetrends.com', action='store_true')
parser.add_argument('-e', '--epss', type=float, help='EPSS threshold (Default 0.2)', default=0.2, metavar='')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='TXT file with CVEs (One per Line)',
                    required=False, metavar='')
parser.add_argument('-n', '--cvss', type=float, help='CVSS threshold (Default 6.0)', default=6.0, metavar='')
parser.add_argument('-o', '--output', type=str, help='Output filename', required=False, metavar='')
parser.add_argument('-t', '--threads', type=str, help='Number of concurrent threads', required=False, metavar='')
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
parser.add_argument('-l', '--list', help='Space separated list of CVEs', nargs='+', required=False, metavar='')

# Global Arguments
args = parser.parse_args()


if __name__ == '__main__':

    # standard args
    header = SIMPLE_HEADER
    epss_threshold = args.epss
    cvss_threshold = args.cvss

    # Temporal lists
    cve_list = []
    threads = []

    if args.verbose:
        header = VERBOSE_HEADER
    if args.cve:
        cve_list.append(args.cve)
        # print(LOGO+header)
        if not os.getenv('NIST_API'):
            print(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                  + '\n\n' + header)
        else:
            print(LOGO + header)
    elif args.list:
        cve_list = args.list
        if not os.getenv('NIST_API'):
            print(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                  + '\n\n' + header)
        else:
            print(LOGO + header)
    elif args.file:
        cve_list = [line.rstrip() for line in args.file]
        if not os.getenv('NIST_API'):
            print(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                  + '\n\n' + header)
        else:
            print(LOGO + header)
    elif args.demo:
        try:
            trends = cve_trends()
            if trends:
                cve_list = trends
                if not os.getenv('NIST_API'):
                    print(
                        LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                        + '\n\n' + header)
                else:
                    print(LOGO + header)
        except json.JSONDecodeError:
            print(f"Unable to connect to CVE Trends")

    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,cisa_kev"+"\n")

    for cve in cve_list:
        if not re.match("(CVE|cve-\d{4}-\d+$)", cve):
            print(f"{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*")
        else:
            t = threading.Thread(target=worker, args=(cve.upper().strip(), cvss_threshold, epss_threshold, args.verbose,
                                                      args.output))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()
