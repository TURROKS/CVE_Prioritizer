#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import argparse
import threading

from scripts.constants import LOGO
from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.helpers import worker

# argparse setup
parser = argparse.ArgumentParser(description="CVE Prioritizer", epilog='Happy Patching',
                                 usage='cve_prioritizer.py -c CVE-XXXX-XXXX')
parser.add_argument('-c', '--cve', type=str, help='Unique CVE-ID', required=False, metavar='')
parser.add_argument('-e', '--epss', type=float, help='EPSS threshold (Default 0.2)', default=0.2, metavar='')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='TXT file with CVEs (One per Line)',
                    required=False, metavar='')
parser.add_argument('-l', '--list', help='Space separated list of CVEs', nargs='+', required=False, metavar='')
parser.add_argument('-n', '--cvss', type=float, help='CVSS threshold (Default 7.0)', default=7.0, metavar='')
parser.add_argument('-o', '--output', type=str, help='Output filename', required=False, metavar='')
parser.add_argument('-t', '--threads', type=str, help='Number of concurrent threads', required=False, metavar='')
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')

# Global Arguments
args = parser.parse_args()


if __name__ == '__main__':

    # standard args
    num_threads = 3
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
        print(LOGO+header)
    elif args.list:
        cve_list = args.list
        print(LOGO+header)
    elif args.file:
        cve_list = [line.rstrip() for line in args.file]
        print(LOGO+header)

    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,cisa_kev"+"\n")

    for cve in cve_list:
        t = threading.Thread(target=worker, args=(cve, cvss_threshold, epss_threshold, args.verbose, args.output))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
