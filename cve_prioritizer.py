#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

import argparse
import threading

from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.helpers import nist_check
from scripts.helpers import epss_check

# argparse setup
parser = argparse.ArgumentParser(description="CVE Prioritizer tool", epilog='Happy Patching',
                                 usage='cve_prioritizer.py -c CVE-XXXX-XXXX')
parser.add_argument('-c', '--cve', type=str, help='Unique CVE ID', required=False, metavar='')
parser.add_argument('-e', '--epss', type=float, help='EPSS Threshold (Default 0.2)', default=0.2, metavar='')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='TXT File with CVE IDs (One per Line)',
                    required=False, metavar='')
parser.add_argument('-l', '--list', help='Space Separated List of CVE IDs', nargs='+', required=False, metavar='')
parser.add_argument('-n', '--cvss', type=float, help='CVSS Threshold (Default 7.0)', default=7.0, metavar='')
parser.add_argument('-o', '--output', type=str, help='Output Filename', required=False, metavar='')
parser.add_argument('-t', '--threads', type=str, help='Number of Threads', required=False, metavar='')
parser.add_argument('-v', '--verbose', help='Verbose Mode', default=False, action='store_true')

# Global Arguments
args = parser.parse_args()


def main(cve_id, cvss_score, epss_score, verbose_print):

    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    if verbose_print:
        try:
            if nist_result.get("cisa_kev"):
                print(f"{cve_id:<18}{'Priority 1+':<13}"
                      f"{epss_result.get('epss'):<9}"
                      # f"{epss_result.get('percentile'):<6}"
                      f"{nist_result.get('cvss_baseScore'):<6}"
                      f"{nist_result.get('cvss_severity'):<12}TRUE")
            elif nist_result.get("cvss_baseScore") >= cvss_score:
                if epss_result.get("epss") >= epss_score:
                    print(f"{cve_id:<18}{'Priority 1':<13}"
                          f"{epss_result.get('epss'):<9}"
                          # f"{epss_result.get('percentile'):<6}"
                          f"{nist_result.get('cvss_baseScore'):<6}"
                          f"{nist_result.get('cvss_severity'):<12}FALSE")
                else:
                    print(f"{cve_id:<18}{'Priority 2':<13}"
                          f"{epss_result.get('epss'):<9}"
                          # f"{epss_result.get('percentile'):<6}"
                          f"{nist_result.get('cvss_baseScore'):<6}"
                          f"{nist_result.get('cvss_severity'):<12}FALSE")
            else:
                if epss_result.get("epss") >= epss_score:
                    print(f"{cve_id:<18}{'Priority 3':<13}"
                          f"{epss_result.get('epss'):<9}"
                          # f"{epss_result.get('percentile'):<6}"
                          f"{nist_result.get('cvss_baseScore'):<6}"
                          f"{nist_result.get('cvss_severity'):<12}FALSE")
                else:
                    print(f"{cve_id:<18}{'Priority 4':<13}"
                          f"{epss_result.get('epss'):<9}"
                          # f"{epss_result.get('percentile'):<6}"
                          f"{nist_result.get('cvss_baseScore'):<6}"
                          f"{nist_result.get('cvss_severity'):<12}FALSE")
        except (TypeError, AttributeError):
            pass
    else:
        try:
            if nist_result.get("cisa_kev"):
                print(f"{cve_id:<18}Priority 1+")
            elif nist_result.get("cvss_baseScore") >= cvss_score:
                if epss_result.get("epss") >= epss_score:
                    print(f"{cve_id:<18}Priority 1")
                else:
                    print(f"{cve_id:<18}Priority 2")
            else:
                if epss_result.get("epss") >= epss_score:
                    print(f"{cve_id:<18}Priority 3")
                else:
                    print(f"{cve_id:<18}Priority 4")
        except (TypeError, AttributeError):
            pass
            # print("Unable to fetch results, check your internet connection or Input")


if __name__ == '__main__':

    num_threads = 3

    cve_list = []
    header = SIMPLE_HEADER
    threads = []
    epss_threshold = args.epss
    cvss_threshold = args.cvss
    verbose = False

    if args.verbose:
        header = VERBOSE_HEADER
        verbose = True
    if args.cve:
        cve_list.append(args.cve)
        print(header)
    elif args.list:
        cve_list = args.list
        print(header)
    elif args.file:
        cve_list = [line.rstrip() for line in args.file]
        print(header)

    for cve in cve_list:

        t = threading.Thread(target=main, args=(cve, cvss_threshold, epss_threshold, verbose))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
