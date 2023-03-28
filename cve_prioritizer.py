#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

import argparse
import threading

from scripts.helpers import nist_check
from scripts.helpers import epss_check

# argparse setup
parser = argparse.ArgumentParser(description="CVE Prioritizer tool", epilog='Happy Patching')
parser.add_argument('-c', '--cve', type=str, help='Unique CVE ID', required=False, metavar='')
parser.add_argument('-e', '--epss', type=float, help='EPSS Threshold (Default 0.2)', default=0.2, metavar='')
parser.add_argument('-f', '--file', type=str, help='TXT File with CVE IDs (One per Line)', required=False, metavar='')
parser.add_argument('-l', '--list', type=str, help='Comma Separated List of CVE IDs', required=False, metavar='')
parser.add_argument('-n', '--cvss', type=float, help='CVSS Threshold (Default 7.0)', default=7.0, metavar='')
parser.add_argument('-o', '--output', type=str, help='Output Filename', required=False, metavar='')
parser.add_argument('-t', '--threads', type=str, help='Number of Threads', required=False, metavar='')
parser.add_argument('-v', '--verbose', type=str, help='Verbose Mode', default=False, metavar='')

# Global Arguments
args = parser.parse_args()


def main(cve_id):

    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    if nist_result[1] is True:
        print(f"{cve_id:<18}Priority 1+")
    elif nist_result[0] >= 7.0:
        if epss_result >= 0.2:
            print(f"{cve_id:<18}Priority 1")
        else:
            print(f"{cve_id:<18}Priority 2")
    else:
        if epss_result >= 0.2:
            print(f"{cve_id:<18}Priority 3")
        else:
            print(f"{cve_id:<18}Priority 4")


if __name__ == '__main__':

    num_threads = 3
    cves = ["CVE-2017-16885", "CVE-2020-29127", "CVE-2020-4657", "CVE-2019-0808", "CVE-2023-23397"]

    threads = []

    for cve in cves:

        t = threading.Thread(target=main, args=(cve,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
