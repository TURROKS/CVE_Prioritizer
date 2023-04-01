#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import argparse
import threading

from scripts.constants import LOGO
from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.helpers import nist_check
from scripts.helpers import epss_check

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


def main(cve_id, cvss_score, epss_score, verbose_print, save_output=None):

    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    # Output for verbose mode
    if verbose_print:
        if save_output:
            with open(save_output, 'a') as working_file:
                try:
                    if nist_result.get("cisa_kev"):
                        print(f"{cve_id:<18}"
                              f"{'Priority 1+':<13}"
                              f"{epss_result.get('epss'):<9}"
                              f"{nist_result.get('cvss_baseScore'):<6}"
                              f"{nist_result.get('cvss_version'):<10}"
                              f"{nist_result.get('cvss_severity'):<10}TRUE")
                        working_file.write(f"{cve_id},"
                                           f"Priority 1+,"
                                           f"{epss_result.get('epss')},"
                                           f"{nist_result.get('cvss_baseScore')},"
                                           f"{nist_result.get('cvss_version')},"
                                           f"{nist_result.get('cvss_severity')},TRUE"+"\n")
                    elif nist_result.get("cvss_baseScore") >= cvss_score:
                        if epss_result.get("epss") >= epss_score:
                            print(f"{cve_id:<18}{'Priority 1':<13}"
                                  f"{epss_result.get('epss'):<9}"
                                  f"{nist_result.get('cvss_baseScore'):<6}"
                                  f"{nist_result.get('cvss_version'):<10}"
                                  f"{nist_result.get('cvss_severity'):<10}FALSE")
                            working_file.write(f"{cve_id},"
                                               f"Priority 1,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                        else:
                            print(f"{cve_id:<18}"
                                  f"{'Priority 2':<13}"
                                  f"{epss_result.get('epss'):<9}"
                                  f"{nist_result.get('cvss_baseScore'):<6}"
                                  f"{nist_result.get('cvss_version'):<10}"
                                  f"{nist_result.get('cvss_severity'):<10}FALSE")
                            working_file.write(f"{cve_id},"
                                               f"Priority 2,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                    else:
                        if epss_result.get("epss") >= epss_score:
                            print(f"{cve_id:<18}"
                                  f"{'Priority 3':<13}"
                                  f"{epss_result.get('epss'):<9}"
                                  f"{nist_result.get('cvss_baseScore'):<6}"
                                  f"{nist_result.get('cvss_version'):<10}"
                                  f"{nist_result.get('cvss_severity'):<10}FALSE")
                            working_file.write(f"{cve_id},"
                                               f"Priority 3,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                        else:
                            print(f"{cve_id:<18}{'Priority 4':<13}"
                                  f"{epss_result.get('epss'):<9}"
                                  f"{nist_result.get('cvss_baseScore'):<6}"
                                  f"{nist_result.get('cvss_version'):<10}"
                                  f"{nist_result.get('cvss_severity'):<10}FALSE")
                            working_file.write(f"{cve_id},"
                                               f"Priority 4,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                except (TypeError, AttributeError):
                    pass
        else:
            try:
                if nist_result.get("cisa_kev"):
                    print(f"{cve_id:<18}{'Priority 1+':<13}"
                          f"{epss_result.get('epss'):<9}"
                          f"{nist_result.get('cvss_baseScore'):<6}"
                          f"{nist_result.get('cvss_version'):<10}"
                          f"{nist_result.get('cvss_severity'):<10}TRUE")
                elif nist_result.get("cvss_baseScore") >= cvss_score:
                    if epss_result.get("epss") >= epss_score:
                        print(f"{cve_id:<18}{'Priority 1':<13}"
                              f"{epss_result.get('epss'):<9}"
                              f"{nist_result.get('cvss_baseScore'):<6}"
                              f"{nist_result.get('cvss_version'):<10}"
                              f"{nist_result.get('cvss_severity'):<10}FALSE")
                    else:
                        print(f"{cve_id:<18}{'Priority 2':<13}"
                              f"{epss_result.get('epss'):<9}"
                              f"{nist_result.get('cvss_baseScore'):<6}"
                              f"{nist_result.get('cvss_version'):<10}"
                              f"{nist_result.get('cvss_severity'):<10}FALSE")
                else:
                    if epss_result.get("epss") >= epss_score:
                        print(f"{cve_id:<18}{'Priority 3':<13}"
                              f"{epss_result.get('epss'):<9}"
                              f"{nist_result.get('cvss_baseScore'):<6}"
                              f"{nist_result.get('cvss_version'):<10}"
                              f"{nist_result.get('cvss_severity'):<10}FALSE")
                    else:
                        print(f"{cve_id:<18}{'Priority 4':<13}"
                              f"{epss_result.get('epss'):<9}"
                              f"{nist_result.get('cvss_baseScore'):<6}"
                              f"{nist_result.get('cvss_version'):<10}"
                              f"{nist_result.get('cvss_severity'):<10}FALSE")
            except (TypeError, AttributeError):
                pass
    # output for simple mode
    else:
        if save_output:
            with open(save_output, 'a') as working_file:
                try:
                    if nist_result.get("cisa_kev"):
                        print(f"{cve_id:<18}"
                              f"Priority 1+")
                        working_file.write(f"{cve_id},"
                                           f"Priority 1+,"
                                           f"{epss_result.get('epss')},"
                                           f"{nist_result.get('cvss_baseScore')},"
                                           f"{nist_result.get('cvss_version')},"
                                           f"{nist_result.get('cvss_severity')},TRUE" + "\n")
                    elif nist_result.get("cvss_baseScore") >= cvss_score:
                        if epss_result.get("epss") >= epss_score:
                            print(f"{cve_id:<18}"
                                  f"Priority 1")
                            working_file.write(f"{cve_id},"
                                               f"Priority 1,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                        else:
                            print(f"{cve_id:<18}"
                                  f"Priority 2")
                            working_file.write(f"{cve_id},"
                                               f"Priority 2,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                    else:
                        if epss_result.get("epss") >= epss_score:
                            print(f"{cve_id:<18}"
                                  f"Priority 3")
                            working_file.write(f"{cve_id},"
                                               f"Priority 3,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
                        else:
                            print(f"{cve_id:<18}Priority 4")
                            working_file.write(f"{cve_id},"
                                               f"Priority 4,"
                                               f"{epss_result.get('epss')},"
                                               f"{nist_result.get('cvss_baseScore')},"
                                               f"{nist_result.get('cvss_version')},"
                                               f"{nist_result.get('cvss_severity')},FALSE" + "\n")
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


if __name__ == '__main__':

    # standard args
    num_threads = 3
    header = SIMPLE_HEADER
    epss_threshold = args.epss
    cvss_threshold = args.cvss
    verbose = False

    # Temporal lists
    cve_list = []
    threads = []

    if args.verbose:
        header = VERBOSE_HEADER
        verbose = True
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
        t = threading.Thread(target=main, args=(cve, cvss_threshold, epss_threshold, verbose, args.output))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
