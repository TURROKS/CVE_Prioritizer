#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

import threading

from scripts.helpers import nist_check
from scripts.helpers import epss_check


def main(cve_id):

    # cisa_result = cisa_check(cve_id)
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
