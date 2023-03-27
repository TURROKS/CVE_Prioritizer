#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "0.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

import requests
import threading

from scripts.constants import CISA_BASE_URL
from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL


# Check EPSS for the CVE
def epss_check(cve_id):
    epss_url = EPSS_URL + f"?cve={cve_id}"
    epss_response = requests.get(epss_url)
    epss_status_code = epss_response.status_code

    if epss_status_code == 200:
        if epss_response.json().get("total") > 0:
            # print(f"{cve_id} is present in EPSS.")
            for cve in epss_response.json().get("data"):
                epss = cve.get("epss")
                percentile = int(float(cve.get("percentile"))*100)
                # print(f"EPSS: {epss}, {cve_id} is more likely to be exploited that {percentile}% of the known CVEs")
                return float(epss)
        else:
            # print(f"{cve_id} is not present in EPSS.")
            return False
    else:
        print("Error connecting to EPSS")


# Check NIST NVD for the CVE
def nist_check(cve_id):
    nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
    nvd_response = requests.get(nvd_url)
    nvd_status_code = nvd_response.status_code

    if nvd_status_code == 200:
        if nvd_response.json().get("totalResults") > 0:
            # print(f"{cve_id} is present in NIST NVD.")
            for id in nvd_response.json().get("vulnerabilities"):
                if id.get("cve").get("metrics").get("cvssMetricV31"):
                    for metric in id.get("cve").get("metrics").get("cvssMetricV31"):
                        version = "Ver 3.1"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss)
                elif id.get("cve").get("metrics").get("cvssMetricV30"):
                    for metric in id.get("cve").get("metrics").get("cvssMetricV30"):
                        version = "Ver 3.0"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss)
                elif id.get("cve").get("metrics").get("cvssMetricV2"):
                    for metric in id.get("cve").get("metrics").get("cvssMetricV2"):
                        version = "Ver 2.0"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss)
        else:
            print(f"{cve_id} is not present in NIST NVD.")
            return False
    else:
        print("Error connecting to NVD")


# Check CISA Known Exploited Vulnerabilities catalog for the CVE
def cisa_check(cve_id):
    cisa_response = requests.get(CISA_BASE_URL)
    cisa_status_code = cisa_response.status_code
    cisa_json = cisa_response.json()

    if cisa_status_code == 200:
        if cisa_json.get("count") > 0:
            vulnerabilities = cisa_json.get("vulnerabilities")
            for cve in vulnerabilities:
                if cve_id == cve.get("cveID"):
                    # print(f"{cve_id} is present in CISA KEV catalog.")
                    return True
            # print(f"{cve_id} is not present in CISA KEV catalog.")
            return False
    else:
        print("Error connecting to CISA")


def main(cve_id):

    cisa_result = cisa_check(cve_id)
    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    if cisa_result:
        print(f"{cve_id} Priority 1+")
    elif nist_result >= 7.0:
        if epss_result >= 0.2:
            print(f"{cve_id} Priority 1")
        else:
            print(f"{cve_id} Priority 2")
    else:
        if epss_result >= 0.2:
            print(f"{cve_id} Priority 3")
        else:
            print(f"{cve_id} Priority 4")


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
