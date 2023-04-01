#!/usr/bin/env python3
# This file contains the functions that create the reports

import requests

from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.1"
__maintainer__ = "Mario Rojas"
__status__ = "Development"


def epss_check(cve_id):
    epss_url = EPSS_URL + f"?cve={cve_id}"
    epss_response = requests.get(epss_url)
    epss_status_code = epss_response.status_code

    if epss_status_code == 200:
        if epss_response.json().get("total") > 0:
            for cve in epss_response.json().get("data"):
                results = {"epss": float(cve.get("epss")),
                           "percentile": int(float(cve.get("percentile"))*100)}
                return results
        else:
            return False
    else:
        print("Error connecting to EPSS")


# Check NIST NVD for the CVE
def nist_check(cve_id):
    nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
    nvd_response = requests.get(nvd_url)
    nvd_status_code = nvd_response.status_code

    if nvd_status_code == 200:
        cisa_kev = False
        if nvd_response.json().get("totalResults") > 0:
            for unique_cve in nvd_response.json().get("vulnerabilities"):

                # Check if present in CISA's KEV
                if unique_cve.get("cve").get("cisaExploitAdd"):
                    cisa_kev = True

                # Collect CVSS Data
                if unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                        results = {"cvss_version": "Ver 3.1",
                                   "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                   "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                   "cisa_kev": cisa_kev}
                        return results
                elif unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                        results = {"cvss_version": "Ver 3.0",
                                   "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                   "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                   "cisa_kev": cisa_kev}
                        return results
                elif unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                        results = {"cvss_version": "Ver 2.0",
                                   "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                   "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                   "cisa_kev": cisa_kev}
                        return results
        else:
            print(f"{cve_id:<18}Not Found in NIST NVD.")
    else:
        print(f"{cve_id:<18}Error")
