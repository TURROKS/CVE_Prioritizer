#!/usr/bin/env python3
# This file contains the functions that create the reports

import requests

from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"


# Collect EPSS Scores
def epss_check(cve_id):

    try:
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
    except requests.exceptions.ConnectionError:
        print(f"Unable to connect to EPSS, Check your Internet connection or try again")
        return None


# Check NIST NVD for the CVE
def nist_check(cve_id):

    try:
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
                            results = {"cvss_version": "CVSS 3.1",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                            results = {"cvss_version": "CVSS 3.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                            results = {"cvss_version": "CVSS 2.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev}
                            return results
                    elif unique_cve.get("cve").get("vulnStatus") != "Analyzed":
                        print(f"{cve_id:<18}{unique_cve.get('cve').get('vulnStatus')}")
            else:
                print(f"{cve_id:<18}Not Found in NIST NVD.")
        else:
            print(f"{cve_id:<18}Error")
    except requests.exceptions.ConnectionError:
        print(f"Unable to connect to NIST NVD, Check your Internet connection or try again")
        return None


# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, save_output=None):

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
