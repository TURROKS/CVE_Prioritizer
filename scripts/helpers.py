#!/usr/bin/env python3
# This file contains the functions that create the reports

import os
import requests

from dotenv import load_dotenv
from termcolor import colored

from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.4.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

load_dotenv()


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
                print(f"{cve_id:<18}Not Found in EPSS.")
        else:
            print("Error connecting to EPSS")
    except requests.exceptions.ConnectionError:
        print(f"Unable to connect to EPSS, Check your Internet connection or try again")
        return None


# Check NIST NVD for the CVE
def nist_check(cve_id):

    try:
        nvd_key = os.getenv('NIST_API')
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        header = {'apiKey': f'{nvd_key}'}

        # Check if API has been provided
        if nvd_key:
            nvd_response = requests.get(nvd_url, headers=header)
        else:
            nvd_response = requests.get(nvd_url)

        nvd_status_code = nvd_response.status_code

        if nvd_status_code == 200:
            cisa_kev = False
            if nvd_response.json().get("totalResults") > 0:
                for unique_cve in nvd_response.json().get("vulnerabilities"):

                    # Check if present in CISA's KEV
                    if unique_cve.get("cve").get("cisaExploitAdd"):
                        cisa_kev = True

                    try:
                        cpe = unique_cve.get("cve").get("configurations")[0].get("nodes")[0].get("cpeMatch")[0].get("criteria")
                    except TypeError:
                        cpe = 'cpe:2.3:::::::::::'

                    # Collect CVSS Data
                    if unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                            results = {"cvss_version": "CVSS 3.1",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "cpe": cpe}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                            results = {"cvss_version": "CVSS 3.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "cpe": cpe}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                            results = {"cvss_version": "CVSS 2.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "cpe": cpe}
                            return results
                    elif unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                        print(f"{cve_id:<18}NIST Status: {unique_cve.get('cve').get('vulnStatus')}")
            else:
                print(f"{cve_id:<18}Not Found in NIST NVD.")
                exit()
        else:
            print(f"{cve_id:<18}Error code {nvd_status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Unable to connect to NIST NVD, Check your Internet connection or try again")
        return None


def colored_print(priority):
    if priority == 'Priority 1+':
        return colored(priority, 'red')
    elif priority == 'Priority 1':
        return colored(priority, 'red')
    elif priority == 'Priority 2':
        return colored(priority, 'yellow')
    elif priority == 'Priority 3':
        return colored(priority, 'yellow')
    elif priority == 'Priority 4':
        return colored(priority, 'green')


# Extract CVE product details
def parse_cpe(cpe_str):
    """
    Parses a CPE URI string and extracts the vendor, product, and version.
    Assumes the CPE string is in the format: cpe:/a:vendor:product:version:update:edition:language
    """
    # Splitting the CPE string into components
    parts = cpe_str.split(':')

    # Extracting vendor, product, and version
    vendor = parts[3] if len(parts) > 2 else None
    product = parts[4] if len(parts) > 3 else None

    return vendor, product


# Truncate for printing
def truncate_string(input_string, max_length):
    """
    Truncates a string to a maximum length, appending an ellipsis if the string is too long.
    """
    if len(input_string) > max_length:
        return input_string[:max_length - 3] + "..."
    else:
        return input_string


# Function manages the outputs
def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cvss_severity, cisa_kev,
                    verbose, cpe, no_color):

    color_priority = colored_print(priority)
    vendor, product = parse_cpe(cpe)

    if verbose:
        if no_color:
            print(f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                  f"{cisa_kev:<10}{truncate_string(vendor,15):<18}{truncate_string(product, 20)}")
        else:
            print(f"{cve_id:<18}{priority:<13}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                  f"{cisa_kev:<10}{truncate_string(vendor, 15):<18}{truncate_string(product, 20)}")
    else:
        if no_color:
            print(f"{cve_id:<18}{color_priority:<22}")
        else:
            print(f"{cve_id:<18}{priority:<13}")
    if working_file:
        working_file.write(f"{cve_id},{priority},{epss},{cvss_base_score},{cvss_version},{cvss_severity},"
                           f"{cisa_kev},{cpe},{vendor},{product}\n")


# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, sem, colored_output, save_output=None):
    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    working_file = None
    if save_output:
        working_file = open(save_output, 'a')

    try:
        if nist_result.get("cisa_kev"):
            print_and_write(working_file, cve_id, 'Priority 1+', epss_result.get('epss'),
                            nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                            nist_result.get('cvss_severity'), 'TRUE', verbose_print, nist_result.get('cpe'),
                            colored_output)
        elif nist_result.get("cvss_baseScore") >= cvss_score:
            if epss_result.get("epss") >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 1', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print, nist_result.get('cpe'),
                                colored_output)
            else:
                print_and_write(working_file, cve_id, 'Priority 2', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print, nist_result.get('cpe'),
                                colored_output)
        else:
            if epss_result.get("epss") >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 3', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print, nist_result.get('cpe'),
                                colored_output)
            else:
                print_and_write(working_file, cve_id, 'Priority 4', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print, nist_result.get('cpe'),
                                colored_output)
    except (TypeError, AttributeError):
        pass

    if working_file:
        working_file.close()

    sem.release()


# Function retrieves data from CVE Trends
def cve_trends():

    cve_list = []

    try:
        html = requests.get("https://cvetrends.com/api/cves/7days")
        parsed = html.json()
        if html.status_code == 200:
            for cve in parsed.get("data"):
                cve_list.append(cve.get("cve"))
        else:
            return None
    except ConnectionError:
        print(f"Unable to connect to CVE Trends, Check your Internet connection or try again")
        return None

    return cve_list
