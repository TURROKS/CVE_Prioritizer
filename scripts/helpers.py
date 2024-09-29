#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.6.4"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import os
import requests

import click
from dotenv import load_dotenv
from termcolor import colored

from scripts.constants import EPSS_URL, NIST_BASE_URL, VULNCHECK_BASE_URL, VULNCHECK_KEV_BASE_URL, CISA_KEV_URL

load_dotenv()


# Collect EPSS Scores
def epss_check(cve_id):
    """
    Function collects EPSS from FIRST.org
    """

    try:
        epss_url = EPSS_URL + f"?cve={cve_id}"
        epss_response = requests.get(epss_url)
        epss_status_code = epss_response.status_code

        if epss_status_code == 200:
            if epss_response.json().get("total") > 0:
                for cve in epss_response.json().get("data"):
                    results = {"epss": float(cve.get("epss")),
                               "percentile": int(float(cve.get("percentile")) * 100)}
                    return results
            else:
                click.echo(f"{cve_id:<18}Not Found in EPSS.")
        else:
            click.echo(f"Error connecting to EPSS - {epss_status_code}")
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to EPSS, Check your Internet connection or try again")
        return None


# Check NIST NVD for the CVE
def nist_check(cve_id, api_key):
    """
    Function collects NVD Data
    """

    try:
        nvd_key = None

        if api_key:
            nvd_key = api_key
        elif os.getenv('NIST_API'):
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
            ransomware = ''

            if nvd_response.json().get("totalResults") > 0:
                for unique_cve in nvd_response.json().get("vulnerabilities"):

                    # Check if present in CISA's KEV
                    if unique_cve.get("cve").get("cisaExploitAdd"):
                        cisa_kev = True

                        # Check ransomware use
                        kev_data = requests.get(CISA_KEV_URL)

                        if kev_data.status_code == 200:
                            kev_list = kev_data.json()
                            for entry in kev_list.get('vulnerabilities'):
                                if entry.get('cveID') == cve_id:
                                    ransomware = str(entry.get('knownRansomwareCampaignUse')).upper()
                        else:
                            ransomware = 'Error'

                    try:
                        cpe = unique_cve.get("cve").get("configurations")[0].get("nodes")[0].get("cpeMatch")[0].get(
                            "criteria")
                    except TypeError:
                        cpe = 'cpe:2.3:::::::::::'

                    # Collect CVSS Data
                    if unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                            results = {"cvss_version": "CVSS 3.1",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "ransomware": ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                            results = {"cvss_version": "CVSS 3.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "ransomware": ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                        for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                            results = {"cvss_version": "CVSS 2.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("baseSeverity"),
                                       "cisa_kev": cisa_kev,
                                       "ransomware": ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                        click.echo(f"{cve_id:<18}NIST Status: {unique_cve.get('cve').get('vulnStatus')}")
                        results = {"cvss_version": "",
                                   "cvss_baseScore": "",
                                   "cvss_severity": "",
                                   "cisa_kev": "",
                                   "ransomware": "",
                                   "cpe": "",
                                   "vector": ""}
                        return results
            else:
                click.echo(f"{cve_id:<18}Not Found in NIST NVD.")
                results = {"cvss_version": "",
                           "cvss_baseScore": "",
                           "cvss_severity": "",
                           "cisa_kev": "",
                           "ransomware": "",
                           "cpe": "",
                           "vector": ""}
                return results
        else:
            click.echo(f"{cve_id:<18}Error code {nvd_status_code}")
            results = {"cvss_version": "",
                       "cvss_baseScore": "",
                       "cvss_severity": "",
                       "cisa_kev": "",
                       "ransomware": "",
                       "cpe": "",
                       "vector": ""}
            return results
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to NIST NVD, Check your Internet connection or try again")
        return None


# Check Vulncheck NVD++
def vulncheck_check(cve_id, api_key):
    """
    Function collects VulnCheck NVD2 Data
    """

    try:
        vulncheck_key = None
        if api_key:
            vulncheck_key = api_key
        elif os.getenv('VULNCHECK_API'):
            vulncheck_key = os.getenv('VULNCHECK_API')

        vulncheck_url = VULNCHECK_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        # Check if API has been provided
        if vulncheck_key:
            vulncheck_response = requests.get(vulncheck_url, headers=header, params=params)
        else:
            click.echo("VulnCheck requires an API key")
            exit()

        vc_status_code = vulncheck_response.status_code

        if vc_status_code == 200:
            vc_kev = False
            vc_used_by_ransomware = 'Error'
            if vulncheck_response.json().get("_meta").get("total_documents") > 0:
                for unique_cve in vulncheck_response.json().get("data"):

                    # Check if present in CISA's KEV
                    if unique_cve.get("cisaExploitAdd"):
                        vc_kev = True

                        # Check ransomware use
                        vulncheck_url = VULNCHECK_KEV_BASE_URL + f"?cve={cve_id}"
                        vulncheck_response = requests.get(vulncheck_url, headers=header, params=params).json()
                        vc_used_by_ransomware = str(vulncheck_response.get("data")[0].get("knownRansomwareCampaignUse")).upper()

                    try:
                        cpe = unique_cve.get("configurations")[0].get("nodes")[0].get("cpeMatch")[0].get(
                            "criteria")
                    except TypeError:
                        cpe = 'cpe:2.3:::::::::::'

                    # Collect CVSS Data
                    if unique_cve.get("metrics").get("cvssMetricV31"):
                        for metric in unique_cve.get("metrics").get("cvssMetricV31"):
                            results = {"cvss_version": "CVSS 3.1",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": vc_kev,
                                       "ransomware": vc_used_by_ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("metrics").get("cvssMetricV30"):
                        for metric in unique_cve.get("metrics").get("cvssMetricV30"):
                            results = {"cvss_version": "CVSS 3.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                                       "cisa_kev": vc_kev,
                                       "ransomware": vc_used_by_ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("metrics").get("cvssMetricV2"):
                        for metric in unique_cve.get("metrics").get("cvssMetricV2"):
                            results = {"cvss_version": "CVSS 2.0",
                                       "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                                       "cvss_severity": metric.get("baseSeverity"),
                                       "cisa_kev": vc_kev,
                                       "ransomware": vc_used_by_ransomware,
                                       "cpe": cpe,
                                       "vector": metric.get("cvssData").get("vectorString")}
                            return results
                    elif unique_cve.get("vulnStatus") == "Awaiting Analysis":
                        click.echo(f"{cve_id:<18}NIST Status: {unique_cve.get('vulnStatus')}")
                        results = {"cvss_version": "",
                                   "cvss_baseScore": "",
                                   "cvss_severity": "",
                                   "cisa_kev": "",
                                   "ransomware": "",
                                   "cpe": "",
                                   "vector": ""}
                        return results
            else:
                click.echo(f"{cve_id:<18}Not Found in VulnCheck.")
                results = {"cvss_version": "",
                           "cvss_baseScore": "",
                           "cvss_severity": "",
                           "cisa_kev": "",
                           "ransomware": "",
                           "cpe": "",
                           "vector": ""}
                return results
        else:
            click.echo(f"{cve_id:<18}Error code {vc_status_code}")
            results = {"cvss_version": "",
                       "cvss_baseScore": "",
                       "cvss_severity": "",
                       "cisa_kev": "",
                       "ransomware": "",
                       "cpe": "",
                       "vector": ""}
            return results
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to VulnCheck, Check your Internet connection or try again")
        return None


def vulncheck_kev(cve_id, api_key):
    """
    Check Vulncheck's KEV catalog
    """

    vc_exploited = False
    vc_used_by_ransomware = False

    try:
        vulncheck_key = None
        if api_key:
            vulncheck_key = api_key
        elif os.getenv('VULNCHECK_API'):
            vulncheck_key = os.getenv('VULNCHECK_API')

        # local variables
        vulncheck_url = VULNCHECK_KEV_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        # Check if API has been provided
        if vulncheck_key:
            vulncheck_response = requests.get(vulncheck_url, headers=header, params=params).json()

            if vulncheck_response.get('data'):
                vc_exploited = True
                vc_used_by_ransomware = str(vulncheck_response.get('data')[0].get('knownRansomwareCampaignUse')).upper()
                return vc_exploited, vc_used_by_ransomware
            else:
                return vc_exploited, vc_used_by_ransomware
        else:
            click.echo("VulnCheck requires an API key")
            exit()
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to VulnCheck, Check your Internet connection or try again")
        return None, None


def colored_print(priority):
    """
    Function used to handle colored print
    """
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
def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cvss_severity, kev, ransomware,
                    source, verbose, cpe, vector, no_color):
    color_priority = colored_print(priority)
    vendor, product = parse_cpe(cpe)

    if verbose:
        if no_color:
            click.echo(
                f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                f"{truncate_string(product, 20):<23}{vector}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                       f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                       f"{truncate_string(product, 20):<23}{vector}")
    else:
        if no_color:
            click.echo(f"{cve_id:<18}{color_priority:<22}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}")
    if working_file:
        working_file.write(f"{cve_id},{priority},{epss},{cvss_base_score},{cvss_version},{cvss_severity},"
                           f"{kev},{ransomware},{source},{cpe},{vendor},{product},{vector}\n")


# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, sem, colored_output, save_output=None, api=None,
           nvd_plus=None, vc_kev=None, results=None):
    """
    Main Function
    """
    kev_source = 'CISA'
    if vc_kev:
        cve_result = vulncheck_check(cve_id, api)
        exploited = vulncheck_kev(cve_id, api)[0]
        kev_source = 'VULNCHECK'
    elif nvd_plus:
        cve_result = vulncheck_check(cve_id, api)
        exploited = cve_result.get("cisa_kev")
    else:
        if 'vulncheck' in str(api).lower():
            click.echo("Wrong API Key provided (VulnCheck)")
            exit()
        cve_result = nist_check(cve_id, api)
        exploited = cve_result.get("cisa_kev")
    epss_result = epss_check(cve_id)

    try:
        if exploited:
            ransomware = cve_result.get('ransomware')
            print_and_write(save_output, cve_id, 'Priority 1+', epss_result.get('epss'),
                            cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                            cve_result.get('cvss_severity'), 'TRUE', ransomware, kev_source, verbose_print,
                            cve_result.get('cpe'), cve_result.get('vector'), colored_output)
        elif cve_result.get("cvss_baseScore") >= cvss_score:
            if epss_result.get("epss") >= epss_score:
                print_and_write(save_output, cve_id, 'Priority 1', epss_result.get('epss'),
                                cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                cve_result.get('cvss_severity'), '', '', kev_source, verbose_print,
                                cve_result.get('cpe'), cve_result.get('vector'), colored_output)
            else:
                print_and_write(save_output, cve_id, 'Priority 2', epss_result.get('epss'),
                                cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                cve_result.get('cvss_severity'), '', '', kev_source, verbose_print,
                                cve_result.get('cpe'), cve_result.get('vector'), colored_output)
        else:
            if epss_result.get("epss") >= epss_score:
                print_and_write(save_output, cve_id, 'Priority 3', epss_result.get('epss'),
                                cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                cve_result.get('cvss_severity'), '', '', kev_source, verbose_print,
                                cve_result.get('cpe'), cve_result.get('vector'), colored_output)
            else:
                print_and_write(save_output, cve_id, 'Priority 4', epss_result.get('epss'),
                                cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                cve_result.get('cvss_severity'), '', '', kev_source, verbose_print,
                                cve_result.get('cpe'), cve_result.get('vector'), colored_output)
        if results is not None:
            results.append({
                'cve_id': cve_id,
                'priority': 'P1+' if exploited else 'P1' if cve_result.get(
                    "cvss_baseScore") >= cvss_score and epss_result.get(
                    "epss") >= epss_score else 'P2' if epss_result.get(
                    "epss") < epss_score else 'P3' if epss_result.get("epss") >= epss_score else 'P4',
                'epss': epss_result.get('epss'),
                'cvss_base_score': cve_result.get('cvss_baseScore'),
                'cvss_version': cve_result.get('cvss_version'),
                'cvss_severity': cve_result.get('cvss_severity'),
                'kev': 'TRUE' if exploited else 'FALSE',
                'kev_source': kev_source,
                'cpe': cve_result.get('cpe'),
                'vector': cve_result.get('vector')
            })
    except (TypeError, AttributeError):
        pass

    sem.release()


def update_env_file(file, key, value):
    """Update the .env file with the new key value."""
    env_file_path = file
    env_lines = []
    key_found = False

    # Read the current .env file and update the key if it exists
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as file:
            for line in file:
                if line.startswith(key):
                    env_lines.append(f'{key}="{value}"\n')
                    key_found = True
                else:
                    env_lines.append(line)

    # If the key was not found, add it to the end
    if not key_found:
        env_lines.append(f'{key}="{value}"\n')

    # Write the changes back to the .env file
    with open(env_file_path, 'w') as file:
        file.writelines(env_lines)
