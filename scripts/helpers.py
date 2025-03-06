#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.8.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import logging
import os
import re
import requests
import click
from dotenv import load_dotenv
from termcolor import colored
from scripts.constants import EPSS_URL, NIST_BASE_URL, VULNCHECK_BASE_URL, VULNCHECK_KEV_BASE_URL, CISA_KEV_URL
import xml.etree.ElementTree as ET

load_dotenv()

# Configure logging to write to a file in the current working directory
logging.basicConfig(
    filename=os.path.join(os.getcwd(), 'cve_prioritizer_logs.txt'),
    filemode='w',  # Overwrite the log file on each run
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# Collect EPSS Scores
def epss_check(cve_id):
    """
    Function collects EPSS from FIRST.org
    """
    try:
        epss_url = EPSS_URL + f"?cve={cve_id}"
        epss_response = requests.get(epss_url)
        epss_response.raise_for_status()

        response_data = epss_response.json()
        if response_data.get("total") > 0:
            for cve in response_data.get("data"):
                results = {"epss": float(cve.get("epss")),
                           "percentile": int(float(cve.get("percentile")) * 100)}
                return results
        else:
            logger.warning(f"{cve_id} - Not Found in EPSS.")
            click.echo(f"{cve_id:<18}Not Found in EPSS.")
            return {"epss": None, "percentile": None}
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"{cve_id} - HTTP error occurred: {http_err}")
        click.echo(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError:
        logger.error(f"{cve_id} - Unable to connect to EPSS, check your Internet connection or try again")
        click.echo("Unable to connect to EPSS, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        logger.error(f"{cve_id} - The request to EPSS timed out")
        click.echo("The request to EPSS timed out")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"{cve_id} - An error occurred: {req_err}")
        click.echo(f"An error occurred: {req_err}")
    except ValueError as val_err:
        logger.error(f"{cve_id} - Error processing the response: {val_err}")
        click.echo(f"Error processing the response: {val_err}")

    return {"epss": None, "percentile": None}


# Check NIST NVD for the CVE
def nist_check(cve_id, api_key):
    """
    Function collects NVD Data
    """
    try:
        nvd_key = api_key or os.getenv('NIST_API')
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        headers = {'apiKey': nvd_key} if nvd_key else {}

        nvd_response = requests.get(nvd_url, headers=headers)
        nvd_response.raise_for_status()

        response_data = nvd_response.json()
        if response_data.get("totalResults") > 0:
            for unique_cve in response_data.get("vulnerabilities"):
                cisa_kev = unique_cve.get("cve").get("cisaExploitAdd", False)
                ransomware = ''
                if cisa_kev:
                    kev_data = requests.get(CISA_KEV_URL)
                    kev_data.raise_for_status()
                    kev_list = kev_data.json()
                    for entry in kev_list.get('vulnerabilities', []):
                        if entry.get('cveID') == cve_id:
                            ransomware = str(entry.get('knownRansomwareCampaignUse')).upper()

                cpe = unique_cve.get("cve").get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                metrics = unique_cve.get("cve").get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        for metric in metrics[version]:
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": cisa_kev,
                                "ransomware": ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                    click.echo(f"{cve_id:<18}Awaiting NVD Analysis")
                    logger.info(f"{cve_id} - Awaiting NVD Analysis")
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            click.echo(f"{cve_id:<18}Not Found in NIST NVD.")
            logger.warning(f"{cve_id} - Not Found in NIST NVD.")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        click.echo(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
        logger.error(f"{cve_id} - HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        click.echo("Unable to connect to NIST NVD, check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to NIST NVD, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        click.echo("The request to NIST NVD timed out")
        logger.error(f"{cve_id} - The request to NIST NVD timed out")
    except requests.exceptions.RequestException as req_err:
        click.echo(f"An error occurred: {req_err}")
        logger.error(f"{cve_id} - An error occurred: {req_err}")
    except ValueError as val_err:
        click.echo(f"Error processing the response: {val_err}")
        logger.error(f"{cve_id} - Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }


# Check Vulncheck NVD++
def vulncheck_check(cve_id, api_key, kev_check):
    """
    Function collects VulnCheck NVD2 Data
    """
    try:
        vulncheck_key = api_key or os.getenv('VULNCHECK_API')
        if not vulncheck_key:
            click.echo("VulnCheck requires an API key")
            logger.error("VulnCheck requires an API key")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }

        vulncheck_url = VULNCHECK_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        vulncheck_response = requests.get(vulncheck_url, headers=header, params=params)
        vulncheck_response.raise_for_status()

        response_data = vulncheck_response.json()
        if response_data.get("_meta", {}).get("total_documents", 0) > 0:
            kev_data = requests.get(CISA_KEV_URL)
            kev_data.raise_for_status()
            kev_list = kev_data.json()

            for unique_cve in response_data.get("data", []):
                vc_kev = False
                vc_used_by_ransomware = ''
                if kev_check:
                    vc_kev, vc_used_by_ransomware = vulncheck_kev(unique_cve.get('id'), api_key)
                elif unique_cve.get("cisaExploitAdd"):
                    vc_kev = True
                    for entry in kev_list.get('vulnerabilities', []):
                        if entry.get('cveID') == cve_id:
                            vc_used_by_ransomware = str(entry.get('knownRansomwareCampaignUse')).upper()

                cpe = unique_cve.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                metrics = unique_cve.get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        for metric in metrics[version]:
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": vc_kev,
                                "ransomware": vc_used_by_ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("vulnStatus") == "Awaiting Analysis":
                    click.echo(f"{cve_id:<18}NIST Status: {unique_cve.get('vulnStatus')}")
                    logger.info(f"{cve_id} - NIST Status: {unique_cve.get('vulnStatus')}")
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            click.echo(f"{cve_id:<18}Not Found in VulnCheck.")
            logger.warning(f"{cve_id} - Not Found in VulnCheck.")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        click.echo(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
        logger.error(f"{cve_id} - HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        click.echo("Unable to connect to VulnCheck, check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to VulnCheck, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        click.echo("The request to VulnCheck timed out")
        logger.error(f"{cve_id} - The request to VulnCheck timed out")
    except requests.exceptions.RequestException as req_err:
        click.echo(f"An error occurred: {req_err}")
        logger.error(f"{cve_id} - An error occurred: {req_err}")
    except ValueError as val_err:
        click.echo(f"Error processing the response: {val_err}")
        logger.error(f"{cve_id} - Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }


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
            logger.error(f"{cve_id} - VulnCheck requires an API key")
            exit()
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to VulnCheck, Check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to VulnCheck, Check your Internet connection or try again")
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
    try:
        kev_source = 'CISA'
        if vc_kev:
            cve_result = vulncheck_check(cve_id, api, vc_kev)
            # exploited = vulncheck_kev(cve_id, api)[0]
            exploited = cve_result.get('cisa_kev')
            kev_source = 'VULNCHECK'
        elif nvd_plus:
            cve_result = vulncheck_check(cve_id, api, vc_kev)
            exploited = cve_result.get("cisa_kevs")
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
    except Exception as e:
        logger.error(f"Error in worker thread for CVE {cve_id}: {e}")
    finally:
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


def is_valid_cve(cve_id):
    return re.match(r'^CVE-\d{4}-\d{4,}$', cve_id) is not None


def parse_report(file, report_type):
    cve_ids = set()
    if report_type == 'nessus':
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            cve_ids.update(
                cve.text.strip().upper()
                for report_item in root.findall(".//ReportItem")
                for cve in report_item.findall("cve")
                if is_valid_cve(cve.text.strip().upper())
            )
            return cve_ids
        except ET.ParseError as e:
            click.echo(f"Error parsing XML file: {e}")
            return []
        except Exception as e:
            click.echo(f"An error occurred: {e}")
            return []
    elif report_type == 'openvas':
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            for nvt in root.findall(".//nvt"):
                # Look for ref elements that have type="cve"
                for ref in nvt.findall(".//ref[@type='cve']"):
                    cve = ref.get("id")
                    if cve:
                        cve_ids.add(cve.strip())
            return list(cve_ids)
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return []
        except Exception as e:
            print(f"An error occurred: {e}")
            return []
    return list(cve_ids)
