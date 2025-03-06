#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.8.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import json
import os
import re
import threading
import time
from threading import Semaphore

import click
from dotenv import load_dotenv
from datetime import datetime, timezone

from scripts.constants import LOGO, SIMPLE_HEADER, VERBOSE_HEADER
from scripts.helpers import parse_report, update_env_file, worker

load_dotenv()
Throttle_msg = ''


# argparse setup
@click.command()
@click.option('-a', '--api', type=str, help='Your API Key')
@click.option('-c', '--cve', type=str, help='Unique CVE-ID')
@click.option('-e', '--epss', type=float, default=0.2, help='EPSS threshold (Default 0.2)')
@click.option('-f', '--file', type=click.File('r'), help='TXT file with CVEs (One per Line)')
@click.option('-j', '--json_file', type=click.Path(), required=False, help='JSON output')
@click.option('-n', '--cvss', type=float, default=6.0, help='CVSS threshold (Default 6.0)')
@click.option('-o', '--output', type=click.File('w'), help='Output filename')
@click.option('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('-l', '--list', help='Comma separated list of CVEs')
@click.option('-nc', '--no-color', is_flag=True, help='Disable Colored Output')
@click.option('-sa', '--set-api', is_flag=True, help='Save API keys')
@click.option('-vc', '--vulncheck', is_flag=True, help='Use NVD++ - Requires VulnCheck API')
@click.option('-vck', '--vulncheck_kev', is_flag=True, help='Use Vulncheck KEV - Requires VulnCheck API')
@click.option('--nessus', is_flag=True, help='Parse Nessus file')
@click.option('--openvas', is_flag=True, help='Parse OpenVAS file')
def main(api, cve, epss, file, cvss, output, threads, verbose, list, no_color, set_api, vulncheck, vulncheck_kev,
         json_file, nessus, openvas):

    # Global Arguments
    color_enabled = not no_color
    throttle_msg = ''

    # standard args
    header = VERBOSE_HEADER if verbose else SIMPLE_HEADER
    epss_threshold = epss
    cvss_threshold = cvss
    sem = Semaphore(threads)

    # Temporal lists
    cve_list = []
    threads = []

    if set_api:
        services = ['nist_nvd', 'vulncheck']
        service = click.prompt("Please choose a service to set the API key",
                               type=click.Choice(services, case_sensitive=False))
        api_key = click.prompt(f"Enter the API key for {service}", hide_input=True)

        if service == 'nist_nvd':
            update_env_file('.env', 'NIST_API', api_key)
        elif service == 'vulncheck':
            update_env_file('.env', 'VULNCHECK_API', api_key)

        click.echo(f"API key for {service} updated successfully.")
    if verbose:
        header = VERBOSE_HEADER

    if cve:
        cve_list.append(cve)
    elif list:
        cve_list = list.split(',')
    elif file:
        if nessus:
            cve_list = parse_report(file, 'nessus')
        elif openvas:
            cve_list = parse_report(file, 'openvas')
        else:
            cve_list = [line.rstrip() for line in file]

    if not api and not os.getenv('NIST_API') and not vulncheck:
        if len(cve_list) > 75:
            throttle_msg = 'Large number of CVEs detected, requests will be throttle to avoid API issues'
            click.echo(LOGO + throttle_msg + '\n' +
                       'Warning: Using this tool without specifying a NIST API may result in errors'
                       + '\n\n' + header)
        else:
            click.echo(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                       + '\n\n' + header)
    else:
        click.echo(LOGO + header)

    if output:
        output.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,kev,ransomware,kev_source,cpe,vendor,"
                     "product,vector" + "\n")

    results = []
    for cve in cve_list:
        throttle = 1
        if len(cve_list) > 75 and not os.getenv('NIST_API') and not api and not vulncheck:
            throttle = 6
        if (vulncheck or vulncheck_kev) and (os.getenv('VULNCHECK_API') or api):
            throttle = 0.25
        elif (vulncheck or vulncheck_kev) and not os.getenv('VULNCHECK_API') and not api:
            click.echo("VulnCheck requires an API key")
            exit()
        if not re.match(r'(CVE|cve-\d{4}-\d+$)', cve):
            click.echo(f'{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*')
        else:
            sem.acquire()
            t = threading.Thread(target=worker, args=(cve.upper().strip(), cvss_threshold, epss_threshold, verbose,
                                                      sem, color_enabled, output, api, vulncheck, vulncheck_kev,
                                                      results))
            threads.append(t)
            t.start()
            time.sleep(throttle)

    for t in threads:
        t.join()

    if json_file:
        metadata = {
            'generator': 'CVE Prioritizer',
            'generation_date': datetime.now(timezone.utc).isoformat(),
            'total_cves': len(cve_list),
            'cvss_threshold': cvss_threshold,
            'epss_threshold': epss_threshold,
        }
        output_data = {
            'metadata': metadata,
            'cves': results,
        }
        with open(json_file, 'w') as json_file:
            json.dump(output_data, json_file, indent=4)


if __name__ == '__main__':
    main()
