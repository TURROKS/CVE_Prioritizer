#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.5.3"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import os
import re
import threading
import time
from threading import Semaphore

import click
from dotenv import load_dotenv

from scripts.constants import LOGO
from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.constants import VERBOSE_HEADER_VC
from scripts.helpers import update_env_file
from scripts.helpers import worker

load_dotenv()
Throttle_msg = ''


# argparse setup
@click.command()
@click.option('-a', '--api', type=str, help='Your API Key')
@click.option('-c', '--cve', type=str, help='Unique CVE-ID')
@click.option('-d', '--demo', is_flag=True, help='Top 10 CVEs of the last 7days from cvetrends.com')
@click.option('-e', '--epss', type=float, default=0.2, help='EPSS threshold (Default 0.2)')
@click.option('-f', '--file', type=click.File('r'), help='TXT file with CVEs (One per Line)')
@click.option('-n', '--cvss', type=float, default=6.0, help='CVSS threshold (Default 6.0)')
@click.option('-o', '--output', type=click.File('w'), help='Output filename')
@click.option('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('-l', '--list', help='Comma separated list of CVEs')
@click.option('-nc', '--no-color', is_flag=True, help='Disable Colored Output')
@click.option('-sa', '--set-api', is_flag=True, help='Save API keys')
@click.option('-vc', '--vulncheck', is_flag=True, help='Use NVD++ - Requires VulnCheck API')
@click.option('-vck', '--vulncheck_kev', is_flag=True, help='Use Vulncheck KEV - Requires VulnCheck API')
def main(api, cve, demo, epss, file, cvss, output, threads, verbose, list, no_color, set_api, vulncheck, vulncheck_kev):
    # Global Arguments
    color_enabled = not no_color
    throttle_msg = ''

    # standard args
    header = SIMPLE_HEADER
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
        if vulncheck_kev:
            header = VERBOSE_HEADER_VC
    if cve:
        cve_list.append(cve)
        if not api:
            if not os.getenv('NIST_API') and not vulncheck:
                click.echo(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
                           + '\n\n' + header)
            else:
                click.echo(LOGO + header)
        else:
            click.echo(LOGO + header)
    elif list:
        cve_list = list.split(',')
        if not api:
            if not os.getenv('NIST_API') and not vulncheck:
                if len(cve_list) > 75:
                    throttle_msg = 'Large number of CVEs detected, requests will be throttle to avoid API issues'
                click.echo(LOGO + throttle_msg + '\n'
                           + 'Warning: Using this tool without specifying a NIST API may result in errors' + '\n\n'
                           + header)
            else:
                click.echo(LOGO + header)
        else:
            click.echo(LOGO + header)
    elif file:
        cve_list = [line.rstrip() for line in file]
        if not api:
            if not os.getenv('NIST_API') and not vulncheck:
                if len(cve_list) > 75:
                    throttle_msg = "Large number of CVEs detected, requests will be throttle to avoid API issues"
                click.echo(LOGO + throttle_msg + '\n'
                           + 'Warning: Using this tool without specifying a NIST API may result in errors' + '\n\n'
                           + header)
            else:
                click.echo(LOGO + header)
        else:
            click.echo(LOGO + header)
    elif demo:
        click.echo('Unfortunately, due to Twitter’s recent API change, the CVETrends is currently unable to run.')
        # try:
        #     trends = cve_trends()
        #     if trends:
        #         cve_list = trends
        #         if not os.getenv('NIST_API'):
        #             click.echo(
        #                 LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
        #                 + '\n\n' + header)
        #         else:
        #             click.echo(LOGO + header)
        # except json.JSONDecodeError:
        #     click.echo(f"Unable to connect to CVE Trends")

    if output:
        if vulncheck_kev:
            output.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,vulncheck_kev,cpe,vendor,product,vector"
                         + "\n")
        else:
            output.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,cisa_kev,cpe,vendor,product,vector"
                         + "\n")

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
                                                      sem, color_enabled, output, api, vulncheck, vulncheck_kev))
            threads.append(t)
            t.start()
            time.sleep(throttle)

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
