#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "0.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

import requests

from scripts.constants import CISA_BASE_URL
from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL

# Enter the CVE ID that you want to check
cve_id = "CVE-2021-34527"

# Check EPSS for the CVE
epss_url = EPSS_URL + f"?cve={cve_id}"
epss_response = requests.get(epss_url)
epss_status_code = epss_response.status_code

if epss_status_code == 200:
    if epss_response.json().get("total") > 0:
        print(f"{cve_id} is present in EPSS.")
    else:
        print(f"{cve_id} is not present in EPSS.")
else:
    print("Error connecting to EPSS")

# Check NIST NVD for the CVE
nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
nvd_response = requests.get(nvd_url)
nvd_status_code = nvd_response.status_code

if nvd_status_code == 200:
    if nvd_response.json().get("totalResults") > 0:
        print(f"{cve_id} is present in NIST NVD.")
    else:
        print(f"{cve_id} is not present in NIST NVD.")
else:
    print("Error connecting to NVD")

# Check CISA Known Exploited Vulnerabilities catalog for the CVE

cisa_response = requests.get(CISA_BASE_URL)
cisa_status_code = cisa_response.status_code
cisa_json = cisa_response.json()

if cisa_status_code == 200:
    if cisa_json.get("count") > 0:
        vulnerabilities = cisa_json.get("vulnerabilities")
        for cve in vulnerabilities:
            if cve_id == cve.get("cveID"):
                print(f"{cve_id} is present in CISA KEV catalog.")
    else:
        print(f"{cve_id} is not present in CISA KEV catalog.")
else:
    print("Error connecting to CISA")
