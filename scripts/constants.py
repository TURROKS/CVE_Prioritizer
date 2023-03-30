#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "0.1.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"

SIMPLE_HEADER = f"{'CVE-ID':<18}Priority"
# VERBOSE_HEADER = f"{'CVE-ID':<18}{'PRIORITY':<13}{'EPSS':<9}{'PERC':<6}{'CVSS':<6}{'SEVERITY':<12}CISA_KEV"
VERBOSE_HEADER = f"{'CVE-ID':<18}{'PRIORITY':<13}{'EPSS':<9}{'CVSS':<6}{'SEVERITY':<12}CISA_KEV"
EPSS_URL = "https://api.first.org/data/v1/epss"
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_BASE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
