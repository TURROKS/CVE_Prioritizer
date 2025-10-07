#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# API URLs
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NUCLEI_BASE_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
VULNCHECK_BASE_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"
VULNCHECK_KEV_BASE_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
CVELIST_RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

# Visuals
SIMPLE_HEADER = f"{'CVE-ID':<18}Priority"+"\n"+("-"*30)
VERBOSE_HEADER = (f"{'CVE-ID':<18}{'PRIORITY':<13}{'EPSS':<9}{'CVSS':<6}{'VERSION':<10}{'SEVERITY':<10}{'KEV':<7}"
                  f"{'RANSOMWARE':<12}{'EXPLOITED':<11}{'VENDOR':<18}{'PRODUCT':<23}VECTOR")+"\n"+("-"*170)
LOGO = r"""
░█▀▀░█░█░█▀▀                                
░█░░░▀▄▀░█▀▀                                
░▀▀▀░░▀░░▀▀▀                                
░█▀█░█▀▄░▀█▀░█▀█░█▀▄░▀█▀░▀█▀░▀█▀░▀▀█░█▀▀░█▀▄
░█▀▀░█▀▄░░█░░█░█░█▀▄░░█░░░█░░░█░░▄▀░░█▀▀░█▀▄
░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀▀▀░▀░▀ 
v1.10.1                          BY TURROKS
                                                  
"""""
