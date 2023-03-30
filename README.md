# CVE Prioritizer Tool

CVE_Prioritizer uses CVSS, EPSS and CISA's Known Exploited Vulnerabilities to help you prioritize vulnerability patching.

## Usage

### Inputs

CVE_Prioritizer allows you to provide the input CVEs on different ways.

#### Single CVE

To check a single CVE you can use the -c or --cve flags

`python3 cve_details.py -c CVE-2020-29127`

![single s.png](misc%2Fsingle%20s.png)

#### List of CVEs

You can also provide a list of **space** separated CVEs

`python3 cve_prioritizer.py -l CVE-2020-29127 CVE-2017-16885`

![list.png](misc%2Flist.png)

#### File with CVES

You can additionally import a file with CVE IDs (One per line)

`python3 cve_prioritizer.py -f ~\Desktop\CheckThisCVEs.txt`

![file.png](misc%2Ffile.png)

### Outputs

You can decide how much information is provided by choosing verbose mode, Prioritizer will by default give you the 
summary results (CVE-ID + Priority), but you can use the -v or --verbose flags to get additional information such as:

- EPSS Score
- CVSS Base Score
- CVSS Severity
- CISA KEV: TRUE OR FALSE

![single v.png](misc%2Fsingle%20v.png)
