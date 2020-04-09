### Trivy CVSS Tools

This repository contains two simple Python scripts that, together with the JSON files in [this repository](https://github.com/olbat/nvdcve) enable a CI/CD pipeline ir similar tooling to augment a [Trivy](https://github.com/aquasecurity/trivy) container scan report with CVSS scores where they are available.

#### process-nvdcve.py

This tool is used to parse all of the [JSON files](https://github.com/olbat/nvdcve/tree/master/nvdcve) contained in the nvdcve repo - example usage might be:

```bash
$ git clone https://github.com/olbat/nvdcve.git
$ python process-nvdcve.py nvdcve/nvdcve
```

By default, the above will output a (gzipped) JSON file, that when decompressed is of the form:

```json
"CVE-YYYY-XXXXX": {
  "base_score": 4.5,
  "impact_score": 6.7,
  "exploitability_score": 4.3
}
```

The script will check each vulnerability, preferring the CVSSv3 scores if available, and including the CVSSv2 scores if not.

#### add-cvss.py

This script takes an existing Trivy report and gzipped CVSS file as input, and outputs an augmented report to stdout. Example might look like this:

```bash
$ trivy -q --cache-dir /tmp/trivy -f json debian:stable-slim > trivy_report.json
$ python add-cvss.py trivy_report.json cvss.json.gz > new_report.json
$ cat new_report.json | jq '.[0].Vulnerabilities[0]'
{
  "VulnerabilityID": "CVE-2011-3374",
  "PkgName": "apt",
  "InstalledVersion": "1.8.2",
  "LayerID": "sha256:5d23f9193e1f7fed41a87ee03d9e7d656cc2b115eef61e15fe5517c4578bbeac",
  "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
  "Severity": "MEDIUM",
  "References": [
    "https://access.redhat.com/security/cve/cve-2011-3374",
    "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480",
    "https://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-3374.html",
    "https://security-tracker.debian.org/tracker/CVE-2011-3374",
    "https://snyk.io/vuln/SNYK-LINUX-APT-116518"
  ],
  "CVSS": {                         # This section was added by the script
    "base_score": 3.7,              #
    "impact_score": 1.4,            #
    "exploitability_score": 2.2     #
  }
}
```
