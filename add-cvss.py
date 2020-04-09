#!/usr/bin/env python3

# Author: Jon Seager <jnsgr.uk / jnsgruk@github>
# License: MIT <https://opensource.org/licenses/MIT>
#
# A simple, quick script that parses the simplified JSON output
# from `process-nvdcve.py` and augments a JSON formatted
# Trivy report to include CVSS scores
#
#
# Usage: python add-cvss.py <trivy-json-report> <cvss-json-file>
# Example: python add-cvss.py cvss.json.gz output.json > new_report.json

import gzip
import json
import logging
import sys
from json.decoder import JSONDecodeError

# Get the filename of the CVSS JSON
cvss_filename = sys.argv[1]
# Get the filename of the trivy report from the first argument
report_filename = sys.argv[2]


def parse_file_or_quit(filename, gzipped=False):
    try:
        file = gzip.open(filename, "rb") if gzipped else open(filename, "r")
        parsed = json.load(file)
        file.close()
        return parsed
    except JSONDecodeError:
        print(f"File: {filename} is not valid JSON! Exiting...",
              file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        # If file not found, bail out!
        print(f"File: {filename} not found. Exiting...", file=sys.stderr)
        sys.exit(1)
    except:
        # If file not found, bail out!
        print(
            f"Error opening file: {filename}, is it the right format? Exiting...", file=sys.stderr)
        sys.exit(1)


# Open and parse the files
report_json = parse_file_or_quit(report_filename)
cvss_json = parse_file_or_quit(cvss_filename, gzipped=True)

# Iterate over items in the trivy report
if report_json[0]["Vulnerabilities"] != None:
    for item in report_json[0]["Vulnerabilities"]:
        try:
            # Get the CVE name to index the CVSS file
            cve_name = item['VulnerabilityID']
            # Add the CVSS info if available
            item["CVSS"] = cvss_json[cve_name]
        except KeyError:
            # If not available set blank and move on
            item["CVSS"] = {}
            continue
# Dump the JSON to stdout
print(json.dumps(report_json, indent=2, ensure_ascii=False))
