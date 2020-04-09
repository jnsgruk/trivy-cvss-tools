#!/usr/bin/env python3

# Author: Jon Seager <jonseager@gmail.com>
# License: MIT <https://opensource.org/licenses/MIT>
#
# Processes the JSON files found at:
# https://github.com/olbat/nvdcve/tree/master/nvdcve
#
# Reduces down to a single JSON object where each key
# is the name of a CVE, which contains an object with
# the base score, impact score and exploitability score
#
# Usage: python process-nvdcve.py <path-to-folder-with-json-files> <output-filename>
# Example: python process-nvdcve.py nvdcve/nvdcve cvss.json.gz

import gzip
import json
import os
import sys
from json.decoder import JSONDecodeError

# Get the filename of the trivy report from the first argument
directory = sys.argv[1]
files = os.listdir(directory)
try:
    output_file = sys.argv[2]
except:
    output_file = "cvss.json.gz"

output = {}

# Iterate over each file
for file in files:
    # Get the path of the file
    path = os.path.join(directory, file)
    try:
        # Try to open the file
        with open(path, "r") as f:
            # Attempt to parse the JSON file
            try:
                cve_data = json.load(f)
            except JSONDecodeError as e:
                print(
                    f"Invalid JSON Received for {cve_name}", file=sys.stderr)
                continue

            # Fetch the full CVE name
            cve_name = file.split(".")[0]

            # Fetch the CVSS v3 info where possible
            try:
                if cve_data["impact"]["baseMetricV3"]:
                    # Collate the scores into a dict
                    scores = {
                        "base_score": cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"],
                        "impact_score": cve_data["impact"]["baseMetricV3"]["impactScore"],
                        "exploitability_score": cve_data["impact"]["baseMetricV3"]["exploitabilityScore"],
                    }
                    output[cve_name] = scores
                # If found, carry on and don't add CVSS v2 data
                continue
            except KeyError as e:
                pass

            # Fetch the CVSS v2 info where possible
            try:
                if cve_data["impact"]["baseMetricV2"]:
                    # Collate the scores into a dict
                    scores = {
                        "base_score": cve_data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"],
                        "impact_score": cve_data["impact"]["baseMetricV2"]["impactScore"],
                        "exploitability_score": cve_data["impact"]["baseMetricV2"]["exploitabilityScore"],
                    }
                    output[cve_name] = scores
            except KeyError as e:
                print(
                    f"Couldn't find CVSS data for {cve_name}", file=sys.stderr)
                continue
    except FileNotFoundError as e:
        # File not found - move on! This should never happen...
        print(
            f"Couldn't find CVSS data for {cve_name}", file=sys.stderr)

# Output a gzipped json file!
try:
    with gzip.GzipFile(output_file, "wb+") as f:
        f.write(json.dumps(output, indent=2).encode())
except:
    print(f"Unable to write {output_file}! Exiting!", file=sys.stderr)
