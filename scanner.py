import os
import re
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

# Stored patterns
PATTERNS = {

    "AWS Access Key":
    r"AKIA[0-9A-Z]{16}",

    "Google API Key":
    r"AIza[0-9A-Za-z\-_]{35}",

    "Generic API Key":
    r"(?i)(api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9\-_]{16,}[\"']?",

    "Password":
    r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?.+[\"']?",

    "Bearer Token":
    r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",

    "JWT Token":
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",

    "Private Key":
    r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? PRIVATE KEY-----"
}

# Scans a single file
def scan_file(file_path):

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):

            for secret_name, pattern in PATTERNS.items():

                matches = re.findall(pattern, line)

                if matches:

                    findings.append({
                        "file": file_path,
                        "line": line_number,
                        "type": secret_name,
                        "match": line.strip()
                    })

    except Exception as error:
        logging.error(f"Could not scan file: {file_path}")
        logging.error(error)

    return findings

# Scans ALL files in a FOLDER.
def scan_directory(directory_path):

    all_findings = []

    for root, dirs, files in os.walk(directory_path):

        for file_name in files:

            full_path = os.path.join(root, file_name)

            logging.info(f"Scanning: {full_path}")

            file_findings = scan_file(full_path)

            all_findings.extend(file_findings)

    return all_findings

# Prints the findings
def print_report(findings):

    print("SECRET SCAN REPORT")
    print("==============================\n")

    if not findings:
        print("No secrets found.")
        return

    for item in findings:

        print(f"File: {item['file']}")
        print(f"Line: {item['line']}")
        print(f"Type: {item['type']}")
        print(f"Match: {item['match']}")
        print("-" * 40)

    print(f"\nTotal Findings: {len(findings)}")

# main
def main():

    parser = argparse.ArgumentParser(
        description="Simple CLI tool for detecting hardcoded secrets"
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to a file or directory to scan"
    )

    args = parser.parse_args()

    target_path = args.path

    if not os.path.exists(target_path):
        logging.error("The provided path does not exist.")
        return

    findings = []

    # If the input is a file
    if os.path.isfile(target_path):

        logging.info(f"Scanning file: {target_path}")

        findings = scan_file(target_path)

    # If the input is a directory
    elif os.path.isdir(target_path):

        logging.info(f"Scanning directory: {target_path}")

        findings = scan_directory(target_path)

    print_report(findings)

if __name__ == "__main__":
    main()