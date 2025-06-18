import argparse
import csv
import re
import sys
from typing import List, Set, Pattern, Dict

# Indicator regexes (for extraction)
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"


def load_iocs(iocfile: str) -> Set[str]:
    iocs = set()
    if iocfile.endswith('.csv'):
        with open(iocfile, newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    iocs.add(cell.strip())
    else:
        with open(iocfile) as f:
            for line in f:
                ioc = line.strip()
                if ioc:
                    iocs.add(ioc)
    return iocs


def load_regex_patterns(regexfile: str) -> List[Pattern]:
    patterns = []
    with open(regexfile) as f:
        for line in f:
            pattern = line.strip()
            if pattern:
                try:
                    patterns.append(re.compile(pattern))
                except re.error as e:
                    print(f"[!] Invalid regex skipped: {pattern} ({e})", file=sys.stderr)
    return patterns


def extract_indicators(line: str) -> Dict[str, List[str]]:
    indicators = {
        'ip': re.findall(IP_REGEX, line),
        'domain': re.findall(DOMAIN_REGEX, line),
        'hash': re.findall(HASH_REGEX, line),
        'email': re.findall(EMAIL_REGEX, line),
    }
    return indicators


def parse_log(logfile: str, iocs: Set[str], regex_patterns: List[Pattern], output: str):
    results = []
    with open(logfile) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            indicators = extract_indicators(line)
            matches = []
            # Check for IOC matches
            for ind_type, values in indicators.items():
                for val in values:
                    if val in iocs:
                        matches.append((ind_type, val, 'IOC'))
            # Check for regex pattern matches
            for pattern in regex_patterns:
                for match in pattern.findall(line):
                    matches.append(('regex', match, 'Pattern'))
            if matches:
                for ind_type, val, match_type in matches:
                    results.append({
                        'line': lineno,
                        'indicator_type': ind_type,
                        'indicator': val,
                        'match_type': match_type,
                        'log': line
                    })
                # Console output
                print(f"[!] Line {lineno}: {line}")
                for ind_type, val, match_type in matches:
                    print(f"    -> {match_type} match: {ind_type} = {val}")
    # Write CSV
    if output:
        with open(output, 'w', newline='') as csvfile:
            fieldnames = ['line', 'indicator_type', 'indicator', 'match_type', 'log']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"\n[+] Results written to {output}")


def main():
    parser = argparse.ArgumentParser(description="Log Parser with IOC and Regex Support")
    parser.add_argument('--logfile', required=True, help='Path to log file')
    parser.add_argument('--iocfile', help='Path to IOC file (TXT or CSV)')
    parser.add_argument('--regexfile', help='Path to regex pattern file (one per line)')
    parser.add_argument('--output', default='results.csv', help='CSV output file (default: results.csv)')
    args = parser.parse_args()

    iocs = set()
    if args.iocfile:
        iocs = load_iocs(args.iocfile)
        print(f"[+] Loaded {len(iocs)} IOCs from {args.iocfile}")
    regex_patterns = []
    if args.regexfile:
        regex_patterns = load_regex_patterns(args.regexfile)
        print(f"[+] Loaded {len(regex_patterns)} regex patterns from {args.regexfile}")

    parse_log(args.logfile, iocs, regex_patterns, args.output)


if __name__ == '__main__':
    main() 