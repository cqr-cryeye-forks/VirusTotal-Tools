__author__ = 'Matthew Clairmont'
__version__ = '1.3'
__date__ = 'July 8, 2024'

import os
import csv
import time
import requests
import argparse
from typing import List, Dict, Optional

def domain_scanner(domain: str, apikey: str) -> Optional[Dict[str, str]]:
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}
    try:
        response = requests.post(url, params=params)
        response.raise_for_status()
        json_response = response.json()
        if json_response['response_code'] != 1:
            print(f'There was an error submitting the domain {domain} for scanning: {json_response["verbose_msg"]}')
            return None
        print(f'{domain} was scanned successfully.')
        return {'domain': domain, 'status': 'queued'} if json_response['response_code'] == -2 else None
    except requests.RequestException as e:
        print(f'Error scanning domain {domain}: {e}')
        return None

def domain_report_reader(domain: str, apikey: str, delay: bool) -> Optional[List[str]]:
    if delay:
        print(f'There was a delay in scanning {domain}. Waiting for 10s to ensure the report is ready.')
        time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}
    try:
        response = requests.post(url, params=params)
        response.raise_for_status()
        json_response = response.json()
        if json_response['response_code'] == 0:
            print(f'There was an error retrieving the report for {domain}.')
            return None
        if json_response['response_code'] == -2:
            print(f'Report for {domain} is not ready yet. Please check the site\'s report.')
            return None

        permalink = json_response['permalink']
        scandate = json_response['scan_date']
        positives = json_response['positives']
        total = json_response['total']
        return [scandate, domain.replace('.', '[.]'), str(positives), str(total), permalink]

    except requests.RequestException as e:
        print(f'Error retrieving report for {domain}: {e}')
        return None

def main():
    parser = argparse.ArgumentParser(description="VirusTotal Domain Scanner")
    parser.add_argument('--apikey', type=str, required=True, help='Your VirusTotal API key')
    parser.add_argument('--apitype', type=str, choices=['public', 'private'], required=True, help='Type of your API key')
    parser.add_argument('--domains_file', type=str, required=True, help='Path to the file containing domains')

    args = parser.parse_args()
    apikey = args.apikey
    apitype = args.apitype
    domains_file = args.domains_file

    sleeptime = 1 if apitype == 'private' else 15

    if os.path.exists('results.csv'):
        os.remove('results.csv')

    with open('results.csv', 'w', newline='') as file:
        header = ['Scan Date', 'Domain', 'Detection Ratio', 'Vendor', 'Category', 'Permalink']
        header_writer = csv.writer(file)
        header_writer.writerow(header)

    domain_errors = []
    with open(domains_file, 'r') as infile:
        for domain in infile:
            domain = domain.strip()
            delay_info = domain_scanner(domain, apikey)
            data = domain_report_reader(domain, apikey, delay_info is not None)
            if data:
                with open('results.csv', 'a', newline='') as file:
                    data_writer = csv.writer(file)
                    data_writer.writerow(data)
            else:
                domain_errors.append(domain)
            time.sleep(sleeptime)

    if domain_errors:
        print(f'There were {len(domain_errors)} errors scanning domains: {domain_errors}')

if __name__ == '__main__':
    main()
