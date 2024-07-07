__author__ = 'Matthew Clairmont'
__version__ = '1.1'
__date__ = 'July 8, 2024'

import time
import requests
import csv
from typing import List, Dict, Optional

apikey = ''  # ENTER API KEY HERE

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domain_errors: List[str] = []
delay: Dict[str, str] = {}


def domain_scanner(domain: str) -> Optional[Dict[str, str]]:
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}
    try:
        response = client.post(url, params=params)
        response.raise_for_status()
        json_response = response.json()
        domain_sani = domain.replace('.', '[.]')

        if json_response['response_code'] != 1:
            print(
                f'There was an error submitting the domain {domain_sani} for scanning: {json_response["verbose_msg"]}')
            return None
        print(f'{domain_sani} was scanned successfully.')
        if json_response['response_code'] == -2:
            delay[domain] = 'queued'
            return {'domain': domain, 'status': 'queued'}
        return None

    except requests.RequestException as e:
        print(f'Error scanning domain {domain}: {e}')
        domain_errors.append(domain)
        return None


def domain_report_reader(domain: str, delay: bool) -> Optional[List[str]]:
    if delay:
        print(f'There was a delay in scanning {domain}. Waiting for 10s to ensure the report is ready.')
        time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}
    try:
        response = client.post(url, params=params)
        response.raise_for_status()
        json_response = response.json()
        domain_sani = domain.replace('.', '[.]')

        if json_response['response_code'] == 0:
            print(f'There was an error retrieving the report for {domain_sani}.')
            return None
        if json_response['response_code'] == -2:
            print(f'Report for {domain_sani} is not ready yet. Please check the site\'s report.')
            return None

        print(f'Report is ready for {domain_sani}')
        permalink = json_response['permalink']
        scandate = json_response['scan_date']
        positives = json_response['positives']
        total = json_response['total']

        return [scandate, domain_sani, str(positives), str(total), permalink]

    except requests.RequestException as e:
        print(f'Error retrieving report for {domain}: {e}')
        domain_errors.append(domain)
        return None


def main():
    # Open results file and write header
    try:
        with open('results.csv', 'w', newline='') as rfile:
            data_writer = csv.writer(rfile)
            header = ['Scan Date', 'Domain', '# of Positive Scans', '# of Total Scans', 'Permalink']
            data_writer.writerow(header)

    except IOError as ioerr:
        print('Please ensure the file is closed.')
        print(ioerr)
        return

    try:
        with open('domains.txt', 'r') as infile:
            for domain in infile:
                domain = domain.strip()
                try:
                    delay_info = domain_scanner(domain)
                    data = domain_report_reader(domain, delay_info is not None)
                    if data:
                        with open('results.csv', 'a', newline='') as rfile:
                            data_writer = csv.writer(rfile)
                            data_writer.writerow(data)
                        time.sleep(15)  # wait for VT API rate limiting
                except Exception as err:
                    print(f'Encountered an error but scanning will continue: {err}')
                    pass

    except IOError as ioerr:
        print('Please ensure the file exists and is closed.')
        print(ioerr)

    # Inform the user if there were any errors encountered
    count = len(domain_errors)
    if count > 0:
        print(f'There were {count} errors scanning domains')
        print(domain_errors)


if __name__ == '__main__':
    main()
