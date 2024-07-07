import requests
import time
from typing import Any, Dict

# requests setup
requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False

apikey = input('Enter your API key: ')


def get_hash_report(apikey: str, filehash: str) -> None:
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {"apikey": apikey, "resource": filehash, "allinfo": True}

    while True:
        try:
            r = client.get(url, params=params)
            r.raise_for_status()
            if r.status_code == 429:
                print('Encountered rate-limiting. Sleeping for 45 seconds.')
                time.sleep(45)
                continue

            response = r.json()
            parse_hash_report(response)
            break

        except requests.RequestException as e:
            print(f'HTTP error occurred: {e}')
            break


def parse_hash_report(response: Dict[str, Any]) -> None:
    detections = response.get('positives', 0)
    if detections >= 1:
        scan_results = response.get('scans', {})

        print('\nAV Name, Malware Name, Definitions Version, Last Updated')
        for vendor, result in scan_results.items():
            if result.get('detected', False):
                info_date = result.get('update', 'N/A')
                detected_name = result.get('result', 'N/A')
                definition_version = result.get('version', 'N/A')

                print(f'{vendor}, {detected_name}, {definition_version}, {info_date}')
    else:
        print('No malicious detections found.')


if __name__ == '__main__':
    while True:
        filehash = input('Enter a file hash: \n')
        get_hash_report(apikey, filehash)
