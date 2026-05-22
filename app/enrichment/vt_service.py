import requests
import time
import base64
from flask import current_app

class VirusTotalService:
    def __init__(self):
        self.api_keys = []
        self.current_key_index = 0
        self._load_keys()

    def _load_keys(self):
        keys_str = current_app.config.get('VT_API_KEYS', '')
        if keys_str:
            self.api_keys = [k.strip() for k in keys_str.split(',') if k.strip()]

    def _get_active_key(self):
        if not self.api_keys:
            return None
        return self.api_keys[self.current_key_index]

    def _rotate_key(self):
        if len(self.api_keys) > 1:
            self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
            return True
        return False

    def _make_request(self, endpoint, method='GET', data=None):
        retries = len(self.api_keys)
        while retries > 0:
            key = self._get_active_key()
            if not key:
                return None

            headers = {
                "accept": "application/json",
                "x-apikey": key
            }

            url = f"https://www.virustotal.com/api/v3/{endpoint}"
            try:
                if method == 'GET':
                    response = requests.get(url, headers=headers, timeout=10)
                else:
                    response = requests.post(url, headers=headers, data=data, timeout=10)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429: # Rate limit
                    if self._rotate_key():
                        retries -= 1
                        continue
                    else:
                        break
                elif response.status_code == 401: # Invalid key
                    if self._rotate_key():
                        retries -= 1
                        continue
                    else:
                        break
                else:
                    break
            except Exception as e:
                print(f"VT Request Error: {e}")
                break
        return None

    def get_file_report(self, sha256):
        data = self._make_request(f"files/{sha256}")
        return self._parse_report(data)

    def get_url_report(self, url):
        # VT requires URLs to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = self._make_request(f"urls/{url_id}")
        return self._parse_report(data)

    def get_ip_report(self, ip):
        data = self._make_request(f"ip_addresses/{ip}")
        return self._parse_report(data)

    def _parse_report(self, data):
        if not data or 'data' not in data:
            return None

        attr = data['data']['attributes']
        stats = attr.get('last_analysis_stats', {})

        return {
            'positives': stats.get('malicious', 0),
            'total': sum(stats.values()),
            'last_analysis_date': attr.get('last_analysis_date'),
            'reputation': attr.get('reputation', 0),
            'malicious_engines': self._get_malicious_engines(attr.get('last_analysis_results', {}))
        }

    def _get_malicious_engines(self, results):
        engines = []
        for engine, res in results.items():
            if res.get('category') == 'malicious':
                engines.append(engine)
        return engines
