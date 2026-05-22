import re

class HeaderAnalyzerService:
    @staticmethod
    def analyze(headers):
        results = {
            'display_name_spoofing': False,
            'origin_ip': None,
            'relay_chain': [],
            'inconsistencies': []
        }

        # 1. Origin IP and Relay Chain Analysis
        received = headers.get('Received', [])
        if isinstance(received, list):
            for entry in reversed(received): # Analyze from oldest to newest
                results['relay_chain'].append(str(entry))
                # The oldest hop often contains the true origin IP or first relay
                if not results['origin_ip']:
                    ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(entry))
                    if ip_match:
                        results['origin_ip'] = ip_match.group(1)

        # 2. Display Name Spoofing Detection
        from_header = headers.get('From', '')
        display_name_match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if display_name_match:
            display_name = display_name_match.group(1).strip()
            actual_email = display_name_match.group(2).strip()

            inner_email = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', display_name)
            if inner_email and inner_email.group(1).lower() != actual_email.lower():
                results['display_name_spoofing'] = True
                results['inconsistencies'].append(f"Display name contains a different email ({inner_email.group(1)}) than actual sender ({actual_email})")

        # 3. Return-Path Mismatch
        return_path = headers.get('Return-Path', '')
        if return_path and from_header:
            from_email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', from_header)
            rp_email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', return_path)
            if from_email_match and rp_email_match:
                if from_email_match.group(1).lower() != rp_email_match.group(1).lower():
                    results['inconsistencies'].append(f"From address ({from_email_match.group(1)}) mismatched with Return-Path ({rp_email_match.group(1)})")

        return results
