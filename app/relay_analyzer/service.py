import re

class RelayAnalyzer:
    @staticmethod
    def analyze(headers):
        received = headers.get('Received', [])
        if not isinstance(received, list):
            received = [str(received)]

        hops = []
        for i, entry in enumerate(reversed(received)):
            hop = RelayAnalyzer._parse_hop(str(entry), i + 1)
            hops.append(hop)

        # Identify first external entry point
        # Simplistic: first hop after internal relays
        # In this mock, we flag hops with suspicious IPs or patterns

        return {
            'hops': hops,
            'summary': {
                'total_hops': len(hops),
                'first_external_hop': hops[0] if hops else None
            }
        }

    @staticmethod
    def _parse_hop(entry, hop_num):
        # Example: from mx.google.com ([1.2.3.4]) by ...
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', entry)
        ip = ip_match.group(1) if ip_match else None

        flags = []
        if ip:
            # Mock suspicious ASN or geo check
            if ip.startswith('10.') or ip.startswith('192.168.'):
                flags.append({'type': 'INTERNAL_IP', 'severity': 'INFO'})
            elif ip.startswith('1.2.3.'): # Mock "bad" range
                flags.append({'type': 'SUSPICIOUS_SOURCE', 'severity': 'MEDIUM'})

        return {
            'hop': hop_num,
            'content': entry,
            'ip': ip,
            'flags': flags
        }
