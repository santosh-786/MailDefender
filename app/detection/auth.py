import spf
import dkim
import dns.resolver
import re

class AuthAnalyzerService:
    @staticmethod
    def analyze(raw_email, sender_ip, from_address):
        results = {
            'spf': AuthAnalyzerService._check_spf(sender_ip, from_address),
            'dkim': AuthAnalyzerService._check_dkim(raw_email, from_address),
            'dmarc': AuthAnalyzerService._check_dmarc(from_address)
        }
        return results

    @staticmethod
    def _check_spf(ip, from_addr):
        if not ip or not from_addr:
            return {'result': 'none', 'explanation': 'Missing IP or From address for SPF check', 'aligned': False}
        try:
            domain = AuthAnalyzerService._extract_domain(from_addr)
            sender_str = AuthAnalyzerService._extract_email_string(from_addr)
            result, code, explanation = spf.check2(i=ip, s=sender_str, h=domain)

            # Alignment check: SPF domain should match From domain
            aligned = False
            if result == 'pass':
                aligned = True # Simplistic: spf.check2 already uses from_addr

            return {
                'result': result,
                'code': code,
                'explanation': explanation,
                'aligned': aligned
            }
        except Exception as e:
            return {'result': 'error', 'explanation': str(e), 'aligned': False}

    @staticmethod
    def _check_dkim(raw_email, from_addr):
        if not raw_email:
            return {'result': 'none', 'explanation': 'No raw email for DKIM check', 'aligned': False}
        if isinstance(raw_email, str):
            raw_email = raw_email.encode()
        try:
            d = dkim.DKIM(raw_email)
            valid = d.verify()

            # Alignment check
            aligned = False
            if valid:
                from_domain = AuthAnalyzerService._extract_domain(from_addr)
                # dkim.verify might have many signatures, but we want to see if any match from_domain
                # d.domain is the domain in the signature
                if d.domain and from_domain and d.domain.decode().lower() == from_domain.lower():
                    aligned = True

            return {
                'result': 'pass' if valid else 'fail',
                'explanation': 'DKIM signature verification',
                'aligned': aligned,
                'signature_domain': d.domain.decode() if d.domain else None
            }
        except Exception as e:
            return {'result': 'none', 'explanation': str(e), 'aligned': False}

    @staticmethod
    def _check_dmarc(from_addr):
        domain = AuthAnalyzerService._extract_domain(from_addr)
        if not domain:
            return {'result': 'none', 'explanation': 'Could not extract domain', 'policy': None}
        try:
            query = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(query, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    if txt_string.startswith(b'v=DMARC1'):
                        record = txt_string.decode()
                        policy = 'none'
                        if 'p=quarantine' in record.lower(): policy = 'quarantine'
                        if 'p=reject' in record.lower(): policy = 'reject'

                        return {
                            'result': 'pass',
                            'record': record,
                            'policy': policy,
                            'explanation': f"DMARC record found with policy: {policy}"
                        }
            return {'result': 'none', 'explanation': 'No DMARC record found', 'policy': None}
        except Exception as e:
            return {'result': 'none', 'explanation': str(e), 'policy': None}

    @staticmethod
    def _extract_email_string(from_addr):
        # Handle "Name <email@example.com>"
        match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(from_addr))
        if match:
            return match.group(1)
        return str(from_addr)

    @staticmethod
    def _extract_domain(from_addr):
        email = AuthAnalyzerService._extract_email_string(from_addr)
        if '@' in email:
            return email.split('@')[-1]
        return email
