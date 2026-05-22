import spf
import dkim
import dns.resolver

class AuthAnalyzerService:
    @staticmethod
    def analyze(raw_email, sender_ip, from_address):
        results = {
            'spf': AuthAnalyzerService._check_spf(sender_ip, from_address),
            'dkim': AuthAnalyzerService._check_dkim(raw_email),
            'dmarc': AuthAnalyzerService._check_dmarc(from_address)
        }
        return results

    @staticmethod
    def _check_spf(ip, from_addr):
        if not ip or not from_addr:
            return {'result': 'none', 'explanation': 'Missing IP or From address'}
        try:
            domain = AuthAnalyzerService._extract_domain(from_addr)
            # spf.check2 requires a string for s (sender)
            sender_str = AuthAnalyzerService._extract_email_string(from_addr)
            result, code, explanation = spf.check2(i=ip, s=sender_str, h=domain)
            return {'result': result, 'code': code, 'explanation': explanation}
        except Exception as e:
            return {'result': 'error', 'explanation': str(e)}

    @staticmethod
    def _check_dkim(raw_email):
        if isinstance(raw_email, str):
            raw_email = raw_email.encode()
        try:
            d = dkim.DKIM(raw_email)
            valid = d.verify()
            return {'result': 'pass' if valid else 'fail', 'explanation': 'DKIM signature verification'}
        except Exception as e:
            return {'result': 'none', 'explanation': str(e)}

    @staticmethod
    def _check_dmarc(from_addr):
        domain = AuthAnalyzerService._extract_domain(from_addr)
        if not domain:
            return {'result': 'none', 'explanation': 'Could not extract domain'}
        try:
            query = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(query, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    if txt_string.startswith(b'v=DMARC1'):
                        return {'result': 'found', 'record': txt_string.decode()}
            return {'result': 'none', 'explanation': 'No DMARC record found'}
        except Exception as e:
            return {'result': 'none', 'explanation': str(e)}

    @staticmethod
    def _extract_email_string(from_addr):
        if isinstance(from_addr, list) and len(from_addr) > 0:
            item = from_addr[0]
            if isinstance(item, dict):
                return item.get('email', '')
            if isinstance(item, tuple):
                return item[1] # ('Name', 'email@example.com')
        return str(from_addr)

    @staticmethod
    def _extract_domain(from_addr):
        email = AuthAnalyzerService._extract_email_string(from_addr)
        if '@' in email:
            return email.split('@')[-1]
        return email
