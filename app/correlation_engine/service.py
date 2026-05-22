import re

class TrustCorrelationEngine:
    FREE_MAIL_DOMAINS = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com', 'icloud.com']

    @staticmethod
    def analyze(headers, auth_results):
        results = {
            'trust_score': 100,
            'inconsistencies': [],
            'signals': {}
        }

        from_email = TrustCorrelationEngine._extract_email(headers.get('From', ''))
        return_path = TrustCorrelationEngine._extract_email(headers.get('Return-Path', ''))
        reply_to = TrustCorrelationEngine._extract_email(headers.get('Reply-To', ''))

        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""

        # 1. Identity Consistency
        if return_path and from_email and return_path.lower() != from_email.lower():
            results['inconsistencies'].append({
                'type': 'IDENTITY_MISMATCH',
                'description': f"From ({from_email}) and Return-Path ({return_path}) do not match",
                'severity': 'MEDIUM'
            })
            results['trust_score'] -= 20

        if reply_to and from_email and reply_to.lower() != from_email.lower():
            # Check if domain matches at least
            reply_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ""
            if reply_domain != from_domain:
                results['inconsistencies'].append({
                    'type': 'REPLY_TO_MISMATCH',
                    'description': f"Reply-To ({reply_to}) domain differs from From ({from_email})",
                    'severity': 'MEDIUM'
                })
                results['trust_score'] -= 15

        # 2. Authentication Alignment Correlation
        spf = auth_results.get('spf', {})
        if spf.get('result') == 'pass' and not spf.get('aligned'):
            results['inconsistencies'].append({
                'type': 'SPF_MISALIGNMENT',
                'description': "SPF passed but domain is not aligned with From header",
                'severity': 'LOW'
            })
            results['trust_score'] -= 10

        dkim = auth_results.get('dkim', {})
        if dkim.get('result') == 'pass' and not dkim.get('aligned'):
            results['inconsistencies'].append({
                'type': 'DKIM_MISALIGNMENT',
                'description': f"DKIM passed but signed by different domain ({dkim.get('signature_domain')})",
                'severity': 'LOW'
            })
            results['trust_score'] -= 10

        # 3. Free-mail Impersonation
        display_name = TrustCorrelationEngine._extract_display_name(headers.get('From', ''))
        inner_email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', display_name)
        if inner_email_match:
            inner_email = inner_email_match.group(1).lower()
            inner_domain = inner_email.split('@')[-1]
            if inner_domain in TrustCorrelationEngine.FREE_MAIL_DOMAINS and inner_email != from_email.lower():
                results['inconsistencies'].append({
                    'type': 'FREE_MAIL_IMPERSONATION',
                    'description': f"Display name impersonates a free-mail account ({inner_email})",
                    'severity': 'HIGH'
                })
                results['trust_score'] -= 40

        # 4. Auth-Pass but Identity-Fail
        if (spf.get('result') == 'pass' or dkim.get('result') == 'pass') and results['trust_score'] < 70:
             results['inconsistencies'].append({
                'type': 'DECEPTIVE_AUTH',
                'description': "Technical authentication passed but identity signals are highly inconsistent",
                'severity': 'HIGH'
            })
             results['trust_score'] -= 10

        results['trust_score'] = max(0, results['trust_score'])
        return results

    @staticmethod
    def _extract_email(header_val):
        match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(header_val))
        return match.group(1) if match else ""

    @staticmethod
    def _extract_display_name(header_val):
        match = re.search(r'^([^<]*)', str(header_val))
        return match.group(1).strip() if match else ""
