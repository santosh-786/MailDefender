import re
import tldextract
from urllib.parse import urlparse

class ThreatAnalyzerService:
    # IOC Regex patterns
    IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'
    EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'

    @staticmethod
    def analyze(parsed_email, auth_results):
        iocs = ThreatAnalyzerService._extract_iocs(parsed_email)
        scoring = ThreatAnalyzerService._calculate_score(parsed_email, auth_results, iocs)

        return {
            'iocs': iocs,
            'scoring': scoring
        }

    @staticmethod
    def _extract_iocs(parsed_email):
        text = f"{parsed_email['body_plain']} {parsed_email['body_html']}"

        urls = list(set(re.findall(ThreatAnalyzerService.URL_REGEX, text)))
        ips = list(set(re.findall(ThreatAnalyzerService.IP_REGEX, text)))
        emails = list(set(re.findall(ThreatAnalyzerService.EMAIL_REGEX, text)))

        domains = []
        for url in urls:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                domains.append(f"{ext.domain}.{ext.suffix}")
        domains = list(set(domains))

        return {
            'urls': urls,
            'ips': ips,
            'emails': emails,
            'domains': domains
        }

    @staticmethod
    def _calculate_score(parsed_email, auth_results, iocs):
        score = 0
        reasons = []

        # Authentication Checks
        if auth_results['spf'].get('result') in ['fail', 'softfail']:
            score += 25
            reasons.append(f"SPF result is {auth_results['spf']['result']}")

        if auth_results['dkim'].get('result') == 'fail':
            score += 20
            reasons.append("DKIM verification failed")

        if auth_results['dmarc'].get('result') == 'none':
            score += 10
            reasons.append("DMARC record missing")

        # URL Checks
        suspicious_tlds = ['zip', 'review', 'country', 'kim', 'science', 'gdn', 'click', 'link']
        for url in iocs['urls']:
            ext = tldextract.extract(url)
            if ext.suffix in suspicious_tlds:
                score += 15
                reasons.append(f"Suspicious TLD: .{ext.suffix} in {url}")
                break # Only count once for brevity

            # Check for IP-based URLs
            if re.match(ThreatAnalyzerService.IP_REGEX, ext.domain):
                score += 20
                reasons.append(f"IP-based URL detected: {url}")

        # Sender Spoofing
        from_email = ""
        from_val = parsed_email['headers'].get('From', '')
        # extract email from "Name <email@example.com>" or "email@example.com"
        email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(from_val))
        if email_match:
            from_email = email_match.group(1)

        reply_to_val = parsed_email['headers'].get('Reply-To', '')
        if reply_to_val:
            reply_to_email = ""
            rt_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(reply_to_val))
            if rt_match:
                reply_to_email = rt_match.group(1)

            if reply_to_email and from_email and reply_to_email.lower() != from_email.lower():
                score += 15
                reasons.append(f"Reply-To mismatch: {reply_to_email} vs {from_email}")

        # Risk Level
        risk_level = "Low"
        if score >= 75:
            risk_level = "Critical"
        elif score >= 50:
            risk_level = "High"
        elif score >= 25:
            risk_level = "Medium"

        return {
            'score': score,
            'reasons': reasons,
            'risk_level': risk_level
        }
