import re
import tldextract

class URLAnalyzerService:
    URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'

    SUSPICIOUS_TLDS = ['zip', 'review', 'country', 'kim', 'science', 'gdn', 'click', 'link', 'top', 'xyz', 'work']
    SHORTENERS = ['bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly']
    CLOUD_STORAGE = ['docs.google.com', 'drive.google.com', 'dropbox.com', 'onedrive.live.com', 's3.amazonaws.com']

    @staticmethod
    def analyze(parsed_data):
        text = f"{parsed_data['body_plain']} {parsed_data['body_html']}"
        urls = list(set(re.findall(URLAnalyzerService.URL_REGEX, text)))

        results = []
        for url in urls:
            analysis = URLAnalyzerService._analyze_single_url(url)
            results.append(analysis)

        return results

    @staticmethod
    def _analyze_single_url(url):
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        findings = []
        is_suspicious = False

        # 1. IP-based URL
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ext.domain):
            findings.append("IP-based URL")
            is_suspicious = True

        # 2. Suspicious TLD
        if ext.suffix in URLAnalyzerService.SUSPICIOUS_TLDS:
            findings.append(f"Suspicious TLD: .{ext.suffix}")
            is_suspicious = True

        # 3. URL Shortener
        if domain in URLAnalyzerService.SHORTENERS:
            findings.append("URL shortener detected")
            is_suspicious = True

        # 4. Cloud Storage
        if domain in URLAnalyzerService.CLOUD_STORAGE:
            findings.append("Cloud storage link (potential malware delivery)")
            # Not necessarily suspicious on its own but worth flagging

        # 5. Punycode detection
        if domain.startswith('xn--'):
            findings.append("Punycode/Homoglyph domain detected")
            is_suspicious = True

        # 6. Harvest patterns
        if any(keyword in url.lower() for keyword in ['login', 'verify', 'account', 'secure', 'update', 'signin']):
            findings.append("Potential credential harvesting pattern")

        return {
            'url': url,
            'domain': domain,
            'findings': findings,
            'is_suspicious': is_suspicious
        }
