import re

class IOCExtractor:
    IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'

    @staticmethod
    def extract(parsed_data, url_results, attachment_results):
        text = f"{parsed_data['body_plain']} {parsed_data['body_html']}"

        # 1. IP Addresses
        ips = list(set(re.findall(IOCExtractor.IP_REGEX, text)))
        # Filter out internal/common IPs if needed

        # 2. Email Addresses
        emails = list(set(re.findall(IOCExtractor.EMAIL_REGEX, text)))

        # 3. URLs and Domains (from URL analysis)
        urls = []
        domains = []
        for ur in url_results:
            urls.append(ur['url'])
            domains.append(ur['domain'])
        urls = list(set(urls))
        domains = list(set(domains))

        # 4. Hashes (from attachment analysis)
        hashes = {
            'md5': [],
            'sha1': [],
            'sha256': []
        }
        for ar in attachment_results:
            hashes['md5'].append(ar['hashes']['md5'])
            hashes['sha1'].append(ar['hashes']['sha1'])
            hashes['sha256'].append(ar['hashes']['sha256'])

        hashes['md5'] = list(set(hashes['md5']))
        hashes['sha1'] = list(set(hashes['sha1']))
        hashes['sha256'] = list(set(hashes['sha256']))

        return {
            'ips': ips,
            'emails': emails,
            'urls': urls,
            'domains': domains,
            'hashes': hashes
        }
