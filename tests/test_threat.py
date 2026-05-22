import pytest
from app.detection.url import URLAnalyzerService
from app.ioc.extractor import IOCExtractor

def test_url_analysis():
    parsed_data = {
        'body_plain': 'Check http://1.2.3.4/login and http://evil.zip',
        'body_html': ''
    }
    results = URLAnalyzerService.analyze(parsed_data)

    ip_url = next(r for r in results if '1.2.3.4' in r['url'])
    zip_url = next(r for r in results if 'evil.zip' in r['url'])

    assert ip_url['is_suspicious'] is True
    assert "IP-based URL" in ip_url['findings']

    assert zip_url['is_suspicious'] is True
    assert "Suspicious TLD: .zip" in zip_url['findings']

def test_ioc_extraction():
    parsed_data = {
        'body_plain': 'Contact phish@example.com',
        'body_html': ''
    }
    url_results = [{'url': 'http://evil.com', 'domain': 'evil.com'}]
    attachment_results = [{
        'hashes': {'md5': 'm', 'sha1': 's', 'sha256': 's256'},
        'filename': 'f'
    }]

    iocs = IOCExtractor.extract(parsed_data, url_results, attachment_results)
    assert 'phish@example.com' in iocs['emails']
    assert 'evil.com' in iocs['domains']
    assert 's256' in iocs['hashes']['sha256']
