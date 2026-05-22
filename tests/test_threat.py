import pytest
from app.services.threat_analyzer import ThreatAnalyzerService

def test_extract_iocs():
    parsed_email = {
        'body_plain': 'Check this link http://malicious.com and contact me at phish@example.com',
        'body_html': '<p>Internal IP 192.168.1.1</p>'
    }
    iocs = ThreatAnalyzerService._extract_iocs(parsed_email)
    assert 'http://malicious.com' in iocs['urls']
    assert 'phish@example.com' in iocs['emails']
    assert '192.168.1.1' in iocs['ips']
    assert 'malicious.com' in iocs['domains']

def test_scoring_logic():
    parsed_email = {
        'from': 'attacker@evil.com',
        'headers': {
            'From': 'attacker@evil.com',
            'Reply-To': 'different@evil.com'
        },
        'body_plain': '',
        'body_html': ''
    }
    auth_results = {
        'spf': {'result': 'fail'},
        'dkim': {'result': 'fail'},
        'dmarc': {'result': 'none'}
    }
    iocs = {'urls': [], 'ips': [], 'emails': [], 'domains': []}

    scoring = ThreatAnalyzerService._calculate_score(parsed_email, auth_results, iocs)
    # 25 (spf) + 20 (dkim) + 10 (dmarc) + 15 (reply-to) = 70
    assert scoring['score'] == 70
    assert scoring['risk_level'] == "High"
