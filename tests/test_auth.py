import pytest
from app.detection.auth import AuthAnalyzerService

def test_extract_domain():
    assert AuthAnalyzerService._extract_domain("user@example.com") == "example.com"
    assert AuthAnalyzerService._extract_domain("Name <user@example.com>") == "example.com"

def test_check_spf_missing_data():
    res = AuthAnalyzerService._check_spf(None, None)
    assert res['result'] == 'none'

def test_check_dkim_no_raw():
    res = AuthAnalyzerService._check_dkim(None, "user@example.com")
    assert res['result'] == 'none'
