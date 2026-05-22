import pytest
from app.services.auth_analyzer import AuthAnalyzerService

def test_extract_domain():
    assert AuthAnalyzerService._extract_domain("user@example.com") == "example.com"
    assert AuthAnalyzerService._extract_domain([{'email': 'user@example.com'}]) == "example.com"

def test_check_spf_missing_data():
    res = AuthAnalyzerService._check_spf(None, None)
    assert res['result'] == 'none'

def test_check_dkim_no_sig():
    raw = "From: user@example.com\n\nBody"
    res = AuthAnalyzerService._check_dkim(raw)
    # dkimpy might return fail if no signature is found depending on implementation,
    # or raise an exception which we catch and return 'none'
    assert res['result'] in ['none', 'fail']
