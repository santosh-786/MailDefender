import pytest
from app.parser.service import EmailParserService

def test_parse_raw_email():
    raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test body.
"""
    parsed = EmailParserService.parse_raw(raw_email)
    assert parsed['subject'] == "Test Email"
    assert "sender@example.com" in parsed['headers']['From']
    assert "This is a test body." in parsed['body_plain']

def test_sanitization():
    raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test HTML
Content-Type: text/html

<html><body><p>Hello</p><script>alert(1)</script><a href="http://evil.com">Click</a></body></html>
"""
    parsed = EmailParserService.parse_raw(raw_email)
    assert "<script>" not in parsed['body_html']
    assert "href" not in parsed['body_html'] # Attributes should be stripped in our strict config
    assert "<p>Hello</p>" in parsed['body_html']
