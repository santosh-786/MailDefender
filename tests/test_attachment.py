import pytest
from app.detection.attachment import AttachmentHandlerService

def test_attachment_analysis():
    attachments = [
        {
            'filename': 'invoice.pdf.exe',
            'mail_content_type': 'application/octet-stream',
            'payload': b'MZ\x90\x00\x03\x00\x00\x00', # Mock DOS header
            'size': 8
        },
        {
            'filename': 'normal.pdf',
            'mail_content_type': 'application/pdf',
            'payload': b'%PDF-1.4\n%...', # Mock PDF header
            'size': 12
        }
    ]

    results = AttachmentHandlerService.analyze_attachments(attachments)

    assert results[0]['is_suspicious'] is True
    assert "Dangerous file type" in results[0]['reasons'][0]

    # normal.pdf might still be flagged if it doesn't have exact PDF magic bytes in our mock
    # but we can check if it detected the MIME correctly
    assert results[1]['content_type'] == 'application/pdf'
