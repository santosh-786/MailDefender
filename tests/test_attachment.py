import pytest
from app.services.attachment_handler import AttachmentHandlerService

def test_attachment_analysis():
    attachments = [
        {
            'filename': 'invoice.pdf.exe',
            'mail_content_type': 'application/octet-stream',
            'payload': b'fake executable content',
            'size': 23
        },
        {
            'filename': 'report.docm',
            'mail_content_type': 'application/vnd.ms-word.document.macroEnabled.12',
            'payload': b'fake macro content',
            'size': 18
        },
        {
            'filename': 'normal.pdf',
            'mail_content_type': 'application/pdf',
            'payload': b'normal pdf',
            'size': 10
        }
    ]

    results = AttachmentHandlerService.analyze_attachments(attachments)

    assert results[0]['is_suspicious'] is True
    assert "Double extension" in results[0]['reasons'][1] or "Dangerous executable" in results[0]['reasons'][0]

    assert results[1]['is_suspicious'] is True
    assert "Macro-enabled" in results[1]['reasons'][0]

    assert results[2]['is_suspicious'] is False
    assert results[2]['hashes']['md5'] is not None
