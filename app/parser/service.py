import mailparser
import bleach
import os
import puremagic

class EmailParserService:
    @staticmethod
    def parse_eml(file_path):
        # MIME type validation
        try:
            file_type = puremagic.from_file(file_path, mime=True)
        except:
            file_type = 'application/octet-stream'
        # eml files can be message/rfc822 or text/plain
        if file_type not in ['message/rfc822', 'text/plain']:
            # Log this in real app
            pass

        mail = mailparser.parse_from_file(file_path)
        with open(file_path, 'rb') as f:
            raw_content = f.read()
        data = EmailParserService._format_mail_data(mail)
        data['raw_content'] = raw_content
        return data

    @staticmethod
    def parse_raw(raw_content):
        mail = mailparser.parse_from_string(raw_content)
        data = EmailParserService._format_mail_data(mail)
        data['raw_content'] = raw_content.encode() if isinstance(raw_content, str) else raw_content
        return data

    @staticmethod
    def _format_mail_data(mail):
        def format_addr(addr_list):
            if not addr_list:
                return ""
            return ", ".join([f"{name} <{email}>" if name else email for name, email in addr_list])

        headers = {
            'From': format_addr(mail.from_),
            'To': format_addr(mail.to),
            'Subject': mail.subject,
            'Date': str(mail.date) if mail.date else "",
            'Message-ID': mail.message_id,
            'Reply-To': format_addr(mail.reply_to),
            'Return-Path': mail.headers.get('Return-Path'),
            'X-Originating-IP': mail.headers.get('X-Originating-IP'),
            'Received': mail.received
        }

        # Extract body and sanitize strictly
        body_html = mail.text_html[0] if mail.text_html else ""
        body_plain = mail.text_plain[0] if mail.text_plain else ""

        # Strict allowlist for HTML
        allowed_tags = ['p', 'b', 'i', 'u', 'br', 'hr', 'strong', 'em', 'table', 'thead', 'tbody', 'tr', 'th', 'td']
        sanitized_html = bleach.clean(
            body_html,
            tags=allowed_tags,
            attributes={},
            strip=True,
            strip_comments=True
        )

        attachments = []
        for attachment in mail.attachments:
            attachments.append({
                'filename': attachment['filename'],
                'mail_content_type': attachment['mail_content_type'],
                'payload': attachment['payload'],
                'size': len(attachment['payload']) if attachment['payload'] else 0
            })

        return {
            'headers': headers,
            'body_html': sanitized_html,
            'body_plain': body_plain,
            'attachments': attachments,
            'subject': mail.subject,
        }
