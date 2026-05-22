import mailparser
import bleach

class EmailParserService:
    @staticmethod
    def parse_eml(file_path):
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
            'Date': mail.date,
            'Message-ID': mail.message_id,
            'Reply-To': mail.reply_to,
            'Return-Path': mail.headers.get('Return-Path'),
            'X-Originating-IP': mail.headers.get('X-Originating-IP'),
            'Received': mail.received
        }

        # Extract body and sanitize
        body_html = mail.text_html[0] if mail.text_html else ""
        body_plain = mail.text_plain[0] if mail.text_plain else ""

        sanitized_html = bleach.clean(body_html, tags=['p', 'b', 'i', 'u', 'a', 'br'], attributes={'a': ['href']})

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
            'from': mail.from_,
            'to': mail.to
        }
