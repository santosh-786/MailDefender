import hashlib
import os

class AttachmentHandlerService:
    SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.vbs', '.js', '.jar', '.bat', '.cmd', '.msi', '.ps1'}
    OFFICE_EXTENSIONS = {'.docm', '.xlsm', '.pptm'}

    @staticmethod
    def analyze_attachments(attachments):
        results = []
        for att in attachments:
            content = att['payload']
            if isinstance(content, str):
                content = content.encode()

            # Use empty bytes if content is None
            if content is None:
                content = b''

            hashes = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }

            filename = att['filename']
            _, ext = os.path.splitext(filename.lower())

            is_suspicious = False
            reasons = []

            if ext in AttachmentHandlerService.SUSPICIOUS_EXTENSIONS:
                is_suspicious = True
                reasons.append(f"Dangerous executable extension: {ext}")

            if ext in AttachmentHandlerService.OFFICE_EXTENSIONS:
                is_suspicious = True
                reasons.append(f"Macro-enabled Office document: {ext}")

            # Detect double extension
            if filename.count('.') >= 2:
                parts = filename.split('.')
                if parts[-2].lower() in ['txt', 'jpg', 'pdf', 'png']:
                    is_suspicious = True
                    reasons.append(f"Double extension detected: {filename}")

            results.append({
                'filename': filename,
                'content_type': att['mail_content_type'],
                'size': att['size'],
                'hashes': hashes,
                'is_suspicious': is_suspicious,
                'reasons': reasons
            })

        return results
