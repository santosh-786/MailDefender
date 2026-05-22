import hashlib
import os
import puremagic
from app.detection.yara_service import YaraService

class AttachmentHandlerService:
    yara = YaraService()
    SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.vbs', '.js', '.jar', '.bat', '.cmd', '.msi', '.ps1', '.html', '.htm'}
    OFFICE_EXTENSIONS = {'.docm', '.xlsm', '.pptm'}

    @staticmethod
    def analyze_attachments(attachments):
        results = []
        for att in attachments:
            content = att['payload']
            if isinstance(content, str):
                content = content.encode()

            if content is None:
                content = b''

            hashes = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }

            filename = att['filename']
            _, ext = os.path.splitext(filename.lower())

            # Magic byte validation
            try:
                actual_mime = puremagic.from_string(content, mime=True)
            except:
                actual_mime = 'application/octet-stream'

            is_suspicious = False
            reasons = []

            # 1. MIME vs Extension mismatch
            if ext == '.pdf' and actual_mime != 'application/pdf':
                is_suspicious = True
                reasons.append(f"MIME mismatch: Extension is .pdf but actual type is {actual_mime}")

            # 2. Dangerous types
            if ext in AttachmentHandlerService.SUSPICIOUS_EXTENSIONS or actual_mime in ['application/x-executable', 'application/x-msdos-program']:
                is_suspicious = True
                reasons.append(f"Dangerous file type detected: {actual_mime} ({ext})")

            # 3. Macro-enabled
            if ext in AttachmentHandlerService.OFFICE_EXTENSIONS:
                is_suspicious = True
                reasons.append(f"Macro-enabled Office document: {ext}")

            # 4. Double extension
            if filename.count('.') >= 2:
                parts = filename.split('.')
                if parts[-2].lower() in ['txt', 'jpg', 'pdf', 'png', 'docx', 'xlsx']:
                    is_suspicious = True
                    reasons.append(f"Double extension detected: {filename}")

            # 5. Password protection (Simplified check for ZIP/Office)
            if actual_mime == 'application/zip':
                # In a real app we'd use zipfile to check for encryption
                pass

            # 6. YARA Scanning
            yara_matches = AttachmentHandlerService.yara.scan_data(content)
            if yara_matches:
                is_suspicious = True
                reasons.append(f"YARA matches: {', '.join(yara_matches)}")

            results.append({
                'filename': filename,
                'content_type': actual_mime,
                'mail_content_type': att['mail_content_type'],
                'size': att['size'],
                'hashes': hashes,
                'is_suspicious': is_suspicious,
                'reasons': reasons
            })

        return results
