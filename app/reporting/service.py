import bleach

class ReportService:
    @staticmethod
    def sanitize_html(html_content):
        # Allow safe tags and attributes for analyst utility
        allowed_tags = bleach.ALLOWED_TAGS | {'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'thead', 'tbody', 'tr', 'th', 'td'}
        allowed_attrs = bleach.ALLOWED_ATTRIBUTES.copy()

        # We strip href from <a> to prevent accidental clicks, but keep the text

        return bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attrs,
            strip=True
        )

class ReportingService:
    @staticmethod
    def generate_report_data(parsed_data, header_results, auth_results, url_results, attachment_results, risk_report, iocs):
        return {
            'subject': parsed_data['subject'],
            'body_html': ReportService.sanitize_html(parsed_data['body_html']),
            'body_plain': parsed_data['body_plain'],
            'headers': parsed_data['headers'],
            'header_analysis': header_results,
            'auth_results': auth_results,
            'url_analysis': url_results,
            'attachment_analysis': attachment_results,
            'risk_factors': risk_report['factors'],
            'iocs': iocs,
            'summary': ReportingService._generate_summary(risk_report)
        }

    @staticmethod
    def _generate_summary(risk_report):
        if risk_report['score'] >= 80:
            return "This email is highly likely to be a phishing attempt. Multiple critical indicators were detected."
        elif risk_report['score'] >= 60:
            return "Suspicious activity detected. Manual investigation is recommended."
        elif risk_report['score'] >= 30:
            return "Some unusual patterns were detected, but no definitive phishing indicators were found."
        return "No significant threats were detected in this email."
