from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename
import os
import uuid
from app.models import EmailAnalysis
from app import db
from app.services.email_parser import EmailParserService
from app.services.auth_analyzer import AuthAnalyzerService
from app.services.threat_analyzer import ThreatAnalyzerService
from app.services.attachment_handler import AttachmentHandlerService

bp = Blueprint('main', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@bp.route('/')
def index():
    analyses = EmailAnalysis.query.order_by(EmailAnalysis.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', analyses=analyses)

@bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        raw_headers = request.form.get('raw_headers')
        file = request.files.get('email_file')

        parsed_data = None
        filename = "pasted_headers.txt"

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            parsed_data = EmailParserService.parse_eml(filepath)
            # We can delete the file after parsing for security as per requirements
            os.remove(filepath)
        elif raw_headers:
            parsed_data = EmailParserService.parse_raw(raw_headers)
        else:
            flash('No valid input provided')
            return redirect(request.url)

        if parsed_data:
            # Perform Analysis
            # Mocking sender IP as we don't have it from a file usually unless extracted from Received headers
            # In a real scenario, we might extract the first relay IP
            sender_ip = ""
            if parsed_data['headers'].get('Received'):
                # Very basic extraction of first IP
                import re
                received = str(parsed_data['headers']['Received'])
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
                if ip_match:
                    sender_ip = ip_match.group(1)

            from_addr = parsed_data['from']
            raw_content = parsed_data['raw_content']

            auth_results = AuthAnalyzerService.analyze(raw_content, sender_ip, from_addr)
            threat_results = ThreatAnalyzerService.analyze(parsed_data, auth_results)
            attachment_results = AttachmentHandlerService.analyze_attachments(parsed_data['attachments'])

            # Save to Database
            analysis = EmailAnalysis(
                filename=filename,
                subject=parsed_data['subject'],
                sender=str(parsed_data['from']),
                recipient=str(parsed_data['to']),
                risk_score=threat_results['scoring']['score'],
                risk_level=threat_results['scoring']['risk_level']
            )
            analysis.set_headers(parsed_data['headers'])
            analysis.set_auth_results(auth_results)
            analysis.set_ioc_results(threat_results['iocs'])
            analysis.set_attachments(attachment_results)

            import json
            analysis.report_data_json = json.dumps({
                'body_html': parsed_data['body_html'],
                'body_plain': parsed_data['body_plain'],
                'scoring_reasons': threat_results['scoring']['reasons']
            })

            db.session.add(analysis)
            db.session.commit()

            return redirect(url_for('main.results', id=analysis.id))

    return render_template('upload.html')

@bp.route('/results/<int:id>')
def results(id):
    analysis = EmailAnalysis.query.get_or_404(id)
    import json
    report_data = json.loads(analysis.report_data_json)
    return render_template('results.html', analysis=analysis, report_data=report_data)
