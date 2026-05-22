from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename
import os
import uuid
import json
from app.models import EmailAnalysis
from app import db
from app.parser.service import EmailParserService
from app.detection.auth import AuthAnalyzerService
from app.detection.attachment import AttachmentHandlerService
from app.detection.header import HeaderAnalyzerService
from app.detection.url import URLAnalyzerService
from app.scoring.engine import RiskScoringEngine
from app.ioc.extractor import IOCExtractor
from app.reporting.service import ReportingService

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
        filename = "pasted_content.txt"

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            parsed_data = EmailParserService.parse_eml(filepath)
            os.remove(filepath)
        elif raw_headers:
            parsed_data = EmailParserService.parse_raw(raw_headers)
        else:
            flash('No valid input provided')
            return redirect(request.url)

        if parsed_data:
            # 1. Header Analysis
            header_results = HeaderAnalyzerService.analyze(parsed_data['headers'])

            # 2. Authentication Analysis
            sender_ip = header_results.get('origin_ip', '')
            auth_results = AuthAnalyzerService.analyze(parsed_data['raw_content'], sender_ip, parsed_data['headers'].get('From', ''))

            # 3. URL Analysis
            url_results = URLAnalyzerService.analyze(parsed_data)

            # 4. Attachment Analysis
            attachment_results = AttachmentHandlerService.analyze_attachments(parsed_data['attachments'])

            # 5. IOC Extraction
            iocs = IOCExtractor.extract(parsed_data, url_results, attachment_results)

            # 6. Risk Scoring
            risk_report = RiskScoringEngine.calculate(
                header_results,
                auth_results,
                url_results,
                attachment_results
            )

            # 7. Generate Report Data
            report_data = ReportingService.generate_report_data(
                parsed_data,
                header_results,
                auth_results,
                url_results,
                attachment_results,
                risk_report,
                iocs
            )

            # Save to Database
            analysis = EmailAnalysis(
                filename=filename,
                subject=parsed_data['subject'],
                sender=parsed_data['headers'].get('From', 'Unknown'),
                recipient=parsed_data['headers'].get('To', 'Unknown'),
                risk_score=risk_report['score'],
                risk_level=risk_report['risk_level'],
                report_data_json=json.dumps(report_data)
            )
            analysis.set_headers(parsed_data['headers'])
            analysis.set_auth_results(auth_results)
            analysis.set_ioc_results(iocs)
            analysis.set_attachments(attachment_results)

            db.session.add(analysis)
            db.session.commit()

            return redirect(url_for('main.results', id=analysis.id))

    return render_template('upload.html')

@bp.route('/results/<int:id>')
def results(id):
    analysis = EmailAnalysis.query.get_or_404(id)
    report_data = json.loads(analysis.report_data_json)
    return render_template('results.html', analysis=analysis, report_data=report_data)
