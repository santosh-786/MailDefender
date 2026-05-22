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
from app.correlation_engine.service import TrustCorrelationEngine
from app.relay_analyzer.service import RelayAnalyzer
from app.rule_engine.rules import RulesLibrary
from app.rule_engine.engine import DetectionResult
from app.ioc.extractor import IOCExtractor
from app.ioc_graph.mapper import IOCGraphMapper
from app.scoring_v2.engine import ScoringEngineV2
from app.workflow.service import WorkflowService
from app.reporting.service import ReportService
from app.enrichment.vt_service import VirusTotalService

bp = Blueprint('main', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@bp.route('/')
def index():
    query = request.args.get('q')
    if query:
        analyses = WorkflowService.search_past_analyses(query)
    else:
        analyses = EmailAnalysis.query.order_by(EmailAnalysis.timestamp.desc()).limit(20).all()
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
            # 1. Base Analysis
            header_results = HeaderAnalyzerService.analyze(parsed_data['headers'])
            sender_ip = header_results.get('origin_ip', '')
            auth_results = AuthAnalyzerService.analyze(parsed_data['raw_content'], sender_ip, parsed_data['headers'].get('From', ''))
            url_results = URLAnalyzerService.analyze(parsed_data)
            attachment_results = AttachmentHandlerService.analyze_attachments(parsed_data['attachments'])

            # 2. Advanced Engines
            correlation_results = TrustCorrelationEngine.analyze(parsed_data['headers'], auth_results)
            relay_results = RelayAnalyzer.analyze(parsed_data['headers'])
            body_iocs = IOCExtractor.extract(parsed_data, url_results, attachment_results)
            ioc_graph = IOCGraphMapper.map_relationships(parsed_data, url_results, attachment_results, body_iocs)

            # 2.5 External Enrichment (VirusTotal)
            vt_service = VirusTotalService()
            enrichment_results = {'files': {}, 'urls': {}, 'ips': {}}

            # Limited to top hits for performance in free tier
            for att in attachment_results[:2]:
                report = vt_service.get_file_report(att['hashes']['sha256'])
                if report: enrichment_results['files'][att['filename']] = report

            for ur in url_results[:3]:
                report = vt_service.get_url_report(ur['url'])
                if report: enrichment_results['urls'][ur['url']] = report

            if header_results.get('origin_ip'):
                report = vt_service.get_ip_report(header_results['origin_ip'])
                if report: enrichment_results['ips'][header_results['origin_ip']] = report

            # 3. Rule Engine Execution
            auth_rules = RulesLibrary.get_auth_rules()
            content_rules = RulesLibrary.get_content_rules()
            behavioral_rules = RulesLibrary.get_behavioral_rules()

            auth_rule_results = [
                DetectionResult(auth_rules[0], "SPF fail", auth_results['spf']['result'] in ['fail', 'softfail']),
                DetectionResult(auth_rules[1], "DKIM fail", auth_results['dkim']['result'] == 'fail'),
                DetectionResult(auth_rules[2], "DMARC missing", auth_results['dmarc']['result'] == 'none'),
                DetectionResult(auth_rules[3], "SPF misaligned", not auth_results['spf']['aligned'])
            ]

            content_rule_results = [
                DetectionResult(content_rules[0], "Suspicious URL", any(u['is_suspicious'] for u in url_results)),
                DetectionResult(content_rules[1], "IP URL", any(u['is_ip_url'] for u in url_results)),
                DetectionResult(content_rules[2], "Dangerous attachment", any(a['is_suspicious'] for a in attachment_results))
            ]

            behavioral_rule_results = [
                DetectionResult(behavioral_rules[0], "Identity mismatch", any(inc['type'] == 'IDENTITY_MISMATCH' for inc in correlation_results['inconsistencies'])),
                DetectionResult(behavioral_rules[1], "Free-mail impersonation", any(inc['type'] == 'FREEMAIL_IMPERSONATION' for inc in correlation_results['inconsistencies']))
            ]

            # 4. Scoring V2
            risk_report = ScoringEngineV2.calculate(
                auth_rule_results,
                content_rule_results,
                [], # infra
                behavioral_rule_results,
                correlation_results
            )

            # Save to Database
            analysis = EmailAnalysis(
                filename=filename,
                subject=parsed_data['subject'],
                sender=parsed_data['headers'].get('From', 'Unknown'),
                recipient=parsed_data['headers'].get('To', 'Unknown'),
                risk_score=risk_report['risk_score'],
                risk_level=risk_report['risk_level']
            )
            analysis.set_headers(parsed_data['headers'])
            analysis.set_auth_results(auth_results)
            analysis.set_ioc_results(body_iocs) # Store flat IOCs for CSV Export
            analysis.set_attachments(attachment_results)
            analysis.set_enrichment_results(enrichment_results)

            report_data = {
                'body_html': ReportService.sanitize_html(parsed_data['body_html']),
                'body_plain': parsed_data['body_plain'],
                'risk_score': risk_report['risk_score'],
                'trust_score': risk_report['trust_score'],
                'confidence_score': risk_report['confidence_score'],
                'explanation': risk_report['explanation'],
                'categories': risk_report['categories'],
                'trust_correlation': correlation_results,
                'relay_analysis': relay_results,
                'ioc_graph': ioc_graph,
                'body_iocs': body_iocs,
                'auth_results': auth_results,
                'attachment_analysis': attachment_results,
                'enrichment': enrichment_results
            }
            analysis.report_data_json = json.dumps(report_data)

            db.session.add(analysis)
            db.session.commit()

            return redirect(url_for('main.results', id=analysis.id))

    return render_template('upload.html')

@bp.route('/results/<int:id>')
def results(id):
    analysis = EmailAnalysis.query.get_or_404(id)
    report_data = json.loads(analysis.report_data_json)
    return render_template('results.html', analysis=analysis, report_data=report_data)

@bp.route('/workflow/<int:id>', methods=['POST'])
def update_workflow(id):
    status = request.form.get('status')
    notes = request.form.get('notes')
    WorkflowService.update_status(id, status, notes)
    return redirect(url_for('main.results', id=id))
