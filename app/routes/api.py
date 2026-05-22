from flask import Blueprint, jsonify, send_file
from app.models import EmailAnalysis
import csv
import io

bp = Blueprint('api', __name__)

@bp.route('/export/<int:id>/json')
def export_json(id):
    analysis = EmailAnalysis.query.get_or_404(id)
    return jsonify({
        'id': analysis.id,
        'subject': analysis.subject,
        'sender': analysis.sender,
        'risk_score': analysis.risk_score,
        'risk_level': analysis.risk_level,
        'iocs': analysis.get_ioc_results(),
        'attachments': analysis.get_attachments()
    })

@bp.route('/export/<int:id>/csv')
def export_csv(id):
    analysis = EmailAnalysis.query.get_or_404(id)
    iocs = analysis.get_ioc_results()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Type', 'Value'])

    for url in iocs.get('urls', []):
        writer.writerow(['URL', url])
    for ip in iocs.get('ips', []):
        writer.writerow(['IP', ip])
    for domain in iocs.get('domains', []):
        writer.writerow(['Domain', domain])
    for email in iocs.get('emails', []):
        writer.writerow(['Email', email])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'iocs_{id}.csv'
    )
