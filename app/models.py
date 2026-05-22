from app import db
from datetime import datetime
import json
import uuid

class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class EmailAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(50), unique=True)
    filename = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    sender = db.Column(db.String(255))
    recipient = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Workflow fields
    status = db.Column(db.String(50), default='New') # New, Phishing, Benign, Suspicious
    analyst_notes = db.Column(db.Text)

    # Store results as JSON strings
    headers_json = db.Column(db.Text)
    auth_results_json = db.Column(db.Text)
    ioc_results_json = db.Column(db.Text)
    attachments_json = db.Column(db.Text)
    enrichment_results_json = db.Column(db.Text)

    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))

    report_data_json = db.Column(db.Text)

    def __init__(self, **kwargs):
        super(EmailAnalysis, self).__init__(**kwargs)
        if not self.case_id:
            self.case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

    def set_headers(self, data):
        self.headers_json = json.dumps(data, cls=CustomEncoder)

    def get_headers(self):
        return json.loads(self.headers_json) if self.headers_json else {}

    def set_auth_results(self, data):
        self.auth_results_json = json.dumps(data, cls=CustomEncoder)

    def get_auth_results(self):
        return json.loads(self.auth_results_json) if self.auth_results_json else {}

    def set_ioc_results(self, data):
        self.ioc_results_json = json.dumps(data, cls=CustomEncoder)

    def get_ioc_results(self):
        return json.loads(self.ioc_results_json) if self.ioc_results_json else {}

    def set_attachments(self, data):
        self.attachments_json = json.dumps(data, cls=CustomEncoder)

    def get_attachments(self):
        return json.loads(self.attachments_json) if self.attachments_json else []

    def set_enrichment_results(self, data):
        self.enrichment_results_json = json.dumps(data, cls=CustomEncoder)

    def get_enrichment_results(self):
        return json.loads(self.enrichment_results_json) if self.enrichment_results_json else {}
