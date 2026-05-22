from app.models import EmailAnalysis
from app import db

class WorkflowService:
    @staticmethod
    def update_status(analysis_id, status, notes=None):
        analysis = EmailAnalysis.query.get(analysis_id)
        if analysis:
            analysis.status = status
            if notes:
                analysis.analyst_notes = notes
            db.session.commit()
            return True
        return False

    @staticmethod
    def search_past_analyses(query):
        return EmailAnalysis.query.filter(
            (EmailAnalysis.subject.contains(query)) |
            (EmailAnalysis.sender.contains(query)) |
            (EmailAnalysis.case_id.contains(query))
        ).all()
