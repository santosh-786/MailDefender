import logging
import json
from flask import request

class StructuredLogger:
    @staticmethod
    def setup():
        logging.basicConfig(level=logging.INFO)
        # In a real app we'd use a custom formatter for JSON

    @staticmethod
    def log_analysis(analysis_id, risk_level, score):
        log_data = {
            'event': 'analysis_completed',
            'analysis_id': analysis_id,
            'risk_level': risk_level,
            'score': score,
            'remote_addr': request.remote_addr
        }
        logging.info(json.dumps(log_data))

    @staticmethod
    def log_error(error_type, message):
        log_data = {
            'event': 'error',
            'type': error_type,
            'message': message
        }
        logging.error(json.dumps(log_data))
