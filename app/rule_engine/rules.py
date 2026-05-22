from app.rule_engine.engine import Rule

class RulesLibrary:
    @staticmethod
    def get_auth_rules():
        return [
            Rule('AUTH_001', 'SPF Failure', 'SPF validation failed', 25, 0.9, 'T1566'),
            Rule('AUTH_002', 'DKIM Failure', 'DKIM signature verification failed', 20, 0.9, 'T1566'),
            Rule('AUTH_003', 'DMARC Missing', 'DMARC record missing', 10, 0.7),
            Rule('AUTH_004', 'SPF Misalignment', 'SPF domain mismatch', 15, 0.8),
        ]

    @staticmethod
    def get_content_rules():
        return [
            Rule('CONT_001', 'Suspicious URL', 'URL with suspicious TLD or pattern', 15, 0.7, 'T1566.002'),
            Rule('CONT_002', 'IP-based URL', 'URL uses direct IP address', 20, 0.9, 'T1566.002'),
            Rule('CONT_003', 'Suspicious Attachment', 'Dangerous file type or double extension', 30, 0.8, 'T1566.001'),
        ]

    @staticmethod
    def get_behavioral_rules():
        return [
            Rule('BEH_001', 'Display Name Spoofing', 'Identity impersonation in From header', 30, 0.85, 'T1566.003'),
            Rule('BEH_002', 'Free-mail Impersonation', 'Impersonating common free-mail services', 35, 0.9, 'T1566.003'),
        ]
