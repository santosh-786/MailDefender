class RiskScoringEngine:
    @staticmethod
    def calculate(header_results, auth_results, url_results, attachment_results):
        score = 0
        factors = []

        # 1. Authentication Factors
        spf = auth_results.get('spf', {})
        if spf.get('result') in ['fail', 'softfail']:
            weight = 25 if spf.get('result') == 'fail' else 15
            factors.append({
                'rule': 'SPF_FAILURE',
                'weight': weight,
                'reason': f"SPF validation {spf.get('result')}",
                'evidence': spf.get('explanation')
            })
            score += weight
        elif not spf.get('aligned') and spf.get('result') == 'pass':
            factors.append({
                'rule': 'SPF_MISALIGNMENT',
                'weight': 10,
                'reason': "SPF domain does not align with From domain",
                'evidence': "Potential spoofing attempt via aligned domain"
            })
            score += 10

        dkim = auth_results.get('dkim', {})
        if dkim.get('result') == 'fail':
            factors.append({
                'rule': 'DKIM_FAILURE',
                'weight': 20,
                'reason': "DKIM signature verification failed",
                'evidence': dkim.get('explanation')
            })
            score += 20

        dmarc = auth_results.get('dmarc', {})
        if dmarc.get('result') == 'none':
            factors.append({
                'rule': 'DMARC_MISSING',
                'weight': 10,
                'reason': "DMARC record missing",
                'evidence': "Domain lacks email authentication policy"
            })
            score += 10
        elif dmarc.get('policy') == 'none':
            factors.append({
                'rule': 'DMARC_WEAK_POLICY',
                'weight': 5,
                'reason': "DMARC policy is set to 'none'",
                'evidence': "Domain has no enforcement policy"
            })
            score += 5

        # 2. Header Factors
        if header_results.get('display_name_spoofing'):
            factors.append({
                'rule': 'DISPLAY_NAME_SPOOFING',
                'weight': 25,
                'reason': "Display name contains a different email than actual sender",
                'evidence': header_results['inconsistencies'][0]
            })
            score += 25

        for inc in header_results.get('inconsistencies', []):
            if "Return-Path" in inc:
                factors.append({
                    'rule': 'RETURN_PATH_MISMATCH',
                    'weight': 15,
                    'reason': "Return-Path mismatched with From header",
                    'evidence': inc
                })
                score += 15

        # 3. URL Factors
        for ur in url_results:
            if ur['is_suspicious']:
                weight = 15
                factors.append({
                    'rule': 'SUSPICIOUS_URL',
                    'weight': weight,
                    'reason': f"Suspicious URL: {ur['domain']}",
                    'evidence': ", ".join(ur['findings'])
                })
                score += weight
                # Limit URL scoring to avoid excessive points
                if score > 100: break

        # 4. Attachment Factors
        for ar in attachment_results:
            if ar['is_suspicious']:
                weight = 30
                factors.append({
                    'rule': 'SUSPICIOUS_ATTACHMENT',
                    'weight': weight,
                    'reason': f"Suspicious attachment: {ar['filename']}",
                    'evidence': ", ".join(ar['reasons'])
                })
                score += weight
                if score > 150: break

        # Normalize score
        final_score = min(score, 100)

        risk_level = "Low"
        if final_score >= 80: risk_level = "Critical"
        elif final_score >= 60: risk_level = "High"
        elif final_score >= 30: risk_level = "Medium"

        return {
            'score': final_score,
            'factors': factors,
            'risk_level': risk_level
        }
