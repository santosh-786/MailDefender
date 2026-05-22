class ScoringEngineV2:
    @staticmethod
    def calculate(auth_results, content_results, infra_results, behavioral_results, correlation_results):
        # Category Scores
        auth_score = ScoringEngineV2._calculate_category(auth_results)
        content_score = ScoringEngineV2._calculate_category(content_results)
        infra_score = ScoringEngineV2._calculate_category(infra_results)
        behavioral_score = ScoringEngineV2._calculate_category(behavioral_results)

        # Confidence Weighting
        # We calculate average confidence of matched rules
        all_matched = auth_results + content_results + infra_results + behavioral_results
        avg_confidence = sum(r.rule.confidence for r in all_matched) / len(all_matched) if all_matched else 1.0

        raw_risk = (auth_score + content_score + infra_score + behavioral_score)
        risk_score = min(100, int(raw_risk * avg_confidence))

        trust_score = correlation_results.get('trust_score', 100)

        risk_level = "Low"
        if risk_score >= 80: risk_level = "Critical"
        elif risk_score >= 60: risk_level = "High"
        elif risk_score >= 30: risk_level = "Medium"

        return {
            'risk_score': risk_score,
            'trust_score': trust_score,
            'confidence_score': int(avg_confidence * 100),
            'risk_level': risk_level,
            'categories': {
                'authentication': auth_score,
                'content': content_score,
                'infrastructure': infra_score,
                'behavioral': behavioral_score
            },
            'explanation': ScoringEngineV2._generate_explanation(risk_score, trust_score)
        }

    @staticmethod
    def _calculate_category(results):
        return sum(r.rule.weight for r in results if r.matched)

    @staticmethod
    def _generate_explanation(risk, trust):
        if risk > 70 and trust < 50:
            return "High Risk: Consistent phishing indicators detected with very low identity trust."
        if risk > 50:
            return "Medium-High Risk: Multiple suspicious patterns identified."
        if trust < 70:
            return "Suspicious: Identity inconsistencies detected despite low direct risk indicators."
        return "Low Risk: No significant threats or inconsistencies detected."
