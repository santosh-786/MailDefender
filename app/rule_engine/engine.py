class Rule:
    def __init__(self, rule_id, name, description, weight, confidence, mitre_tag=None):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.weight = weight
        self.confidence = confidence
        self.mitre_tag = mitre_tag

class DetectionResult:
    def __init__(self, rule, evidence, matched=False):
        self.rule = rule
        self.evidence = evidence
        self.matched = matched

class RuleEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def run_all(self, context):
        results = []
        # Context would contain all analysis data
        return results
