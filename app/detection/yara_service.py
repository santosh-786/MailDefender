import yara
import os

class YaraService:
    RULES_PATH = 'app/detection/rules/malware.yar'

    # Default simple rule if file doesn't exist
    DEFAULT_RULE = """
    rule Suspicious_Strings {
        strings:
            $a = "powershell" nocase
            $b = "cmd.exe" nocase
            $c = "eval(" nocase
            $d = "base64" nocase
        condition:
            any of them
    }
    """

    def __init__(self):
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        try:
            if os.path.exists(self.RULES_PATH):
                self.rules = yara.compile(filepath=self.RULES_PATH)
            else:
                self.rules = yara.compile(source=self.DEFAULT_RULE)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")

    def scan_data(self, data):
        if not self.rules:
            return []

        matches = self.rules.match(data=data)
        return [m.rule for m in matches]
