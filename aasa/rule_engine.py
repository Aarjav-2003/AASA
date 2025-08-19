import yaml
import re
from urllib.parse import urlparse

class RuleEngine:
    def __init__(self, rules_path="rules.yaml", whitelist_path="sample_configs/whitelist_domains.txt"):
        # Load rules
        with open(rules_path) as f:
            self.rules = yaml.safe_load(f)

        # Load whitelist domains
        with open(whitelist_path) as f:
            self.whitelist = {line.strip() for line in f if line.strip()}

    def evaluate_permissions(self, permissions):
        score = 0
        flagged = []
        for perm in permissions:
            if perm in self.rules.get("permissions", {}):
                score += self.rules["permissions"][perm]
                flagged.append(perm)
        return score, flagged

    def evaluate_strings(self, strings):
        score = 0
        flagged = []
        for s in strings:
            for keyword, weight in self.rules.get("keywords", {}).items():
                if keyword.lower() in s.lower():
                    score += weight
                    flagged.append(s)
        return score, flagged

    def evaluate_urls(self, urls):
        score = 0
        flagged = []
        for url in urls:
            domain = urlparse(url).netloc
            if domain not in self.whitelist:
                score += self.rules.get("url_penalty", 5)
                flagged.append(url)
        return score, flagged

    def evaluate_obfuscation(self, class_names):
        score = 0
        flagged = []
        for cls in class_names:
            if len(cls) <= 2:
                score += self.rules.get("obfuscation", {}).get("short_class_names", 5)
                flagged.append(cls)
        return score, flagged

    def evaluate_obfuscation(self, obf_items):
        score = 0
        flagged = []
        for item in obf_items:
            # Short class names
            if len(item) <= 2:
                score += self.rules["obfuscation"]["short_class_names"]
                flagged.append(item)
        # High entropy or encoded strings
            elif re.fullmatch(r'[A-Za-z0-9+/=]{20,}', item):
                score += self.rules["obfuscation"]["encoded_strings"]
                flagged.append(item)
            else:
            # You can add high_entropy_names scoring if desired
                score += self.rules["obfuscation"].get("high_entropy_names", 0)
                flagged.append(item)
        return score, flagged




