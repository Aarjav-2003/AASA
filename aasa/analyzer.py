import hashlib
import re
import math
import collections
from androguard.misc import AnalyzeAPK
from aasa.rule_engine import RuleEngine

class Analyzer:
    def __init__(self, apk_path, rules_path="rules.yaml", whitelist_path="sample_configs/whitelist_domains.txt"):
        self.apk_path = apk_path
        self.apk, self.dex, self.dx = AnalyzeAPK(apk_path)
        self.rule_engine = RuleEngine(rules_path, whitelist_path)

    # ---------- Malicious hash check ----------
    def check_malicious_hash(self):
        with open("malicious_hashes.txt", "rb") as f:
            bad_hashes = {line.strip().decode() for line in f}
        h = hashlib.sha256(open(self.apk_path, "rb").read()).hexdigest()
        return h in bad_hashes

    # ---------- Extract all strings ----------
    def extract_strings(self):
        strings = set()
        for d in self.dex:
            for string in d.get_strings():
                s = str(string)
                if len(s) > 3:
                    strings.add(s)
        return list(strings)

    # ---------- Extract URLs from strings ----------
    def extract_urls(self, strings):
        url_pattern = re.compile(r"https?://[^\s\"'<>]+")
        return [s for s in strings if url_pattern.match(s)]

    # ---------- Calculate entropy ----------
    def calc_entropy(self, s):
        p, lns = collections.Counter(s), float(len(s))
        return -sum(count/lns * math.log2(count/lns) for count in p.values())

    # ---------- Enhanced obfuscation check ----------
    def check_obfuscation_enhanced(self):
        findings = []

        # Class names
        class_names = self.apk.get_activities()
        for cls in class_names:
            # Short names heuristic
            if len(cls) <= 2:
                findings.append(cls)
            # High entropy heuristic
            if self.calc_entropy(cls) > 3.5:
                findings.append(cls)

        # Strings (possible encoded/obfuscated strings)
        for s in self.extract_strings():
            if re.fullmatch(r'[A-Za-z0-9+/=]{20,}', s):
                findings.append(s)

        return findings

    # ---------- Run full analysis ----------
    def run_analysis(self):
        findings = {}

        # Check malicious hash
        if self.check_malicious_hash():
            findings["malicious_hash"] = ["Known malicious APK hash detected!"]
            return 100, findings  # Max risk

        # Permissions
        perms = self.apk.get_permissions()
        perm_score, flagged_perms = self.rule_engine.evaluate_permissions(perms)
        findings["suspicious_permissions"] = flagged_perms

        # Strings & URLs
        strings = self.extract_strings()
        urls = self.extract_urls(strings)
        url_score, flagged_urls = self.rule_engine.evaluate_urls(urls)
        str_score, flagged_strings = self.rule_engine.evaluate_strings(strings)
        findings["hardcoded_strings"] = flagged_strings
        findings["hardcoded_urls"] = flagged_urls

        # Obfuscation
        obf_findings = self.check_obfuscation_enhanced()
        obf_score, flagged_classes = self.rule_engine.evaluate_obfuscation(obf_findings)
        findings["obfuscation_indicators"] = flagged_classes

        total_score = perm_score + url_score + str_score + obf_score
        return total_score, findings




