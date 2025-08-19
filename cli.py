import argparse
import sys
import re
from aasa.analyzer import Analyzer

# Terminal color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def colorize_score(score):
    if score >= 50:
        return f"{Colors.RED}{score}{Colors.RESET}"
    elif score >= 20:
        return f"{Colors.YELLOW}{score}{Colors.RESET}"
    else:
        return f"{Colors.GREEN}{score}{Colors.RESET}"

def main():
    parser = argparse.ArgumentParser(
        description="📱 AASA - Android APK Security Analyzer"
    )
    parser.add_argument(
        "-f", "--file", dest="apk", required=True,
        help="Path to APK file"
    )
    parser.add_argument(
        "-o", "--output", default="report.txt",
        help="Output report file (default: report.txt)"
    )
    parser.add_argument(
        "-j", "--json", default=None,
        help="Optional: Save findings in JSON format"
    )

    args = parser.parse_args()

    try:
        analyzer = Analyzer(args.apk)
        score, findings = analyzer.run_analysis()

        # 🖥️ Terminal output with colors
        print(f"\n=== AASA Android Security Report ===")
        print(f"APK: {args.apk}")
        print(f"Risk Score: {colorize_score(score)}\n")

        for category, items in findings.items():
            if category == "malicious_hash":
                header = f"{Colors.RED}[{category.upper()}]{Colors.RESET}"
            else:
                header = f"{Colors.CYAN}[{category.upper()}]{Colors.RESET}"

            print(header)
            if items:
                for i in items:
                    if category == "malicious_hash":
                        print(f"{Colors.RED} - {i}{Colors.RESET}")
                    else:
                        print(f" - {i}")
            else:
                print(" (none)")
            print("")

        # 📝 Text report
        with open(args.output, "w") as f:
            f.write("=== AASA Android Security Report ===\n\n")
            f.write(f"APK: {args.apk}\n")
            f.write(f"Risk Score: {score}\n\n")
            for category, items in findings.items():
                f.write(f"[{category.upper()}]\n")
                if items:
                    for i in items:
                        f.write(f" - {i}\n")
                else:
                    f.write(" (none)\n")
                f.write("\n")

        print(f"✅ Analysis complete! Report saved to: {args.output}")

        # 💾 Optional JSON export
        if args.json:
            import json
            with open(args.json, "w") as jf:
                json.dump({"apk": args.apk, "score": score, "findings": findings}, jf, indent=4)
            print(f"📂 JSON results saved to: {args.json}")

    except FileNotFoundError:
        print(f"❌ Error: APK file '{args.apk}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

'''import argparse
import sys
from aasa.analyzer import Analyzer

# Terminal color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def colorize_score(score):
    if score >= 50:
        return f"{Colors.RED}{score}{Colors.RESET}"
    elif score >= 20:
        return f"{Colors.YELLOW}{score}{Colors.RESET}"
    else:
        return f"{Colors.GREEN}{score}{Colors.RESET}"

def main():
    parser = argparse.ArgumentParser(
        description="📱 AASA - Android APK Security Analyzer"
    )
    parser.add_argument(
        "-f", "--file", dest="apk", required=True,
        help="Path to APK file"
    )
    parser.add_argument(
        "-o", "--output", default="report.txt",
        help="Output report file (default: report.txt)"
    )
    parser.add_argument(
        "-j", "--json", default=None,
        help="Optional: Save findings in JSON format"
    )

    args = parser.parse_args()

    try:
        analyzer = Analyzer(args.apk)
        score, findings = analyzer.run_analysis()

        # 🖥️ Terminal output with colors
        print(f"\n=== AASA Android Security Report ===")
        print(f"APK: {args.apk}")
        print(f"Risk Score: {colorize_score(score)}\n")

        for category, items in findings.items():
            print(f"{Colors.CYAN}[{category.upper()}]{Colors.RESET}")
            if items:
                for i in items:
                    print(f" - {i}")
            else:
                print(" (none)")
            print("")

        # 📝 Text report
        with open(args.output, "w") as f:
            f.write("=== AASA Android Security Report ===\n\n")
            f.write(f"APK: {args.apk}\n")
            f.write(f"Risk Score: {score}\n\n")
            for category, items in findings.items():
                f.write(f"[{category.upper()}]\n")
                if items:
                    for i in items:
                        f.write(f" - {i}\n")
                else:
                    f.write(" (none)\n")
                f.write("\n")

        print(f"✅ Analysis complete! Report saved to: {args.output}")

        # 💾 Optional JSON export
        if args.json:
            import json
            with open(args.json, "w") as jf:
                json.dump({"apk": args.apk, "score": score, "findings": findings}, jf, indent=4)
            print(f"📂 JSON results saved to: {args.json}")

    except FileNotFoundError:
        print(f"❌ Error: APK file '{args.apk}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()'''

