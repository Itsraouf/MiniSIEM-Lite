#!/usr/bin/env python3
"""
MiniSIEM-Lite - A Beginner-Friendly Log Analysis & Alerting Tool
"""

import argparse
import sys
import os
from datetime import datetime

# Import our modules
from parser import LogParser
from detector import DetectionEngine
from alert import AlertManager

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="MiniSIEM-Lite: Security Log Analysis & Alerting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f logs/sample_auth.log -t auth
  %(prog)s -f logs/sample_ssh.log -t ssh -o report.txt
  %(prog)s -f logs/sample_auth.log --verbose

Detection Rules:
  - Brute Force: >5 failed logins from same IP in 5 minutes
  - Success After Failure: Login success after multiple failures
  - Off-Hours Login: Login outside 9AM-5PM
        """
    )
    
    parser.add_argument('-f', '--file', required=True,
                       help='Path to log file (e.g., logs/sample_auth.log)')
    parser.add_argument('-t', '--type', default='auth',
                       choices=['auth', 'ssh'],
                       help='Log type: auth (default) or ssh')
    parser.add_argument('-o', '--output',
                       help='Save report to file (JSON or TXT)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed processing information')
    parser.add_argument('--rules', default='rules/detection_rules.json',
                       help='Path to custom rules file')
    
    args = parser.parse_args()
    
    # Check if log file exists
    if not os.path.exists(args.file):
        print(f"❌ Error: Log file not found: {args.file}")
        sys.exit(1)
    
    # Print banner
    print("=" * 60)
    print("🔍 MiniSIEM-Lite - Security Log Analysis")
    print("=" * 60)
    
    # Step 1: Parse logs
    if args.verbose:
        print(f"[1/3] Parsing {args.type} log: {args.file}")
    
    log_parser = LogParser()
    parsed_logs = log_parser.parse_file(args.file, args.type)
    
    if not parsed_logs:
        print("❌ No logs were parsed. Check file format and type.")
        sys.exit(1)
    
    if args.verbose:
        print(f"   ✓ Parsed {len(parsed_logs)} log entries")
    
    # Step 2: Detect threats
    if args.verbose:
        print(f"[2/3] Analyzing with detection rules")
    
    detector = DetectionEngine(args.rules)
    alerts = detector.analyze_logs(parsed_logs)
    
    # Step 3: Display alerts
    if args.verbose:
        print(f"[3/3] Processing alerts")
    
    alert_manager = AlertManager()
    
    if alerts:
        print(f"\n🚨 SECURITY ALERTS DETECTED ({len(alerts)} total)")
        print("-" * 60)
        for alert in alerts:
            alert_manager.display_alert(alert)
        alert_manager.display_summary(alerts)
    else:
        print("\n✅ No security alerts detected.")
        print("   All log entries appear normal.")
    
    # Step 4: Generate report if requested
    if args.output:
        generate_report(alerts, args.output, args.file)
        print(f"\n📄 Report saved to: {args.output}")
    
    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)

def generate_report(alerts, output_file, source_file):
    """Generate a report file in JSON or TXT format"""
    report_data = {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'total_alerts': len(alerts),
        'alerts': alerts
    }
    
    if output_file.endswith('.json'):
        import json
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    else:
        # TXT format
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("MiniSIEM-Lite Security Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {report_data['generated_at']}\n")
            f.write(f"Source: {report_data['source_file']}\n")
            f.write(f"Total Alerts: {report_data['total_alerts']}\n\n")
            
            if alerts:
                f.write("DETECTED THREATS:\n")
                f.write("-" * 40 + "\n")
                for i, alert in enumerate(alerts, 1):
                    f.write(f"\nAlert #{i}: {alert['title']}\n")
                    f.write(f"  Severity: {alert['severity']}\n")
                    f.write(f"  Description: {alert['description']}\n")
                    f.write(f"  IP: {alert.get('ip_address', 'N/A')}\n")
                    f.write(f"  Rule: {alert['rule']}\n")
                    f.write(f"  Time: {alert['timestamp']}\n")
            else:
                f.write("No security threats detected.\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("End of Report\n")

if __name__ == "__main__":
    main()