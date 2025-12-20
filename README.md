  MiniSIEM-Lite 

A beginner friendly SIEM tool I built to analyze logs and detect security threats. After wrestling with regex and debugging for hours, I finally got SSH and Apache detection working properly!


  Why I Built This
  
i spent 4 months to fully understand how splunk works and get used to it ... and throught my experience i have noticed that it could be hard for absolute begineers to jump straight to splunk / elk / Qradar 

To understand how real SIEM tools work under the hood. This project taught me log parsing, regex patterns, and debugging persistence when Apache detection refused to work and how detection rules work 

   What It Does

SSH Analysis:

Brute force attacks (>5 failures in 5 minutes)

Suspicious logins (success after failures)

Off-hours access (outside 9AM-5PM)

Apache Analysis: (finally fixed after debugging!)

SQL injection attempts

Directory traversal (/../../../etc/passwd)

Admin page access (even 403 responses)

Vulnerable PHP file access

🚀 Quick Start
bash
# Clone and setup
git clone https://github.com/Itsraouf/MiniSIEM-Lite.git
cd MiniSIEM-Lite
pip install colorama

# Analyze logs
python minisiem.py -f logs/sample_auth.log -t auth
python minisiem.py -f logs/sample_apache.log -t apache -v
📁 Project Structure
text
minisiem.py          # CLI interface
parser.py            # Log parser (SSH + Apache)
detector.py          # 7 detection rules
alert.py             # Color-coded alerts
report.py            # JSON/TXT reports
rules/detection_rules.json  # Rule definitions
logs/sample_*.log    # Test logs
🔧 The Fixes That Made It Work
Apache detection was broken - Fixed parser to keep HTTP status codes (not overwrite with "UNKNOWN")

Wrong timestamps - Now shows actual attack time, not current time

Missing CLI option - Added -t apache support

📊 7 Detection Rules
Type	Rule	What It Catches
SSH	Brute Force	>5 failed logins in 5min
SSH	Success After Failure	Login after multiple failures
SSH	Off-Hours Login	Login outside 9AM-5PM
Apache	SQL Injection	' OR '1'='1 patterns
Apache	Directory Traversal	../ or /etc/passwd
Apache	Admin Access	/admin, /wp-admin pages
Apache	PHP Exploit	wp-login.php, xmlrpc.php
🐛 Sample Output
text
🚨 SECURITY ALERTS DETECTED (6 total)
------------------------------------------------------------
╔════════════════════════════════════════════════════════════╗
║ SQL Injection Attempt                                     ║
╠════════════════════════════════════════════════════════════╣
║ Severity:    HIGH                                         ║
║ Description: SQL pattern: /index.php?page=1' OR '1'='1    ║
║ IP Address:  192.168.1.103                                ║
║ Time:        2024-12-18 10:30:50                          ║
╚════════════════════════════════════════════════════════════╝

📄 License
MIT License - feel free to use and modify.

Built with Python, regex battles, and stubborn debugging. 