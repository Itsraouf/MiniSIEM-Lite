import json
import re
from datetime import datetime, timedelta

class DetectionEngine:
    def __init__(self, rules_file='rules/detection_rules.json'):
        self.rules = self._load_rules(rules_file)
        self.alerts = []
        
    def _load_rules(self, rules_file):
        """Load detection rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
            print(f"[INFO] Loaded {len(rules)} detection rules")
            return rules
        except FileNotFoundError:
            print(f"[ERROR] Rules file not found: {rules_file}")
            return {}
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in rules file: {rules_file}")
            return {}
    
    def analyze_logs(self, parsed_logs, log_type='auth'):
        """Analyze parsed logs against all rules"""
        print(f"\n[ANALYSIS] Analyzing {len(parsed_logs)} {log_type} logs for threats...")
        
        # Reset alerts for new analysis
        self.alerts = []
        
        # Apply each detection rule that matches the log type
        for rule_name, rule in self.rules.items():
            rule_log_types = rule.get('log_type', [])
            
            # Check if this rule applies to our log type
            if log_type in rule_log_types or 'all' in rule_log_types:
                print(f"  └─ Applying rule: {rule_name}")
                self._apply_rule(rule_name, rule, parsed_logs, log_type)
        
        return self.alerts
    
    def _apply_rule(self, rule_name, rule, parsed_logs, log_type):
        """Apply a single detection rule to logs"""
        # SSH/Auth rules
        if rule_name == 'ssh_brute_force' or rule_name == 'brute_force':
            self._detect_brute_force(rule, parsed_logs)
        elif rule_name == 'success_after_failure':
            self._detect_success_after_failure(rule, parsed_logs)
        elif rule_name == 'off_hours_login':
            self._detect_off_hours_login(rule, parsed_logs)
        
        # Apache rules
        elif rule_name == 'apache_sql_injection':
            self._detect_sql_injection(rule, parsed_logs)
        elif rule_name == 'apache_directory_traversal':
            self._detect_directory_traversal(rule, parsed_logs)
        elif rule_name == 'apache_admin_access':
            self._detect_admin_access(rule, parsed_logs)
        elif rule_name == 'apache_php_exploit':
            self._detect_php_exploit(rule, parsed_logs)
    
    def _detect_brute_force(self, rule, parsed_logs):
        """Detect multiple failed logins from same IP"""
        time_window = rule.get('time_window', 300)  # Default 5 minutes
        
        # Group logs by IP
        ip_logs = {}
        for log in parsed_logs:
            if log.get('status') == 'FAILURE':
                ip = log.get('source_ip')
                if ip:
                    if ip not in ip_logs:
                        ip_logs[ip] = []
                    ip_logs[ip].append(log)
        
        # Check each IP for brute force
        for ip, logs in ip_logs.items():
            if len(logs) >= 5:  # More than 5 failures
                # Sort by timestamp
                logs.sort(key=lambda x: x.get('timestamp', datetime.min))
                
                # Check if failures are within time window
                first_failure = logs[0].get('timestamp')
                last_failure = logs[-1].get('timestamp')
                
                if isinstance(first_failure, datetime) and isinstance(last_failure, datetime):
                    time_diff = (last_failure - first_failure).total_seconds()
                    
                    if time_diff <= time_window:
                        alert = {
                            'rule': 'ssh_brute_force',
                            'severity': rule.get('severity', 'HIGH'),
                            'title': 'Possible SSH Brute Force Attack',
                            'description': f'Multiple failed logins from {ip} within {time_window} seconds',
                            'ip_address': ip,
                            'attempts': len(logs),
                            'first_attempt': first_failure.strftime('%H:%M:%S') if isinstance(first_failure, datetime) else str(first_failure),
                            'last_attempt': last_failure.strftime('%H:%M:%S') if isinstance(last_failure, datetime) else str(last_failure),
                            'timestamp': last_failure.strftime('%Y-%m-%d %H:%M:%S')  # FIXED: Use log timestamp
                        }
                        self.alerts.append(alert)
    
    def _detect_success_after_failure(self, rule, parsed_logs):
        """Detect successful login after multiple failures from same IP"""
        time_window = rule.get('time_window', 600)  # Default 10 minutes
        
        # Group logs by IP
        ip_activity = {}
        for log in parsed_logs:
            ip = log.get('source_ip')
            if not ip:
                continue
                
            if ip not in ip_activity:
                ip_activity[ip] = {'failures': [], 'successes': []}
            
            if log.get('status') == 'FAILURE':
                ip_activity[ip]['failures'].append(log)
            elif log.get('status') == 'SUCCESS':
                ip_activity[ip]['successes'].append(log)
        
        # Check each IP for pattern
        for ip, activities in ip_activity.items():
            if len(activities['failures']) >= 3 and len(activities['successes']) > 0:
                # Get timestamps
                failures_with_timestamp = [log for log in activities['failures'] if 'timestamp' in log]
                successes_with_timestamp = [log for log in activities['successes'] if 'timestamp' in log]
                
                if failures_with_timestamp and successes_with_timestamp:
                    last_failure = max([log['timestamp'] for log in failures_with_timestamp])
                    first_success = min([log['timestamp'] for log in successes_with_timestamp])
                    
                    if isinstance(last_failure, datetime) and isinstance(first_success, datetime):
                        time_diff = (first_success - last_failure).total_seconds()
                        if time_diff <= time_window:
                            alert = {
                                'rule': 'success_after_failure',
                                'severity': rule.get('severity', 'MEDIUM'),
                                'title': 'Successful Login After Multiple Failures',
                                'description': f'IP {ip} succeeded after {len(activities["failures"])} failures',
                                'ip_address': ip,
                                'failed_attempts': len(activities['failures']),
                                'success_time': first_success.strftime('%H:%M:%S'),
                                'last_failure': last_failure.strftime('%H:%M:%S'),
                                'timestamp': first_success.strftime('%Y-%m-%d %H:%M:%S')  # FIXED: Use log timestamp
                            }
                            self.alerts.append(alert)
    
    def _detect_off_hours_login(self, rule, parsed_logs):
        """Detect logins outside normal business hours (9AM-5PM)"""
        for log in parsed_logs:
            if log.get('status') == 'SUCCESS':
                timestamp = log.get('timestamp')
                if isinstance(timestamp, datetime):
                    hour = timestamp.hour
                    if hour < 9 or hour > 17:  # Outside 9AM-5PM
                        alert = {
                            'rule': 'off_hours_login',
                            'severity': rule.get('severity', 'LOW'),
                            'title': 'Login Outside Normal Hours',
                            'description': f'User {log.get("user")} logged in at {hour:02d}:{timestamp.minute:02d}',
                            'ip_address': log.get('source_ip'),
                            'user': log.get('user'),
                            'login_time': timestamp.strftime('%H:%M:%S'),
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S')  # FIXED: Use log timestamp
                        }
                        self.alerts.append(alert)
    
    def _detect_sql_injection(self, rule, parsed_logs):
        """Detect SQL injection attempts in web requests"""
        sql_patterns = [
            r'.*SELECT.*FROM.*',
            r'.*UNION.*SELECT.*',
            r'.*INSERT.*INTO.*',
            r'.*DROP.*TABLE.*',
            r'.*DELETE.*FROM.*',
            r".*OR.*1.*=.*1.*",
            r".*' OR '.*'='.*",
            r".*;--.*"
        ]
        
        for log in parsed_logs:
            if 'path' in log:
                path = log['path']
                for pattern in sql_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        log_timestamp = log.get('timestamp', datetime.now())
                        timestamp_str = log_timestamp.strftime('%Y-%m-%d %H:%M:%S') if isinstance(log_timestamp, datetime) else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        alert = {
                            'rule': 'apache_sql_injection',
                            'severity': rule.get('severity', 'HIGH'),
                            'title': 'Possible SQL Injection Attempt',
                            'description': f'SQL injection pattern detected in request: {path[:50]}...',
                            'ip_address': log.get('ip'),
                            'path': path,
                            'method': log.get('method'),
                            'timestamp': timestamp_str  
                        }
                        self.alerts.append(alert)
                        break
    
    def _detect_directory_traversal(self, rule, parsed_logs):
        """Detect directory traversal attempts"""
        traversal_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'\.\.%2f',
            r'\.\.%5c',
            r'/etc/passwd',
            r'/etc/shadow',
            r'C:\\Windows\\System32'
        ]
        
        for log in parsed_logs:
            if 'path' in log:
                path = log['path']
                for pattern in traversal_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        log_timestamp = log.get('timestamp', datetime.now())
                        timestamp_str = log_timestamp.strftime('%Y-%m-%d %H:%M:%S') if isinstance(log_timestamp, datetime) else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        alert = {
                            'rule': 'apache_directory_traversal',
                            'severity': rule.get('severity', 'HIGH'),
                            'title': 'Directory Traversal Attempt',
                            'description': f'Path traversal detected: {path[:50]}...',
                            'ip_address': log.get('ip'),
                            'path': path,
                            'method': log.get('method'),
                            'timestamp': timestamp_str  
                        }
                        self.alerts.append(alert)
                        break
    
    def _detect_admin_access(self, rule, parsed_logs):
        """Detect access to admin pages"""
        admin_paths = [
            '/admin',
            '/wp-admin',
            '/administrator',
            '/backend',
            '/cp',
            '/controlpanel',
            '/dashboard'
        ]
        
        for log in parsed_logs:
            if 'path' in log:
                path = log['path'].lower()
                for admin_path in admin_paths:
                    if admin_path in path:
                        
                        status = str(log.get('status', ''))
                        if status.isdigit() and int(status) < 500:  
                            log_timestamp = log.get('timestamp', datetime.now())
                            timestamp_str = log_timestamp.strftime('%Y-%m-%d %H:%M:%S') if isinstance(log_timestamp, datetime) else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            
                            alert = {
                                'rule': 'apache_admin_access',
                                'severity': rule.get('severity', 'MEDIUM'),
                                'title': 'Admin Page Access Detected',
                                'description': f'Access to admin page ({status}): {path[:50]}...',
                                'ip_address': log.get('ip'),
                                'path': path,
                                'status': status,
                                'timestamp': timestamp_str  
                            }
                            self.alerts.append(alert)
                            break
    
    def _detect_php_exploit(self, rule, parsed_logs):
        """Detect access to known vulnerable PHP files"""
        vulnerable_files = [
            '/wp-login.php',
            '/xmlrpc.php',
            '/phpmyadmin/',
            '/phpinfo.php',
            '/test.php',
            '/shell.php',
            '/cmd.php',
            '/backdoor.php'
        ]
        
        for log in parsed_logs:
            if 'path' in log:
                path = log['path'].lower()
                for vuln_file in vulnerable_files:
                    if vuln_file in path:
                        log_timestamp = log.get('timestamp', datetime.now())
                        timestamp_str = log_timestamp.strftime('%Y-%m-%d %H:%M:%S') if isinstance(log_timestamp, datetime) else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        alert = {
                            'rule': 'apache_php_exploit',
                            'severity': rule.get('severity', 'MEDIUM'),
                            'title': 'Access to Potentially Vulnerable PHP File',
                            'description': f'Access to {vuln_file} detected',
                            'ip_address': log.get('ip'),
                            'path': path,
                            'method': log.get('method'),
                            'timestamp': timestamp_str  
                        }
                        self.alerts.append(alert)
                        break

# Test function
if __name__ == "__main__":
    # Import parser to test
    from parser import LogParser
    
    print("=" * 60)
    print("TESTING DETECTION ENGINE WITH ALL RULES")
    print("=" * 60)
    
    # Test SSH logs
    print("\n[TEST 1] Testing SSH/Auth logs:")
    parser = LogParser()
    ssh_logs = parser.parse_file('logs/sample_auth.log', log_type='auth')
    
    detector = DetectionEngine()
    ssh_alerts = detector.analyze_logs(ssh_logs, log_type='auth')
    
    print(f"[RESULTS] Found {len(ssh_alerts)} SSH security alerts")
    
    # Test Apache logs
    print("\n[TEST 2] Testing Apache logs:")
    apache_logs = parser.parse_file('logs/sample_apache.log', log_type='apache')
    
    if apache_logs:
        apache_alerts = detector.analyze_logs(apache_logs, log_type='apache')
        print(f"[RESULTS] Found {len(apache_alerts)} Apache security alerts")
        
        if apache_alerts:
            for i, alert in enumerate(apache_alerts, 1):
                print(f"\n🔔 ALERT #{i}: {alert['title']}")
                print(f"   Severity: {alert['severity']}")
                print(f"   Description: {alert['description']}")
                print(f"   IP Address: {alert.get('ip_address', 'N/A')}")
                print(f"   Time: {alert['timestamp']}")
    else:
        print("No Apache logs were parsed")
    
    print("\n" + "=" * 60)
