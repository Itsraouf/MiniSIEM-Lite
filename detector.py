import json
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
    
    def analyze_logs(self, parsed_logs):
        """Analyze parsed logs against all rules"""
        print(f"\n[ANALYSIS] Analyzing {len(parsed_logs)} logs for threats...")
        
        # Reset alerts for new analysis
        self.alerts = []
        
        # Apply each detection rule
        for rule_name, rule in self.rules.items():
            print(f"  └─ Applying rule: {rule_name}")
            self._apply_rule(rule_name, rule, parsed_logs)
        
        return self.alerts
    
    def _apply_rule(self, rule_name, rule, parsed_logs):
        """Apply a single detection rule to logs"""
        if rule_name == 'brute_force':
            self._detect_brute_force(rule, parsed_logs)
        elif rule_name == 'success_after_failure':
            self._detect_success_after_failure(rule, parsed_logs)
        elif rule_name == 'off_hours_login':
            self._detect_off_hours_login(rule, parsed_logs)
    
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
                logs.sort(key=lambda x: x['timestamp'])
                
                # Check if failures are within time window
                first_failure = logs[0]['timestamp']
                last_failure = logs[-1]['timestamp']
                time_diff = (last_failure - first_failure).total_seconds()
                
                if time_diff <= time_window:
                    alert = {
                        'rule': 'brute_force',
                        'severity': rule.get('severity', 'HIGH'),
                        'title': 'Possible SSH Brute Force Attack',
                        'description': f'Multiple failed logins from {ip} within {time_window} seconds',
                        'ip_address': ip,
                        'attempts': len(logs),
                        'first_attempt': first_failure.strftime('%H:%M:%S'),
                        'last_attempt': last_failure.strftime('%H:%M:%S'),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
                # Check if success occurred after failures
                last_failure = max([log['timestamp'] for log in activities['failures']])
                first_success = min([log['timestamp'] for log in activities['successes']])
                
                if first_success > last_failure:
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
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        self.alerts.append(alert)
    
    def _detect_off_hours_login(self, rule, parsed_logs):
        """Detect logins outside normal business hours (9AM-5PM)"""
        for log in parsed_logs:
            if log.get('status') == 'SUCCESS':
                hour = log['timestamp'].hour
                if hour < 9 or hour > 17:  # Outside 9AM-5PM
                    alert = {
                        'rule': 'off_hours_login',
                        'severity': rule.get('severity', 'LOW'),
                        'title': 'Login Outside Normal Hours',
                        'description': f'User {log.get("user")} logged in at {hour:02d}:{log["timestamp"].minute:02d}',
                        'ip_address': log.get('source_ip'),
                        'user': log.get('user'),
                        'login_time': log['timestamp'].strftime('%H:%M:%S'),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    self.alerts.append(alert)

# Test function
if __name__ == "__main__":
    # Import parser to test
    from parser import LogParser
    
    print("=" * 60)
    print("TESTING DETECTION ENGINE")
    print("=" * 60)
    
    # Parse logs
    parser = LogParser()
    logs = parser.parse_file('logs/sample_auth.log', log_type='auth')
    
    # Analyze for threats
    detector = DetectionEngine()
    alerts = detector.analyze_logs(logs)
    
    print(f"\n[RESULTS] Found {len(alerts)} security alerts:")
    print("-" * 60)
    
    for i, alert in enumerate(alerts, 1):
        print(f"\n🔔 ALERT #{i}: {alert['title']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Description: {alert['description']}")
        print(f"   IP Address: {alert.get('ip_address', 'N/A')}")
        print(f"   Rule: {alert['rule']}")
        print(f"   Time: {alert['timestamp']}")
    
    print("\n" + "=" * 60)