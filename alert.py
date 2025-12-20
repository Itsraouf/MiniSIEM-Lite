import json
from datetime import datetime

class AlertManager:
    def __init__(self):

        self.colors = {
            'HIGH': '\033[91m',    
            'MEDIUM': '\033[93m',  
            'LOW': '\033[92m',     
            'RESET': '\033[0m'     
        }
    
    def display_alert(self, alert):
        """Display a single alert with colored severity"""
        severity = alert.get('severity', 'UNKNOWN')
        color = self.colors.get(severity, self.colors['RESET'])
        
        print(f"{color}╔{'═' * 60}╗{self.colors['RESET']}")
        print(f"{color}║ {alert['title'][:58]:<58} ║{self.colors['RESET']}")
        print(f"{color}╠{'═' * 60}╣{self.colors['RESET']}")
        print(f"║ {'Severity:':<12} {severity:<46} ║")
        print(f"║ {'Description:':<12} {alert['description'][:46]:<46} ║")
        print(f"║ {'IP Address:':<12} {alert.get('ip_address', 'N/A')[:46]:<46} ║")
        print(f"║ {'Rule:':<12} {alert['rule'][:46]:<46} ║")
        print(f"║ {'Time:':<12} {alert['timestamp'][:46]:<46} ║")
        print(f"╚{'═' * 60}╝")
        print()  
    
    def display_summary(self, alerts):
        """Display a summary of all alerts"""
        if not alerts:
            print("✅ No security alerts detected.")
            return
        
        print(f"\n📊 SECURITY ALERT SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total Alerts: {len(alerts)}")
        
        # Count by severity
        severity_count = {}
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            count = severity_count.get(severity, 0)
            color = self.colors.get(severity, self.colors['RESET'])
            print(f"{color}{severity}: {count}{self.colors['RESET']}")
        
        print(f"{'=' * 60}")

# Test function
if __name__ == "__main__":
    # Create sample alerts for testing
    sample_alerts = [
        {
            'rule': 'brute_force',
            'severity': 'HIGH',
            'title': 'Possible SSH Brute Force Attack',
            'description': 'Multiple failed logins from 192.168.1.10 within 300 seconds',
            'ip_address': '192.168.1.10',
            'attempts': 7,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'rule': 'off_hours_login',
            'severity': 'LOW',
            'title': 'Login Outside Normal Hours',
            'description': 'User dave logged in at 22:05',
            'ip_address': '192.168.1.13',
            'user': 'dave',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    ]
    
    alert_manager = AlertManager()
    print("Testing Alert Manager...")
    print("=" * 60)
    
    for alert in sample_alerts:
        alert_manager.display_alert(alert)
    
    alert_manager.display_summary(sample_alerts)
