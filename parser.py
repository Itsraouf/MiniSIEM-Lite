import re
import os
from datetime import datetime

class LogParser:
    def __init__(self):
        # Updated regex patterns - more flexible
        self.patterns = {
            'ssh': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            'auth': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)'
        }
        
    def parse_line(self, line, log_type='auth'):
        """Parse a single log line into structured data"""
        if log_type not in self.patterns:
            return None
            
        match = re.match(self.patterns[log_type], line)
        if not match:
            # Try more flexible pattern
            flexible_pattern = r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<service>\S+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)'
            match = re.match(flexible_pattern, line)
            if not match:
                print(f"[WARNING] Failed to parse line: {line[:50]}...")
                return None
            
        log_entry = match.groupdict()
        
        # Extract additional details from message
        log_entry['source_ip'] = self._extract_ip(log_entry['message'])
        log_entry['user'] = self._extract_user(log_entry['message'])
        log_entry['status'] = self._extract_status(log_entry['message'])
        log_entry['timestamp'] = self._normalize_timestamp(log_entry['timestamp'])
        
        return log_entry
    
    def _extract_ip(self, message):
        """Extract IP address from log message"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None
    
    def _extract_user(self, message):
        """Extract username from log message"""
        # Pattern for: "for invalid user bob" or "for root" or "for alice"
        user_pattern = r'(?:for|user)\s+(?:invalid\s+user\s+)?(\w+)'
        match = re.search(user_pattern, message)
        return match.group(1) if match else None
    
    def _extract_status(self, message):
        """Extract success/failure status"""
        message_lower = message.lower()
        if 'accepted password' in message_lower:
            return 'SUCCESS'
        elif 'failed password' in message_lower:
            return 'FAILURE'
        return 'UNKNOWN'
    
    def _normalize_timestamp(self, timestamp_str):
        """Convert timestamp to datetime object"""
        # Add current year since logs don't include it
        current_year = datetime.now().year
        full_timestamp = f"{current_year} {timestamp_str}"
        
        try:
            return datetime.strptime(full_timestamp, '%Y %b %d %H:%M:%S')
        except ValueError:
            return timestamp_str
    
    def parse_file(self, filepath, log_type='auth'):
        """Parse entire log file"""
        parsed_logs = []
        
        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            return parsed_logs
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:  # Skip empty lines
                    parsed = self.parse_line(line, log_type)
                    if parsed:
                        parsed_logs.append(parsed)
                    else:
                        print(f"[WARNING] Line {line_num} failed to parse")
        
        print(f"[SUCCESS] Parsed {len(parsed_logs)} logs from {filepath}")
        return parsed_logs

# Quick test function
if __name__ == "__main__":
    parser = LogParser()
    
    print("=" * 50)
    print("TESTING LOG PARSER")
    print("=" * 50)
    
    # Test with sample auth log
    test_logs = parser.parse_file('logs/sample_auth.log', log_type='auth')
    
    if test_logs:
        print(f"\n✓ First parsed log entry:")
        for key, value in test_logs[0].items():
            print(f"  {key}: {value}")
        
        print(f"\n✓ Total logs parsed: {len(test_logs)}")
        
        # Count statuses
        status_count = {}
        ip_count = {}
        for log in test_logs:
            status = log.get('status', 'UNKNOWN')
            status_count[status] = status_count.get(status, 0) + 1
            
            ip = log.get('source_ip')
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1
        
        print(f"\n✓ Status breakdown:")
        for status, count in status_count.items():
            print(f"  {status}: {count}")
        
        print(f"\n✓ IP activity:")
        for ip, count in ip_count.items():
            print(f"  {ip}: {count} events")
    else:
        print("\n✗ No logs were parsed. Check file path and format.")
    
    print("\n" + "=" * 50)