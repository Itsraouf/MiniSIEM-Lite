import re
import os
from datetime import datetime

class LogParser:
    def __init__(self):
        self.patterns = {
            "ssh": r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)",
            "auth": r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)",
            "apache": r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<path>.*?) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\S+)(?: "(?P<referrer>.*?)" "(?P<user_agent>.*?)")?',
        }

    def parse_line(self, line, log_type="auth"):
        """Parse a single log line into structured data"""
        if log_type not in self.patterns:
            return None

        match = re.match(self.patterns[log_type], line.strip())
        if not match:
            return None

        log_entry = match.groupdict()

        # Handle different log types
        if log_type in ["auth", "ssh"]:
            # SSH logs have 'message' field
            if "message" in log_entry:
                message = log_entry["message"]
                log_entry["source_ip"] = self._extract_ip(message)
                log_entry["user"] = self._extract_user(message)
                log_entry["status"] = self._extract_status(message)
            else:
                log_entry["source_ip"] = None
                log_entry["user"] = None
                log_entry["status"] = "UNKNOWN"

            # Parse timestamp
            if "timestamp" in log_entry:
                log_entry["timestamp"] = self._normalize_timestamp(log_entry["timestamp"])

        elif log_type == "apache":
            
            if "ip" in log_entry:
                ip = log_entry["ip"]
                ip = ip.replace("ï»¿", "").strip()
                log_entry["ip"] = ip
                log_entry["source_ip"] = ip  
            # Parse Apache timestamp
            if "timestamp" in log_entry:
                log_entry["timestamp"] = self._parse_apache_timestamp(log_entry["timestamp"])
            log_entry["user"] = None
            
        return log_entry

    def _extract_ip(self, message):
        """Extract IP address from SSH log message"""
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None

    def _extract_user(self, message):
        """Extract username from SSH log message"""
        user_pattern = r"(?:for|user)\s+(?:invalid\s+user\s+)?(\w+)"
        match = re.search(user_pattern, message)
        return match.group(1) if match else None

    def _extract_status(self, message):
        """Extract success/failure status from SSH log"""
        message_lower = message.lower()
        if "accepted password" in message_lower:
            return "SUCCESS"
        elif "failed password" in message_lower:
            return "FAILURE"
        return "UNKNOWN"

    def _normalize_timestamp(self, timestamp_str):
        """Convert SSH timestamp to datetime object"""
        current_year = datetime.now().year
        full_timestamp = f"{current_year} {timestamp_str}"

        try:
            return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except ValueError:
            return timestamp_str

    def _parse_apache_timestamp(self, timestamp_str):
        """Convert Apache timestamp to datetime object"""
        try:
            timestamp_str = timestamp_str.replace(' -', ' -').strip()
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            
            try:
                timestamp_str = timestamp_str.split()[0]
                return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return timestamp_str

    def parse_file(self, filepath, log_type="auth"):
        """Parse entire log file"""
        parsed_logs = []

        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            return parsed_logs

        with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    parsed = self.parse_line(line, log_type)
                    if parsed:
                        parsed_logs.append(parsed)

        print(f"[SUCCESS] Parsed {len(parsed_logs)} logs from {filepath}")
        return parsed_logs


# Test function
if __name__ == "__main__":
    parser = LogParser()

    print("=" * 60)
    print("TESTING PARSER WITH ALL LOG TYPES")
    print("=" * 60)

    # Test SSH logs
    print("\n[TEST 1] Testing SSH/Auth logs:")
    ssh_logs = parser.parse_file("logs/sample_auth.log", log_type="auth")
    if ssh_logs:
        print(f"✓ Parsed {len(ssh_logs)} SSH logs")
        print(f"  First log source_ip: {ssh_logs[0].get('source_ip')}")

    # Test Apache logs
    print("\n[TEST 2] Testing Apache logs:")
    apache_logs = parser.parse_file("logs/sample_apache.log", log_type="apache")
    if apache_logs:
        print(f"✓ Parsed {len(apache_logs)} Apache logs")
        print(f"  First log ip: {apache_logs[0].get('ip')}")
        print(f"  First log path: {apache_logs[0].get('path')}")
        print(f"  First log status: {apache_logs[0].get('status')}") 

    print("\n" + "=" * 60)
