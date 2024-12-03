import re
import csv
from collections import defaultdict, Counter

# Constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Functions
def parse_log(file_path):
    """Reads the log file and returns a list of log entries."""
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_entries):
    """Counts the number of requests per IP address."""
    ip_counts = Counter()
    for entry in log_entries:
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", entry)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

def most_frequent_endpoint(log_entries):
    """Identifies the most frequently accessed endpoint."""
    endpoint_counts = Counter()
    for entry in log_entries:
        match = re.search(r"\"(?:GET|POST) (\/\S*)", entry)
        if match:
            endpoint_counts[match.group(1)] += 1
    if endpoint_counts:
        most_common = endpoint_counts.most_common(1)[0]
        return most_common
    return None, 0

def detect_suspicious_activity(log_entries, threshold=FAILED_LOGIN_THRESHOLD):
    """Detects IP addresses with failed login attempts exceeding the threshold."""
    failed_login_counts = Counter()
    for entry in log_entries:
        if "401" in entry or "Invalid credentials" in entry:
            match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", entry)
            if match:
                failed_login_counts[match.group(1)] += 1
    return {ip: count for ip, count in failed_login_counts.items() if count > threshold}

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activities, output_file):
    """Saves the results to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        writer.writerow([])  # Blank line

        # Write suspicious activities
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main Execution
if __name__ == "__main__":
    log_entries = parse_log(LOG_FILE)

    # Analyze the log
    ip_request_counts = count_requests_per_ip(log_entries)
    most_accessed = most_frequent_endpoint(log_entries)
    suspicious_ips = detect_suspicious_activity(log_entries)

    # Display Results
    print("Requests per IP Address:")
    for ip, count in ip_request_counts.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_request_counts, most_accessed, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")
