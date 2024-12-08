import re
import csv
from collections import defaultdict, Counter

LOG_FILE = "sample.log"  # Replace with your log file name
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Function to parse log file and extract details
def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            ip_requests[ip] += 1

            # Extract endpoint and status code
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^ ]+) HTTP', line)
            status_code_match = re.search(r'" (\d{3}) ', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1
            if status_code_match and int(status_code_match.group(1)) == 401:
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

# Function to display results in the terminal
def display_results(ip_requests, endpoint_access, failed_attempts):
    # Sort data for display
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = endpoint_access.most_common(1)
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display IP Request Counts
    print("Requests per IP :")
    print("IP Address,Request Count")
    for ip, count in sorted_ips:
        print(f"{ip},{count}")

    # Display Most Accessed Endpoint
    print("\nMost Accessed Endpoint:")
    print("Endpoint,Access Count")
    if most_accessed_endpoint:
        endpoint, count = most_accessed_endpoint[0]
        print(f"{endpoint},{count}")

    # Display Suspicious Activity
    print("\nSuspicious Activity:")
    print("IP Address,Failed Login Attempts:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip},{count}")
    else:
        print("No suspicious activity detected.")

# Function to save results to a CSV file
def save_to_csv(ip_requests, endpoint_access, failed_attempts):
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = endpoint_access.most_common(1)
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Request Counts
        writer.writerow(["Count Requests per IP Address:"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ips)

        # Write Most Accessed Endpoint
        if most_accessed_endpoint:
            writer.writerow([])
            writer.writerow(["Most Accessed Frequently Endpoint:"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0][0], most_accessed_endpoint[0][1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity:"])
        writer.writerow(["IP Address", "Failed Login Attempts:"])
        if suspicious_ips:
            writer.writerows(suspicious_ips.items())
        else:
            writer.writerow(["No suspicious activity detected."])

    print(f"\nResults saved to {OUTPUT_CSV}")

# Main function
if __name__ == "__main__":
    ip_requests, endpoint_access, failed_attempts = parse_log(LOG_FILE)
    display_results(ip_requests, endpoint_access, failed_attempts)
    save_to_csv(ip_requests, endpoint_access, failed_attempts)
