import json
import boto3
import os
from botocore.exceptions import ClientError

# Initialize the boto3 clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')
geo_location_api = "https://freegeoip.app/json/"  #API for geo-location

# Constants
THRESHOLD_REQUESTS = 100  # Threshold for suspicious number of requests
ALERT_SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:SecurityAlerts'

def lambda_handler(event, context):
    # Extract the log data (assuming the log event is passed in event parameter)
    log_data = event['log_data']  
    ip_address = log_data['ip_address']
    bucket_name = log_data['bucket_name']
    request_count = log_data['request_count']
    user_agent = log_data['user_agent']
    timestamp = log_data['timestamp']

    # Step 1: Geo-location Check
    if not is_known_ip(ip_address):
        if is_ip_suspicious(ip_address):
            take_action(ip_address, bucket_name, user_agent, timestamp)

    # Step 2: Check if the number of requests is suspicious
    if request_count > THRESHOLD_REQUESTS:
        take_action(ip_address, bucket_name, user_agent, timestamp)

    # Step 3: No suspicious activity detected
    return {"status": "No action required"}

def is_known_ip(ip_address):
    known_ips = os.getenv('KNOWN_IPS')
    if ip_address in known_ips:
        return True
    else:
        return False

def is_ip_suspicious(ip_address):
    try:
        # Call geo-location API to check the location of the IP
        response = requests.get(geo_location_api + ip_address)
        location_data = response.json()
        
        # Example check: If the IP is from a high-risk country
        if location_data['country_code'] in ['IR', 'KP']:
            return True
        
    except Exception as e:
        print(f"Failed to determine location for IP {ip_address}: {e}")
    
    return False

def take_action(ip_address, bucket_name, user_agent, timestamp):
    # Step 1: Block IP in S3 bucket policy
    block_ip(ip_address, bucket_name)

    # Step 2: Send an alert to the security team
    alert_security_team(ip_address, bucket_name, user_agent, timestamp)

    # Step 3: Log the incident
    log_incident(ip_address, bucket_name, user_agent, timestamp)

def block_ip(ip_address, bucket_name):
    # Modify S3 bucket policy to block the IP
    try:
        bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(bucket_policy['Policy'])

        # Add a new policy statement to block the IP
        policy['Statement'].append({
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
            "Condition": {
                "IpAddress": {"aws:SourceIp": ip_address}
            }
        })

        # Apply the updated policy
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        print(f"Blocked IP {ip_address} on bucket {bucket_name}")

    except ClientError as e:
        print(f"Error blocking IP {ip_address} on bucket {bucket_name}: {e}")

def alert_security_team(ip_address, bucket_name, user_agent, timestamp):
    message = f"Suspicious activity detected in S3 bucket {bucket_name}:\n" \
              f"IP Address: {ip_address}\nUser-Agent: {user_agent}\nTime: {timestamp}"
    
    try:
        response = sns_client.publish(
            TopicArn=ALERT_SNS_TOPIC_ARN,
            Message=message,
            Subject="Security Alert: Suspicious S3 Access"
        )
        print(f"Security alert sent: {response['MessageId']}")

    except ClientError as e:
        print(f"Failed to send security alert: {e}")

def log_incident(ip_address, bucket_name, user_agent, timestamp):
    try:
        cloudwatch_client.put_metric_data(
            Namespace='Security',
            MetricData=[
                {
                    'MetricName': 'SuspiciousS3Access',
                    'Dimensions': [
                        {'Name': 'IP', 'Value': ip_address},
                        {'Name': 'Bucket', 'Value': bucket_name},
                    ],
                    'Value': 1,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
            ]
        )
        print(f"Incident logged for IP {ip_address} accessing bucket {bucket_name}")

    except ClientError as e:
        print(f"Failed to log incident: {e}")

