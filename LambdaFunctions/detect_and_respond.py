import json
import boto3
import os
import requests
from botocore.exceptions import ClientError

# Initialize the boto3 clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')
geo_location_api = "https://freegeoip.app/json/"  #API for geo-location

# Constants
THRESHOLD_REQUESTS = 100  # Threshold for suspicious number of requests
ALERT_SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:SecurityAlerts'
VPC_ID = os.getenv('VPCID')

def lambda_handler(event, context):
    # Extract the log data (assuming the log event is passed in event parameter)
    log_data = event['log_data']  
    ip_address = log_data['ip_address']
    request_count = log_data['request_count']
    user_agent = log_data['user_agent']
    timestamp = log_data['timestamp']

    # Step 1: Geo-location Check
    if not is_known_ip(ip_address):
        if is_ip_suspicious(ip_address):
            take_vpc_action(ip_address,  user_agent, timestamp)

    # Step 2: Check if the number of requests is suspicious
    if request_count > THRESHOLD_REQUESTS:
        take_vpc_action(ip_address, user_agent, timestamp)

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

def take_vpc_action(ip_address, user_agent, timestamp):
    # Step 1: Block IP in the VPC by updating Network ACLs
    block_ip_in_vpc(ip_address)

    # Step 2: Send an alert to the security team
    alert_security_team(ip_address, user_agent, timestamp)

    # Step 3: Log the incident
    log_incident(ip_address, user_agent, timestamp)

def block_ip_in_vpc(ip_address):
    try:
        # Describe Network ACLs in the VPC
        response = ec2_client.describe_network_acls(
            Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]
        )

        for acl in response['NetworkAcls']:
            acl_id = acl['NetworkAclId']
            # Create a new deny rule for the suspicious IP
            response = ec2_client.create_network_acl_entry(
                NetworkAclId=acl_id,
                RuleNumber=100,  # Choose an appropriate rule number that doesn't conflict
                Protocol='-1',  # '-1' means all protocols
                RuleAction='deny',
                Egress=False,  # Ingress rule
                CidrBlock=f'{ip_address}/32',  # Block only this specific IP
                PortRange={'From': 0, 'To': 65535}  # Block all ports
            )
            print(f"Blocked IP {ip_address} in Network ACL {acl_id}")

    except ClientError as e:
        print(f"Error blocking IP {ip_address} in VPC {VPC_ID}: {e}")

def alert_security_team(ip_address, user_agent, timestamp):
    message = f"Suspicious activity detected:\n" \
              f"IP Address: {ip_address}\nUser-Agent: {user_agent}\nTime: {timestamp}\n" \
              f"Action: IP blocked across VPC {VPC_ID}"
    
    try:
        response = sns_client.publish(
            TopicArn=ALERT_SNS_TOPIC_ARN,
            Message=message,
            Subject="Security Alert: VPC-Wide Block Applied"
        )
        print(f"Security alert sent: {response['MessageId']}")

    except ClientError as e:
        print(f"Failed to send security alert: {e}")

def log_incident(ip_address, user_agent, timestamp):
    try:
        cloudwatch_client.put_metric_data(
            Namespace='Security',
            MetricData=[
                {
                    'MetricName': 'SuspiciousVPCActivity',
                    'Dimensions': [
                        {'Name': 'IP', 'Value': ip_address},
                        {'Name': 'VPC', 'Value': VPC_ID},
                    ],
                    'Value': 1,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
            ]
        )
        print(f"Incident logged for IP {ip_address} within VPC {VPC_ID}")

    except ClientError as e:
        print(f"Failed to log incident: {e}")
