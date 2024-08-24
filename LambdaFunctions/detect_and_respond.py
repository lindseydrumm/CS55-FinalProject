import json
import boto3
import os
from botocore.exceptions import ClientError
from urllib import request, error

# Initialize the boto3 clients
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')
geo_location_api = "https://api.ipbase.com/v2/info?apikey=ipb_live_PXfrD4SmDAPfliJp8JfccDgBysKqySP16Fjz0XbV&ip="  #API for geo-location

# Constants
THRESHOLD_REQUESTS = 100  # Threshold for suspicious number of requests
ALERT_SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:727979661750:Security-Alerts.fifo'
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
        print('Number of Requests is suspicious')
        take_vpc_action(ip_address, user_agent, timestamp)

    return {"status": "Log checked successfully"}

def is_known_ip(ip_address):
    known_ips = os.getenv('KNOWN_IPS') # Ideally this would get known ips from a databse somewhere
    if ip_address in known_ips:
        return True
    else:
        return False

def is_ip_suspicious(ip_address):
    try:
        # Call geo-location API to check the location of the IP
        url = geo_location_api + ip_address
        with request.urlopen(url) as response:
            location_data = json.loads(response.read().decode())

        # Example check: If the IP is from a high-risk country
        print(f"location of request:{location_data['data']['location']['country']['alpha2']}")
        if location_data['data']['location']['country']['alpha2'] in ['IR', 'KP', 'RU']:
            return True

    except error.URLError as e:
        print(f"Failed to determine location for IP {ip_address}: {e}")
    
    return False

def take_vpc_action(ip_address, user_agent, timestamp):
    print(f"Taking action against: {ip_address}")
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
            
            # Gather existing rule numbers
            existing_rule_numbers = set(entry['RuleNumber'] for entry in acl['Entries'])

            # Find an available rule number (e.g., start from 1 and go up)
            new_rule_number = next(iter(existing_rule_numbers))
            while new_rule_number in existing_rule_numbers:
                new_rule_number += 1
                
            # Create a new deny rule for the suspicious IP
            response = ec2_client.create_network_acl_entry(
                NetworkAclId=acl_id,
                RuleNumber=new_rule_number,  # Choose an appropriate rule number that doesn't conflict
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
            Subject="Security Alert: VPC-Wide Block Applied",
            MessageGroupId="security-alerts",  # Add a MessageGroupId
            MessageDeduplicationId=f"{ip_address}-{timestamp}"
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
