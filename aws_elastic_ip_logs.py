import json
import boto3
import time

cloudwatch_logs_client = boto3.client('logs')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    log_event(event, context)

    try:
        event_source = event['source']
        detail_type = event['detail-type']
        event_time = event['time']
        event_name = event['detail']['eventName']
        event_region = event['region']
        user_identity = event['detail']['userIdentity']['principalId'].split(':')[1]

        instance_id_or_public_ip_or_dns_name = ''

        if 'detail' in event and 'responseElements' in event['detail']:
            response_elements = event['detail']['responseElements']
            if 'instancesSet' in response_elements:
                instance_id = response_elements['instancesSet']['items'][0]['instanceId']
                message = f"Received EC2 instance creation event: {event_source} {detail_type}\n" \
                          f"Event_name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Instance ID: {instance_id}\n" \
                          f"Region: {event_region}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Instance ID: {instance_id}"
            elif 'publicIp' in response_elements:
                public_ip = response_elements['publicIp']
                message = f"Received Elastic IP allocation event: {event_source} {detail_type}\n" \
                          f"Event_name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Public IP: {public_ip}\n" \
                          f"Region: {event_region}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Elastic IP: {public_ip}"
            elif 'loadBalancers' in response_elements:
                load_balancers = response_elements['loadBalancers']
                if load_balancers:
                    dns_name = load_balancers[0]['dNSName']
                    message = f"Received ELB creation event creation event: {event_source} {detail_type}\n" \
                              f"Event_name: {event_name}\n" \
                              f"User: {user_identity}\n" \
                              f"Load Balancer DNS: {dns_name}\n" \
                              f"Region: {event_region}\n" \
                              f"Time: {event_time}"
                    instance_id_or_public_ip_or_dns_name = f"ELB Event: {event_name}"
                else:
                    print("No load balancers found in the event.")
                    return
            else:
                print("Unsupported event or no response elements found in the event.")
                return

            subject=f"AWS Notification: {instance_id_or_public_ip_or_dns_name} - User: {user_identity} - {event_region}" #The official AWS resources that confirm the 100-character limit for SNS subject lines

            print(message)
            sns_client.publish(
                TopicArn='arn:aws:sns:us-east-1:xxxxxxxxxx:PublicIPNotificationTopic',
                Message=message,
                Subject=subject
            )
        else:
            print("No 'detail' key or 'responseElements' key found in the event.")
            return
    except KeyError as e:
        print(f"Error: {e}")
        print(f"Event: {event}")

def log_event(event, context):
    log_group_name = '/aws/lambda/Aws_External_Ip_Notified'
    log_stream_name = context.log_stream_name

    log_events = [{'timestamp': int(round(time.time() * 1000)), 'message': json.dumps(event)}]
    response = cloudwatch_logs_client.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=log_events
    )
