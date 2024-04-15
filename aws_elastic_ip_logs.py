import json
import boto3
import time

cloudwatch_logs_client = boto3.client('logs')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    log_event(event, context)

    try:
        source = event.get('source')
        detail_type = event.get('detail-type')
        event_time = event.get('time')
        detail = event.get('detail', {})
        user_identity = detail.get('userIdentity', {}).get('principalId', '').split(':')[1]

        instance_id_or_public_ip_or_dns_name = ''

        if 'responseElements' in detail or 'requestParameters' in detail:
            response_elements = detail.get('responseElements', {})
            request_parameters = detail.get('requestParameters', {})
            
            if 'changeBatch' in request_parameters:
                route53_action = request_parameters['changeBatch']['changes'][0]['action']
                resource_record_set = request_parameters['changeBatch']['changes'][0]['resourceRecordSet']['name']
                message = f"Cria registro de DNS no Route53: {source} {detail_type}\n" \
                          f"Event_name: {detail.get('eventName')}\n" \
                          f"User: {user_identity}\n" \
                          f"Route53 Event: {route53_action}\n" \
                          f"Name: {resource_record_set}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Route53 Record Name: {resource_record_set}"
            elif 'instancesSet' in response_elements:
                instance_id = response_elements['instancesSet']['items'][0]['instanceId']
                message = f"Received EC2 instance creation event: {source} {detail_type}\n" \
                          f"Event_name: {detail.get('eventName')}\n" \
                          f"User: {user_identity}\n" \
                          f"Instance ID: {instance_id}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Instance ID: {instance_id}"
            elif 'publicIp' in response_elements:
                public_ip = response_elements['publicIp']
                message = f"Received Elastic IP allocation event: {source} {detail_type}\n" \
                          f"Event_name: {detail.get('eventName')}\n" \
                          f"User: {user_identity}\n" \
                          f"Public IP: {public_ip}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Elastic IP: {public_ip}"
            elif 'loadBalancers' in response_elements:
                load_balancers = response_elements['loadBalancers']
                if load_balancers:
                    dns_name = load_balancers[0]['dNSName']
                    message = f"Received ELB creation event: {source} {detail_type}\n" \
                              f"Event_name: {detail.get('eventName')}\n" \
                              f"User: {user_identity}\n" \
                              f"Load Balancer DNS: {dns_name}\n" \
                              f"Region: {event.get('region')}\n" \
                              f"Time: {event_time}"
                    instance_id_or_public_ip_or_dns_name = f"ELB Event: {detail.get('eventName')}"
                else:
                    print("No load balancers found in the event.")
                    return
            else:
                print("Unsupported event or no response elements found in the event.")
                return

            subject = f"AWS Notification: {instance_id_or_public_ip_or_dns_name} - User: {user_identity} - {event.get('region')}"

            print(message)
            sns_client.publish(
                TopicArn='arn:aws:sns:sa-east-1:123456789012:PublicIPNotificationTopic',
                Message=message,
                Subject=subject[:100]  # Ensure subject is within 100 characters
            )
        else:
            print("No 'responseElements' or 'requestParameters' key found in the event.")
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
