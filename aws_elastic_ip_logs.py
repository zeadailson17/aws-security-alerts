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
        event_name = detail.get('eventName')
        user_identity = detail.get('userIdentity', {}).get('principalId', '').split(':')[1]

        instance_id_or_public_ip_or_dns_name = ''
        message = ''

        if 'responseElements' in detail or 'requestParameters' in detail:
            response_elements = detail.get('responseElements')
            request_parameters = detail.get('requestParameters')

            if event_name == 'CreateSecurityGroup':
                security_group_id = response_elements.get('groupId')
                security_group_name = request_parameters.get('groupName')
                security_group_description = request_parameters.get('groupDescription')
                security_group_vpc_id = request_parameters.get('vpcId')
                message = f"Create Security Group event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Security Group ID: {security_group_id}\n" \
                          f"Security Group Name: {security_group_name}\n" \
                          f"Security Group Description: {security_group_description}\n" \
                          f"Security Group VPC ID: {security_group_vpc_id}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Security Group Event: {event_name}"
            elif event_name == 'DeleteSecurityGroup':
                security_group_id = response_elements.get('groupId')
                message = f"Delete Security Group event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Security Group ID: {security_group_id}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Security Group Event: {event_name}"
            elif event_name == 'ModifySecurityGroupRules':
                modify_request = request_parameters.get('ModifySecurityGroupRulesRequest', {})
                security_group_id = request_parameters.get('ModifySecurityGroupRulesRequest', {}).get('GroupId')
                security_group_rule = modify_request.get('SecurityGroupRule', {}).get('SecurityGroupRule', {})
                security_group_rule_cidrIpv4 = security_group_rule.get('CidrIpv4')
                security_group_rule_description = security_group_rule.get('Description')
                security_group_rule_from_port = security_group_rule.get('FromPort')
                security_group_rule_to_port = security_group_rule.get('ToPort')
                security_group_rule_protocol = security_group_rule.get('IpProtocol')
                message = f"Modify Security Group Rules event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Security Group ID: {security_group_id}\n" \
                          f"Security Group Rule CIDR IPv4: {security_group_rule_cidrIpv4}\n" \
                          f"Security Group Rule Description: {security_group_rule_description}\n" \
                          f"Security Group Rule From Port: {security_group_rule_from_port}\n" \
                          f"Security Group Rule To Port: {security_group_rule_to_port}\n" \
                          f"Security Group Rule Protocol: {security_group_rule_protocol}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Security Group Rule Event: {event_name}"
            elif event_name == 'AuthorizeSecurityGroupIngress':
                security_group_rule_set = response_elements.get('securityGroupRuleSet', {})
                items = security_group_rule_set.get('items', [])
                for item in items:
                    group_id = item.get('groupId')
                    ip_protocol = item.get('ipProtocol')
                    from_port = item.get('fromPort')
                    to_port = item.get('toPort')
                    cidr_ipv4 = item.get('cidrIpv4')
                    description = item.get('description')
                message = f"Authorize Security Group Ingress Event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Security Group ID: {group_id}\n" \
                          f"Description: {description}\n" \
                          f"Protocol: {ip_protocol}\n" \
                          f"From Port: {from_port}\n" \
                          f"To Port: {to_port}\n" \
                          f"CIDR IPv4: {cidr_ipv4}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = "Authorize Security Group Ingress"
            elif event_name == 'RevokeSecurityGroupIngress':
                revoked_group_rule_set = response_elements.get('revokedSecurityGroupRuleSet', {})
                items_revoked = revoked_group_rule_set.get('items', [])
                for item in items_revoked:
                    group_id_revoked = item.get('groupId')
                    ip_protocol_revoked = item.get('ipProtocol')
                    from_port_revoked = item.get('fromPort')
                    to_port_revoked = item.get('toPort')
                    cidr_ipv4_revoked = item.get('cidrIpv4')
                message = f"Revoke Security Group Ingress Event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Security Group ID: {group_id_revoked}\n" \
                          f"Protocol: {ip_protocol_revoked}\n" \
                          f"From Port: {from_port_revoked}\n" \
                          f"To Port: {to_port_revoked}\n" \
                          f"CIDR IPv4: {cidr_ipv4_revoked}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = "Revoke Security Group Ingress"
            elif 'changeBatch' in request_parameters:
                route53_action = request_parameters['changeBatch']['changes'][0]['action']
                resource_record_set = request_parameters['changeBatch']['changes'][0]['resourceRecordSet']['name']
                message = f"Change DNS Registry Route53: {source} {detail_type}\n" \
                          f"Event_name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Route53 Event: {route53_action}\n" \
                          f"Name: {resource_record_set}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Route53 Record Name: {resource_record_set}"               
            elif response_elements and 'instancesSet' in response_elements:
                instance_id = response_elements['instancesSet']['items'][0]['instanceId']
                message = f"Received EC2 instance creation event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Instance ID: {instance_id}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Instance ID: {instance_id}"
            elif response_elements and 'publicIp' in response_elements:
                public_ip = response_elements['publicIp']
                message = f"Received Elastic IP allocation event: {source} {detail_type}\n" \
                          f"Event Name: {event_name}\n" \
                          f"User: {user_identity}\n" \
                          f"Public IP: {public_ip}\n" \
                          f"Region: {event.get('region')}\n" \
                          f"Time: {event_time}"
                instance_id_or_public_ip_or_dns_name = f"Elastic IP: {public_ip}"
            elif response_elements and 'loadBalancers' in response_elements:
                load_balancers = response_elements['loadBalancers']
                if load_balancers:
                    dns_name = load_balancers[0]['dNSName']
                    message = f"Received ELB creation event: {source} {detail_type}\n" \
                              f"Event Name: {event_name}\n" \
                              f"User: {user_identity}\n" \
                              f"Load Balancer DNS: {dns_name}\n" \
                              f"Region: {event.get('region')}\n" \
                              f"Time: {event_time}"
                    instance_id_or_public_ip_or_dns_name = f"ELB Event: {event_name}"
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
