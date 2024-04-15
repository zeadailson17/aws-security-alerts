provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudwatch_event_rule" "cloudtrail_events" {
  name        = "CloudTrailEventsRule"
  description = "Rule to capture CloudTrail events for EC2 instance creation, Elastic IP allocation, and ELB creation"
  event_pattern = jsonencode({
    "source" : ["aws.ec2", "aws.elasticloadbalancing"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["ec2.amazonaws.com", "elasticloadbalancing.amazonaws.com"],
      "eventName" : ["RunInstances", "AllocateAddress", "CreateLoadBalancer"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_events.name
  target_id = "LambdaTarget"
  arn       = aws_lambda_function.lambda_function.arn
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "aws_elastic_ip_logs.py"
  output_path = "aws_elastic_ip_logs.zip"
}

resource "aws_lambda_function" "lambda_function" {
  filename      = "aws_elastic_ip_logs.zip"
  function_name = "Aws_External_Ip_Notified"
  role          = aws_iam_role.lambda_role.arn
  handler       = "aws_elastic_ip_logs.lambda_handler"
  runtime       = "python3.11"
}

resource "aws_lambda_permission" "eventbridge_permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.arn
  principal     = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.cloudtrail_events.arn
}

resource "aws_sns_topic" "sns_topic" {
  name = "PublicIPNotificationTopic"
}

resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.sns_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lambda_function.arn
}

resource "aws_sns_topic_subscription" "email_subscription" {
  for_each  = toset(["aaaaa@email.com", "bbbbb@email.com"])
  topic_arn = aws_sns_topic.sns_topic.arn
  protocol  = "email"
  endpoint  = each.value
}


resource "aws_iam_role" "lambda_role" {
  name = "LambdaExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name = "LambdaCloudWatchLogsPolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams"
          ]
          Resource = "arn:aws:logs:*:*:*"
        }
      ]
    })
  }
}

resource "aws_iam_policy" "sns_publish_policy" {
  name        = "SNSPublishPolicy"
  description = "Allows publishing messages to the SNS topic"

  policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sns:Publish",
        "Resource": "${aws_sns_topic.sns_topic.arn}"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy_attachment" "sns_publish_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.sns_publish_policy.arn
}

resource "aws_iam_policy_attachment" "lambda_role_attachment" {
  name       = "LambdaCloudWatchLogsPolicyAttachment"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/Aws_External_Ip_Notified"
  retention_in_days = 30
}

output "sns_topic_arn" {
  value = aws_sns_topic.sns_topic.arn
}
