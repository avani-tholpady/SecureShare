"""
SecureShare - Automated AWS Cloud Deployment Script
Deploys SecureShare serverless backend to AWS:
- S3 Private Document Storage Bucket (AES-256 encrypted, 100% public access blocked, CORS enabled)
- DynamoDB Table 'ShareLinks' (PROVISIONED: 5 RCU / 5 WCU - 100% within AWS Always Free Tier)
- Least-Privilege IAM Execution Role for Lambda
- AWS Lambda Function (Python 3.12, 256MB)
- Amazon API Gateway (HTTP API with CORS and binary support)

Free Tier Alignment:
- DynamoDB & Lambda: Covered by AWS Always Free Tier.
- S3 & API Gateway: Covered by AWS 12-Month Free Tier (standard rates apply thereafter).
"""

import os
import sys
import json
import time
import boto3
from botocore.exceptions import ClientError

def print_cost_breakdown():
    print("=" * 75)
    print("           SECURESHARE - AWS FREE TIER & COST TRANSPARENCY AUDIT")
    print("=" * 75)
    print("Service Breakdown & Free-Tier Eligibility:")
    print(" 1. Amazon DynamoDB Table ('ShareLinks')")
    print("    - Configuration: PROVISIONED (5 RCU, 5 WCU, TTL enabled)")
    print("    - Free Tier Status: ALWAYS FREE (Includes up to 25 RCU, 25 WCU, 25 GB storage).")
    print("    - Idle/Monthly Cost: $0.00 / month indefinitely.")
    print(" 2. AWS Lambda Function ('SecureShareBackend')")
    print("    - Configuration: 256 MB memory, Python 3.12")
    print("    - Free Tier Status: ALWAYS FREE (Includes 1,000,000 requests & 3.2M sec compute/mo).")
    print("    - Idle/Monthly Cost: $0.00 / month indefinitely.")
    print(" 3. Amazon S3 Private Bucket ('secureshare-documents-<account>-<region>')")
    print("    - Configuration: Private, AES-256, 30-day lifecycle auto-cleanup")
    print("    - Free Tier Status: 12-MONTH FREE TIER ONLY (5 GB storage, 20k GET, 2k PUT).")
    print("    - Post-Free-Tier Cost: ~$0.023/GB/month (fractions of a cent for moderate use).")
    print(" 4. Amazon API Gateway HTTP API ('SecureShare-API')")
    print("    - Configuration: HTTP API v2 with CORS")
    print("    - Free Tier Status: 12-MONTH FREE TIER ONLY (1,000,000 calls/month).")
    print("    - Post-Free-Tier Cost: $1.00 per 1,000,000 requests thereafter.")
    print(" 5. IAM & CloudWatch Logs")
    print("    - Configuration: 7-day log retention to prevent storage fee accumulation.")
    print("    - Cost: Free within basic allowances.")
    print("-" * 75)
    print("CRITICAL NOTICE:")
    print(" - This project is NOT permanently free across all components.")
    print(" - Lambda & DynamoDB (Provisioned) are Always Free.")
    print(" - S3 & API Gateway are free for your account's first 12 months.")
    print(" - Cost Control Recommendation: Set up an AWS Budget alert at $1.00/month.")
    print("=" * 75)

def deploy():
    print_cost_breakdown()

    # Step 1: Verify AWS Credentials
    print("\n[1/6] Verifying AWS Credentials...")
    try:
        sts = boto3.client("sts")
        caller = sts.get_caller_identity()
        account_id = caller["Account"]
        current_arn = caller["Arn"]
        region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        print(f" ✓ Authenticated as: {current_arn}")
        print(f" ✓ AWS Account ID: {account_id}")
        print(f" ✓ AWS Region: {region}")
    except Exception as e:
        print("\n❌ ERROR: AWS credentials not found or invalid.")
        print(f"   Details: {e}")
        print("\nTo configure AWS credentials, run:")
        print("   set AWS_ACCESS_KEY_ID=your_access_key")
        print("   set AWS_SECRET_ACCESS_KEY=your_secret_key")
        print("   set AWS_DEFAULT_REGION=us-east-1")
        sys.exit(1)

    s3_client = boto3.client("s3", region_name=region)
    dynamodb = boto3.resource("dynamodb", region_name=region)
    iam_client = boto3.client("iam", region_name=region)
    lambda_client = boto3.client("lambda", region_name=region)
    apigw_client = boto3.client("apigatewayv2", region_name=region)
    logs_client = boto3.client("logs", region_name=region)

    bucket_name = os.environ.get("S3_BUCKET_NAME", f"secureshare-documents-{account_id}-{region}")
    table_name = os.environ.get("DYNAMODB_TABLE_NAME", "ShareLinks")
    role_name = "SecureShareLambdaExecutionRole"
    function_name = "SecureShareBackend"

    # Step 2: Create S3 Private Bucket with CORS & Encryption
    print(f"\n[2/6] Ensuring S3 Bucket '{bucket_name}'...")
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        print(f" ✓ Bucket '{bucket_name}' already exists.")
    except ClientError:
        print(f" Creating private bucket '{bucket_name}'...")
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region}
            )

    # Server-Side Encryption (AES-256)
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )

    # Block 100% of public access
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    # Configure S3 CORS for direct browser-to-S3 Presigned PUT uploads
    s3_client.put_bucket_cors(
        Bucket=bucket_name,
        CORSConfiguration={
            "CORSRules": [
                {
                    "AllowedHeaders": ["*"],
                    "AllowedMethods": ["GET", "PUT", "HEAD"],
                    "AllowedOrigins": ["*"],
                    "MaxAgeSeconds": 300
                }
            ]
        }
    )

    # Configure 30-day lifecycle expiration to avoid storage accumulation
    s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "ExpireOldDocumentsAfter30Days",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Expiration": {"Days": 30}
                }
            ]
        }
    )
    print(" ✓ S3 private bucket configured (AES-256, CORS enabled, 30-day lifecycle).")

    # Step 3: Create DynamoDB Table in PROVISIONED mode (Always Free Tier)
    print(f"\n[3/6] Ensuring DynamoDB Table '{table_name}'...")
    try:
        table = dynamodb.Table(table_name)
        table.load()
        print(f" ✓ DynamoDB table '{table_name}' already exists.")
    except ClientError:
        print(f" Creating DynamoDB table '{table_name}' (PROVISIONED 5 RCU / 5 WCU - Always Free)...")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "token", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"}],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5
            }
        )
        table.wait_until_exists()
        # Enable TTL on expires_at for automatic zero-cost record pruning
        boto3.client("dynamodb", region_name=region).update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"}
        )
        print(" ✓ DynamoDB table created with Always-Free provisioned capacity & TTL.")

    # Step 4: Ensure CloudWatch Log Retention & IAM Execution Role
    print(f"\n[4/6] Ensuring CloudWatch Logs & IAM Execution Role '{role_name}'...")
    log_group_name = f"/aws/lambda/{function_name}"
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
    except ClientError:
        pass
    try:
        logs_client.put_retention_policy(logGroupName=log_group_name, retentionInDays=7)
    except Exception:
        pass

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role_arn = None
    try:
        role = iam_client.get_role(RoleName=role_name)
        role_arn = role["Role"]["Arn"]
        print(f" ✓ IAM role already exists: {role_arn}")
    except ClientError:
        print(f" Creating IAM role '{role_name}'...")
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Least privilege execution role for SecureShare Lambda"
        )
        role_arn = role["Role"]["Arn"]

    # Attach basic execution role policy
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

    # Least-privilege scoped permissions
    custom_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:HeadObject"
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:HeadBucket"],
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:DescribeTable"
                ],
                "Resource": f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
            }
        ]
    }
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="SecureShareLeastPrivilegePolicy",
        PolicyDocument=json.dumps(custom_policy)
    )
    print(" ✓ Attached least-privilege policy for S3 & DynamoDB.")

    # Step 5: Build & Deploy Lambda Function
    print(f"\n[5/6] Building & Deploying Lambda Function '{function_name}'...")
    import build_package
    build_package.build()

    zip_path = os.path.join(os.path.dirname(__file__), "dist", "secureshare-lambda.zip")
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    lambda_arn = None
    try:
        fn = lambda_client.get_function(FunctionName=function_name)
        print(f" Updating existing Lambda function '{function_name}'...")
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Environment={
                "Variables": {
                    "S3_BUCKET_NAME": bucket_name,
                    "DYNAMODB_TABLE_NAME": table_name,
                    "AWS_REGION": region
                }
            }
        )
        lambda_arn = fn["Configuration"]["FunctionArn"]
        print(" ✓ Lambda function updated.")
    except ClientError:
        print(f" Creating Lambda function '{function_name}'...")
        time.sleep(5)  # Wait for IAM role propagation
        fn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Description="SecureShare Expiring Link Backend Service",
            Timeout=30,
            MemorySize=256,
            Environment={
                "Variables": {
                    "S3_BUCKET_NAME": bucket_name,
                    "DYNAMODB_TABLE_NAME": table_name,
                    "AWS_REGION": region
                }
            }
        )
        lambda_arn = fn["FunctionArn"]
        print(" ✓ Lambda function created.")

    # Step 6: Create or Update API Gateway (HTTP API)
    print(f"\n[6/6] Configuring API Gateway...")
    apis = apigw_client.get_apis().get("Items", [])
    api_id = None
    for api in apis:
        if api["Name"] == "SecureShare-API":
            api_id = api["ApiId"]
            break

    if not api_id:
        print(" Creating HTTP API 'SecureShare-API'...")
        new_api = apigw_client.create_api(
            Name="SecureShare-API",
            ProtocolType="HTTP",
            CorsConfiguration={
                "AllowHeaders": ["Content-Type", "Authorization", "X-Requested-With", "Accept"],
                "AllowMethods": ["GET", "POST", "OPTIONS"],
                "AllowOrigins": ["*"],
                "MaxAge": 300
            }
        )
        api_id = new_api["ApiId"]

    # Lambda Integration
    integrations = apigw_client.get_integrations(ApiId=api_id).get("Items", [])
    integration_id = integrations[0]["IntegrationId"] if integrations else None

    if not integration_id:
        int_res = apigw_client.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=lambda_arn,
            PayloadFormatVersion="2.0"
        )
        integration_id = int_res["IntegrationId"]

    routes = apigw_client.get_routes(ApiId=api_id).get("Items", [])
    route_keys = [r["RouteKey"] for r in routes]
    target = f"integrations/{integration_id}"

    required_routes = [
        "GET /api/health",
        "POST /api/share",
        "POST /api/upload",
        "POST /api/revoke/{token}",
        "DELETE /api/share/{token}",
        "GET /api/download/{token}",
        "POST /api/download/{token}",
        "GET /download/{token}",
        "POST /download/{token}",
        "ANY /{proxy+}"
    ]

    for r_key in required_routes:
        if r_key not in route_keys:
            try:
                apigw_client.create_route(
                    ApiId=api_id,
                    RouteKey=r_key,
                    Target=target
                )
            except Exception:
                pass

    try:
        apigw_client.create_stage(
            ApiId=api_id,
            StageName="$default",
            AutoDeploy=True
        )
    except ClientError:
        pass

    try:
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=f"apigw-invoke-{api_id}",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*"
        )
    except ClientError:
        pass

    api_endpoint = f"https://{api_id}.execute-api.{region}.amazonaws.com"

    print("\n" + "=" * 75)
    print(" 🎉 SECURESHARE DEPLOYMENT COMPLETED SUCCESSFULLY!")
    print("=" * 75)
    print(f" API Gateway Base URL: {api_endpoint}")
    print(f" Health Check URL:    {api_endpoint}/api/health")
    print(f" S3 Private Bucket:   {bucket_name}")
    print(f" DynamoDB Table:      {table_name}")
    print("\nNext step: Connect frontend by setting window.API_BASE_URL in config.js:")
    print(f'   window.API_BASE_URL = "{api_endpoint}";')
    print("=" * 75)

if __name__ == "__main__":
    deploy()
