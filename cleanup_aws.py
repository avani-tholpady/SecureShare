"""
SecureShare - AWS Resource Cleanup Script
Safely and completely tears down all AWS resources created for SecureShare:
- Empties and deletes the S3 Document Bucket
- Deletes the DynamoDB ShareLinks Table
- Deletes the Lambda Function
- Deletes the API Gateway
- Deletes the IAM Role and Policies
- Deletes the CloudWatch Log Group
"""

import os
import sys
import boto3
from botocore.exceptions import ClientError

def cleanup():
    print("=" * 70)
    print("         SECURESHARE - COMPLETE AWS RESOURCE CLEANUP")
    print("=" * 70)

    try:
        sts = boto3.client("sts")
        caller = sts.get_caller_identity()
        account_id = caller["Account"]
        region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        print(f"Authenticated as: {caller['Arn']}")
        print(f"Region: {region}")
    except Exception as e:
        print(f"Error: Unable to authenticate with AWS credentials: {e}")
        sys.exit(1)

    s3 = boto3.client("s3", region_name=region)
    s3_resource = boto3.resource("s3", region_name=region)
    dynamodb = boto3.client("dynamodb", region_name=region)
    lambda_client = boto3.client("lambda", region_name=region)
    apigw = boto3.client("apigatewayv2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    logs = boto3.client("logs", region_name=region)

    bucket_name = os.environ.get("S3_BUCKET_NAME", f"secureshare-documents-{account_id}-{region}")
    table_name = os.environ.get("DYNAMODB_TABLE_NAME", "ShareLinks")
    function_name = "SecureShareBackend"
    role_name = "SecureShareLambdaExecutionRole"
    log_group_name = f"/aws/lambda/{function_name}"

    # 1. Delete API Gateway
    print("\n[1/6] Cleaning up API Gateway...")
    try:
        apis = apigw.get_apis().get("Items", [])
        for api in apis:
            if api.get("Name") == "SecureShare-API":
                apigw.delete_api(ApiId=api["ApiId"])
                print(f" ✓ Deleted API Gateway: {api['ApiId']}")
    except Exception as e:
        print(f" Note: API Gateway cleanup: {e}")

    # 2. Delete Lambda Function
    print("\n[2/6] Cleaning up Lambda Function...")
    try:
        lambda_client.delete_function(FunctionName=function_name)
        print(f" ✓ Deleted Lambda function '{function_name}'.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f" - Lambda function '{function_name}' does not exist.")
        else:
            print(f" Note: Lambda cleanup: {e}")

    # 3. Delete CloudWatch Logs
    print("\n[3/6] Cleaning up CloudWatch Logs...")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
        print(f" ✓ Deleted CloudWatch log group '{log_group_name}'.")
    except ClientError:
        print(f" - Log group '{log_group_name}' not found.")

    # 4. Delete IAM Role & Policies
    print("\n[4/6] Cleaning up IAM Role & Policies...")
    try:
        # Delete inline policy
        try:
            iam.delete_role_policy(
                RoleName=role_name,
                PolicyName="SecureShareLeastPrivilegePolicy"
            )
        except ClientError:
            pass
        # Detach managed policy
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        except ClientError:
            pass
        iam.delete_role(RoleName=role_name)
        print(f" ✓ Deleted IAM role '{role_name}'.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(f" - IAM role '{role_name}' does not exist.")
        else:
            print(f" Note: IAM cleanup: {e}")

    # 5. Delete DynamoDB Table
    print("\n[5/6] Cleaning up DynamoDB Table...")
    try:
        dynamodb.delete_table(TableName=table_name)
        print(f" ✓ Deleted DynamoDB table '{table_name}'.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f" - DynamoDB table '{table_name}' does not exist.")
        else:
            print(f" Note: DynamoDB cleanup: {e}")

    # 6. Empty and Delete S3 Bucket
    print(f"\n[6/6] Emptying and deleting S3 Bucket '{bucket_name}'...")
    try:
        s3.head_bucket(Bucket=bucket_name)
        bkt = s3_resource.Bucket(bucket_name)
        # Delete all object versions and objects
        bkt.object_versions.delete()
        bkt.objects.delete()
        bkt.delete()
        print(f" ✓ Emptied and deleted S3 bucket '{bucket_name}'.")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchBucket"):
            print(f" - S3 bucket '{bucket_name}' does not exist.")
        else:
            print(f" Note: S3 cleanup: {e}")

    print("\n" + "=" * 70)
    print(" ✅ ALL SECURESHARE AWS RESOURCES HAVE BEEN REMOVED.")
    print("=" * 70)

if __name__ == "__main__":
    cleanup()

