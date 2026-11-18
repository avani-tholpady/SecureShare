import os
import boto3

REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "ShareLinks")

dynamo_kwargs = {"region_name": REGION}
endpoint = os.environ.get("DYNAMODB_ENDPOINT_URL")
if endpoint or (not os.environ.get("AWS_ACCESS_KEY_ID") and not os.environ.get("AWS_EXECUTION_ENV")):
    dynamo_kwargs["endpoint_url"] = endpoint or "http://localhost:8000"
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        dynamo_kwargs["aws_access_key_id"] = "testing"
        dynamo_kwargs["aws_secret_access_key"] = "testing"

dynamodb = boto3.resource("dynamodb", **dynamo_kwargs)
table = dynamodb.Table(TABLE_NAME)

print(f"Checking DynamoDB table '{TABLE_NAME}' ({dynamo_kwargs.get('endpoint_url', 'AWS Cloud')})...\n")

try:
    response = table.scan()
    items = response.get("Items", [])
    print(f"Total sharing links stored: {len(items)}\n")
    for item in items:
        print(item)
except Exception as e:
    print(f"Error checking DynamoDB: {e}")
