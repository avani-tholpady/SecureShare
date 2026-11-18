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

print(f"Connecting to DynamoDB at {dynamo_kwargs.get('endpoint_url', 'AWS Cloud')} (Region: {REGION})...")

try:
    table = dynamodb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {
                "AttributeName": "token",
                "KeyType": "HASH"
            }
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "token",
                "AttributeType": "S"
            }
        ],
        BillingMode="PAY_PER_REQUEST"
    )
    table.wait_until_exists()
    print(f"Table '{TABLE_NAME}' created successfully!")

except dynamodb.meta.client.exceptions.ResourceInUseException:
    print(f"Table '{TABLE_NAME}' already exists!")
except Exception as e:
    print("DynamoDB Setup Error:", e)

# Display tables
print("\nAvailable tables:")
for name in dynamodb.meta.client.list_tables().get("TableNames", []):
    print(f" - {name}")
