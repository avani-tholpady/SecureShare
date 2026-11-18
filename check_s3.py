import os
import boto3

REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "secureshare-documents")

s3_kwargs = {"region_name": REGION}
endpoint = os.environ.get("S3_ENDPOINT_URL")
if endpoint or (not os.environ.get("AWS_ACCESS_KEY_ID") and not os.environ.get("AWS_EXECUTION_ENV")):
    s3_kwargs["endpoint_url"] = endpoint or "http://127.0.0.1:5001"
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        s3_kwargs["aws_access_key_id"] = "testing"
        s3_kwargs["aws_secret_access_key"] = "testing"

s3 = boto3.client("s3", **s3_kwargs)

print(f"Checking S3 bucket '{BUCKET_NAME}' ({s3_kwargs.get('endpoint_url', 'AWS Cloud')})...\n")

try:
    response = s3.list_objects_v2(Bucket=BUCKET_NAME)
    contents = response.get("Contents", [])
    print(f"Total files stored in S3: {len(contents)}")
    for obj in contents:
        print(f" - {obj['Key']} ({obj.get('Size', 0)} bytes)")
except Exception as e:
    print(f"Error checking S3: {e}")
