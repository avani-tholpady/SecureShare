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

print(f"Connecting to S3 at {s3_kwargs.get('endpoint_url', 'AWS Cloud')} (Region: {REGION})...")

try:
    if REGION == "us-east-1":
        s3.create_bucket(Bucket=BUCKET_NAME)
    else:
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            CreateBucketConfiguration={"LocationConstraint": REGION}
        )
    print(f"S3 bucket '{BUCKET_NAME}' created successfully!")
except Exception as e:
    print(f"Bucket creation note: {e}")

try:
    response = s3.list_buckets()
    print("\nAvailable buckets:")
    for bucket in response.get("Buckets", []):
        print(f" - {bucket['Name']}")
except Exception as e:
    print(f"Error listing buckets: {e}")
