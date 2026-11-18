
import boto3

# Connect to local S3 simulator
s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:5001",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

BUCKET_NAME = "secureshare-documents"

# Create bucket
try:
    s3.create_bucket(Bucket=BUCKET_NAME)
    print("S3 bucket created successfully!")

except Exception as e:
    print("Bucket creation:", e)

# Display buckets
response = s3.list_buckets()

print("\nAvailable buckets:")

for bucket in response["Buckets"]:
    print(bucket["Name"])
