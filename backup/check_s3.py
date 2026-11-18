
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:5001",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

response = s3.list_objects_v2(
    Bucket="secureshare-documents"
)

print("Files stored in S3:")

for obj in response.get("Contents", []):
    print(obj["Key"])
