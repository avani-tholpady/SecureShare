import boto3

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8000",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

table = dynamodb.Table("ShareLinks")

response = table.scan()

print("Sharing links stored in DynamoDB:\n")

for item in response["Items"]:
    print(item)