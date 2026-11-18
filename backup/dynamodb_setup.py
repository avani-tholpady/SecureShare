
import boto3

# Connect to local DynamoDB
dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8000",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

# Create ShareLinks table
try:
    table = dynamodb.create_table(
        TableName="ShareLinks",

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

        ProvisionedThroughput={
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5
        }
    )

    table.wait_until_exists()

    print("ShareLinks table created successfully!")

except dynamodb.meta.client.exceptions.ResourceInUseException:
    print("ShareLinks table already exists!")

# Display tables
print("\nAvailable tables:")

for name in dynamodb.meta.client.list_tables()["TableNames"]:
    print(name)
