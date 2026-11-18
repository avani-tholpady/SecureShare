"""
Flask Application End-to-End Tests
Verifies app.py works locally with Moto S3 and DynamoDB under test environment.
Tests both Presigned S3 upload initiation and direct multipart upload.
"""

import unittest
import json
import time
import io
import boto3
from moto import mock_aws

import app

class TestFlaskApp(unittest.TestCase):

    def setUp(self):
        self.mock_aws = mock_aws()
        self.mock_aws.start()

        self.region = "us-east-1"
        self.bucket_name = "secureshare-documents"
        self.table_name = "ShareLinks"

        app.REGION_NAME = self.region
        app.BUCKET_NAME = self.bucket_name
        app.TABLE_NAME = self.table_name

        self.s3 = boto3.client("s3", region_name=self.region)
        self.s3.create_bucket(Bucket=self.bucket_name)

        self.dynamodb = boto3.resource("dynamodb", region_name=self.region)
        self.table = self.dynamodb.create_table(
            TableName=self.table_name,
            KeySchema=[{"AttributeName": "token", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"}],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        )
        self.table.wait_until_exists()

        app.s3 = self.s3
        app.dynamodb = self.dynamodb
        app.table = self.table

        app.app.config["TESTING"] = True
        self.client = app.app.test_client()

    def tearDown(self):
        self.mock_aws.stop()

    def test_health_check(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])

    def test_static_routes(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"SecureShare", res.data)

        res_css = self.client.get("/style.css")
        self.assertEqual(res_css.status_code, 200)

        res_js = self.client.get("/script.js")
        self.assertEqual(res_js.status_code, 200)

    def test_presigned_s3_upload_initiation_and_download(self):
        # 1. Initiate upload
        res = self.client.post(
            "/api/share",
            json={
                "filename": "presigned_test.pdf",
                "file_size": 1024,
                "content_type": "application/pdf",
                "expiry": "24 hours",
                "max_downloads": "2"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("upload_url", data)
        token = data["token"]

        # Put file into S3 to simulate client direct upload
        item = self.table.get_item(Key={"token": token})["Item"]
        self.s3.put_object(Bucket=self.bucket_name, Key=item["object_key"], Body=b"Fake PDF Content")

        # 2. Download file via token
        dl_res = self.client.get(f"/download/{token}")
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, b"Fake PDF Content")

    def test_direct_multipart_upload_fallback(self):
        file_data = (io.BytesIO(b"Hello Direct Multipart"), "direct.txt")
        res = self.client.post(
            "/api/share",
            data={
                "file": file_data,
                "expiry": "24 hours",
                "max_downloads": "2"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 200)
        token = res.get_json()["token"]

        dl_res = self.client.get(f"/download/{token}")
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, b"Hello Direct Multipart")

    def test_password_protected_flow(self):
        res = self.client.post(
            "/api/share",
            json={
                "filename": "secret.txt",
                "content_type": "text/plain",
                "expiry": "1 hour",
                "max_downloads": "3",
                "password": "Password123"
            }
        )
        token = res.get_json()["token"]
        item = self.table.get_item(Key={"token": token})["Item"]
        self.s3.put_object(Bucket=self.bucket_name, Key=item["object_key"], Body=b"Secret Content")

        # GET API without password -> 401
        res401 = self.client.get(f"/api/download/{token}", headers={"Accept": "application/json"})
        self.assertEqual(res401.status_code, 401)

        # POST with wrong password -> 403
        res403 = self.client.post(
            f"/api/download/{token}",
            json={"password": "WrongPassword"},
            headers={"Accept": "application/json"}
        )
        self.assertEqual(res403.status_code, 403)

        # POST with correct password -> 200 file
        res200 = self.client.post(
            f"/api/download/{token}",
            data={"password": "Password123"}
        )
        self.assertEqual(res200.status_code, 200)
        self.assertEqual(res200.data, b"Secret Content")

    def test_download_limit(self):
        res = self.client.post(
            "/api/share",
            json={
                "filename": "single.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "1"
            }
        )
        token = res.get_json()["token"]
        item = self.table.get_item(Key={"token": token})["Item"]
        self.s3.put_object(Bucket=self.bucket_name, Key=item["object_key"], Body=b"Once only")

        # 1st download succeeds
        dl1 = self.client.get(f"/download/{token}")
        self.assertEqual(dl1.status_code, 200)

        # 2nd download rejected with 429
        dl2 = self.client.get(f"/download/{token}")
        self.assertEqual(dl2.status_code, 429)

    def test_revoke_link(self):
        res = self.client.post(
            "/api/share",
            json={
                "filename": "cancel.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "5"
            }
        )
        token = res.get_json()["token"]
        item = self.table.get_item(Key={"token": token})["Item"]
        self.s3.put_object(Bucket=self.bucket_name, Key=item["object_key"], Body=b"Cancel Content")

        # Revoke link
        rev_res = self.client.post(f"/api/revoke/{token}")
        self.assertEqual(rev_res.status_code, 200)

        # Download attempt -> 404
        dl_res = self.client.get(f"/download/{token}")
        self.assertEqual(dl_res.status_code, 404)

if __name__ == "__main__":
    unittest.main()
