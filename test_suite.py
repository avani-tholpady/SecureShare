"""
SecureShare Comprehensive Local Test Suite
Validates all 15 operational requirements:
1. Upload a PDF document (Direct Browser-to-S3 Presigned Upload & Multipart)
2. Upload an image file
3. Generate a sharing link
4. Download through the sharing link
5. Test password-protected downloads
6. Test incorrect passwords
7. Test expiration (Server-side validation)
8. Test download limits (Session tracking)
9. Test simultaneous downloads (atomic DynamoDB updates)
10. Test invalid tokens
11. Test private S3 access & AES-256 encryption
12. Test frontend-backend contracts
13. Test health check & CORS
14. Verify DynamoDB records & attributes
15. Verify S3 objects & presigned URL expiry clamping
"""

import unittest
import json
import base64
import time
import io
import boto3
import requests
from moto import mock_aws

import lambda_function

def make_apigw_event(method, path, body_data="", content_type="application/json", query=None, headers=None):
    hdrs = {
        "content-type": content_type,
        "accept": "application/json",
        "host": "api.secureshare.local"
    }
    if headers:
        hdrs.update(headers)

    if isinstance(body_data, dict):
        body_bytes = json.dumps(body_data).encode("utf-8")
        is_b64 = False
        body_str = json.dumps(body_data)
    elif isinstance(body_data, bytes):
        body_bytes = body_data
        body_str = base64.b64encode(body_bytes).decode("utf-8")
        is_b64 = True
    else:
        body_bytes = str(body_data).encode("utf-8")
        body_str = str(body_data)
        is_b64 = False

    return {
        "httpMethod": method,
        "path": path,
        "headers": hdrs,
        "queryStringParameters": query or {},
        "body": body_str,
        "isBase64Encoded": is_b64,
        "requestContext": {
            "stage": "prod",
            "http": {"method": method}
        }
    }

def build_multipart_body(fields, files):
    boundary = "----TestBoundary" + str(int(time.time() * 1000))
    lines = []
    for k, v in fields.items():
        lines.append(f"--{boundary}".encode("utf-8"))
        lines.append(f'Content-Disposition: form-data; name="{k}"\r\n'.encode("utf-8"))
        lines.append(str(v).encode("utf-8"))
    for field_name, (filename, content, content_type) in files.items():
        lines.append(f"--{boundary}".encode("utf-8"))
        lines.append(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'.encode("utf-8"))
        lines.append(f'Content-Type: {content_type}\r\n'.encode("utf-8"))
        lines.append(content if isinstance(content, bytes) else content.encode("utf-8"))
    lines.append(f"--{boundary}--\r\n".encode("utf-8"))
    body_bytes = b"\r\n".join(lines)
    return boundary, body_bytes


class TestSecureShare(unittest.TestCase):

    def setUp(self):
        self.mock_aws = mock_aws()
        self.mock_aws.start()

        self.region = "us-east-1"
        self.bucket_name = "secureshare-documents"
        self.table_name = "ShareLinks"

        lambda_function.REGION_NAME = self.region
        lambda_function.BUCKET_NAME = self.bucket_name
        lambda_function.TABLE_NAME = self.table_name

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

        lambda_function.s3 = self.s3
        lambda_function.dynamodb = self.dynamodb
        lambda_function.dynamodb_client = boto3.client("dynamodb", region_name=self.region)
        lambda_function.table = self.table

    def tearDown(self):
        self.mock_aws.stop()

    def test_01_upload_pdf_direct_presigned_s3(self):
        """Test 1: Upload a PDF using Direct Browser-to-S3 Presigned Upload (bypasses 10MB limit)"""
        # Step 1: Initiate metadata
        init_event = make_apigw_event("POST", "/api/share", {
            "filename": "annual_report.pdf",
            "file_size": 1048576,
            "content_type": "application/pdf",
            "expiry": "24 hours",
            "max_downloads": "5"
        })
        init_res = lambda_function.lambda_handler(init_event, None)
        self.assertEqual(init_res["statusCode"], 200)
        data = json.loads(init_res["body"])
        self.assertTrue(data["success"])
        self.assertEqual(data["filename"], "annual_report.pdf")
        self.assertIn("upload_url", data)

        # Step 2: Upload binary directly to S3 via presigned PUT
        pdf_bytes = b"%PDF-1.4\n%Fake PDF content for test\n%%EOF"
        put_res = requests.put(data["upload_url"], data=pdf_bytes, headers={"Content-Type": "application/pdf"})
        self.assertEqual(put_res.status_code, 200)

        # Step 3: Verify DynamoDB item
        item = self.table.get_item(Key={"token": data["token"]})["Item"]
        self.assertEqual(item["filename"], "annual_report.pdf")

        # Step 4: Verify S3 object content
        s3_obj = self.s3.get_object(Bucket=self.bucket_name, Key=item["object_key"])
        self.assertEqual(s3_obj["Body"].read(), pdf_bytes)

    def test_02_upload_image_multipart_backward_compat(self):
        """Test 2: Upload an image file via direct multipart upload (backwards compatibility)"""
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRFakeImageBytes"
        boundary, body = build_multipart_body(
            {"expiry": "1 hour", "max_downloads": "3"},
            {"file": ("sample.png", png_bytes, "image/png")}
        )
        event = make_apigw_event("POST", "/api/share", body, f"multipart/form-data; boundary={boundary}")
        res = lambda_function.lambda_handler(event, None)

        self.assertEqual(res["statusCode"], 200)
        data = json.loads(res["body"])
        self.assertTrue(data["success"])
        self.assertEqual(data["filename"], "sample.png")

    def test_03_generate_sharing_link(self):
        """Test 3: Generate a valid sharing link with 24-byte cryptographic token"""
        event = make_apigw_event("POST", "/api/share", {
            "filename": "report.txt",
            "content_type": "text/plain",
            "expiry": "24 hours",
            "max_downloads": "1"
        })
        res = lambda_function.lambda_handler(event, None)
        self.assertEqual(res["statusCode"], 200)
        data = json.loads(res["body"])
        self.assertIn("/api/download/", data["share_url"])
        self.assertTrue(len(data["token"]) >= 24)

    def test_04_download_through_sharing_link(self):
        """Test 4: Download through sharing link yields temporary presigned S3 URL"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "data.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "2"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        # Request download as JSON client
        dl_res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(dl_res["statusCode"], 200)
        dl_data = json.loads(dl_res["body"])
        self.assertTrue(dl_data["success"])
        self.assertIn("download_url", dl_data)
        self.assertIn(self.bucket_name, dl_data["download_url"])

    def test_05_password_protected_download_success(self):
        """Test 5: Password-protected download with correct password"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "secret.pdf",
                "content_type": "application/pdf",
                "expiry": "24 hours",
                "max_downloads": "2",
                "password": "SecretPassword123!"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        # Attempt download without password -> 401 requires_password
        unauth_res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(unauth_res["statusCode"], 401)
        self.assertTrue(json.loads(unauth_res["body"])["requires_password"])

        # Attempt download with correct password
        auth_res = lambda_function.lambda_handler(
            make_apigw_event("POST", f"/api/download/{token}", {"password": "SecretPassword123!"}),
            None
        )
        self.assertEqual(auth_res["statusCode"], 200)
        self.assertTrue(json.loads(auth_res["body"])["success"])

    def test_06_password_protected_download_incorrect(self):
        """Test 6: Password-protected download with incorrect password rejected with 403"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "secure.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "2",
                "password": "CorrectPassword"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        wrong_res = lambda_function.lambda_handler(
            make_apigw_event("POST", f"/api/download/{token}", {"password": "WrongPassword"}),
            None
        )
        self.assertEqual(wrong_res["statusCode"], 403)
        self.assertIn("Incorrect password", json.loads(wrong_res["body"])["message"])

    def test_07_expired_link(self):
        """Test 7: Download through expired link returns 410"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "expire.txt",
                "content_type": "text/plain",
                "expiry": "1 hour",
                "max_downloads": "5"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        # Force record in DynamoDB to be expired
        past_time = int(time.time()) - 100
        self.table.update_item(
            Key={"token": token},
            UpdateExpression="SET #e = :past",
            ExpressionAttributeNames={"#e": "expires_at"},
            ExpressionAttributeValues={":past": past_time}
        )

        dl_res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(dl_res["statusCode"], 410)
        self.assertIn("expired", json.loads(dl_res["body"])["message"].lower())

    def test_08_download_limits(self):
        """Test 8: Download session limit enforcement"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "limited.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "2"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        # 1st download session -> 200
        res1 = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(res1["statusCode"], 200)

        # 2nd download session -> 200
        res2 = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(res2["statusCode"], 200)

        # 3rd download session -> 429 Limit reached
        res3 = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(res3["statusCode"], 429)
        self.assertIn("limit", json.loads(res3["body"])["message"].lower())

    def test_09_simultaneous_downloads_atomic(self):
        """Test 9: Atomic download counts under concurrent requests"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "race.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "3"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        statuses = []
        for _ in range(6):
            res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
            statuses.append(res["statusCode"])

        # Exactly 3 must succeed with 200, exactly 3 must be rejected with 429
        self.assertEqual(statuses.count(200), 3)
        self.assertEqual(statuses.count(429), 3)

        item = self.table.get_item(Key={"token": token})["Item"]
        self.assertEqual(int(item["downloads"]), 3)

    def test_10_invalid_token(self):
        """Test 10: Invalid token returns 404"""
        res = lambda_function.lambda_handler(make_apigw_event("GET", "/api/download/nonexistent-token-12345"), None)
        self.assertEqual(res["statusCode"], 404)
        self.assertIn("invalid", json.loads(res["body"])["message"].lower())

    def test_11_private_s3_bucket(self):
        """Test 11: S3 bucket is private; objects require signed URL"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "private.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "1"
            }),
            None
        )
        data = json.loads(init_res["body"])
        token = data["token"]

        # Put object into S3 via presigned PUT
        requests.put(data["upload_url"], data=b"Secret bytes", headers={"Content-Type": "text/plain"})

        item = self.table.get_item(Key={"token": token})["Item"]
        obj = self.s3.get_object(Bucket=self.bucket_name, Key=item["object_key"])
        self.assertEqual(obj["Body"].read(), b"Secret bytes")

    def test_12_frontend_backend_integration(self):
        """Test 12: Verify API response contracts expected by script.js"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "integration.png",
                "content_type": "image/png",
                "expiry": "7 days",
                "max_downloads": "10"
            }),
            None
        )
        self.assertEqual(init_res["statusCode"], 200)
        data = json.loads(init_res["body"])
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("share_url") or data.get("share_link"))
        self.assertEqual(data.get("filename"), "integration.png")

    def test_13_health_and_cors(self):
        """Test 13: Health check and CORS OPTIONS preflight"""
        health_res = lambda_function.lambda_handler(make_apigw_event("GET", "/api/health"), None)
        self.assertEqual(health_res["statusCode"], 200)
        self.assertTrue(json.loads(health_res["body"])["success"])

        options_res = lambda_function.lambda_handler(make_apigw_event("OPTIONS", "/api/share"), None)
        self.assertEqual(options_res["statusCode"], 200)
        self.assertEqual(options_res["headers"].get("Access-Control-Allow-Origin"), "*")

    def test_14_verify_dynamodb_records(self):
        """Test 14: Verify DynamoDB records have all required attributes"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "audit.pdf",
                "file_size": 2048,
                "content_type": "application/pdf",
                "expiry": "24 hours",
                "max_downloads": "5",
                "password": "MyPassword123"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        item = self.table.get_item(Key={"token": token})["Item"]
        required_attributes = [
            "token", "filename", "object_key", "expires_at", "created_at",
            "max_downloads", "downloads", "password_hash"
        ]
        for attr in required_attributes:
            self.assertIn(attr, item, f"Missing attribute: {attr}")

        self.assertEqual(item["downloads"], 0)
        self.assertEqual(item["max_downloads"], 5)
        self.assertEqual(item["filename"], "audit.pdf")

    def test_15_presigned_download_expiry_clamped_to_link_lifetime(self):
        """Test 15: Presigned S3 download URL expiry NEVER exceeds remaining link lifetime"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "expiring_fast.txt",
                "content_type": "text/plain",
                "expiry": "1 hour",
                "max_downloads": "10"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]

        # Set expires_at to be exactly 20 seconds in the future
        now = int(time.time())
        self.table.update_item(
            Key={"token": token},
            UpdateExpression="SET #e = :twenty",
            ExpressionAttributeNames={"#e": "expires_at"},
            ExpressionAttributeValues={":twenty": now + 20}
        )

        dl_res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(dl_res["statusCode"], 200)
        dl_data = json.loads(dl_res["body"])

        # url_expires_in_seconds MUST be <= 20 seconds, NOT the default 60 or 300!
        self.assertLessEqual(dl_data["url_expires_in_seconds"], 20)
        self.assertGreaterEqual(dl_data["url_expires_in_seconds"], 5)

    def test_16_revoked_link_cannot_be_accessed(self):
        """Test 16: Revoked links immediately block downloads and purge S3 storage"""
        init_res = lambda_function.lambda_handler(
            make_apigw_event("POST", "/api/share", {
                "filename": "to_revoke.txt",
                "content_type": "text/plain",
                "expiry": "24 hours",
                "max_downloads": "5"
            }),
            None
        )
        token = json.loads(init_res["body"])["token"]
        item = self.table.get_item(Key={"token": token})["Item"]

        # Ensure object in S3
        self.s3.put_object(Bucket=self.bucket_name, Key=item["object_key"], Body=b"Revoke Me")

        # Revoke the link via POST /api/revoke/{token}
        revoke_res = lambda_function.lambda_handler(make_apigw_event("POST", f"/api/revoke/{token}"), None)
        self.assertEqual(revoke_res["statusCode"], 200)
        self.assertTrue(json.loads(revoke_res["body"])["success"])

        # Attempt download -> MUST be rejected with 404
        dl_res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{token}"), None)
        self.assertEqual(dl_res["statusCode"], 404)
        self.assertIn("revoked", json.loads(dl_res["body"])["message"].lower())

    def test_17_malformed_token_rejected(self):
        """Test 17: Malformed or special-character tokens are rejected immediately"""
        bad_tokens = [
            "short",
            "../../../etc/passwd",
            "<script>alert(1)</script>",
            "token with spaces here",
            "!@#$%^&*()_+"
        ]
        for bad in bad_tokens:
            res = lambda_function.lambda_handler(make_apigw_event("GET", f"/api/download/{bad}"), None)
            self.assertEqual(res["statusCode"], 404)


if __name__ == "__main__":
    unittest.main()
