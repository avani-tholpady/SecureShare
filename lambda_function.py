"""
SecureShare - AWS Lambda Function Handler
Implements Cloud-Based Secure Document Exchange & Expiring Link System.
Compatible with Amazon API Gateway (HTTP API & REST API) and AWS Lambda.
Supports:
- Direct browser-to-private-S3 upload via Presigned PUT (bypasses 10MB API Gateway & 6MB Lambda payload limits)
- Direct multipart upload (for API/CLI backwards compatibility)
- Server-side metadata validation, expiration calculation, and password hashing
- Clamped presigned download URL lifetime (never exceeds remaining link expiration)
- Atomic download-session counting via DynamoDB conditional updates
"""

import os
import io
import json
import time
import uuid
import secrets
import base64
import re
import boto3
from botocore.exceptions import ClientError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.wrappers import Request

# ----------------------------------------------------------------------
# AWS CLIENTS & CONFIGURATION (FROM ENVIRONMENT VARIABLES)
# ----------------------------------------------------------------------
REGION_NAME = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "secureshare-documents")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "ShareLinks")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "").rstrip("/")
API_BASE_URL = os.environ.get("API_BASE_URL", "").rstrip("/")
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

s3_kwargs = {"region_name": REGION_NAME}
if os.environ.get("S3_ENDPOINT_URL"):
    s3_kwargs["endpoint_url"] = os.environ.get("S3_ENDPOINT_URL")

dynamodb_kwargs = {"region_name": REGION_NAME}
if os.environ.get("DYNAMODB_ENDPOINT_URL"):
    dynamodb_kwargs["endpoint_url"] = os.environ.get("DYNAMODB_ENDPOINT_URL")

s3 = boto3.client("s3", **s3_kwargs)
dynamodb = boto3.resource("dynamodb", **dynamodb_kwargs)
dynamodb_client = boto3.client("dynamodb", **dynamodb_kwargs)
table = dynamodb.Table(TABLE_NAME)


# ----------------------------------------------------------------------
# HELPER: CORS & RESPONSES
# ----------------------------------------------------------------------
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Accept",
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS"
}

def json_response(status_code, body_dict, extra_headers=None):
    headers = {**CORS_HEADERS, "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body_dict)
    }

def html_response(status_code, html_content):
    headers = {**CORS_HEADERS, "Content-Type": "text/html; charset=utf-8"}
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": html_content
    }

def redirect_response(location_url):
    headers = {**CORS_HEADERS, "Location": location_url}
    return {
        "statusCode": 302,
        "headers": headers,
        "body": ""
    }


# ----------------------------------------------------------------------
# HELPER: EXPIRATION TIME PARSER
# ----------------------------------------------------------------------
def parse_expiry_seconds(value):
    if not value:
        return 86400  # Default 24 hours
    value = str(value).strip().lower()

    if value.isdigit():
        return int(value) * 3600

    match = re.fullmatch(r"(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?", value)
    if not match:
        raise ValueError("Invalid expiration time")

    number = int(match.group(1))
    unit = match.group(2) or "h"

    if number <= 0:
        raise ValueError("Expiration must be greater than zero")

    if unit.startswith("m"):
        return number * 60
    elif unit.startswith("h"):
        return number * 3600
    elif unit.startswith("d"):
        return number * 86400

    raise ValueError("Invalid expiration unit")


# ----------------------------------------------------------------------
# HELPER: S3 BUCKET ENSURE
# ----------------------------------------------------------------------
def ensure_bucket():
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
    except ClientError as e:
        code = str(e.response.get("Error", {}).get("Code", ""))
        if code in ("404", "NoSuchBucket", "NotFound"):
            if REGION_NAME == "us-east-1":
                s3.create_bucket(Bucket=BUCKET_NAME)
            else:
                s3.create_bucket(
                    Bucket=BUCKET_NAME,
                    CreateBucketConfiguration={"LocationConstraint": REGION_NAME}
                )
        else:
            raise


# ----------------------------------------------------------------------
# HELPER: PARSE REQUEST FROM API GATEWAY EVENT
# ----------------------------------------------------------------------
def parse_api_gateway_request(event):
    http_method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("path") or event.get("rawPath", "/")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    query_params = event.get("queryStringParameters") or {}

    raw_body = event.get("body") or ""
    is_b64 = event.get("isBase64Encoded", False)

    if isinstance(raw_body, str):
        if is_b64:
            body_bytes = base64.b64decode(raw_body)
        else:
            body_bytes = raw_body.encode("utf-8")
    elif isinstance(raw_body, bytes):
        body_bytes = raw_body
    else:
        body_bytes = b""

    content_type = headers.get("content-type", "")

    environ = {
        "REQUEST_METHOD": http_method,
        "PATH_INFO": path,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body_bytes)),
        "wsgi.input": io.BytesIO(body_bytes)
    }

    werkzeug_req = Request(environ)

    # Try to parse JSON body if applicable
    json_data = {}
    if "application/json" in content_type and body_bytes:
        try:
            json_data = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            pass

    return {
        "method": http_method.upper(),
        "path": path,
        "headers": headers,
        "query": query_params,
        "raw_bytes": body_bytes,
        "json": json_data,
        "req": werkzeug_req
    }


# ----------------------------------------------------------------------
# HTML PASSWORD FORM TEMPLATE
# ----------------------------------------------------------------------
def render_password_page(token, filename=None, error_msg=None):
    error_html = f'<p style="color: #e11d48; margin-bottom: 15px; font-weight: bold;">{error_msg}</p>' if error_msg else ''
    filename_html = f'<p style="color: #667085; margin-bottom: 20px;">File: <strong>{filename}</strong></p>' if filename else ''
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureShare | Password Required</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: Arial, sans-serif; background: #f4f7fb; color: #1d2939; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .card {{ background: white; padding: 35px; border-radius: 14px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); max-width: 440px; width: 90%; text-align: center; }}
        .logo {{ font-size: 24px; font-weight: bold; color: #2563eb; margin-bottom: 20px; }}
        h2 {{ margin-bottom: 8px; font-size: 22px; }}
        p {{ color: #667085; font-size: 14px; margin-bottom: 20px; }}
        input[type="password"] {{ width: 100%; padding: 12px; border: 1px solid #d0d5dd; border-radius: 7px; margin-bottom: 16px; font-size: 15px; }}
        button {{ width: 100%; padding: 14px; background: #2563eb; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }}
        button:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">☁ SecureShare</div>
        <h2>Password Protected Document</h2>
        {filename_html}
        {error_html}
        <p>This document requires a password to download.</p>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter file password" required autofocus>
            <button type="submit">Download Document</button>
        </form>
    </div>
</body>
</html>"""


def render_error_page(title, message, status_code=400):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureShare | {title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: Arial, sans-serif; background: #f4f7fb; color: #1d2939; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .card {{ background: white; padding: 35px; border-radius: 14px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); max-width: 440px; width: 90%; text-align: center; }}
        .icon {{ font-size: 44px; margin-bottom: 12px; }}
        h2 {{ margin-bottom: 10px; font-size: 22px; }}
        p {{ color: #667085; font-size: 14px; margin-bottom: 20px; line-height: 1.5; }}
        a {{ display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 7px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⚠️</div>
        <h2>{title}</h2>
        <p>{message}</p>
        <a href="/">Back to SecureShare</a>
    </div>
</body>
</html>"""


# ----------------------------------------------------------------------
# HANDLER: HEALTH CHECK
# ----------------------------------------------------------------------
def handle_health():
    try:
        ensure_bucket()
        table.load()
        return json_response(200, {
            "success": True,
            "message": "S3 and DynamoDB connected successfully"
        })
    except Exception as e:
        return json_response(500, {
            "success": False,
            "error": str(e)
        })


# ----------------------------------------------------------------------
# HANDLER: FILE UPLOAD & SHARE LINK CREATION
# ----------------------------------------------------------------------
def handle_share(parsed_req, event):
    req = parsed_req["req"]
    json_body = parsed_req["json"]
    object_key = None

    try:
        # Determine whether this is a direct multipart upload or a presigned upload initiation
        file = req.files.get("file") or req.files.get("document")

        if file is not None and file.filename:
            # Multipart upload flow
            raw_filename = file.filename
            content_type = file.mimetype or "application/octet-stream"
            raw_expiry = (
                req.form.get("expiry")
                or req.form.get("expires_in")
                or req.form.get("expiration")
                or "24 hours"
            )
            raw_limit = req.form.get("max_downloads", "").strip()
            password = req.form.get("password", "").strip()
            file_bytes = file.read()
            file_size = len(file_bytes)
            if file_size > MAX_FILE_SIZE:
                return json_response(413, {"success": False, "message": "File size exceeds 16 MB limit"})
        else:
            # Presigned S3 upload metadata initiation (JSON or Form)
            raw_filename = (
                json_body.get("filename")
                or req.form.get("filename")
                or req.form.get("name")
            )
            if not raw_filename:
                return json_response(400, {
                    "success": False,
                    "message": "Please select a file or specify a filename"
                })

            content_type = json_body.get("content_type") or req.form.get("content_type") or "application/octet-stream"
            file_size = json_body.get("file_size") or req.form.get("file_size") or 0
            try:
                file_size = int(file_size)
                if file_size > MAX_FILE_SIZE:
                    return json_response(413, {"success": False, "message": "File size exceeds 16 MB limit"})
            except ValueError:
                pass

            raw_expiry = (
                json_body.get("expiry")
                or req.form.get("expiry")
                or "24 hours"
            )
            raw_limit = str(json_body.get("max_downloads") or req.form.get("max_downloads") or "").strip()
            password = str(json_body.get("password") or req.form.get("password") or "").strip()
            file_bytes = None

        filename = secure_filename(raw_filename)
        if not filename:
            return json_response(400, {
                "success": False,
                "message": "Invalid filename"
            })

        # Expiration calculation
        expiry_seconds = parse_expiry_seconds(raw_expiry)
        now = int(time.time())
        expires_at = now + expiry_seconds

        # Max downloads parsing
        if raw_limit.lower() in ("", "0", "unlimited", "none"):
            max_downloads = None
        else:
            try:
                max_downloads = int(raw_limit)
                if max_downloads < 1:
                    raise ValueError()
            except ValueError:
                return json_response(400, {
                    "success": False,
                    "message": "Invalid download limit"
                })

        # Password hashing
        password_hash = None
        if password:
            password_hash = generate_password_hash(password)

        # Unique token & unique object key
        token = secrets.token_urlsafe(24)
        object_key = f"{uuid.uuid4().hex}_{filename}"

        ensure_bucket()

        # If file bytes are provided directly (multipart upload)
        if file_bytes is not None:
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=object_key,
                Body=file_bytes,
                ContentType=content_type,
                ServerSideEncryption="AES256"
            )
            upload_url = None
        else:
            # Generate Presigned PUT URL for direct browser-to-S3 upload
            # Bypasses API Gateway 10MB & Lambda 6MB limitations completely!
            upload_url = s3.generate_presigned_url(
                "put_object",
                Params={
                    "Bucket": BUCKET_NAME,
                    "Key": object_key,
                    "ContentType": content_type
                },
                ExpiresIn=300
            )

        # Store metadata in DynamoDB
        item = {
            "token": token,
            "filename": filename,
            "object_key": object_key,
            "expires_at": expires_at,
            "downloads": 0,
            "created_at": now,
            "content_type": content_type,
            "file_size": file_size
        }
        if max_downloads is not None:
            item["max_downloads"] = max_downloads
        if password_hash:
            item["password_hash"] = password_hash

        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(#t)",
            ExpressionAttributeNames={"#t": "token"}
        )

        # Build sharing URL
        headers = parsed_req["headers"]
        host = headers.get("host", "localhost")
        stage = event.get("requestContext", {}).get("stage", "")

        if FRONTEND_URL:
            share_url = f"{FRONTEND_URL}/download/{token}"
        elif API_BASE_URL:
            share_url = f"{API_BASE_URL}/api/download/{token}"
        else:
            proto = headers.get("x-forwarded-proto", "https")
            if stage and stage != "$default":
                share_url = f"{proto}://{host}/{stage}/api/download/{token}"
            else:
                share_url = f"{proto}://{host}/api/download/{token}"

        response_body = {
            "success": True,
            "message": "File upload initialized successfully",
            "token": token,
            "filename": filename,
            "share_url": share_url,
            "share_link": share_url,
            "download_url": share_url,
            "url": share_url,
            "expires_at": expires_at,
            "max_downloads": max_downloads
        }

        if upload_url:
            response_body["upload_mode"] = "presigned_s3"
            response_body["upload_url"] = upload_url

        return json_response(200, response_body)

    except Exception as e:
        if object_key and file_bytes is not None:
            try:
                s3.delete_object(Bucket=BUCKET_NAME, Key=object_key)
            except Exception:
                pass

        return json_response(500, {
            "success": False,
            "message": "Could not complete upload",
            "error": str(e)
        })


# ----------------------------------------------------------------------
# HANDLER: DOWNLOAD / VALIDATE SHARE LINK
# ----------------------------------------------------------------------
def handle_download(token, parsed_req, event):
    method = parsed_req["method"]
    headers = parsed_req["headers"]
    req = parsed_req["req"]
    accept_header = headers.get("accept", "")
    is_json_client = "application/json" in accept_header or parsed_req["query"].get("json") == "true"

    try:
        # Validate token format against malformed / injection tokens
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
            if is_json_client:
                return json_response(404, {"success": False, "message": "Invalid sharing link format"})
            return html_response(404, render_error_page("Invalid Link", "The provided link format is invalid.", 404))

        # Retrieve share metadata
        res = table.get_item(Key={"token": token})
        item = res.get("Item")

        if not item or item.get("revoked") is True or item.get("status") == "revoked":
            if is_json_client:
                return json_response(404, {"success": False, "message": "Sharing link is invalid or has been revoked"})
            return html_response(404, render_error_page("Link Inactive", "This sharing link has expired, been revoked, or does not exist.", 404))

        # Check expiration
        now = int(time.time())
        remaining_seconds = int(item["expires_at"]) - now
        if remaining_seconds <= 0:
            if is_json_client:
                return json_response(410, {"success": False, "message": "Sharing link has expired"})
            return html_response(410, render_error_page("Link Expired", "This sharing link has expired and is no longer accessible.", 410))

        # Check password
        password_hash = item.get("password_hash")
        if password_hash:
            submitted_password = None

            if method == "POST":
                # Check form data
                submitted_password = req.form.get("password")
                # Check JSON payload
                if not submitted_password and parsed_req.get("json"):
                    submitted_password = parsed_req["json"].get("password")
            elif method == "GET":
                submitted_password = parsed_req["query"].get("password")

            if not submitted_password:
                if is_json_client or (method == "GET" and "text/html" not in accept_header):
                    return json_response(401, {
                        "success": False,
                        "requires_password": True,
                        "message": "Password required"
                    })
                return html_response(200, render_password_page(token, item["filename"]))

            if not check_password_hash(password_hash, submitted_password):
                if is_json_client:
                    return json_response(403, {"success": False, "message": "Incorrect password"})
                return html_response(403, render_password_page(token, item["filename"], error_msg="Incorrect password. Please try again."))

        # Atomically increment download session count with conditional expression
        # Guarantees link has not expired and download limit has not been reached
        names = {
            "#t": "token",
            "#d": "downloads",
            "#e": "expires_at",
            "#m": "max_downloads"
        }
        values = {
            ":one": 1,
            ":now": now
        }
        condition = "attribute_exists(#t) AND #e > :now AND (attribute_not_exists(#m) OR #d < #m)"

        table.update_item(
            Key={"token": token},
            UpdateExpression="SET #d = #d + :one",
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values
        )

        # Generate temporary presigned S3 download URL
        # SECURITY REQUIREMENT: Presigned URL expiry MUST NEVER exceed remaining link lifetime!
        # Standard expiry: 60 seconds (or remaining_seconds if link expires sooner).
        presigned_expiry = max(5, min(60, remaining_seconds))

        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": BUCKET_NAME,
                "Key": item["object_key"],
                "ResponseContentDisposition": f'attachment; filename="{item["filename"]}"'
            },
            ExpiresIn=presigned_expiry
        )

        if is_json_client:
            return json_response(200, {
                "success": True,
                "download_url": presigned_url,
                "filename": item["filename"],
                "url_expires_in_seconds": presigned_expiry
            })

        # Redirect browser to temporary signed S3 URL
        return redirect_response(presigned_url)

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ConditionalCheckFailedException":
            latest = table.get_item(Key={"token": token}).get("Item", {})
            if latest and int(latest.get("expires_at", 0)) <= int(time.time()):
                if is_json_client:
                    return json_response(410, {"success": False, "message": "Sharing link has expired"})
                return html_response(410, render_error_page("Link Expired", "This sharing link has expired.", 410))

            if is_json_client:
                return json_response(429, {"success": False, "message": "Maximum download limit reached"})
            return html_response(429, render_error_page("Download Limit Reached", "This document has reached its maximum download limit.", 429))

        if is_json_client:
            return json_response(500, {"success": False, "message": "Could not download file", "error": str(e)})
        return html_response(500, render_error_page("Download Error", str(e), 500))

    except Exception as e:
        if is_json_client:
            return json_response(500, {"success": False, "message": "Could not download file", "error": str(e)})
        return html_response(500, render_error_page("Download Error", str(e), 500))


# ----------------------------------------------------------------------
# HANDLER: REVOKE SHARING LINK
# ----------------------------------------------------------------------
def handle_revoke(token, parsed_req, event):
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        return json_response(400, {"success": False, "message": "Invalid token format"})

    try:
        res = table.get_item(Key={"token": token})
        item = res.get("Item")
        if not item:
            return json_response(404, {"success": False, "message": "Sharing link not found"})

        table.update_item(
            Key={"token": token},
            UpdateExpression="SET #r = :true, #status = :revoked",
            ExpressionAttributeNames={"#r": "revoked", "#status": "status"},
            ExpressionAttributeValues={":true": True, ":revoked": "revoked"}
        )

        # Remove underlying S3 object
        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=item["object_key"])
        except Exception:
            pass

        return json_response(200, {
            "success": True,
            "message": "Sharing link revoked successfully"
        })
    except Exception as e:
        return json_response(500, {
            "success": False,
            "error": f"Failed to revoke link: {str(e)}"
        })


# ----------------------------------------------------------------------
# MAIN LAMBDA HANDLER (ROUTER)
# ----------------------------------------------------------------------
def lambda_handler(event, context):
    try:
        parsed_req = parse_api_gateway_request(event)
        method = parsed_req["method"]
        path = parsed_req["path"]

        # Handle CORS OPTIONS Preflight
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": ""
            }

        # Normalize path
        normalized_path = "/" + path.strip("/")

        # Route: Health
        if normalized_path in ("/api/health", "/health"):
            return handle_health()

        # Route: Upload / Share
        if normalized_path in ("/api/share", "/share", "/api/upload", "/upload") and method == "POST":
            return handle_share(parsed_req, event)

        # Route: Revoke
        revoke_match = re.match(r"^/api/revoke/([^/]+)$", normalized_path)
        if revoke_match and method in ("POST", "DELETE"):
            return handle_revoke(revoke_match.group(1), parsed_req, event)

        share_delete_match = re.match(r"^/api/share/([^/]+)$", normalized_path)
        if share_delete_match and method == "DELETE":
            return handle_revoke(share_delete_match.group(1), parsed_req, event)

        # Route: Download / Token
        download_match = re.match(r"^/(?:api/)?download/([^/]+)$", normalized_path)
        if download_match:
            token = download_match.group(1)
            return handle_download(token, parsed_req, event)

        return json_response(404, {
            "success": False,
            "message": f"Route not found: {method} {path}"
        })

    except Exception as e:
        return json_response(500, {
            "success": False,
            "error": f"Unhandled error: {str(e)}"
        })
