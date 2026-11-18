from flask import Flask, request, jsonify, send_file, send_from_directory, redirect
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import ClientError
from io import BytesIO
import boto3
import time
import uuid
import secrets
import os
import re

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
MAX_FILE_SIZE = 16 * 1024 * 1024

# ---------------------------------
# AWS & LOCAL CONFIGURATION
# ---------------------------------
REGION_NAME = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "secureshare-documents")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "ShareLinks")

s3_endpoint = os.environ.get("S3_ENDPOINT_URL")
if not s3_endpoint and not os.environ.get("AWS_ACCESS_KEY_ID") and not os.environ.get("AWS_EXECUTION_ENV"):
    s3_endpoint = "http://127.0.0.1:5001"

dynamo_endpoint = os.environ.get("DYNAMODB_ENDPOINT_URL")
if not dynamo_endpoint and not os.environ.get("AWS_ACCESS_KEY_ID") and not os.environ.get("AWS_EXECUTION_ENV"):
    dynamo_endpoint = "http://localhost:8000"

s3_kwargs = {"region_name": REGION_NAME}
if s3_endpoint:
    s3_kwargs["endpoint_url"] = s3_endpoint
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        s3_kwargs["aws_access_key_id"] = "testing"
        s3_kwargs["aws_secret_access_key"] = "testing"

dynamo_kwargs = {"region_name": REGION_NAME}
if dynamo_endpoint:
    dynamo_kwargs["endpoint_url"] = dynamo_endpoint
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        dynamo_kwargs["aws_access_key_id"] = "testing"
        dynamo_kwargs["aws_secret_access_key"] = "testing"

s3 = boto3.client("s3", **s3_kwargs)
dynamodb = boto3.resource("dynamodb", **dynamo_kwargs)
table = dynamodb.Table(TABLE_NAME)


# ---------------------------------
# CREATE S3 BUCKET IF REQUIRED
# ---------------------------------
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


# ---------------------------------
# EXPIRATION TIME
# ---------------------------------
def get_expiry_seconds(raw_value=None):
    if raw_value is None:
        raw_value = (
            request.form.get("expiry")
            or request.form.get("expires_in")
            or request.form.get("expiration")
            or "24 hours"
        )

    value = str(raw_value).strip().lower()

    if value.isdigit():
        return int(value) * 3600

    match = re.fullmatch(
        r"(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?",
        value
    )

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


# ---------------------------------
# HOME PAGE & STATIC ASSETS
# ---------------------------------
@app.route("/")
def home():
    return send_from_directory(app.root_path, "index.html")

@app.route("/style.css")
@app.route("/static/style.css")
def css():
    return send_from_directory(app.root_path, "style.css", mimetype="text/css")

@app.route("/script.js")
@app.route("/static/script.js")
def javascript():
    return send_from_directory(app.root_path, "script.js", mimetype="application/javascript")

@app.route("/config.js")
def config_js():
    return send_from_directory(app.root_path, "config.js", mimetype="application/javascript")


# ---------------------------------
# HEALTH CHECK
# ---------------------------------
@app.route("/api/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    try:
        ensure_bucket()
        table.load()
        return jsonify({
            "success": True,
            "message": "S3 and DynamoDB connected successfully"
        })
    except Exception as e:
        app.logger.exception("Health check failed")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------
# UPLOAD FILE AND GENERATE LINK
# ---------------------------------
@app.route("/api/share", methods=["POST"])
@app.route("/api/upload", methods=["POST"])
def create_share():
    object_key = None
    file_bytes = None

    try:
        json_data = request.get_json(silent=True) or {}
        file = (
            request.files.get("file")
            or request.files.get("document")
        )

        if file is not None and file.filename:
            # Multipart upload
            raw_filename = file.filename
            content_type = file.mimetype or "application/octet-stream"
            raw_expiry = (
                request.form.get("expiry")
                or request.form.get("expires_in")
                or request.form.get("expiration")
                or "24 hours"
            )
            raw_limit = request.form.get("max_downloads", "").strip()
            password = request.form.get("password", "").strip()
            file_bytes = file.read()
            file_size = len(file_bytes)
            if file_size > MAX_FILE_SIZE:
                return jsonify({"success": False, "message": "File size exceeds 16 MB"}), 413
        else:
            # Presigned S3 upload metadata initiation (JSON or Form)
            raw_filename = (
                json_data.get("filename")
                or request.form.get("filename")
                or request.form.get("name")
            )
            if not raw_filename:
                return jsonify({"success": False, "message": "Please select a file"}), 400

            content_type = json_data.get("content_type") or request.form.get("content_type") or "application/octet-stream"
            file_size = int(json_data.get("file_size") or request.form.get("file_size") or 0)
            if file_size > MAX_FILE_SIZE:
                return jsonify({"success": False, "message": "File size exceeds 16 MB"}), 413

            raw_expiry = json_data.get("expiry") or request.form.get("expiry") or "24 hours"
            raw_limit = str(json_data.get("max_downloads") or request.form.get("max_downloads") or "").strip()
            password = str(json_data.get("password") or request.form.get("password") or "").strip()

        filename = secure_filename(raw_filename)
        if not filename:
            return jsonify({"success": False, "message": "Invalid filename"}), 400

        # Expiration
        expiry_seconds = get_expiry_seconds(raw_expiry)
        now = int(time.time())
        expires_at = now + expiry_seconds

        # Maximum downloads
        if raw_limit.lower() in ("", "0", "unlimited", "none"):
            max_downloads = None
        else:
            max_downloads = int(raw_limit)
            if max_downloads < 1:
                raise ValueError("Invalid download limit")

        # Password protection
        password_hash = None
        if password:
            password_hash = generate_password_hash(password)

        # Unique token & object key
        token = secrets.token_urlsafe(24)
        object_key = uuid.uuid4().hex + "_" + filename

        ensure_bucket()

        # If direct file bytes present
        if file_bytes is not None:
            s3.upload_fileobj(
                BytesIO(file_bytes),
                BUCKET_NAME,
                object_key,
                ExtraArgs={"ContentType": content_type}
            )
            upload_url = None
        else:
            # Generate presigned PUT URL for direct S3 upload
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

        # Generate sharing URL
        frontend_url = os.environ.get("FRONTEND_URL", "").rstrip("/")
        if frontend_url:
            share_url = f"{frontend_url}/download/{token}"
        else:
            share_url = request.host_url.rstrip("/") + "/download/" + token

        res_data = {
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
            res_data["upload_mode"] = "presigned_s3"
            res_data["upload_url"] = upload_url

        return jsonify(res_data), 200

    except Exception as e:
        if object_key and file_bytes is not None:
            try:
                s3.delete_object(Bucket=BUCKET_NAME, Key=object_key)
            except Exception:
                app.logger.exception("S3 rollback failed")

        app.logger.exception("Upload or database error")
        return jsonify({
            "success": False,
            "message": "Could not complete upload",
            "error": str(e)
        }), 500


# ---------------------------------
# REVOKE SHARING LINK
# ---------------------------------
@app.route("/api/revoke/<token>", methods=["POST", "DELETE"])
@app.route("/api/share/<token>", methods=["DELETE"])
def revoke_link(token):
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        return jsonify({"success": False, "message": "Invalid token format"}), 400

    try:
        res = table.get_item(Key={"token": token})
        item = res.get("Item")
        if not item:
            return jsonify({"success": False, "message": "Sharing link not found"}), 404

        table.update_item(
            Key={"token": token},
            UpdateExpression="SET #r = :true, #status = :revoked",
            ExpressionAttributeNames={"#r": "revoked", "#status": "status"},
            ExpressionAttributeValues={":true": True, ":revoked": "revoked"}
        )
        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=item["object_key"])
        except Exception:
            pass

        return jsonify({"success": True, "message": "Sharing link revoked successfully"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------
# DOWNLOAD FILE USING SHARING LINK
# ---------------------------------
@app.route("/download/<token>", methods=["GET", "POST"])
@app.route("/api/download/<token>", methods=["GET", "POST"])
def download_file(token):
    is_api = request.path.startswith("/api/") or "application/json" in request.headers.get("Accept", "")

    try:
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
            return jsonify({"success": False, "message": "Invalid sharing link format"}), 404

        # Find sharing record
        response = table.get_item(Key={"token": token})
        item = response.get("Item")

        if not item or item.get("revoked") is True or item.get("status") == "revoked":
            return jsonify({
                "success": False,
                "message": "Sharing link is invalid or has been revoked"
            }), 404

        # Check expiration
        now = int(time.time())
        remaining_seconds = int(item["expires_at"]) - now
        if remaining_seconds <= 0:
            return jsonify({
                "success": False,
                "message": "Sharing link has expired"
            }), 410

        # Check password
        password_hash = item.get("password_hash")
        if password_hash:
            data = request.get_json(silent=True) or {}
            password = (
                request.form.get("password")
                or data.get("password")
                or request.args.get("password")
                or ""
            )

            if not password:
                if is_api:
                    return jsonify({
                        "success": False,
                        "requires_password": True,
                        "message": "Password required"
                    }), 401

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
        <p>File: <strong>{item['filename']}</strong></p>
        <p>Enter the file password to download:</p>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter file password" required autofocus>
            <button type="submit">Download Document</button>
        </form>
    </div>
</body>
</html>"""

            if not check_password_hash(password_hash, password):
                return jsonify({
                    "success": False,
                    "message": "Incorrect password"
                }), 403

        # Atomically increment download count.
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
        condition = (
            "attribute_exists(#t) "
            "AND #e > :now "
            "AND (attribute_not_exists(#m) OR #d < #m)"
        )

        table.update_item(
            Key={"token": token},
            UpdateExpression="SET #d = #d + :one",
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values
        )

        # Presigned URL expiry clamped to remaining link lifetime
        presigned_expiry = max(5, min(60, remaining_seconds))

        # Generate temporary presigned S3 download URL
        try:
            presigned_url = s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": BUCKET_NAME,
                    "Key": item["object_key"],
                    "ResponseContentDisposition": f'attachment; filename="{item["filename"]}"'
                },
                ExpiresIn=presigned_expiry
            )
            if is_api and request.args.get("json") == "true":
                return jsonify({
                    "success": True,
                    "download_url": presigned_url,
                    "filename": item["filename"],
                    "url_expires_in_seconds": presigned_expiry
                })
        except Exception:
            presigned_url = None

        # Fallback to direct streaming if running locally on Moto S3
        ensure_bucket()
        s3_response = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=item["object_key"]
        )
        file_data = s3_response["Body"].read()

        return send_file(
            BytesIO(file_data),
            mimetype=item.get("content_type", "application/octet-stream"),
            as_attachment=True,
            download_name=item["filename"]
        )

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ConditionalCheckFailedException":
            latest = table.get_item(Key={"token": token}).get("Item", {})
            if latest and int(latest.get("expires_at", 0)) <= int(time.time()):
                return jsonify({
                    "success": False,
                    "message": "Sharing link has expired"
                }), 410

            return jsonify({
                "success": False,
                "message": "Maximum download limit reached"
            }), 429

        app.logger.exception("Download error")
        return jsonify({
            "success": False,
            "message": "Could not download file",
            "error": str(e)
        }), 500

    except Exception as e:
        app.logger.exception("Download error")
        return jsonify({
            "success": False,
            "message": "Could not download file",
            "error": str(e)
        }), 500


# ---------------------------------
# FILE SIZE ERROR
# ---------------------------------
@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "success": False,
        "message": "File size exceeds 16 MB"
    }), 413


# ---------------------------------
# RUN FLASK APPLICATION
# ---------------------------------
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
