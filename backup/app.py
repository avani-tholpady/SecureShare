
from flask import Flask, request, jsonify, send_file, send_from_directory
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

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# ---------------------------------
# S3 CONNECTION
# ---------------------------------

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:5001",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

BUCKET_NAME = "secureshare-documents"


# ---------------------------------
# DYNAMODB CONNECTION
# ---------------------------------

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8000",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="us-east-1"
)

table = dynamodb.Table("ShareLinks")


# ---------------------------------
# CREATE S3 BUCKET IF REQUIRED
# ---------------------------------

def ensure_bucket():
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")

        if code in ("404", "NoSuchBucket", "NotFound"):
            s3.create_bucket(Bucket=BUCKET_NAME)
        else:
            raise


# ---------------------------------
# EXPIRATION TIME
# ---------------------------------

def get_expiry_seconds():
    value = (
        request.form.get("expiry")
        or request.form.get("expires_in")
        or request.form.get("expiration")
        or "1 hour"
    )

    value = value.strip().lower()

    match = re.fullmatch(
        r"(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?",
        value
    )

    if not match:
        raise ValueError("Invalid expiration time")

    number = int(match.group(1))
    unit = match.group(2) or "m"

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
# HOME PAGE
# ---------------------------------

@app.route("/")
def home():
    return send_from_directory(app.root_path, "index.html")


# ---------------------------------
# SERVE CSS FILE
# ---------------------------------

@app.route("/style.css")
@app.route("/static/style.css")
def css():
    return send_from_directory(
        app.root_path,
        "style.css",
        mimetype="text/css"
    )


# ---------------------------------
# SERVE JAVASCRIPT FILE
# ---------------------------------

@app.route("/script.js")
@app.route("/static/script.js")
def javascript():
    return send_from_directory(
        app.root_path,
        "script.js",
        mimetype="application/javascript"
    )


# ---------------------------------
# HEALTH CHECK
# ---------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
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

    try:
        # Get uploaded file
        file = (
            request.files.get("file")
            or request.files.get("document")
        )

        if file is None or not file.filename:
            return jsonify({
                "success": False,
                "message": "Please select a file"
            }), 400

        filename = secure_filename(file.filename)

        if not filename:
            return jsonify({
                "success": False,
                "message": "Invalid filename"
            }), 400

        # Expiration
        expiry_seconds = get_expiry_seconds()
        expires_at = int(time.time()) + expiry_seconds

        # Maximum downloads
        raw_limit = request.form.get("max_downloads", "").strip()

        if raw_limit.lower() in ("", "0", "unlimited", "none"):
            max_downloads = None
        else:
            max_downloads = int(raw_limit)

            if max_downloads < 1:
                raise ValueError("Invalid download limit")

        # Password protection
        password = request.form.get("password", "").strip()

        password_hash = None

        if password:
            password_hash = generate_password_hash(password)

        # Generate unique values
        token = secrets.token_urlsafe(24)

        object_key = uuid.uuid4().hex + "_" + filename

        content_type = (
            file.mimetype or "application/octet-stream"
        )

        # Upload file to S3
        ensure_bucket()

        s3.upload_fileobj(
            file.stream,
            BUCKET_NAME,
            object_key,
            ExtraArgs={
                "ContentType": content_type
            }
        )

        # Prepare DynamoDB record
        item = {
            "token": token,
            "filename": filename,
            "object_key": object_key,
            "expires_at": expires_at,
            "downloads": 0,
            "created_at": int(time.time()),
            "content_type": content_type
        }

        if max_downloads is not None:
            item["max_downloads"] = max_downloads

        if password_hash:
            item["password_hash"] = password_hash

        # Store record in DynamoDB
        # FIX: Use an alias for reserved keyword "token"

        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(#t)",
            ExpressionAttributeNames={
                "#t": "token"
            }
        )

        # Generate sharing URL
        share_url = (
            request.host_url.rstrip("/")
            + "/download/"
            + token
        )

        return jsonify({
            "success": True,
            "message": "File uploaded successfully",
            "token": token,
            "filename": filename,
            "share_url": share_url,
            "share_link": share_url,
            "download_url": share_url,
            "url": share_url,
            "expires_at": expires_at,
            "max_downloads": max_downloads
        }), 200

    except Exception as e:

        # Delete uploaded file if database operation fails
        if object_key:
            try:
                s3.delete_object(
                    Bucket=BUCKET_NAME,
                    Key=object_key
                )
            except Exception:
                app.logger.exception("S3 rollback failed")

        app.logger.exception("Upload or database error")

        return jsonify({
            "success": False,
            "message": "Could not complete upload",
            "error": str(e)
        }), 500


# ---------------------------------
# DOWNLOAD FILE USING SHARING LINK
# ---------------------------------

@app.route("/download/<token>", methods=["GET", "POST"])
@app.route("/api/download/<token>", methods=["GET", "POST"])
def download_file(token):

    is_api = request.path.startswith("/api/")

    try:
        # Find sharing record
        response = table.get_item(
            Key={"token": token}
        )

        item = response.get("Item")

        if not item:
            return jsonify({
                "success": False,
                "message": "Invalid sharing link"
            }), 404

        # Check expiration
        now = int(time.time())

        if now >= int(item["expires_at"]):
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
                or ""
            )

            if not password:
                if is_api:
                    return jsonify({
                        "success": False,
                        "requires_password": True,
                        "message": "Password required"
                    }), 401

                return """
                    <h2>SecureShare</h2>
                    <form method="POST">
                        <p>Enter the file password:</p>
                        <input type="password"
                               name="password"
                               required>
                        <button type="submit">Download</button>
                    </form>
                """

            if not check_password_hash(password_hash, password):
                return jsonify({
                    "success": False,
                    "message": "Incorrect password"
                }), 403

        # Read file from S3
        ensure_bucket()

        s3_response = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=item["object_key"]
        )

        file_data = s3_response["Body"].read()

        # Atomically increment download count.
        # This prevents exceeding the download limit.

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

        # Send downloaded file
        return send_file(
            BytesIO(file_data),
            mimetype=item.get(
                "content_type",
                "application/octet-stream"
            ),
            as_attachment=True,
            download_name=item["filename"]
        )

    except ClientError as e:

        error_code = e.response.get(
            "Error", {}
        ).get("Code", "")

        if error_code == "ConditionalCheckFailedException":

            # Identify why the conditional update failed
            latest = table.get_item(
                Key={"token": token}
            ).get("Item", {})

            if latest and int(latest["expires_at"]) <= int(time.time()):
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
