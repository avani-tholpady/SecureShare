"""
SecureShare Live AWS Verification Test Script
Tests the real deployed AWS Backend in ap-southeast-2:
1. Health Check (GET /api/health)
2. Presigned S3 Upload Initiation (POST /api/share)
3. Direct S3 Upload (PUT to Presigned URL)
4. Unprotected File Download (GET /api/download/{token})
5. Password-Protected Flow (Wrong vs Correct Password)
6. Download Limit Enforcement (Session Tracking)
7. Link Revocation (POST /api/revoke/{token}) & Cleanup
"""

import urllib.request
import urllib.error
import json

BASE_URL = "https://mib95ppjqf.execute-api.ap-southeast-2.amazonaws.com"

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Do not auto-follow redirects, return the 302 response

def make_req(method, path, data=None, headers=None, follow_redirects=True):
    url = f"{BASE_URL}{path}"
    hdrs = headers or {}
    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif isinstance(data, bytes):
            body_bytes = data
        else:
            body_bytes = str(data).encode("utf-8")

    if not follow_redirects:
        opener = urllib.request.build_opener(NoRedirectHandler)
    else:
        opener = urllib.request.build_opener()

    req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=15) as res:
            res_body = res.read().decode("utf-8", errors="replace")
            res_headers = dict(res.headers)
            return res.status, res_body, res_headers
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307):
            return e.code, "", dict(e.headers)
        err_body = e.read().decode("utf-8", errors="replace")
        return e.code, err_body, dict(e.headers)
    except Exception as e:
        return 0, str(e), {}

def run_tests():
    print("=" * 70)
    print("    SECURESHARE - LIVE AWS BACKEND VERIFICATION SUITE")
    print("=" * 70)
    print(f"Target: {BASE_URL}\n")

    # 1. Health check
    print("[Live Test 1] Health check endpoint (GET /api/health)...")
    status, body, _ = make_req("GET", "/api/health")
    assert status == 200, f"Health check failed: {status} {body}"
    print(f" ✓ Health check passed: {body}")

    # 2. Upload initiation
    print("\n[Live Test 2] Presigned S3 upload initiation (POST /api/share)...")
    payload = {
        "filename": "live_test_sample.txt",
        "file_size": 36,
        "content_type": "text/plain",
        "expiry": "1 hour",
        "max_downloads": "2"
    }
    status, body, _ = make_req("POST", "/api/share", payload)
    assert status == 200, f"Upload initiation failed: {status} {body}"
    data = json.loads(body)
    assert data.get("success"), "Response success is not True"
    assert "upload_url" in data, "No upload_url in response"
    token = data["token"]
    upload_url = data["upload_url"]
    share_url = data["share_url"]
    print(f" ✓ Upload URL generated: {upload_url[:65]}...")
    print(f" ✓ Share URL: {share_url}")
    print(f" ✓ Token: {token}")

    # 3. Direct S3 Upload via Presigned PUT
    print("\n[Live Test 3] Direct S3 upload via Presigned PUT URL...")
    test_content = b"SecureShare live AWS deployment test"
    put_req = urllib.request.Request(
        upload_url,
        data=test_content,
        headers={"Content-Type": "text/plain"},
        method="PUT"
    )
    with urllib.request.urlopen(put_req, timeout=15) as s3_res:
        assert s3_res.status == 200, f"S3 PUT failed with status: {s3_res.status}"
    print(" ✓ Direct S3 PUT upload succeeded (HTTP 200)")

    # 4. Download file through sharing token
    print("\n[Live Test 4] Download resolution through token (GET /api/download/{token})...")
    status, dl_body, _ = make_req("GET", f"/api/download/{token}", headers={"Accept": "application/json"})
    assert status == 200, f"Download resolution failed: {status} {dl_body}"
    dl_data = json.loads(dl_body)
    assert "download_url" in dl_data, "No download_url returned"
    s3_download_url = dl_data["download_url"]
    print(f" ✓ S3 signed download URL issued: {s3_download_url[:65]}...")

    # Fetch file binary from signed S3 download URL
    with urllib.request.urlopen(s3_download_url, timeout=15) as file_res:
        downloaded_bytes = file_res.read()
    assert downloaded_bytes == test_content, f"Content mismatch: {downloaded_bytes}"
    print(f" ✓ File downloaded from S3 and verified: '{downloaded_bytes.decode()}'")

    # 5. Password-protected flow
    print("\n[Live Test 5] Password-protected upload and validation...")
    pw_payload = {
        "filename": "confidential.txt",
        "file_size": 25,
        "content_type": "text/plain",
        "expiry": "1 hour",
        "max_downloads": "3",
        "password": "LiveAwsPassword99!"
    }
    status, pw_body, _ = make_req("POST", "/api/share", pw_payload)
    assert status == 200, f"PW upload init failed: {status} {pw_body}"
    pw_data = json.loads(pw_body)
    pw_token = pw_data["token"]
    pw_upload_url = pw_data["upload_url"]

    # Upload secret file
    put_req = urllib.request.Request(
        pw_upload_url,
        data=b"Secret Classified Content",
        headers={"Content-Type": "text/plain"},
        method="PUT"
    )
    with urllib.request.urlopen(put_req, timeout=15) as s3_res:
        assert s3_res.status == 200

    # 5a. Attempt download without password -> 401
    status, no_pw, _ = make_req("GET", f"/api/download/{pw_token}", headers={"Accept": "application/json"})
    assert status == 401, f"Expected 401 without password, got {status} {no_pw}"
    print(" ✓ Unauthenticated request rejected (HTTP 401 requires_password)")

    # 5b. Attempt download with wrong password -> 403
    status, wrong_pw, _ = make_req("POST", f"/api/download/{pw_token}", {"password": "WrongPassword!"}, headers={"Accept": "application/json"})
    assert status == 403, f"Expected 403 with wrong password, got {status} {wrong_pw}"
    print(" ✓ Incorrect password rejected (HTTP 403)")

    # 5c. Attempt download with correct password without following redirect
    status, _, headers = make_req(
        "POST",
        f"/api/download/{pw_token}",
        {"password": "LiveAwsPassword99!"},
        headers={"Accept": "text/html,application/xhtml+xml"},
        follow_redirects=False
    )
    # The server responds with 302 redirect to the presigned S3 URL
    assert status == 302 or "Location" in headers, f"Expected 302 redirect, got {status}"
    location = headers.get("Location") or headers.get("location")
    print(f" ✓ Correct password verified, 302 redirect to S3: {location[:65]}...")

    # Download from location to confirm file
    with urllib.request.urlopen(location, timeout=15) as f_res:
        secret_bytes = f_res.read()
    assert secret_bytes == b"Secret Classified Content"
    print(f" ✓ Secret file downloaded from S3 and verified: '{secret_bytes.decode()}'")

    # 6. Download limit enforcement (single download limit)
    print("\n[Live Test 6] Download session limit enforcement (max_downloads: 1)...")
    single_payload = {
        "filename": "one_time.txt",
        "file_size": 10,
        "content_type": "text/plain",
        "expiry": "1 hour",
        "max_downloads": "1"
    }
    status, single_body, _ = make_req("POST", "/api/share", single_payload)
    assert status == 200
    single_data = json.loads(single_body)
    single_token = single_data["token"]

    # 1st download -> 200
    status, res1, _ = make_req("GET", f"/api/download/{single_token}", headers={"Accept": "application/json"})
    assert status == 200, f"1st download failed: {status}"
    print(" ✓ 1st download session allowed (HTTP 200)")

    # 2nd download -> 429
    status, res2, _ = make_req("GET", f"/api/download/{single_token}", headers={"Accept": "application/json"})
    assert status == 429, f"2nd download should be 429, got {status} {res2}"
    print(" ✓ 2nd download session blocked (HTTP 429 Maximum download limit reached)")

    # 7. Revoke and cleanup
    print("\n[Live Test 7] Revoking and cleaning up test documents...")
    status, rev_res, _ = make_req("POST", f"/api/revoke/{token}")
    print(f" ✓ Revoked token {token}: status {status}")
    status, rev_pw, _ = make_req("POST", f"/api/revoke/{pw_token}")
    print(f" ✓ Revoked token {pw_token}: status {status}")
    status, rev_single, _ = make_req("POST", f"/api/revoke/{single_token}")
    print(f" ✓ Revoked token {single_token}: status {status}")

    # Verify revoked token cannot be downloaded
    status, after_rev, _ = make_req("GET", f"/api/download/{token}", headers={"Accept": "application/json"})
    assert status == 404, f"Revoked link should return 404, got {status}"
    print(" ✓ Verified revoked link returns HTTP 404 (inaccessible)")

    print("\n" + "=" * 70)
    print(" 🎉 ALL 7 LIVE AWS VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
