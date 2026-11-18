# 🔐 SecureShare – Secure Cloud-Based File Sharing

<p align="center">
  <strong>Share files securely. Stay in control.</strong>
</p>

<p align="center">
  <a href="https://secureshare-neon.vercel.app/">🌐 Live Demo</a> ·
  <a href="https://secureshare-neon.vercel.app/">🚀 Try SecureShare</a>
</p>

---

## 🌐 Live Application

**Try SecureShare here:**

### https://secureshare-neon.vercel.app/

SecureShare is a cloud-based file-sharing application that enables users to upload files and share them through secure, temporary links with configurable expiration times, optional password protection and download limits.

## 📌 Overview

Traditional file-sharing methods often provide limited control over how long a file remains accessible and how many times it can be downloaded.

SecureShare addresses this by combining cloud storage with controlled access mechanisms. Users can upload files, configure sharing restrictions and generate unique links that can be shared with others.

The application uses AWS cloud services to manage file storage, backend processing and sharing information.

## ✨ Key Features

- **Secure File Upload:** Upload files up to 16 MB.
- **Drag and Drop:** Easily select files using drag-and-drop functionality.
- **Temporary Sharing Links:** Generate unique links for uploaded files.
- **Link Expiration:** Configure links to expire after 1 hour, 24 hours or 7 days.
- **Password Protection:** Optionally protect shared files with a password.
- **Download Restrictions:** Set maximum download limits of 1, 3, 5 or 10.
- **Private Cloud Storage:** Store files in a private Amazon S3 bucket.
- **Upload Progress Tracking:** Monitor file uploads in real time.
- **One-Click Sharing:** Copy generated sharing links easily.
- **Responsive Interface:** Access the application from desktop, tablet and mobile devices.

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python |
| Cloud Platform | Amazon Web Services (AWS) |
| API Management | Amazon API Gateway |
| Serverless Computing | AWS Lambda |
| File Storage | Amazon S3 |
| Database | Amazon DynamoDB |
| Frontend Hosting | Vercel |

## 🏗️ System Architecture

SecureShare follows a serverless cloud architecture.

```text
              USER
                |
                v
       FRONTEND (VERCEL)
        HTML, CSS, JS
                |
                v
       AMAZON API GATEWAY
                |
                v
          AWS LAMBDA
          (PYTHON)
           /       \
          v         v
    AMAZON S3    DYNAMODB
   (File Storage) (Metadata)
          |
          v
    PRESIGNED URL
          |
          v
    SECURE DOWNLOAD
```

### How It Works

**1. File Selection**

The sender selects a file and configures the expiration period, download limit and optional password.

**2. Upload Request**

The frontend sends file metadata to Amazon API Gateway, which forwards the request to the AWS Lambda backend.

**3. Presigned URL Generation**

Lambda validates the request, generates a unique sharing token and creates a temporary presigned S3 upload URL.

**4. Cloud Storage**

The browser uploads the actual file directly to the private Amazon S3 bucket using the presigned URL. Sharing information is stored in DynamoDB.

**5. Sharing Link Generation**

After a successful upload, SecureShare displays a unique sharing link that the sender can copy and share.

**6. File Download**

When the receiver opens the link, the backend validates the token, expiry, password requirements and download restrictions.

If the request is valid, the receiver gets access through a temporary presigned S3 download URL.

**7. Access Control**

Expired, revoked or download-limit-exceeded links are rejected by the backend.

## 🔒 Security Features

- Private Amazon S3 bucket with Block Public Access enabled.
- AES-256 server-side encryption.
- Temporary presigned URLs for file operations.
- Unique sharing tokens.
- Password hashing on the backend.
- Expiration and download-limit validation.
- Controlled access to shared files.

## ☁️ AWS Deployment Details

The backend is deployed in the AWS Sydney region (`ap-southeast-2`).

| AWS Service | Configuration |
|---|---|
| Amazon S3 | `secureshare-files-2026-4827` |
| DynamoDB | `ShareLinks` |
| AWS Lambda | `SecureShareBackend` |
| API Gateway | HTTP API |

**Backend API:**

https://mib95ppjqf.execute-api.ap-southeast-2.amazonaws.com

**Health Check:**

https://mib95ppjqf.execute-api.ap-southeast-2.amazonaws.com/api/health

The S3 bucket has a 30-day automatic object lifecycle cleanup policy.

## 🧪 Testing

The project was tested using automated test suites and live AWS integration tests.

Reported testing results:

- 7 live AWS integration tests passed.
- 17 serverless backend tests passed.
- 7 Flask application tests passed.
- Total: 31 tests passed.

Tests cover upload initiation, file uploads, downloads, password verification, expiration, download limits and link revocation.

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <your-github-repository-url>
```

### 2. Navigate to the Project

```bash
cd SecureShare
```

### 3. Configure the API

Update `config.js` with your deployed AWS API endpoint:

```javascript
window.API_BASE_URL =
"https://mib95ppjqf.execute-api.ap-southeast-2.amazonaws.com";
```

### 4. Run the Frontend

Open `index.html` using a local development server, such as VS Code Live Server.

The application will connect to the deployed AWS backend.

**Note:** A working AWS backend and correctly configured S3 CORS settings are required for cloud upload and download functionality.

## 📁 Project Structure

```text
SecureShare/
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   ├── script.js
│   └── config.js
│
├── lambda_function.py
├── app.py
├── deploy_aws.py
├── build_package.py
├── requirements.txt
├── requirements-lambda.txt
├── dynamodb_setup.py
├── s3_setup.py
├── test_suite.py
├── test_flask_app.py
├── test_live_aws.py
├── template.yaml
├── vercel.json
└── README.md
```

## 🎯 Future Enhancements

- User authentication and account management.
- Dashboard to manage uploaded files.
- File access analytics.
- Email notifications before link expiration.
- Support for larger file uploads.
- Improved file activity monitoring.

## 👩‍💻 Author

**Avani Tholpady**

Information Science and Engineering Student

## ⭐ Support

If you find SecureShare interesting, consider giving this repository a star on GitHub!

---

<p align="center">
  <strong>SecureShare – Making file sharing simpler, safer and smarter. 🔐</strong>
</p>
