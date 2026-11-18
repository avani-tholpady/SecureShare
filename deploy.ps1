# ====================================================================
# SecureShare - Windows PowerShell Deployment Script
# ====================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SecureShare - Cloud-Based Document Exchange Deployment" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "❌ Error: Python 3 is required but was not found in PATH." -ForegroundColor Red
    exit 1
}

# 2. Build Lambda Package
Write-Host "`n[Step 1] Building Lambda deployment package..." -ForegroundColor Yellow
python build_package.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Error packaging Lambda function." -ForegroundColor Red
    exit 1
}

# 3. Check for SAM CLI
$samCmd = Get-Command sam -ErrorAction SilentlyContinue
if ($samCmd) {
    Write-Host "`n[Step 2] Found AWS SAM CLI. Running SAM build & deploy..." -ForegroundColor Yellow
    sam build
    sam deploy --guided
    exit 0
}

# 4. Fallback to automated Python Boto3 deployment script
Write-Host "`n[Step 2] AWS SAM CLI not installed. Using Python Boto3 deployment..." -ForegroundColor Yellow
python deploy_aws.py

