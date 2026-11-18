# ====================================================================
# SecureShare - Windows PowerShell Cleanup Script
# ====================================================================

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "   SecureShare - AWS Cloud Resource Teardown" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

$confirm = Read-Host "Are you sure you want to delete ALL SecureShare AWS resources? (y/N)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
    Write-Host "Cleanup cancelled." -ForegroundColor Yellow
    exit 0
}

python cleanup_aws.py

