# docker-run.ps1 - PowerShell script for Windows users

Write-Host "Building Docker image..." -ForegroundColor Cyan
docker-compose build

Write-Host "Starting email spoofing tool..." -ForegroundColor Cyan
docker-compose run --rm email-tool interactive