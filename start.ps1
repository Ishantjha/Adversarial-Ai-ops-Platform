# start.ps1
# One-click startup script for AIOps Platform

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "   AIOps Platform - Starting Up" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Activate venv
Write-Host "`n[1] Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Set Python path
$env:PYTHONPATH = (Get-Location).Path
Write-Host "[2] PYTHONPATH set to: $env:PYTHONPATH" -ForegroundColor Yellow

# Check if models exist
if (!(Test-Path "models\isolation_forest.pkl")) {
    Write-Host "`n[3] Models not found. Training now..." -ForegroundColor Red
    python -m src.utils.data_simulator
    python -m src.detectors.anomaly_detector
} else {
    Write-Host "[3] Models found. Skipping training." -ForegroundColor Green
}

# Start API
Write-Host "`n[4] Starting API server..." -ForegroundColor Yellow
Write-Host "    API:       http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "    API Docs:  http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "    Dashboard: Open dashboard/index.html in browser" -ForegroundColor Green
Write-Host "`n Press Ctrl+C to stop the server`n" -ForegroundColor Gray

python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload