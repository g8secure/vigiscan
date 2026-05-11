# run_scanner.ps1
# Launch ZAP, Flask, and open dashboard in browser

# 1️⃣ Start ZAP
Write-Host "Starting OWASP ZAP..."
Start-Process -FilePath "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# 2️⃣ Wait a few seconds to ensure ZAP starts
Start-Sleep -Seconds 10

# 3️⃣ Start Flask App
Write-Host "Starting Flask app..."
Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m flask --app app run"

# 4️⃣ Wait a few seconds to let Flask start
Start-Sleep -Seconds 5

# 5️⃣ Open browser to dashboard
Write-Host "Opening dashboard in default browser..."
Start-Process "http://127.0.0.1:5000"