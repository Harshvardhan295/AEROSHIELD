@echo off
title AeroShield Malware Detector Web App
echo ========================================================
echo   AEROSHIELD: Windows PE Malware Detection 
echo ========================================================
echo.
echo Starting web server on http://localhost:8000 ...
echo Press Ctrl+C to stop the server at any time.
echo.
start http://localhost:8000
"C:\Users\HARSHVARDHAN\AppData\Local\Programs\Python\Python313\python.exe" app\server.py
pause
