@echo off
echo.
echo =============================================
echo CyberSentinel - Startup
echo =============================================
echo.

set GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE

echo Starting Flask server...
echo Open http://127.0.0.1:5000 in your browser
echo.

python app.py
pause