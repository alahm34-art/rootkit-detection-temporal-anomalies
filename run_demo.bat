@echo off
REM ============================================================================
REM  Practical Verification — One-Click Run Script for Windows
REM  ملف تشغيل بنقرة واحدة على ويندوز
REM ============================================================================

setlocal
cd /d "%~dp0"

echo ============================================================================
echo   PRACTICAL VERIFICATION - Rootkit Detection via Kernel Timing
echo   Ahmed Atiyah AL-Zahrani ^& Mohammed Salem Alghamdi  ^|  CYBS60201 OS Security
echo ============================================================================
echo.

REM Check if Python is installed / تأكد من وجود بايثون
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo [خطأ] بايثون غير مثبت او غير موجود في PATH.
    echo.
    echo Download from: https://www.python.org/downloads/
    echo During install, CHECK the box "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo [Step 1] Installing required packages / تثبيت المكتبات...
python -m pip install --quiet --user -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install packages.
    pause
    exit /b 1
)
echo         Done.
echo.

echo [Step 2] Running the analysis / تشغيل التحليل...
echo.
python practical_analysis.py
if errorlevel 1 (
    echo [ERROR] Script failed.
    pause
    exit /b 1
)

echo.
echo ============================================================================
echo   ALL DONE.  Files generated in this folder:
echo   تم.  الملفات المُولّدة في هذا المجلد:
echo     - practical_results.json
echo     - fig2_distribution_shift.png
echo     - fig3_score_separation.png
echo ============================================================================
echo.
pause
