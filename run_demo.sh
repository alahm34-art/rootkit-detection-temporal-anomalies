#!/usr/bin/env bash
# ============================================================================
#  Practical Verification — One-Click Run Script for Mac / Linux
#  ملف تشغيل بنقرة واحدة على ماك / لينكس
# ============================================================================

set -e
cd "$(dirname "$0")"

echo "============================================================================"
echo "  PRACTICAL VERIFICATION - Rootkit Detection via Kernel Timing"
echo "  Ahmed Atiyah AL-Zahrani & Mohammed Salem Alghamdi  |  CYBS60201 OS Security"
echo "============================================================================"
echo ""

# Detect python command / اكتشف أمر بايثون
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "[ERROR] Python is not installed."
    echo "[خطأ] بايثون غير مثبت."
    echo ""
    echo "  Mac:   brew install python3"
    echo "  Linux: sudo apt install python3 python3-pip"
    exit 1
fi

echo "[Step 1] Installing required packages / تثبيت المكتبات..."
$PY -m pip install --quiet --user -r requirements.txt
echo "        Done."
echo ""

echo "[Step 2] Running the analysis / تشغيل التحليل..."
echo ""
$PY practical_analysis.py

echo ""
echo "============================================================================"
echo "  ALL DONE.  Files generated in this folder:"
echo "  تم.  الملفات المُولّدة في هذا المجلد:"
echo "    - practical_results.json"
echo "    - fig2_distribution_shift.png"
echo "    - fig3_score_separation.png"
echo "============================================================================"
