# Practical Verification — Rootkit Detection via Kernel Timing
# العمل التطبيقي — كشف الـ Rootkits عبر تحليل توقيتات الـ Kernel

**Reference / المرجع:**
Landauer et al. (2025), *Trace of the Times*, ACM DTRAP 6(4), 1-26.

**Authors / المنفّذون:**
Ahmed Atiyah AL-Zahrani — ID 447001014 — CYBS60201 — Al-Baha University
Mohammed Salem Alghamdi — ID 447000003 — CYBS60201 — Al-Baha University

---

## 🎯 What this does / وش يسوي هذا

**EN:** Re-implements the rootkit detection algorithm from the paper and produces two figures plus a results JSON file.

**AR:** يعيد بناء خوارزمية كشف الـ rootkit من الورقة ويولّد شكلين + ملف نتائج JSON.

**Expected output / المخرجات المتوقعة:**
- `practical_results.json` — detection metrics
- `fig2_distribution_shift.png` — timing distribution shift
- `fig3_score_separation.png` — anomaly score separation
- **F1 score ≈ 0.999** (paper reports 0.99)

---

## 🚀 How to run in VS Code / طريقة التشغيل في VS Code

### الخيار 1 — Notebook التفاعلي (الأفضل للعرض) ⭐

**ليش هذا الأفضل لك:** تشغّل خلية بخلية، الأشكال تطلع داخل المحرر، تقدر تأخذ سكرين شوت لكل خلية للعرض.

#### الخطوات:

1. **افتح المجلد في VS Code:**
   - File → Open Folder → اختر مجلد `practical_package`

2. **ثبّت الـ Extensions المطلوبة** (مرة واحدة فقط):
   - افتح Extensions (`Ctrl+Shift+X`)
   - ثبّت:
     - **Python** (Microsoft)
     - **Jupyter** (Microsoft)

3. **افتح ملف الـ Notebook:**
   - دبل كليك على `practical_analysis.ipynb`

4. **اختر Python Kernel** (أول مرة):
   - أعلى يمين → "Select Kernel" → اختر Python 3.x

5. **ثبّت المكتبات** (افتح Terminal بـ `` Ctrl+` ``):
   ```
   pip install -r requirements.txt
   ```

6. **شغّل كل خلية بـ `Shift+Enter`** أو اضغط زرّ "Run All" أعلى الـ notebook

### الخيار 2 — السكربت العادي (سريع)

1. افتح `practical_analysis.py` في VS Code
2. اضغط **`F5`** للتشغيل المباشر (تم إعداد launch.json لك)
3. أو في Terminal:
   ```
   python practical_analysis.py
   ```

### الخيار 3 — ملف الـ batch (أبسط)

دبل كليك على `run_demo.bat` من Windows Explorer.

---

## 📸 طريقة أخذ السكرين شوت من VS Code

### من الـ Notebook:
- **بعد ما تشتغل الخلية:** كليك يمين على الشكل → **Save Image As**
- **سكرين شوت كامل لخلية:** Win + Shift + S → اختر المنطقة
- الأشكال نفسها محفوظة كـ PNG عالي الدقة في نفس المجلد

### من الـ Terminal:
- نتائج الـ detection: Win + Shift + S → اختر منطقة النص

---

## ⚙️ Requirements / المتطلبات

- Python 3.8 or newer (مثبت عندك ✓)
- VS Code with Python + Jupyter extensions
- المكتبات: `numpy`, `scipy`, `matplotlib` (السكربت يثبّتها تلقائياً)

---

## 📊 What you should see / وش راح تشوف

في الـ terminal:

```
==============================================================================
  DETECTION RESULTS / نتائج الكشف
==============================================================================
  Optimal threshold        : 1.023e-15
  True positives  (TP)     : 500
  False positives (FP)     : 1
  True negatives  (TN)     : 499
  False negatives (FN)     : 0
  Precision                : 0.9980
  Recall                   : 1.0000
  F1 score                 : 0.9990
  Accuracy                 : 0.9990
  False positive rate      : 0.0020

  Paper reports F1 = 0.99  (TP=499, FN=1, FP=9)
==============================================================================
```

---

## ❓ مشاكل شائعة

### ❌ "Select Kernel" ما يظهر Python
- تأكد من تثبيت **Python extension** و **Jupyter extension**
- اعمل Reload Window: `Ctrl+Shift+P` → "Reload Window"

### ❌ "No module named 'numpy'"
في Terminal داخل VS Code:
```
pip install numpy scipy matplotlib
```

### ❌ الـ Notebook ما يفتح
- جرّب: File → Open → اختر `practical_analysis.ipynb` يدوياً
- تأكد من Jupyter extension

### ❌ Python الخطأ يُستخدم
- `Ctrl+Shift+P` → "Python: Select Interpreter" → اختر النسخة الصحيحة

---

## 📁 File map / خريطة الملفات

```
practical_package/
├── .vscode/
│   ├── launch.json              ← F5 run config
│   └── settings.json            ← Workspace settings
├── practical_analysis.ipynb     ← Interactive notebook (الأفضل)
├── practical_analysis.py        ← Standalone script
├── requirements.txt             ← Python packages
├── run_demo.bat                 ← Windows one-click
├── run_demo.sh                  ← Mac/Linux one-click
├── README.md                    ← This file
│
└── After running / بعد التشغيل:
    ├── practical_results.json
    ├── fig2_distribution_shift.png
    └── fig3_score_separation.png
```

---

## 🔁 Reproducibility / إعادة الإنتاج

البذرة العشوائية مثبّتة على **447001014** (رقم الطالب). كل تشغيل يعطي نفس النتائج.

---

## 📜 License / الترخيص

استخدام أكاديمي لمقرر CYBS60201 — جامعة الباحة.
Based on the open-source release by Landauer et al. (2025), CC BY 4.0.
