# Rootkit Detection through Temporal Anomalies
## Critical Analysis & Reproduction Study

A reproducible implementation of the statistical detection
mechanism proposed by Landauer et al. (2025) in
ACM Digital Threats 6(4).

---

### 📚 Course
**CYBS60202** — Operating System Security
Al-Baha University, M.Sc. Cybersecurity Program

### 👥 Authors
- Ahmed Atiyah AL-Zahrani (447001014)
- Mohammed Salem Alghamdi (447000003)

### 👨‍🏫 Course Instructor
Dr. Anwar Saeed Saleh Alsokari Alghamdi

---

### 🎯 What This Repository Contains
- Synthetic reproduction of detection algorithm
- 9-quantile + Mahalanobis + chi-square pipeline
- Validation against published parameters
- Fully reproducible (fixed seed = 447001014)

### 📊 Results
| Metric | Our Value | Paper Value |
|--------|-----------|-------------|
| F1 Score | 0.999 | 0.99 |
| True Positives | 500 | 499 |
| False Positives | 1 | 9 |

### 🚀 Quick Start
```bash
pip install -r requirements.txt
python practical_analysis.py
```

### 📖 Original Paper
> Landauer, M., et al. (2025).
> Trace of the Times: Rootkit Detection through Temporal
> Anomalies in Kernel Activity.
> ACM Digital Threats: Research and Practice, 6(4).
> DOI: 10.1145/3770085

### ⚠️ Disclaimer
This is an academic reproduction study for educational
purposes. The original research credit belongs entirely to
Landauer et al.

### 📜 License
MIT License — Academic use encouraged with citation.

## 📜 License / الترخيص

استخدام أكاديمي لمقرر CYBS60202 — جامعة الباحة.
Based on the open-source release by Landauer et al. (2025), CC BY 4.0.
